use crate::context::TargetAddress;
use async_trait::async_trait;
use bytes::buf::Chain;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::boxed::Box;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use tokio::net::UdpSocket;

use super::fragment::Fragmentable;

const MAGIC: u32 = 0x5250464d; // &[u8] = b"RPFM";
const ATYP_IPV4: u8 = 1u8;
const ATYP_IPV6: u8 = 2u8;
const ATYP_HOST: u8 = 3u8;

#[derive(Debug, Default)]
pub struct Frame {
    pub addr: Option<TargetAddress>,
    pub session_id: u32,
    pub body: Bytes,
}

#[allow(dead_code)]
impl Frame {
    pub fn new() -> Frame {
        Frame {
            body: Default::default(),
            session_id: 0,
            addr: None,
        }
    }

    pub fn from_body(buf: Bytes) -> Frame {
        Frame {
            addr: None,
            session_id: 0,
            body: buf,
        }
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn len(&self) -> usize {
        self.body.len()
    }

    // Read from UDP socket, set addr to source
    pub async fn recv_from(&mut self, socket: &UdpSocket) -> IoResult<(usize, SocketAddr)> {
        let mut buf = BytesMut::zeroed(65536);
        let (size, source) = socket.recv_from(&mut buf).await?;
        buf.truncate(size);
        self.body = buf.freeze();
        self.addr = Some(source.into());
        Ok((size, source))
    }

    /*
        Serialized buffer format:
        MAGIC: [u8;4] = b"RPFM";
        SESSID: u32
        ATTR_LEN: u16
        BODY_LEN: u16
        ATTR: [T: u8, L:u8, V: [u8]]
        BODY: [u8]
    */
    // Try to read frame header,
    // return expected buffer length or None if buffer is too short for headers,
    pub fn read_head(mut buf: impl Buf) -> IoResult<Option<usize>> {
        if buf.remaining() < 12 {
            return Ok(None);
        }
        let magic = buf.get_u32();
        if magic != MAGIC {
            return Err(IoError::other(format!("Invalid magic: {:?}", magic)));
        }
        let _session_id = buf.get_u32();
        let attr_len = buf.get_u16() as usize;
        let body_len = buf.get_u16() as usize;
        Ok(Some(12 + attr_len + body_len))
    }
    // Read frame from buffer
    pub fn from_buffer(mut buf: Bytes) -> IoResult<Self> {
        if buf.len() < 12 {
            return Err(IoError::new(ErrorKind::InvalidData, "Buffer too short"));
        }
        let mut head = &buf[0..12];
        let magic = head.get_u32();
        if magic != MAGIC {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("Invalid magic: {:?}", magic),
            ));
        }
        let session_id = head.get_u32();
        let attr_len = head.get_u16() as usize;
        let body_len = head.get_u16() as usize;
        if buf.len() < 12 + attr_len + body_len {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "Truncated frame: expecting {:?} bytes , got {:?}",
                    12 + attr_len + body_len,
                    buf.len()
                ),
            ));
        }
        buf.advance(12);
        let attr = buf.split_to(attr_len);
        let body = buf.split_to(body_len);
        let mut frame = Self::from_body(body);
        frame.parse_attr(attr)?;
        frame.session_id = session_id;
        Ok(frame)
    }

    pub fn make_header(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(1024);
        let mut addr = buf.split_off(12);
        encode_address(&mut addr, self.addr.as_ref());
        buf.put_u32(MAGIC);
        buf.put_u32(self.session_id);
        buf.put_u16(addr.len() as u16);
        buf.put_u16(self.body.len() as u16);
        buf.unsplit(addr);
        buf
    }

    pub fn parse_attr(&mut self, buf: Bytes) -> IoResult<()> {
        self.addr = decode_address(buf)?;
        Ok(())
    }

    // Write head and body to output stream
    pub async fn write_to<T: AsyncWrite + Unpin>(&self, output: &mut T) -> IoResult<usize> {
        let head = self.make_header();
        output.write_all(&head).await?;
        output.write_all(&self.body).await?;
        output.flush().await?;
        Ok(head.len() + self.body.len())
    }
}

impl Fragmentable for Frame {
    type Buffer = Chain<BytesMut, Bytes>;
    fn as_buffer(&self) -> Self::Buffer {
        let head = self.make_header();
        head.chain(self.body.clone())
    }

    fn from_buffer(buf: Bytes) -> Option<Self> {
        Frame::from_buffer(buf).ok()
    }
}

pub type FrameIO = (Box<dyn FrameReader>, Box<dyn FrameWriter>);

#[async_trait]
pub trait FrameReader: Send + Sync {
    async fn read(&mut self) -> IoResult<Option<Frame>>;
}

#[async_trait]
pub trait FrameWriter: Send + Sync {
    async fn write(&mut self, frame: Frame) -> IoResult<usize>;
    async fn shutdown(&mut self) -> IoResult<()>;
}

pub fn frames_from_stream<T>(session_id: u32, stream: T) -> FrameIO
where
    T: AsyncRead + AsyncWrite + Sync + Send + 'static,
{
    let (r, w) = split(stream);
    let r = StreamFrameReader::new(r);
    let w = StreamFrameWriter::new(w, session_id);
    (Box::new(r), Box::new(w))
}

struct StreamFrameReader<T> {
    inner: T,
    remaining: Option<BytesMut>,
}

impl<T> StreamFrameReader<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            remaining: None,
        }
    }
}

#[async_trait]
impl<T> FrameReader for StreamFrameReader<T>
where
    T: AsyncRead + Sync + Send + Unpin,
{
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        loop {
            if let Some(buf) = self.remaining.as_mut() {
                if let Some(ret) = Frame::read_head(&buf[..])? {
                    tracing::trace!("read frame from stream: {:?}", ret);
                    if buf.len() >= ret {
                        let buf = buf.split_to(ret).freeze();
                        let ret = Frame::from_buffer(buf).unwrap();
                        return Ok(Some(ret));
                    }
                }
            } else {
                self.remaining = Some(BytesMut::with_capacity(65536 * 2));
            }
            let mut buf = self.remaining.take().unwrap();
            let mut last = buf.split();
            buf.reserve(65536);
            unsafe {
                buf.set_len(65536);
            }
            let len = self.inner.read(&mut buf).await?;
            if len == 0 {
                return Ok(None);
            }
            buf.truncate(len);
            last.unsplit(buf);
            self.remaining = Some(last);
        }
    }
}

struct StreamFrameWriter<T> {
    inner: T,
    session_id: u32,
}

impl<T> StreamFrameWriter<T> {
    fn new(inner: T, session_id: u32) -> Self {
        Self { inner, session_id }
    }
}

#[async_trait]
impl<T> FrameWriter for StreamFrameWriter<T>
where
    T: AsyncWrite + Sync + Send + Unpin,
{
    async fn write(&mut self, mut frame: Frame) -> IoResult<usize> {
        tracing::trace!("write frame to stream: {:?}", frame);
        frame.session_id = self.session_id;
        frame.write_to(&mut self.inner).await
    }
    async fn shutdown(&mut self) -> IoResult<()> {
        self.inner.flush().await?;
        self.inner.shutdown().await?;
        Ok(())
    }
}

fn decode_address(mut buf: Bytes) -> IoResult<Option<TargetAddress>> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.len() < 8 {
        return Err(IoError::new(ErrorKind::InvalidInput, "bad header"));
    }
    let tag = buf.get_u8();
    let len = buf.get_u8() as usize;
    if len > buf.len() {
        return Err(IoError::new(ErrorKind::InvalidInput, "bad header"));
    }
    match tag {
        ATYP_HOST => {
            if len < 2 {
                return Err(IoError::new(ErrorKind::InvalidInput, "bad header"));
            }
            let host = String::from_utf8_lossy(&buf.split_to(len - 2)).to_string();
            let port = buf.get_u16();
            Ok(Some((host, port).into()))
        }
        ATYP_IPV4 => {
            if len != 6 {
                return Err(IoError::new(ErrorKind::InvalidInput, "bad header"));
            }
            let host = buf.get_u32();
            let port = buf.get_u16();
            Ok(Some((host, port).into()))
        }
        ATYP_IPV6 => {
            if len != 18 {
                return Err(IoError::new(ErrorKind::InvalidInput, "bad header"));
            }
            let mut host = [0u8; 16];
            buf.copy_to_slice(&mut host);
            let port = buf.get_u16();
            Ok(Some((host, port).into()))
        }
        _ => Err(IoError::new(ErrorKind::InvalidInput, "bad header")),
    }
}
fn encode_address(buf: &mut BytesMut, addr: Option<&TargetAddress>) {
    if addr.is_none() {
        return;
    }
    let addr = addr.unwrap();
    match addr {
        TargetAddress::DomainPort(host, port) => {
            let str = host.as_bytes();
            let len = str.len() + 2;
            buf.put_u8(ATYP_HOST);
            buf.put_u8(len as u8);
            buf.put_slice(str);
            buf.put_u16(*port);
        }
        TargetAddress::SocketAddr(addr) => match addr {
            SocketAddr::V4(v4) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_u8(6u8);
                buf.put_slice(&v4.ip().octets());
                buf.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_u8(18u8);
                buf.put_slice(&v6.ip().octets());
                buf.put_u16(v6.port());
            }
        },
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_read_head() {
        let raw = b"RPFM\x00\x00\x00\x01\x00\x08\x00\x02\x01\x06\x01\x02\x03\x04\x00\x01abcdef";
        let data = Bytes::from(&raw[..]);
        let len = Frame::read_head(data).unwrap().unwrap();
        assert_eq!(len, 22);
    }
    #[test]
    fn test_buffers() {
        let raw = b"RPFM\x00\x00\x00\x01\x00\x08\x00\x02\x01\x06\x01\x02\x03\x04\x00\x01abcdef";
        let data = Bytes::from(&raw[..]);
        let pkt = Frame::from_buffer(data).unwrap();
        assert_eq!(pkt.body(), &Bytes::from_static(b"ab"));
        assert_eq!(pkt.session_id, 1);
        assert_eq!(pkt.addr, Some("1.2.3.4:1".parse().unwrap()));
        let header = pkt.make_header();
        assert_eq!(header, raw[0..20]);
    }

    use tokio_test::io::Builder;
    #[tokio::test]
    async fn test_stream_read() {
        let raw = b"RPFM\x00\x00\x00\x01\x00\x08\x00\x02\x01\x06\x01\x02\x03\x04\x00\x01abcdef";
        let stream = Builder::new().read(raw).build();
        let mut reader = StreamFrameReader::new(stream);
        let pkt = reader.read().await.unwrap().unwrap();
        assert_eq!(pkt.body(), &Bytes::from_static(b"ab"));
        assert_eq!(pkt.session_id, 1);
        assert_eq!(pkt.addr, Some("1.2.3.4:1".parse().unwrap()));
        let ret = reader.read().await;
        assert!(ret.is_err() || ret.unwrap().is_none());
    }
}
