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

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
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

// Create RFC 9298-aware frame I/O that handles capsule protocol on the wire
pub fn rfc9298_frames_from_stream<T>(session_id: u32, stream: T) -> FrameIO
where
    T: AsyncRead + AsyncWrite + Sync + Send + 'static,
{
    let (r, w) = split(stream);
    let r = Rfc9298StreamFrameReader::new(r, session_id);
    let w = Rfc9298StreamFrameWriter::new(w, session_id);
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

// RFC 9298 Stream Frame Reader - implements FrameReader but handles RFC 9298 wire protocol
struct Rfc9298StreamFrameReader<T> {
    inner: T,
    session_id: u32,
    remaining: Option<BytesMut>,
}

impl<T> Rfc9298StreamFrameReader<T> {
    fn new(inner: T, session_id: u32) -> Self {
        Self {
            inner,
            session_id,
            remaining: None,
        }
    }
}

#[async_trait]
impl<T> FrameReader for Rfc9298StreamFrameReader<T>
where
    T: AsyncRead + Send + Sync + Unpin,
{
    async fn read(&mut self) -> IoResult<Option<Frame>> {
        loop {
            if let Some(buf) = self.remaining.as_mut() {
                // Try to read HTTP Datagram length prefix (variable-length integer)
                if !buf.is_empty() {
                    // Try to decode varint length
                    let mut peek_buf = buf.clone();
                    if let Ok(length) = decode_varint_peek(&mut peek_buf) {
                        let varint_len = buf.len() - peek_buf.len();
                        if buf.len() >= varint_len + length as usize {
                            // We have a complete HTTP Datagram
                            let _length_bytes = buf.split_to(varint_len); // Skip length prefix
                            let datagram_data = buf.split_to(length as usize).freeze();

                            // Decode RFC 9298 capsule
                            if let Ok(rfc9298_frame) = decode_rfc9298_capsule(datagram_data) {
                                // Convert to internal Frame format
                                let mut frame = Frame::from_body(rfc9298_frame.payload);
                                frame.session_id = self.session_id;
                                // RFC 9298 doesn't encode address in the payload, so addr remains None
                                return Ok(Some(frame));
                            }
                        }
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

// RFC 9298 Stream Frame Writer - implements FrameWriter but outputs RFC 9298 wire protocol
struct Rfc9298StreamFrameWriter<T> {
    inner: T,
    session_id: u32,
}

impl<T> Rfc9298StreamFrameWriter<T> {
    fn new(inner: T, session_id: u32) -> Self {
        Self { inner, session_id }
    }
}

#[async_trait]
impl<T> FrameWriter for Rfc9298StreamFrameWriter<T>
where
    T: AsyncWrite + Send + Sync + Unpin,
{
    async fn write(&mut self, frame: Frame) -> IoResult<usize> {
        tracing::trace!(
            "write RFC 9298 frame: session_id={} len={}",
            self.session_id,
            frame.len()
        );

        // Create RFC 9298 capsule with Context ID 0 (UDP payload)
        let rfc9298_frame = Rfc9298Frame::udp_payload(frame.body);
        let encoded_capsule = encode_rfc9298_capsule(&rfc9298_frame);

        // Write HTTP Datagram with variable-length integer length prefix
        let mut length_buf = BytesMut::new();
        encode_varint(&mut length_buf, encoded_capsule.len() as u64);

        self.inner.write_all(&length_buf).await?;
        self.inner.write_all(&encoded_capsule).await?;
        self.inner.flush().await?;

        Ok(length_buf.len() + encoded_capsule.len())
    }

    async fn shutdown(&mut self) -> IoResult<()> {
        self.inner.flush().await?;
        self.inner.shutdown().await?;
        Ok(())
    }
}

// RFC 9298 Capsule Protocol structures and helpers
#[derive(Debug, Clone)]
struct Rfc9298Frame {
    context_id: u64, // 62-bit Context ID
    payload: Bytes,
}

impl Rfc9298Frame {
    fn udp_payload(payload: Bytes) -> Self {
        Self {
            context_id: 0, // Context ID 0 for UDP payloads per RFC 9298
            payload,
        }
    }
}

// Variable-length integer encoding (QUIC style) for RFC 9298
fn encode_varint(buf: &mut BytesMut, value: u64) {
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u16((value | 0x4000) as u16);
    } else if value < 1073741824 {
        buf.put_u32((value | 0x80000000) as u32);
    } else {
        buf.put_u64(value | 0xC000000000000000);
    }
}

fn decode_varint_peek(buf: &mut impl Buf) -> IoResult<u64> {
    if buf.remaining() == 0 {
        return Err(IoError::new(ErrorKind::UnexpectedEof, "Buffer empty"));
    }

    let first_byte = buf.chunk()[0];
    let length = 1 << (first_byte >> 6);

    if buf.remaining() < length {
        return Err(IoError::new(ErrorKind::UnexpectedEof, "Incomplete varint"));
    }

    let mut value = (first_byte & 0x3F) as u64;
    buf.advance(1);
    for _ in 1..length {
        value = (value << 8) | (buf.get_u8() as u64);
    }

    Ok(value)
}

// Encode RFC 9298 capsule
fn encode_rfc9298_capsule(frame: &Rfc9298Frame) -> Bytes {
    let mut buf = BytesMut::new();

    // Encode Context ID as variable-length integer
    encode_varint(&mut buf, frame.context_id);

    // Add payload
    buf.extend_from_slice(&frame.payload);

    buf.freeze()
}

// Decode RFC 9298 capsule
fn decode_rfc9298_capsule(mut data: Bytes) -> IoResult<Rfc9298Frame> {
    if data.is_empty() {
        return Err(IoError::new(ErrorKind::InvalidData, "Empty capsule"));
    }

    let context_id = decode_varint_peek(&mut data)?;
    let payload = data;

    Ok(Rfc9298Frame {
        context_id: context_id & 0x3FFF_FFFF_FFFF_FFFF, // Mask to 62 bits
        payload,
    })
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

    #[test]
    fn test_rfc9298_varint_encoding() {
        // Test small values (1 byte)
        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 42);
        assert_eq!(buf.len(), 1);
        let mut bytes = buf.freeze();
        assert_eq!(decode_varint_peek(&mut bytes).unwrap(), 42);

        // Test medium values (2 bytes)
        let mut buf = BytesMut::new();
        encode_varint(&mut buf, 1000);
        assert_eq!(buf.len(), 2);
        let mut bytes = buf.freeze();
        assert_eq!(decode_varint_peek(&mut bytes).unwrap(), 1000);

        // Test large values (8 bytes)
        let mut buf = BytesMut::new();
        let large_val = 0x3FFF_FFFF_FFFF_FFFF_u64;
        encode_varint(&mut buf, large_val);
        assert_eq!(buf.len(), 8);
        let mut bytes = buf.freeze();
        assert_eq!(decode_varint_peek(&mut bytes).unwrap(), large_val);
    }

    #[test]
    fn test_rfc9298_capsule_encoding() {
        // Test UDP payload (Context ID 0)
        let payload = Bytes::from("Hello, RFC 9298!");
        let frame = Rfc9298Frame::udp_payload(payload.clone());
        assert_eq!(frame.context_id, 0);

        let encoded = encode_rfc9298_capsule(&frame);
        let decoded = decode_rfc9298_capsule(encoded).unwrap();
        assert_eq!(decoded.context_id, 0);
        assert_eq!(decoded.payload, payload);
    }
}
