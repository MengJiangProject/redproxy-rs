use crate::context::TargetAddress;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::boxed::Box;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::SocketAddr;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

const MAGIC: &[u8] = b"RPFM";
const ATYP_IPV4: u8 = 1u8;
const ATYP_IPV6: u8 = 2u8;
const ATYP_HOST: u8 = 3u8;

pub struct Frame {
    pub addr: Option<TargetAddress>,
    pub session_id: u32,
    body: Bytes,
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
        MAGIC: [u8;4] = b"UDPF";
        SESSID: u32
        ATTR_LEN: u16
        ATTR: [T: u8, L:u8, V: [u8]]
        BODY_LEN: u16
        BODY: [u8]
    */
    // Try to read from buffer, return None if frame incomplete,
    // Returns: Some(Ok(frame, remaining)) or Some(Err(error))
    pub fn from_buffer(mut buf: Bytes) -> Option<IoResult<(Self, Bytes)>> {
        if buf.len() < 12 {
            return None;
        }
        let magic = buf.split_to(4);
        if magic != MAGIC {
            return Some(Err(IoError::new(
                ErrorKind::Other,
                format!("Invalid magic: {:?}", magic),
            )));
        }
        let session_id = buf.get_u32();
        let header_len = buf.get_u16() as usize;
        if buf.len() < header_len + 2 {
            return None;
        }
        let header = buf.split_to(header_len);
        let body_len = buf.get_u16() as usize;
        if buf.len() < body_len {
            return None;
        }
        let body = buf.split_to(body_len);
        let mut frame = Self::from_body(body);
        if let Err(e) = frame.parse_header(header) {
            return Some(Err(e));
        }
        frame.session_id = session_id;
        Some(Ok((frame, buf)))
    }

    pub fn make_header(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(256);
        buf.put(MAGIC);
        buf.put_u32(self.session_id);
        let addr = encode_address(self.addr.as_ref());
        buf.put_u16(addr.len() as u16);
        buf.put(addr);
        buf.put_u16(self.body.len() as u16);
        buf.freeze()
    }

    pub fn parse_header(&mut self, header: Bytes) -> IoResult<()> {
        self.addr = decode_address(header)?;
        Ok(())
    }

    // Write head and body to output stream
    pub async fn write_to<T: AsyncWrite + Unpin>(&self, output: &mut T) -> IoResult<()> {
        let head = self.make_header();
        output.write_all(&head).await?;
        output.write_all(&self.body).await?;
        Ok(())
    }
}

pub type Frames = (Box<dyn FrameReader>, Box<dyn FrameWriter>);

#[async_trait]
pub trait FrameReader: Send + Sync {
    async fn read(&mut self) -> IoResult<Option<Frame>>;
}

#[async_trait]
pub trait FrameWriter: Send + Sync {
    async fn write(&mut self, frame: &Frame) -> IoResult<()>;
    async fn shutdown(&mut self) -> IoResult<()>;
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
fn encode_address(addr: Option<&TargetAddress>) -> BytesMut {
    if addr.is_none() {
        return BytesMut::with_capacity(0);
    }
    let addr = addr.unwrap();
    let mut buf = BytesMut::with_capacity(512);
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
    buf
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_buffers() {
        let data = Bytes::from_static(
            b"RPFM\x00\x00\x00\x01\x00\x08\x01\x06\x01\x02\x03\x04\x00\x01\x00\x02abcdef",
        );
        let (pkt, left) = Frame::from_buffer(data.clone()).unwrap().unwrap();
        assert_eq!(pkt.body(), &Bytes::from_static(b"ab"));
        assert_eq!(pkt.session_id, 1);
        assert_eq!(pkt.addr, Some("1.2.3.4:1".parse().unwrap()));
        assert_eq!(left, Bytes::from_static(b"cdef"));
        let header = pkt.make_header();
        assert_eq!(header, data.slice(0..20));
    }
}
