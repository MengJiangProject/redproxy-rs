use bytes::{Buf, BufMut, BytesMut};
static MAGIC: &[u8] = b"UDPPKT";
pub struct UdpBuffer {
    body: BytesMut,
    head: BytesMut,
}
// Why not use Framed in tokio_util::codec?
// Because Decoder and Encoder trait will cause extra copy
impl UdpBuffer {
    pub fn new() -> UdpBuffer {
        let mut head = BytesMut::with_capacity(65536 + 8);
        let mut body = head.split_off(8);
        unsafe { body.set_len(65536) }
        UdpBuffer { body, head }
    }
    pub fn body_mut(&mut self) -> &mut BytesMut {
        &mut self.body
    }
    pub fn finialize(mut self, size: usize) -> BytesMut {
        self.head.put_slice(MAGIC);
        self.head.put_u16(size as u16);
        self.head.unsplit(self.body);
        self.head.truncate(size + 8);
        self.head
    }
    pub fn try_from_buffer(mut buf: &[u8]) -> Option<&[u8]> {
        if buf.len() < 8 {
            return None;
        }
        let magic = &buf[..6];
        if magic != MAGIC {
            panic!("Invalid magic: {:?}", magic);
        }
        buf.advance(6);
        let len = buf.get_u16();
        let len = len as usize;
        if buf.len() < len {
            return None;
        }
        Some(&buf[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_from_buffer() {
        let data = b"UDPPKT\x00\x02abcdef";
        let pkt = UdpBuffer::try_from_buffer(data).unwrap();
        assert_eq!(pkt, b"ab");
    }
}
