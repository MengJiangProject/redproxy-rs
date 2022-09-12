use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub trait Fragmentable: Sized {
    type Buffer;
    fn as_buffer(&self) -> Self::Buffer;
    fn from_buffer(buf: Bytes) -> Option<Self>;
}

// id:u16 total:u7 offset:u7
pub struct Fragments<T> {
    timeout: Duration,
    queue: HashMap<u16, ReassembleQueue>,
    timer: VecDeque<(u16, Instant)>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> Fragments<T>
where
    T: Fragmentable,
    T::Buffer: Buf,
{
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            queue: Default::default(),
            timer: Default::default(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn make_fragments(mtu: usize, next_id: &mut u16, thing: T) -> MakeFragments<T::Buffer> {
        let buf = thing.as_buffer();
        let id = *next_id;
        *next_id += 1;
        MakeFragments::new(id, mtu, buf)
    }

    pub fn reassemble(&mut self, mut buf: Bytes) -> Option<T> {
        let mut head = buf.split_to(4);
        let id = head.get_u16();
        let total = head.get_u8();
        let seq = head.get_u8();
        // log::trace!("reassemble id: {} total: {} seq: {}", id, total, seq);
        if total == 1 && seq == 0 {
            T::from_buffer(buf)
        } else if let Entry::Occupied(mut entry) = self.queue.entry(id) {
            let queue = entry.get_mut();
            if queue.add_fragment(seq, buf) {
                let buf = queue.assemble();
                // log::trace!("reassembled {} bytes", buf.len());
                entry.remove_entry();
                T::from_buffer(buf.freeze())
            } else {
                None
            }
        } else {
            // log::trace!("new entry for {}", id);
            self.queue.insert(id, ReassembleQueue::new(total, seq, buf));
            self.timer.push_back((id, Instant::now() + self.timeout));
            None
        }
    }
    pub fn timer(&mut self) {
        let now = Instant::now();
        for _ in 0..self.timer.partition_point(|x| x.1 < now) {
            let id = self.timer.pop_front().unwrap().0;
            self.queue.remove(&id);
            // log::trace!("removed fragment queue {} by timer", id);
        }
    }
}

pub struct MakeFragments<T> {
    buf: T,
    mtu: usize,
    id: u16,
    total: u8,
    next: u8,
}

impl<T> MakeFragments<T>
where
    T: Buf,
{
    fn new(id: u16, mtu: usize, buf: T) -> MakeFragments<T> {
        assert!(mtu > 4);
        let size = mtu - 4;
        let len = buf.remaining();
        let total = div_ceil(len, size) as u8;
        MakeFragments {
            buf,
            mtu,
            id,
            total,
            next: 0,
        }
    }
}

impl<T: Buf> Iterator for MakeFragments<T> {
    type Item = Bytes;
    fn next(&mut self) -> Option<Bytes> {
        if self.buf.has_remaining() {
            let data_len = self.buf.remaining().min(self.mtu - 4);
            let mut buf = BytesMut::with_capacity(self.mtu);
            buf.put_u16(self.id);
            buf.put_u8(self.total);
            buf.put_u8(self.next);
            unsafe {
                buf.advance_mut(data_len);
            }
            self.buf.copy_to_slice(&mut buf[4..]);
            self.next += 1;
            Some(buf.freeze())
        } else {
            None
        }
    }
}

struct ReassembleQueue {
    bitmap: u128,
    fragments: Vec<Bytes>,
}

impl ReassembleQueue {
    fn new(total: u8, seq: u8, buf: Bytes) -> Self {
        let total = total as usize;
        let this = seq as usize;
        let bitmap = !0u128 << total | 1 << this;
        let mut fragments = vec![Bytes::new(); total];
        fragments[this] = buf;
        Self { bitmap, fragments }
    }
    fn add_fragment(&mut self, seq: u8, buf: Bytes) -> bool {
        let this = seq as usize;
        if self.bitmap & (1 << this) == 0 {
            self.bitmap |= 1 << this;
            self.fragments[this] = buf;
            return !self.bitmap == 0;
        }
        false
    }
    fn assemble(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.fragments.len() * self.fragments[0].len());
        for fragment in self.fragments.iter() {
            buf.extend(fragment)
        }
        buf
    }
}

#[inline]
const fn div_ceil(a: usize, b: usize) -> usize {
    let d = a / b;
    let r = a % b;
    if r > 0 && b > 0 {
        d + 1
    } else {
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct TestBuffer {
        pub buf: Bytes,
    }
    impl Fragmentable for TestBuffer {
        type Buffer = Bytes;
        fn as_buffer(&self) -> Self::Buffer {
            self.buf.clone()
        }

        fn from_buffer(buf: Bytes) -> Option<Self> {
            Some(Self { buf })
        }
    }

    #[test]
    fn reassemble_queue() {
        let buf = TestBuffer {
            buf: Bytes::from_static(b"1234567890"),
        };
        let mut f = Fragments::new(Duration::from_secs(1));
        assert_eq!(f.reassemble(b"\x00\x00\x03\x001234"[..].into()), None);
        assert_eq!(f.reassemble(b"\x00\x00\x03\x00EEEE"[..].into()), None); // duplicate
        assert_eq!(f.reassemble(b"\x00\x00\x03\x0290"[..].into()), None); // out of order
        assert_eq!(f.reassemble(b"\x00\x00\x03\x04EEEE"[..].into()), None); // illegal
        assert_eq!(f.reassemble(b"\x00\x01\x03\x02EE"[..].into()), None); // id mismatch
        assert_eq!(f.reassemble(b"\x00\x00\x03\x015678"[..].into()), Some(buf));
    }

    #[test]
    fn fragmention() {
        let buf = TestBuffer {
            buf: Bytes::from_static(b"1234567890"),
        };
        let mut frags = Fragments::make_fragments(8, &mut 0, buf);
        assert_eq!(frags.next(), Some(b"\x00\x00\x03\x001234"[..].into()));
        assert_eq!(frags.next(), Some(b"\x00\x00\x03\x015678"[..].into()));
        assert_eq!(frags.next(), Some(b"\x00\x00\x03\x0290"[..].into()));
        assert_eq!(frags.next(), None);
    }
}
