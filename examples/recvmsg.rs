use std::io::IoSliceMut;
use std::os::unix::prelude::RawFd;

use easy_error::Terminator;
use libc::in_pktinfo;
use nix::fcntl::{FcntlArg, OFlag};
use nix::sys::socket::sockopt::Ipv4PacketInfo;
use nix::sys::socket::{
    bind, recvmsg, setsockopt, socket, ControlMessageOwned, MsgFlags, SockaddrIn,
};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
use nix::{cmsg_space, fcntl::fcntl};
use tokio::io::unix::AsyncFd;

#[tokio::main]
async fn main() -> Result<(), Terminator> {
    let socket = AsyncUdpSocket::new(1234)?;
    let mut buf = [0u8; 1024];
    let ret = socket.read(&mut buf).await?;
    println!(
        "read {} bytes from {} on interface {:?}",
        ret.0, ret.1, ret.2
    );
    Ok(())
}

pub struct AsyncUdpSocket {
    inner: AsyncFd<RawFd>,
}

impl AsyncUdpSocket {
    pub fn new(port: u16) -> std::io::Result<Self> {
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )?;
        let addr = SockaddrIn::new(0, 0, 0, 0, port);
        bind(fd, &addr)?;
        set_nonblocking(fd)?;
        setsockopt(fd, Ipv4PacketInfo, &true)?;
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    pub async fn read(&self, out: &mut [u8]) -> std::io::Result<(usize, SockaddrIn, in_pktinfo)> {
        loop {
            let mut guard = self.inner.readable().await?;
            let mut iov = [IoSliceMut::new(out)];
            let mut cmsg_buffer = cmsg_space!(in_pktinfo);
            let flags = MsgFlags::empty();
            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                recvmsg(fd, &mut iov, Some(&mut cmsg_buffer), flags)
                    .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
            }) {
                Ok(result) => {
                    return result.map(|ret| {
                        let pktinfo = match ret.cmsgs().next() {
                            Some(ControlMessageOwned::Ipv4PacketInfo(pktinfo)) => pktinfo,
                            Some(_) => panic!("Unexpected control message"),
                            None => panic!("No control message"),
                        };
                        (ret.bytes, ret.address.unwrap(), pktinfo)
                    })
                }
                Err(_would_block) => continue,
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    let mut flags = fcntl(fd, FcntlArg::F_GETFD)?;
    flags |= libc::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags)))?;
    Ok(())
}
