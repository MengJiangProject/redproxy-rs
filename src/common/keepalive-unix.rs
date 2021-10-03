use std::time::Duration;

use easy_error::{Error, ResultExt};
use mio::net::{TcpKeepalive, TcpSocket};
use tokio::net::TcpStream;

fn to_socket(stream: &TcpStream) -> TcpSocket {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let fd = stream.as_raw_fd();
    let dup_fd = unsafe { libc::dup(fd) };
    unsafe { TcpSocket::from_raw_fd(dup_fd) }
}

pub fn set_keepalive(stream: &TcpStream) -> Result<(), Error> {
    let socket = to_socket(stream);
    socket
        .set_keepalive_params(TcpKeepalive::new().with_time(Duration::from_secs(10)))
        .context("set_keepalive")
}
