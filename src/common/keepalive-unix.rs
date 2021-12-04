use std::os::unix::prelude::AsRawFd;

use easy_error::{Error, ResultExt};
use nix::sys::socket::{setsockopt, sockopt::KeepAlive};
use tokio::net::TcpStream;

pub fn set_keepalive(stream: &TcpStream) -> Result<(), Error> {
    setsockopt(stream.as_raw_fd(), KeepAlive, &true).context("setsockopt")
}
