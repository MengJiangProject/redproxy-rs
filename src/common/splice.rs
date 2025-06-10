// Most parts of this module came from crate tokio-pipe (https://github.com/yskszk63/tokio-pipe/blob/master/src/lib.rs).
// But that crate can't have SPLICE_F_MOVE set. so I have to keep a local version.

use nix::errno::Errno;
use nix::fcntl::{SpliceFFlags, splice};
use nix::unistd::pipe as c_pipe;
use std::io::{self, Result as IoResult};
use std::os::fd::AsFd;
use std::os::unix::prelude::{AsRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

pub fn pipe() -> IoResult<(AsyncFd<OwnedFd>, AsyncFd<OwnedFd>)> {
    let pipe = c_pipe()?;
    // let pipe = unsafe { (OwnedFd::from_raw_fd(pipe.0), OwnedFd::from_raw_fd(pipe.1)) };
    let pipe = (AsyncFd::new(pipe.0)?, AsyncFd::new(pipe.1)?);
    Ok(pipe)
}

pub async fn async_splice(
    fd_in: &mut AsyncFd<impl AsRawFd>,
    fd_out: &AsyncFd<impl AsRawFd>,
    len: usize,
    has_more_data: bool,
) -> IoResult<usize> {
    // There is only one reader and one writer, so it only needs to polled once.
    let mut read_ready = fd_in.readable().await?;
    let mut write_ready = fd_out.writable().await?;

    // Prepare args for the syscall
    let mut flags = SpliceFFlags::SPLICE_F_NONBLOCK | SpliceFFlags::SPLICE_F_MOVE;
    if has_more_data {
        flags |= SpliceFFlags::SPLICE_F_MORE
    }

    loop {
        let ret = splice(fd_in.as_fd(), None, fd_out.as_fd(), None, len, flags);
        match ret {
            Err(e) if e == Errno::EWOULDBLOCK => {
                // Since tokio might use epoll's edge-triggered mode, we cannot blindly
                // clear the readiness, otherwise it would block forever.
                //
                // So what we do instead is to use test_read_write_readiness, which
                // uses poll to test for readiness.
                //
                // Poll always uses level-triggered mode and it does not require
                // any registration at all.
                let (read_readiness, write_readiness) =
                    unsafe { test_read_write_readiness(fd_in.as_raw_fd(), fd_out.as_raw_fd())? };

                if !read_readiness {
                    read_ready.clear_ready();
                    read_ready = fd_in.readable().await?;
                }

                if !write_readiness {
                    write_ready.clear_ready();
                    write_ready = fd_out.writable().await?;
                }
            }
            Err(e) => break Err(io::Error::from_raw_os_error(e as i32)),
            Ok(ret) => break Ok(ret),
        }
    }
}

unsafe fn test_read_write_readiness(reader: RawFd, writer: RawFd) -> io::Result<(bool, bool)> {
    use libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, poll, pollfd};

    let mut fds = [
        pollfd {
            fd: reader,
            events: POLLIN,
            revents: 0,
        },
        pollfd {
            fd: writer,
            events: POLLOUT,
            revents: 0,
        },
    ];

    // Specify timeout to 0 so that it returns immediately.
    let ret = unsafe { poll(&mut fds[0], 2, 0) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    let is_read_ready = match fds[0].revents {
        POLLERR | POLLHUP | POLLIN => true,
        POLLNVAL => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd of reader is invalid",
            ));
        }
        _ => false,
    };

    let is_writer_ready = match fds[1].revents {
        POLLERR | POLLHUP | POLLOUT => true,
        POLLNVAL => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd of writer is invalid",
            ));
        }
        _ => false,
    };

    Ok((is_read_ready, is_writer_ready))
}
