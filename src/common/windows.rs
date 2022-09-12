// Code copied from mio internal api, those are not exposed but there is no point to include another library for this.
use std::io::{Error as IoError, Result as IoResult};
use std::net::SocketAddr;
use winapi::shared::in6addr::{in6_addr_u, IN6_ADDR};
use winapi::shared::inaddr::{in_addr_S_un, IN_ADDR};
use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN};
use winapi::shared::ws2ipdef::{SOCKADDR_IN6_LH_u, SOCKADDR_IN6_LH};
use winapi::{
    ctypes::c_int,
    um::winsock2::{
        bind as win_bind, closesocket, connect as win_connect, setsockopt, socket as win_socket,
        INVALID_SOCKET, PF_INET, PF_INET6, SOCKET, SOCKET_ERROR, SOL_SOCKET, SO_KEEPALIVE,
        SO_REUSEADDR,
    },
};

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        let res = unsafe { $fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(IoError::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

pub fn socket(addr: SocketAddr, socket_type: c_int) -> IoResult<SOCKET> {
    let domain = match addr {
        SocketAddr::V4(..) => PF_INET,
        SocketAddr::V6(..) => PF_INET6,
    };

    syscall!(
        win_socket(domain, socket_type, 0),
        PartialEq::eq,
        INVALID_SOCKET
    )
    .map(|x| x as SOCKET)
}

pub fn set_reuse_addr(fd: SOCKET, val: bool) -> IoResult<()> {
    syscall!(
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &val as *const _ as _,
            std::mem::size_of::<bool>() as _,
        ),
        PartialEq::eq,
        SOCKET_ERROR
    )
    .map(|_| ())
}

pub fn set_keepalive(fd: SOCKET, val: bool) -> IoResult<()> {
    syscall!(
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &val as *const _ as _,
            std::mem::size_of::<bool>() as _,
        ),
        PartialEq::eq,
        SOCKET_ERROR
    )
    .map(|_| ())
}

pub fn bind(fd: SOCKET, addr: SocketAddr) -> IoResult<()> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);
    syscall!(
        win_bind(fd, raw_addr.as_ptr(), raw_addr_length,),
        PartialEq::eq,
        SOCKET_ERROR
    )
    .map_err(|err| {
        // Close the socket if we hit an error, ignoring the error
        // from closing since we can't pass back two errors.
        let _ = unsafe { closesocket(fd) };
        err
    })
    .map(|_| ())
}

pub fn connect(fd: SOCKET, addr: SocketAddr) -> IoResult<()> {
    let (raw_addr, raw_addr_length) = socket_addr(&addr);
    syscall!(
        win_connect(fd, raw_addr.as_ptr(), raw_addr_length,),
        PartialEq::eq,
        SOCKET_ERROR
    )
    .map_err(|err| {
        // Close the socket if we hit an error, ignoring the error
        // from closing since we can't pass back two errors.
        let _ = unsafe { closesocket(fd) };
        err
    })
    .map(|_| ())
}

#[repr(C)]
pub(crate) union SocketAddrCRepr {
    v4: SOCKADDR_IN,
    v6: SOCKADDR_IN6_LH,
}

impl SocketAddrCRepr {
    pub(crate) fn as_ptr(&self) -> *const SOCKADDR {
        self as *const _ as *const SOCKADDR
    }
}

pub(crate) fn socket_addr(addr: &SocketAddr) -> (SocketAddrCRepr, c_int) {
    match addr {
        SocketAddr::V4(ref addr) => {
            // `s_addr` is stored as BE on all machine and the array is in BE order.
            // So the native endian conversion method is used so that it's never swapped.
            let sin_addr = unsafe {
                let mut s_un = std::mem::zeroed::<in_addr_S_un>();
                *s_un.S_addr_mut() = u32::from_ne_bytes(addr.ip().octets());
                IN_ADDR { S_un: s_un }
            };

            let sockaddr_in = SOCKADDR_IN {
                sin_family: AF_INET as ADDRESS_FAMILY,
                sin_port: addr.port().to_be(),
                sin_addr,
                sin_zero: [0; 8],
            };

            let sockaddr = SocketAddrCRepr { v4: sockaddr_in };
            (sockaddr, std::mem::size_of::<SOCKADDR_IN>() as c_int)
        }
        SocketAddr::V6(ref addr) => {
            let sin6_addr = unsafe {
                let mut u = std::mem::zeroed::<in6_addr_u>();
                *u.Byte_mut() = addr.ip().octets();
                IN6_ADDR { u }
            };
            let u = unsafe {
                let mut u = std::mem::zeroed::<SOCKADDR_IN6_LH_u>();
                *u.sin6_scope_id_mut() = addr.scope_id();
                u
            };

            let sockaddr_in6 = SOCKADDR_IN6_LH {
                sin6_family: AF_INET6 as ADDRESS_FAMILY,
                sin6_port: addr.port().to_be(),
                sin6_addr,
                sin6_flowinfo: addr.flowinfo(),
                u,
            };

            let sockaddr = SocketAddrCRepr { v6: sockaddr_in6 };
            (sockaddr, std::mem::size_of::<SOCKADDR_IN6_LH>() as c_int)
        }
    }
}
