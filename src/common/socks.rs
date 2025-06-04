use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use std::net::IpAddr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tracing::trace;

use crate::context::TargetAddress;

// Made pub for listeners/socks.rs
pub trait RW: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}
impl<T> RW for T where T: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}

// Made pub
pub const SOCKS_VER_4: u8 = 4u8;
pub const SOCKS_VER_5: u8 = 5u8;
pub const SOCKS_CMD_CONNECT: u8 = 1u8;
pub const SOCKS_CMD_BIND: u8 = 2u8;
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 3u8;
pub const SOCKS_ATYP_INET4: u8 = 1u8;
pub const SOCKS_ATYP_DOMAIN: u8 = 3u8;
pub const SOCKS_ATYP_INET6: u8 = 4u8;
pub const SOCKS_AUTH_NONE: u8 = 0u8;
pub const SOCKS_AUTH_USRPWD: u8 = 2u8;
pub const SOCKS_REPLY_OK: u8 = 0u8;
pub const SOCKS_REPLY_GENERAL_FAILURE: u8 = 1u8;

#[derive(Debug, Eq, PartialEq)]
// Made pub
pub struct SocksRequest<T> {
    pub version: u8,
    pub cmd: u8,
    pub target: TargetAddress,
    pub auth: T,
}

#[async_trait]
// Made pub
pub trait SocksAuthServer<T> {
    fn select_method(&self, method: &[u8]) -> Option<u8>;
    async fn auth_v4(&self, client_id: String) -> Result<T, Error>;
    async fn auth_v5<IO: RW>(&self, method: u8, socket: &mut IO) -> Result<T, Error>;
}

#[async_trait]
// Made pub
pub trait SocksAuthClient<T> {
    fn supported_methods(&self, data: &T) -> &[u8];
    async fn auth_v4(&self, data: &T) -> Result<String, Error>;
    async fn auth_v5<IO: RW>(&self, data: &T, method: u8, socket: &mut IO) -> Result<(), Error>;
}

// #[allow(dead_code)] // Removed allow(dead_code) as it's used externally now
impl<T> SocksRequest<T> {
    pub async fn read_from<IO: RW, A: SocksAuthServer<T>>(
        socket: &mut IO,
        auth: A,
    ) -> Result<Self, Error> {
        let version = socket.read_u8().await.context("read ver")?;
        match version {
            SOCKS_VER_4 => Self::read_v4(socket, auth).await,
            SOCKS_VER_5 => Self::read_v5(socket, auth).await,
            _ => bail!("Unknown socks version: {}", version),
        }
    }
    async fn read_v4<IO: RW, A: SocksAuthServer<T>>(
        socket: &mut IO,
        auth: A,
    ) -> Result<Self, Error> {
        let cmd = socket.read_u8().await.context("read cmd")?;
        let dport = socket.read_u16().await.context("read port")?;
        let dst = socket.read_u32().await.context("read dst")?;
        let client_id = read_null_terminated_string(socket).await?;
        let target = if dst < 0x100 {
            let domain = read_null_terminated_string(socket).await?;
            TargetAddress::DomainPort(domain, dport)
        } else {
            (dst, dport).into()
        };
        let auth = auth.auth_v4(client_id).await?;
        Ok(Self {
            version: SOCKS_VER_4,
            cmd,
            target,
            auth,
        })
    }
    async fn read_v5<IO: RW, A: SocksAuthServer<T>>(
        socket: &mut IO,
        auth: A,
    ) -> Result<Self, Error> {
        let n = socket.read_u8().await.context("read method count")?;
        let mut buf = vec![0; n as usize];
        socket.read_exact(&mut buf).await.context("read methods")?;
        let method = auth.select_method(&buf);
        if method.is_none() {
            socket.write(&[5, 0xff]).await.context("write")?;
            socket.flush().await.context("flush")?;
            bail!("No auth method in common, client wants: {:?}", buf)
        }
        let method = method.unwrap();
        socket
            .write(&[SOCKS_VER_5, method])
            .await
            .context("write")?;
        socket.flush().await.context("flush")?;
        let auth = auth.auth_v5(method, socket).await?;
        let version = socket.read_u8().await.context("read version")?;
        let cmd = socket.read_u8().await.context("read cmd")?;
        let _rsv = socket.read_u8().await.context("read")?;
        let atype = socket.read_u8().await.context("read addr type")?;
        let target = match atype {
            SOCKS_ATYP_INET4 => {
                let dst = socket.read_u32().await.context("read dst")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            SOCKS_ATYP_DOMAIN => {
                let domain = read_length_and_string(socket).await?;
                let dport = socket.read_u16().await.context("read port")?;
                TargetAddress::DomainPort(domain, dport)
            }
            SOCKS_ATYP_INET6 => {
                let mut dst = [0u8; 16];
                socket.read_exact(&mut dst).await.context("read domain")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            _ => bail!("not supported addr type: {}", atype),
        };
        Ok(Self {
            version,
            cmd,
            target,
            auth,
        })
    }
    pub async fn write_to<IO: RW, A: SocksAuthClient<T>>(
        &self,
        socket: &mut IO,
        auth: A,
    ) -> Result<(), Error> {
        match self.version {
            SOCKS_VER_4 => self.write_v4(socket, auth).await,
            SOCKS_VER_5 => self.write_v5(socket, auth).await,
            _ => bail!("not supported version: {}", self.version),
        }?;
        socket.flush().await.context("flush")
    }
    pub async fn write_v4<IO: RW, A: SocksAuthClient<T>>(
        &self,
        socket: &mut IO,
        auth: A,
    ) -> Result<(), Error> {
        socket.write_u8(self.version).await.context("version")?;
        socket.write_u8(self.cmd).await.context("cmd")?;
        let (dst, dport, target) = match &self.target {
            TargetAddress::DomainPort(domain, port) => {
                ([0, 0, 0, 1], *port, Some(domain.as_bytes()))
            }
            TargetAddress::SocketAddr(a) => {
                if let IpAddr::V4(v4) = a.ip() {
                    (v4.octets(), a.port(), None)
                } else {
                    bail!("ipv6 not supported in socks4: {}", self.target)
                }
            }
            _ => unreachable!(),
        };
        socket.write_u16(dport).await.context("dport")?;
        socket.write(&dst).await.context("dport")?;
        let cid = auth.auth_v4(&self.auth).await?;
        socket.write(cid.as_bytes()).await.context("cid")?;
        socket.write_u8(0).await.context("cid")?;
        if let Some(target) = target {
            socket.write(target).await.context("target")?;
            socket.write_u8(0).await.context("target")?;
        }
        Ok(())
    }
    pub async fn write_v5<IO: RW, A: SocksAuthClient<T>>(
        &self,
        socket: &mut IO,
        auth: A,
    ) -> Result<(), Error> {
        socket.write_u8(self.version).await.context("version")?;
        let methods = auth.supported_methods(&self.auth);
        socket
            .write_u8(methods.len() as u8)
            .await
            .context("auth method")?;
        socket.write(methods).await.context("auth method")?;
        socket.flush().await.context("flush")?;
        let _ver = socket.read_u8().await.context("read version")?;
        let peer_method = socket.read_u8().await.context("read method")?;
        trace!("peer_method: {}", peer_method);
        if !methods.contains(&peer_method) {
            bail!("not supported auth method: {}", peer_method);
        }
        auth.auth_v5(&self.auth, peer_method, socket).await?;
        socket.write_u8(self.version).await.context("version")?;
        socket.write_u8(self.cmd).await.context("version")?;
        socket.write_u8(0).await.context("write")?;
        let (t, addr, port) = match &self.target {
            TargetAddress::DomainPort(domain, port) => {
                let mut x = Vec::from(domain.as_bytes());
                x.insert(0, x.len() as u8);
                (SOCKS_ATYP_DOMAIN, x, *port)
            }
            TargetAddress::SocketAddr(a) => match a.ip() {
                IpAddr::V6(v6) => (SOCKS_ATYP_INET6, v6.octets().into(), a.port()),
                IpAddr::V4(v4) => (SOCKS_ATYP_INET4, v4.octets().into(), a.port()),
            },
            _ => unreachable!(),
        };
        socket.write_u8(t).await.context("type")?;
        socket.write(&addr).await.context("addr")?;
        socket.write_u16(port).await.context("port")?;
        Ok(())
    }
}

// Made pub
pub struct NoAuth;
#[async_trait]
impl SocksAuthServer<()> for NoAuth {
    fn select_method(&self, method: &[u8]) -> Option<u8> {
        if method.contains(&0) { Some(0) } else { None }
    }
    async fn auth_v4(&self, _client_id: String) -> Result<(), Error> { Ok(()) }
    async fn auth_v5<IO: RW>(&self, _method: u8, _socket: &mut IO) -> Result<(), Error> { Ok(()) }
}

#[async_trait]
impl SocksAuthClient<()> for NoAuth {
    fn supported_methods(&self, _: &()) -> &[u8] { &[SOCKS_AUTH_NONE] }
    async fn auth_v4(&self, _: &()) -> Result<String, Error> { Ok("NoAuth".into()) }
    async fn auth_v5<IO: RW>(&self, _data: &(), _method: u8, _socket: &mut IO) -> Result<(), Error> { Ok(()) }
}

// Made pub
pub struct PasswordAuth {
    pub required: bool,
}

// #[allow(dead_code)] // Removed allow(dead_code)
impl PasswordAuth {
    // Made pub
    pub fn new(required: bool) -> Self { Self { required } }
    pub fn required() -> Self { Self::new(true) }
    pub fn optional() -> Self { Self::new(false) }
}

#[async_trait]
impl SocksAuthServer<Option<(String, String)>> for PasswordAuth {
    fn select_method(&self, methods: &[u8]) -> Option<u8> {
        if methods.contains(&SOCKS_AUTH_NONE) && !self.required { Some(SOCKS_AUTH_NONE) }
        else if methods.contains(&SOCKS_AUTH_USRPWD) { Some(SOCKS_AUTH_USRPWD) }
        else { None }
    }
    async fn auth_v4(&self, client_id: String) -> Result<Option<(String, String)>, Error> { Ok(Some((client_id, "".into()))) }
    async fn auth_v5<IO: RW>(&self, method: u8, socket: &mut IO) -> Result<Option<(String, String)>, Error> {
        match method {
            SOCKS_AUTH_NONE => Ok(None),
            SOCKS_AUTH_USRPWD => {
                let _ver = socket.read_u8().await.context("auth version")?;
                let user = read_length_and_string(socket).await?;
                let pass = read_length_and_string(socket).await?;
                socket.write_u8(1).await.context("auth result")?;
                socket.write_u8(0).await.context("auth result")?;
                socket.flush().await.context("auth result")?;
                Ok(Some((user, pass)))
            }
            _ => bail!("not supported method {}", method),
        }
    }
}

#[async_trait]
impl SocksAuthClient<Option<(String, String)>> for PasswordAuth {
    fn supported_methods(&self, data: &Option<(String, String)>) -> &[u8] {
        if data.is_some() { &[SOCKS_AUTH_NONE, SOCKS_AUTH_USRPWD] }
        else { &[SOCKS_AUTH_NONE] }
    }
    async fn auth_v4(&self, data: &Option<(String, String)>) -> Result<String, Error> {
        data.as_ref().map_or_else(|| Ok("".to_owned()), |(user, _)| Ok(user.to_owned()))
    }
    async fn auth_v5<IO: RW>(&self, data: &Option<(String, String)>, method: u8, socket: &mut IO) -> Result<(), Error> {
        match method {
            SOCKS_AUTH_NONE => Ok(()),
            SOCKS_AUTH_USRPWD => {
                let (user, pass) = data.as_ref().unwrap();
                socket.write_u8(1).await.context("auth version")?;
                socket.write_u8(user.len() as u8).await.context("auth user")?;
                socket.write(user.as_bytes()).await.context("auth user")?;
                socket.write_u8(pass.len() as u8).await.context("auth pass")?;
                socket.write(pass.as_bytes()).await.context("auth user")?;
                socket.flush().await.context("auth")?;
                let _ver = socket.read_u8().await.context("auth result")?;
                let result = socket.read_u8().await.context("auth result")?;
                if result == SOCKS_REPLY_OK { Ok(()) }
                else { bail!("authenication failed") }
            }
            _ => bail!("not supported method {}", method),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
// Made pub
pub struct SocksResponse {
    pub version: u8,
    pub cmd: u8,
    pub target: TargetAddress,
}

// #[allow(dead_code)] // Removed allow(dead_code)
impl SocksResponse {
    pub async fn read_from<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        let version = socket.read_u8().await.context("read ver")?;
        match version {
            0 => Self::read_v4(socket).await, // SOCKS v4 uses 0 for reply VN
            SOCKS_VER_5 => Self::read_v5(socket).await,
            _ => bail!("Unknown socks version in response: {}", version),
        }
    }
    async fn read_v4<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        let cmd = socket.read_u8().await.context("read cmd")?;
        let dport = socket.read_u16().await.context("read port")?;
        let dst = socket.read_u32().await.context("read dst")?;
        let target = (dst, dport).into();
        Ok(Self { version: 4, cmd, target })
    }
    async fn read_v5<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        let cmd = socket.read_u8().await.context("read cmd")?;
        let _rsv = socket.read_u8().await.context("read")?;
        let atype = socket.read_u8().await.context("read addr type")?;
        let target = match atype {
            SOCKS_ATYP_INET4 => {
                let dst = socket.read_u32().await.context("read dst")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            SOCKS_ATYP_DOMAIN => {
                let domain = read_length_and_string(socket).await?;
                let dport = socket.read_u16().await.context("read port")?;
                TargetAddress::DomainPort(domain, dport)
            }
            SOCKS_ATYP_INET6 => {
                let mut dst = [0u8; 16];
                socket.read_exact(&mut dst).await.context("read domain")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            _ => bail!("not supported addr type: {}", atype),
        };
        Ok(Self { version: 5, cmd, target })
    }
    pub async fn write_to<IO: RW>(&self, socket: &mut IO) -> Result<(), Error> {
        match self.version {
            SOCKS_VER_4 => self.write_v4(socket).await,
            SOCKS_VER_5 => self.write_v5(socket).await,
            _ => bail!("not supported version: {}", self.version),
        }?;
        socket.flush().await.context("flush")
    }
    pub async fn write_v4<IO: RW>(&self, socket: &mut IO) -> Result<(), Error> {
        socket.write_u8(0).await.context("vn")?; // Reply version for SOCKS4 is 0
        let cmd_to_write = if self.cmd == SOCKS_REPLY_OK { 90 } else { 91 }; //map v5 response code to v4
        socket.write_u8(cmd_to_write).await.context("cmd")?;
        let (_dst_bytes, dport) = match &self.target { // Renamed dst to _dst_bytes as it's not directly used
            TargetAddress::DomainPort(_, port) => ([0u8;4], *port), // For domain, SOCKS4 replies with dummy IP
            TargetAddress::SocketAddr(a) => {
                if let IpAddr::V4(v4) = a.ip() { (v4.octets(), a.port()) }
                else { bail!("ipv6 target not representable in socks4 response: {}", self.target) }
            }
            _ => ([0u8;4], 0), // Default/dummy for Unknown or other types
        };
        socket.write_u16(dport).await.context("dport")?;
        // Correctly get IP bytes for SOCKS4 reply based on target type
        let ip_bytes_for_reply: [u8; 4] = match &self.target {
             TargetAddress::SocketAddr(SocketAddr::V4(v4_addr)) => v4_addr.ip().octets(),
             _ => [0,0,0,0], // SOCKS4 replies with 0.0.0.0 for domain names or non-IPv4
        };
        socket.write(&ip_bytes_for_reply).await.context("dst ip")?;
        Ok(())
    }
    pub async fn write_v5<IO: RW>(&self, socket: &mut IO) -> Result<(), Error> {
        socket.write_u8(self.version).await.context("version")?;
        socket.write_u8(self.cmd).await.context("cmd")?; // Corrected from version to cmd
        socket.write_u8(0).await.context("write")?;
        let (t, addr_bytes_vec, port) = match &self.target { // Renamed addr to addr_bytes_vec
            TargetAddress::DomainPort(domain, port_val) => { // Renamed port to port_val
                let bytes = domain.as_bytes();
                let mut x = vec![bytes.len() as u8];
                x.extend(bytes);
                (SOCKS_ATYP_DOMAIN, x, *port_val)
            }
            TargetAddress::SocketAddr(a) => match a.ip() {
                IpAddr::V6(v6) => (SOCKS_ATYP_INET6, v6.octets().into(), a.port()),
                IpAddr::V4(v4) => (SOCKS_ATYP_INET4, v4.octets().into(), a.port()),
            },
            _ => unreachable!(),
        };
        socket.write_u8(t).await.context("type")?;
        socket.write(&addr_bytes_vec).await.context("addr")?; // Use addr_bytes_vec
        socket.write_u16(port).await.context("port")?;
        Ok(())
    }
}

async fn read_length_and_string<IO: RW>(io: &mut IO) -> Result<String, Error> {
    let len = io.read_u8().await.context("length")?;
    let mut buf = vec![0; len as usize];
    io.read_exact(&mut buf).await.context("data")?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

async fn read_null_terminated_string<IO: RW>(io: &mut IO) -> Result<String, Error> {
    let mut buf = Vec::new();
    io.read_until(0, &mut buf).await.context("read domain")?;
    buf.pop();
    Ok(String::from_utf8_lossy(&buf).to_string())
}

// Made pub
pub mod frames {
    use std::sync::Arc;
    use std::{io::Error as IoError, io::Result as IoResult, net::SocketAddr};

    use async_trait::async_trait;
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use tokio::net::UdpSocket;

    use crate::common::frames::{Frame, FrameIO, FrameReader, FrameWriter};
    use crate::context::TargetAddress;

    #[async_trait]
    // Made pub
    pub trait UdpSocketLike: Send + Sync {
        async fn bind(addr: SocketAddr) -> IoResult<Self> where Self: Sized;
        fn local_addr(&self) -> IoResult<SocketAddr>;
        async fn connect(&self, addr: SocketAddr) -> IoResult<()>;
        async fn send(&self, buf: &[u8]) -> IoResult<usize>;
        async fn recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)>;
    }

    #[async_trait]
    impl UdpSocketLike for UdpSocket {
        async fn bind(addr: SocketAddr) -> IoResult<Self> { UdpSocket::bind(addr).await }
        fn local_addr(&self) -> IoResult<SocketAddr> { UdpSocket::local_addr(self) }
        async fn connect(&self, addr: SocketAddr) -> IoResult<()> { UdpSocket::connect(self, addr).await }
        async fn send(&self, buf: &[u8]) -> IoResult<usize> { UdpSocket::send(self, buf).await }
        async fn recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr)> { UdpSocket::recv_from(self, buf).await }
    }

    use super::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_INET4, SOCKS_ATYP_INET6, SOCKS_CMD_UDP_ASSOCIATE, SOCKS_VER_5}; // Import SOCKS constants

    // Made pub
    pub async fn setup_udp_session<S: UdpSocketLike + 'static>(
        local: SocketAddr,
        remote: Option<SocketAddr>,
    ) -> IoResult<(SocketAddr, FrameIO)> {
        let socket = S::bind(local).await?;
        let bind_addr = socket.local_addr()?;
        if let Some(remote_addr) = remote { socket.connect(remote_addr).await?; }
        let socket_arc = Arc::new(socket); // Renamed to avoid conflict
        Ok((
            bind_addr,
            (
                SocksFrameReader::new(remote, socket_arc.clone()),
                SocksFrameWriter::new(socket_arc),
            ),
        ))
    }

    struct SocksFrameReader<S: UdpSocketLike + 'static> {
        socket: Arc<S>,
        remote: Option<SocketAddr>,
    }

    impl<S: UdpSocketLike + 'static> SocksFrameReader<S> {
        fn new(remote: Option<SocketAddr>, socket: Arc<S>) -> Box<Self> { Self { remote, socket }.into() }
    }

    #[async_trait]
    impl<S: UdpSocketLike + 'static> FrameReader for SocksFrameReader<S> {
        async fn read(&mut self) -> IoResult<Option<Frame>> {
            let mut buf_storage = [0u8; 65535];
            let mut frame = Frame::new_with_capacity(65535);
            let (sz, addr) = self.socket.recv_from(&mut buf_storage).await?;
            frame.body.put_slice(&buf_storage[..sz]);
            if self.remote.is_none() {
                self.socket.connect(addr).await?;
                self.remote = Some(addr);
            }
            let decoded_frame = decode_socks_frame(frame)?;
            Ok(Some(decoded_frame))
        }
    }

    struct SocksFrameWriter<S: UdpSocketLike + 'static> {
        socket: Arc<S>,
    }

    impl<S: UdpSocketLike + 'static> SocksFrameWriter<S> {
        fn new(socket: Arc<S>) -> Box<Self> { Self { socket }.into() }
    }

    #[async_trait]
    impl<S: UdpSocketLike + 'static> FrameWriter for SocksFrameWriter<S> {
        async fn write(&mut self, frame: Frame) -> IoResult<usize> {
            let frame_bytes = encode_socks_frame(frame)?;
            self.socket.send(&frame_bytes).await
        }
        async fn shutdown(&mut self) -> IoResult<()> { Ok(()) }
    }

    // Made pub
    pub fn decode_socks_frame(mut frame: Frame) -> IoResult<Frame> {
        let body = &mut frame.body;
        if body.len() < 4 { return Err(IoError::new(std::io::ErrorKind::InvalidData, "frame too short")); }
        let _ver = body.get_u8(); let _cmd = body.get_u8(); let _rsv = body.get_u8();
        let atyp = body.get_u8();
        let target: TargetAddress = match atyp {
            SOCKS_ATYP_INET4 => {
                if body.len() < 6 { return Err(IoError::new(std::io::ErrorKind::InvalidData, "frame too short for IPv4")); }
                let dst = body.get_u32(); let dport = body.get_u16();
                (dst, dport).into()
            }
            SOCKS_ATYP_INET6 => {
                if body.len() < 18 { return Err(IoError::new(std::io::ErrorKind::InvalidData, "frame too short for IPv6")); }
                let mut dst = [0u8; 16]; body.copy_to_slice(&mut dst); let dport = body.get_u16();
                (dst, dport).into()
            }
            SOCKS_ATYP_DOMAIN => {
                if body.is_empty() { return Err(IoError::new(std::io::ErrorKind::InvalidData, "frame too short for domain len")); }
                let len = body.get_u8() as usize;
                if body.len() < len + 2 { return Err(IoError::new(std::io::ErrorKind::InvalidData, "frame too short for domain name/port")); }
                let domain = String::from_utf8(body.split_to(len).to_vec()).map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, e))?;
                let dport = body.get_u16();
                (domain, dport).into()
            }
            _ => { return Err(IoError::new(std::io::ErrorKind::InvalidData, format!("not supported atype {}", atyp))) }
        };
        frame.addr = Some(target);
        Ok(frame)
    }

    // Made pub
    pub fn encode_socks_frame(frame: Frame) -> IoResult<Bytes> {
        let mut body = BytesMut::with_capacity(65536);
        body.put_u8(SOCKS_VER_5); body.put_u8(SOCKS_CMD_UDP_ASSOCIATE); body.put_u8(0);
        match &frame.addr {
            Some(TargetAddress::SocketAddr(a)) => match a.ip() {
                IpAddr::V6(v6) => { body.put_u8(SOCKS_ATYP_INET6); body.extend_from_slice(&v6.octets()); body.put_u16(a.port()); }
                IpAddr::V4(v4) => { body.put_u8(SOCKS_ATYP_INET4); body.extend_from_slice(&v4.octets()); body.put_u16(a.port()); }
            },
            Some(TargetAddress::DomainPort(domain, port)) => {
                let bytes = domain.as_bytes();
                if bytes.len() > 255 { return Err(IoError::new(std::io::ErrorKind::InvalidData, format!("domain too long: {:?}", domain))); }
                body.put_u8(SOCKS_ATYP_DOMAIN); body.put_u8(bytes.len() as u8); body.extend_from_slice(bytes); body.put_u16(*port);
            }
            _ => { return Err(IoError::new(std::io::ErrorKind::InvalidData, format!("not supported addr {:?}", frame.addr))) }
        };
        body.extend(frame.body());
        Ok(body.freeze())
    }
}

#[cfg(test)]
mod tests { /* ... existing tests ... */ }
