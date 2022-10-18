use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::trace;
use std::net::IpAddr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use crate::context::TargetAddress;
pub trait RW: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}
impl<T> RW for T where T: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}

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
pub struct SocksRequest<T> {
    pub version: u8,
    pub cmd: u8,
    pub target: TargetAddress,
    pub auth: T,
}

#[async_trait]
pub trait SocksAuthServer<T> {
    fn select_method(&self, method: &[u8]) -> Option<u8>;
    async fn auth_v4(&self, client_id: String) -> Result<T, Error>;
    async fn auth_v5<IO: RW>(&self, method: u8, socket: &mut IO) -> Result<T, Error>;
}

#[async_trait]
pub trait SocksAuthClient<T> {
    fn supported_methods(&self, data: &T) -> &[u8];
    async fn auth_v4(&self, data: &T) -> Result<String, Error>;
    async fn auth_v5<IO: RW>(&self, data: &T, method: u8, socket: &mut IO) -> Result<(), Error>;
}

#[allow(dead_code)]
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
        // pre auth negotiation
        let n = socket.read_u8().await.context("read method count")?;
        let mut buf = vec![0; n as usize];
        socket.read_exact(&mut buf).await.context("read methods")?;
        let method = auth.select_method(&buf);
        if method.is_none() {
            socket.write(&[5, 0xff]).await.context("write")?;
            socket.flush().await.context("flush")?;
            bail!("No auth method in common, client wants: {:?}", buf)
        }

        // authentication
        let method = method.unwrap();
        socket
            .write(&[SOCKS_VER_5, method])
            .await
            .context("write")?;
        socket.flush().await.context("flush")?;
        let auth = auth.auth_v5(method, socket).await?;

        // request
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
        // pre auth negotiation
        socket.write_u8(self.version).await.context("version")?;
        let methods = auth.supported_methods(&self.auth);
        socket
            .write_u8(methods.len() as u8)
            .await
            .context("auth method")?;
        socket.write(methods).await.context("auth method")?;
        socket.flush().await.context("flush")?;

        // authentication
        let _ver = socket.read_u8().await.context("read version")?;
        let peer_method = socket.read_u8().await.context("read method")?;
        trace!("peer_method: {}", peer_method);
        if !methods.contains(&peer_method) {
            bail!("not supported auth method: {}", peer_method);
        }
        auth.auth_v5(&self.auth, peer_method, socket).await?;

        // request
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

pub struct NoAuth;
#[async_trait]
impl SocksAuthServer<()> for NoAuth {
    fn select_method(&self, method: &[u8]) -> Option<u8> {
        if method.contains(&0) {
            Some(0)
        } else {
            None
        }
    }
    async fn auth_v4(&self, _client_id: String) -> Result<(), Error> {
        Ok(())
    }
    async fn auth_v5<IO: RW>(&self, _method: u8, _socket: &mut IO) -> Result<(), Error> {
        Ok(())
    }
}

#[async_trait]
impl SocksAuthClient<()> for NoAuth {
    fn supported_methods(&self, _: &()) -> &[u8] {
        &[SOCKS_AUTH_NONE]
    }
    async fn auth_v4(&self, _: &()) -> Result<String, Error> {
        Ok("NoAuth".into())
    }
    async fn auth_v5<IO: RW>(
        &self,
        _data: &(),
        _method: u8,
        _socket: &mut IO,
    ) -> Result<(), Error> {
        Ok(())
    }
}
pub struct PasswordAuth {
    pub required: bool,
}

#[allow(dead_code)]
impl PasswordAuth {
    fn new(required: bool) -> Self {
        Self { required }
    }
    pub fn required() -> Self {
        Self::new(true)
    }
    pub fn optional() -> Self {
        Self::new(false)
    }
}

#[async_trait]
impl SocksAuthServer<Option<(String, String)>> for PasswordAuth {
    fn select_method(&self, methods: &[u8]) -> Option<u8> {
        if methods.contains(&SOCKS_AUTH_NONE) && !self.required {
            Some(SOCKS_AUTH_NONE)
        } else if methods.contains(&SOCKS_AUTH_USRPWD) {
            Some(SOCKS_AUTH_USRPWD)
        } else {
            None
        }
    }
    async fn auth_v4(&self, client_id: String) -> Result<Option<(String, String)>, Error> {
        Ok(Some((client_id, "".into())))
    }
    async fn auth_v5<IO: RW>(
        &self,
        method: u8,
        socket: &mut IO,
    ) -> Result<Option<(String, String)>, Error> {
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
        if data.is_some() {
            &[SOCKS_AUTH_NONE, SOCKS_AUTH_USRPWD]
        } else {
            &[SOCKS_AUTH_NONE]
        }
    }

    async fn auth_v4(&self, data: &Option<(String, String)>) -> Result<String, Error> {
        data.as_ref()
            .map_or_else(|| Ok("".to_owned()), |(user, _)| Ok(user.to_owned()))
    }

    async fn auth_v5<IO: RW>(
        &self,
        data: &Option<(String, String)>,
        method: u8,
        socket: &mut IO,
    ) -> Result<(), Error> {
        match method {
            SOCKS_AUTH_NONE => Ok(()),
            SOCKS_AUTH_USRPWD => {
                let (user, pass) = data.as_ref().unwrap();
                socket.write_u8(1).await.context("auth version")?;
                socket
                    .write_u8(user.len() as u8)
                    .await
                    .context("auth user")?;
                socket.write(user.as_bytes()).await.context("auth user")?;
                socket
                    .write_u8(pass.len() as u8)
                    .await
                    .context("auth pass")?;
                socket.write(pass.as_bytes()).await.context("auth user")?;
                socket.flush().await.context("auth")?;
                let _ver = socket.read_u8().await.context("auth result")?;
                let result = socket.read_u8().await.context("auth result")?;
                if result == SOCKS_REPLY_OK {
                    Ok(())
                } else {
                    bail!("authenication failed")
                }
            }
            _ => bail!("not supported method {}", method),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SocksResponse {
    pub version: u8,
    pub cmd: u8,
    pub target: TargetAddress,
}

#[allow(dead_code)]
impl SocksResponse {
    pub async fn read_from<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        let version = socket.read_u8().await.context("read ver")?;
        match version {
            0 => Self::read_v4(socket).await,
            5 => Self::read_v5(socket).await,
            _ => bail!("Unknown socks version: {}", version),
        }
    }
    async fn read_v4<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        let cmd = socket.read_u8().await.context("read cmd")?;
        let dport = socket.read_u16().await.context("read port")?;
        let dst = socket.read_u32().await.context("read dst")?;
        let target = (dst, dport).into();
        Ok(Self {
            version: 4,
            cmd,
            target,
        })
    }
    async fn read_v5<IO: RW>(socket: &mut IO) -> Result<Self, Error> {
        // let version = socket.read_u8().await.context("read version")?;
        let cmd = socket.read_u8().await.context("read cmd")?;
        let _rsv = socket.read_u8().await.context("read")?;
        let atype = socket.read_u8().await.context("read addr type")?;
        // trace!("ver:{} cmd:{} atype:{}", version, cmd, atype);
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
            version: 5,
            cmd,
            target,
        })
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
        socket.write_u8(0).await.context("vn")?;
        let cmd = if self.cmd == 0 { 90 } else { 91 }; //map v5 response code to v4
        socket.write_u8(cmd).await.context("cmd")?;
        let (dst, dport) = match &self.target {
            TargetAddress::DomainPort(_, port) => ([0, 0, 0, 1], *port),
            TargetAddress::SocketAddr(a) => {
                if let IpAddr::V4(v4) = a.ip() {
                    (v4.octets(), a.port())
                } else {
                    bail!("ipv6 not supported in socks4: {}", self.target)
                }
            }
            _ => unreachable!(),
        };
        socket.write_u16(dport).await.context("dport")?;
        socket.write(&dst).await.context("dport")?;
        Ok(())
    }
    pub async fn write_v5<IO: RW>(&self, socket: &mut IO) -> Result<(), Error> {
        socket.write_u8(self.version).await.context("version")?;
        socket.write_u8(self.cmd).await.context("version")?;
        socket.write_u8(0).await.context("write")?;
        let (t, addr, port) = match &self.target {
            TargetAddress::DomainPort(domain, port) => {
                let bytes = domain.as_bytes();
                let mut x = vec![bytes.len() as u8];
                x.extend(bytes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use tokio::io::BufReader;
    use tokio_test::io::Builder;
    #[test(tokio::test)]
    async fn parse_request_v4() {
        let input = [4, 1, 0, 5, 1, 2, 3, 4, b'a', b'b', b'c', 0];
        let output = SocksRequest {
            version: 4,
            cmd: 1,
            target: "1.2.3.4:5".parse().unwrap(),
            auth: Some(("abc".to_string(), "".to_string())),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(
            SocksRequest::read_from(&mut stream, PasswordAuth::required())
                .await
                .unwrap(),
            output
        );
    }
    #[test(tokio::test)]
    async fn parse_request_v4a() {
        let input = [
            4, 1, 0, 5, 0, 0, 0, 4, b'a', b'b', b'c', 0, b'x', b'y', b'z', 0,
        ];
        let output = SocksRequest {
            version: 4,
            cmd: 1,
            target: "xyz:5".parse().unwrap(),
            auth: Some(("abc".to_string(), "".to_string())),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(
            SocksRequest::read_from(&mut stream, PasswordAuth::required())
                .await
                .unwrap(),
            output
        );
    }
    #[test(tokio::test)]
    async fn parse_request_v5() {
        let read1 = [
            5, 1, 2, //pre auth
        ];
        let write1 = [
            5, 2, //pre auth
        ];
        let read2 = [
            1, //auth ver
            3, b'a', b'b', b'c', //user
            3, b'd', b'e', b'f', //pass
        ];
        let write2 = [
            1, //auth ver
            0, //auth result
        ];
        let read3 = [
            5, 1, 0, 3, 3, b'x', b'y', b'z', 0, 5, //request
        ];
        let output = SocksRequest {
            version: 5,
            cmd: 1,
            target: "xyz:5".parse().unwrap(),
            auth: Some(("abc".to_string(), "def".to_string())),
        };
        let stream = Builder::new()
            .read(&read1)
            .write(&write1)
            .read(&read2)
            .write(&write2)
            .read(&read3)
            .build();
        let mut stream = BufReader::new(stream);
        assert_eq!(
            SocksRequest::read_from(&mut stream, PasswordAuth::required())
                .await
                .unwrap(),
            output
        );
    }
    #[test(tokio::test)]
    async fn write_request_v4a() {
        let output = [
            4, 1, 0, 5, 0, 0, 0, 1, b'a', b'b', b'c', 0, b'x', b'y', b'z', 0,
        ];
        let input = SocksRequest {
            version: 4,
            cmd: 1,
            target: "xyz:5".parse().unwrap(),
            auth: Some(("abc".to_string(), "".to_string())),
        };
        let stream = Builder::new().write(&output).build();
        let mut stream = BufReader::new(stream);
        input
            .write_to(&mut stream, PasswordAuth::required())
            .await
            .unwrap();
    }
    #[test(tokio::test)]
    async fn write_request_v5() {
        let write1 = [
            5, 2, 0, 2, //pre auth
        ];
        let read1 = [
            5, 2, //pre auth
        ];
        let write2 = [
            1, //auth ver
            3, b'a', b'b', b'c', //user
            3, b'd', b'e', b'f', //pass
        ];
        let read2 = [
            1, //auth ver
            0, //auth result
        ];
        let write3 = [
            5, 1, 0, 3, 3, b'x', b'y', b'z', 0, 5, //request
        ];
        let output = SocksRequest {
            version: 5,
            cmd: 1,
            target: "xyz:5".parse().unwrap(),
            auth: Some(("abc".to_string(), "def".to_string())),
        };
        let stream = Builder::new()
            .write(&write1)
            .read(&read1)
            .write(&write2)
            .read(&read2)
            .write(&write3)
            .build();
        let mut stream = BufReader::new(stream);
        output
            .write_to(&mut stream, PasswordAuth::required())
            .await
            .unwrap();
    }
    #[test(tokio::test)]
    async fn parse_response_v4() {
        let input = [0, 1, 0, 5, 1, 2, 3, 4];
        let output = SocksResponse {
            version: 4,
            cmd: 1,
            target: "1.2.3.4:5".parse().unwrap(),
            // auth: Some(("abc".to_string(), "".to_string())),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(SocksResponse::read_from(&mut stream).await.unwrap(), output);
    }
    #[test(tokio::test)]
    async fn parse_response_v5() {
        let input = [
            5, 1, 0, 4, // ver 5 cmd 1 resv 0 type 4
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ipv6 address ::1
            0, 5, //port 5
        ];
        let output = SocksResponse {
            version: 5,
            cmd: 1,
            target: "[::1]:5".parse().unwrap(),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(SocksResponse::read_from(&mut stream).await.unwrap(), output);
    }
    #[test(tokio::test)]
    async fn write_response_v4() {
        let write = [0, 91, 0, 5, 1, 2, 3, 4];
        let output = SocksResponse {
            version: 4,
            cmd: 1,
            target: "1.2.3.4:5".parse().unwrap(),
            // auth: Some(("abc".to_string(), "".to_string())),
        };
        let stream = Builder::new().write(&write).build();
        let mut stream = BufReader::new(stream);
        output.write_to(&mut stream).await.unwrap();
    }
    #[test(tokio::test)]
    async fn write_response_v5() {
        let write = [
            5, 1, 0, 4, // ver 5 cmd 1 resv 0 type 4
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ipv6 address ::1
            0, 5, //port 5
        ];
        let output = SocksResponse {
            version: 5,
            cmd: 1,
            target: "[::1]:5".parse().unwrap(),
        };
        let stream = Builder::new().write(&write).build();
        let mut stream = BufReader::new(stream);
        output.write_to(&mut stream).await.unwrap();
    }
}
