use async_trait::async_trait;
use easy_error::{bail, Error, ResultExt};
use log::trace;
use std::net::IpAddr;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use crate::context::TargetAddress;
pub trait RW: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}
impl<T> RW for T where T: AsyncBufRead + AsyncWriteExt + Send + Sync + Unpin {}

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
    fn auth_method(&self) -> &[u8];
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
            4 => Self::read_v4(socket, auth).await,
            5 => Self::read_v5(socket, auth).await,
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
            version: 4,
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
            bail!("No auth method selected")
        }

        // authentication
        let method = method.unwrap();
        socket.write(&[5, method]).await.context("write")?;
        socket.flush().await.context("flush")?;
        let auth = auth.auth_v5(method, socket).await?;

        // request
        let version = socket.read_u8().await.context("read version")?;
        let cmd = socket.read_u8().await.context("read cmd")?;
        let _rsv = socket.read_u8().await.context("read")?;
        let atype = socket.read_u8().await.context("read addr type")?;
        let target = match atype {
            1 => {
                let dst = socket.read_u32().await.context("read dst")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            3 => {
                let domain = read_length_and_string(socket).await?;
                let dport = socket.read_u16().await.context("read port")?;
                TargetAddress::DomainPort(domain, dport)
            }
            4 => {
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
            4 => self.write_v4(socket, auth).await,
            5 => self.write_v5(socket, auth).await,
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
        let (dst, dport) = match &self.target {
            TargetAddress::DomainPort(_, port) => ([0u8, 0, 0, 1], *port),
            TargetAddress::SocketAddr(a) => {
                if let IpAddr::V4(v4) = a.ip() {
                    (v4.octets(), a.port())
                } else {
                    ([0, 0, 0, 1], a.port())
                }
            }
        };
        socket.write_u16(dport).await.context("dport")?;
        socket.write(&dst).await.context("dport")?;
        let cid = auth.auth_v4(&self.auth).await?;
        socket.write(cid.as_bytes()).await.context("cid")?;
        socket.write_u8(0).await.context("cid")?;
        Ok(())
    }
    pub async fn write_v5<IO: RW, A: SocksAuthClient<T>>(
        &self,
        socket: &mut IO,
        auth: A,
    ) -> Result<(), Error> {
        // pre auth negotiation
        socket.write_u8(self.version).await.context("version")?;
        let methods = auth.auth_method();
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
                (3u8, x, *port)
            }
            TargetAddress::SocketAddr(a) => match a.ip() {
                IpAddr::V6(v6) => (4u8, v6.octets().into(), a.port()),
                IpAddr::V4(v4) => (1u8, v4.octets().into(), a.port()),
            },
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
    fn auth_method(&self) -> &[u8] {
        &[0]
    }
    async fn auth_v4(&self, _data: &()) -> Result<String, Error> {
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
pub struct PasswordAuth;
#[async_trait]
impl SocksAuthServer<(String, String)> for PasswordAuth {
    fn select_method(&self, method: &[u8]) -> Option<u8> {
        if method.contains(&2) {
            Some(2)
        } else {
            None
        }
    }
    async fn auth_v4(&self, client_id: String) -> Result<(String, String), Error> {
        Ok((client_id, "".into()))
    }
    async fn auth_v5<IO: RW>(
        &self,
        method: u8,
        socket: &mut IO,
    ) -> Result<(String, String), Error> {
        match method {
            2 => {
                let _ver = socket.read_u8().await.context("auth version")?;
                let user = read_length_and_string(socket).await?;
                let pass = read_length_and_string(socket).await?;
                Ok((user, pass))
            }
            _ => panic!("not supported method {}", method),
        }
    }
}

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
            4 => Self::read_v4(socket).await,
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
            1 => {
                let dst = socket.read_u32().await.context("read dst")?;
                let dport = socket.read_u16().await.context("read port")?;
                (dst, dport).into()
            }
            3 => {
                let domain = read_length_and_string(socket).await?;
                let dport = socket.read_u16().await.context("read port")?;
                TargetAddress::DomainPort(domain, dport)
            }
            4 => {
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
            4 => self.write_v4(socket).await,
            5 => self.write_v5(socket).await,
            _ => bail!("not supported version: {}", self.version),
        }?;
        socket.flush().await.context("flush")
    }
    pub async fn write_v4<IO: RW>(&self, socket: &mut IO) -> Result<(), Error> {
        socket.write_u8(self.version).await.context("version")?;
        let cmd = if self.cmd == 0 { 91 } else { 92 }; //map v5 response code to v4
        socket.write_u8(cmd).await.context("cmd")?;
        let (dst, dport) = match &self.target {
            TargetAddress::DomainPort(_, port) => ([0u8, 0, 0, 1], *port),
            TargetAddress::SocketAddr(a) => {
                if let IpAddr::V4(v4) = a.ip() {
                    (v4.octets(), a.port())
                } else {
                    ([0, 0, 0, 1], a.port())
                }
            }
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
                let mut x = Vec::from(domain.as_bytes());
                x.insert(0, x.len() as u8);
                (3u8, x, *port)
            }
            TargetAddress::SocketAddr(a) => match a.ip() {
                IpAddr::V6(v6) => (4u8, v6.octets().into(), a.port()),
                IpAddr::V4(v4) => (1u8, v4.octets().into(), a.port()),
            },
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
    use test_env_log::test;
    use tokio::io::BufReader;
    use tokio_test::io::Builder;
    #[test(tokio::test)]
    async fn parse_request_v4() {
        let input = [4, 1, 0, 5, 1, 2, 3, 4, b'a', b'b', b'c', 0];
        let output = SocksRequest {
            version: 4,
            cmd: 1,
            target: "1.2.3.4:5".parse().unwrap(),
            auth: ("abc".to_string(), "".to_string()),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(
            SocksRequest::read_from(&mut stream, PasswordAuth)
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
            auth: ("abc".to_string(), "".to_string()),
        };
        let stream = Builder::new().read(&input).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(
            SocksRequest::read_from(&mut stream, PasswordAuth)
                .await
                .unwrap(),
            output
        );
    }
}
