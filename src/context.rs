use easy_error::Error;
use std::{
    fmt::{Debug, Display},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufStream},
    net::TcpStream,
};

#[derive(Debug)]
pub struct InvalidAddress;

impl std::fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid address")
    }
}

impl std::error::Error for InvalidAddress {}

#[derive(Debug, Hash, Clone)]
pub enum TargetAddress {
    DomainPort(String, u16),
    SocketAddr(SocketAddr),
}

impl TargetAddress {
    pub async fn connect_tcp(&self) -> std::io::Result<TcpStream> {
        match self {
            Self::DomainPort(host, port) => TcpStream::connect((host.as_str(), *port)).await,
            Self::SocketAddr(addr) => TcpStream::connect(addr).await,
        }
    }
}

impl From<(Ipv4Addr, u16)> for TargetAddress {
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        let a = SocketAddrV4::new(ip, port);
        Self::SocketAddr(SocketAddr::V4(a))
    }
}

impl FromStr for TargetAddress {
    type Err = InvalidAddress;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(a) = SocketAddr::from_str(s) {
            Ok(TargetAddress::SocketAddr(a))
        } else {
            let mut parts = s.rsplitn(2, ':');
            let port = parts.next().ok_or(InvalidAddress)?;
            let host = parts.next().ok_or(InvalidAddress)?;
            let port = port.parse().map_err(|_| InvalidAddress)?;
            Ok(TargetAddress::DomainPort(host.to_string(), port))
        }
    }
}

impl Display for TargetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainPort(domain, port) => write!(f, "{}:{}", domain, port),
            Self::SocketAddr(addr) => write!(f, "{}", addr),
        }
    }
}

pub trait IOStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> IOStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub trait ContextCallback {
    fn on_connect<'a>(&self, ctx: &'a mut Context)
        -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn on_error<'a>(
        &self,
        ctx: &'a mut Context,
        error: Error,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

pub struct Context {
    pub listener: String,
    pub socket: BufStream<Box<dyn IOStream>>,
    pub source: SocketAddr,
    pub target: TargetAddress,
    pub callback: Option<Arc<dyn ContextCallback + Send + Sync>>,
}

impl Context {
    pub async fn on_connect(&mut self) {
        if self.callback.is_some() {
            let cb = self.callback.clone().unwrap();
            cb.on_connect(self).await
        }
    }
    pub async fn on_error(&mut self, error: Error) {
        if self.callback.is_some() {
            let cb = self.callback.clone().unwrap();
            cb.on_error(self, error).await
        }
    }
}

impl std::hash::Hash for Context {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.listener.hash(state);
        self.target.hash(state);
        self.source.hash(state);
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("listener", &self.listener)
            .field("target", &self.target)
            .field("source", &self.source)
            .finish()
    }
}

// use async_trait::async_trait;
// #[async_trait]
// pub trait AsyncInit {
//     async fn init(&mut self) -> Result<(), Error>;
// }
