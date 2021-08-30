use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use lazy_static::lazy_static;
use log::trace;
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
    time::SystemTime,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufStream},
    net::TcpStream,
    sync::{mpsc::Sender, Mutex, MutexGuard, RwLock},
};

#[derive(Debug)]
pub struct InvalidAddress;

impl std::fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid address")
    }
}

impl std::error::Error for InvalidAddress {}

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub enum TargetAddress {
    DomainPort(String, u16),
    SocketAddr(SocketAddr),
    Unknown,
}

impl TargetAddress {
    pub async fn connect_tcp(&self) -> std::io::Result<TcpStream> {
        match self {
            Self::DomainPort(host, port) => TcpStream::connect((host.as_str(), *port)).await,
            Self::SocketAddr(addr) => TcpStream::connect(addr).await,
            _ => unreachable!(),
        }
    }
}

impl From<(Ipv4Addr, u16)> for TargetAddress {
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        let a = SocketAddrV4::new(ip, port);
        Self::SocketAddr(SocketAddr::V4(a))
    }
}

impl From<(u32, u16)> for TargetAddress {
    fn from((ip, port): (u32, u16)) -> Self {
        let ip = ip.into();
        let a = SocketAddrV4::new(ip, port);
        Self::SocketAddr(SocketAddr::V4(a))
    }
}

impl From<([u8; 16], u16)> for TargetAddress {
    fn from((ip, port): ([u8; 16], u16)) -> Self {
        let ip = ip.into();
        let a = SocketAddrV6::new(ip, port, 0, 0);
        Self::SocketAddr(SocketAddr::V6(a))
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
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl Default for TargetAddress {
    fn default() -> Self {
        Self::Unknown
    }
}

pub trait IOStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> IOStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub type IOBufStream = BufStream<Box<dyn IOStream>>;

pub fn make_buffered_stream<T: IOStream + 'static>(stream: T) -> IOBufStream {
    BufStream::new(Box::new(stream))
}

pub trait ContextCallback {
    fn on_connect(&self, ctx: ContextRef) -> Pin<Box<dyn Future<Output = ()> + Send>>;
    fn on_error(&self, ctx: ContextRef, error: Error) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

#[derive(Clone)]
pub struct Context {
    pub id: u64,
    pub create_at: SystemTime,
    pub listener: String,
    pub source: SocketAddr,
    target: TargetAddress,
    socket: Arc<Mutex<IOBufStream>>,
    callback: Option<Arc<dyn ContextCallback + Send + Sync>>,
}

pub type ContextRef = Arc<RwLock<Context>>;
pub type ContextWeakRef = Weak<RwLock<Context>>;

lazy_static! {
    static ref NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(0);
    pub static ref CONTEXT_LIST: std::sync::Mutex<HashMap<u64, ContextWeakRef>> =
        std::sync::Mutex::new(Default::default());
}

impl Context {
    pub fn new(listener: String, socket: IOBufStream, source: SocketAddr) -> ContextRef {
        let socket = Arc::new(Mutex::new(socket));
        let id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
        let ret = Arc::new(RwLock::new(Self {
            id,
            create_at: SystemTime::now(),
            listener,
            socket,
            source,
            target: Default::default(),
            callback: None,
        }));
        CONTEXT_LIST
            .lock()
            .unwrap()
            .insert(id, Arc::downgrade(&ret));
        ret
    }

    /// Set the context's callback.
    pub fn set_callback<T: ContextCallback + Send + Sync + 'static>(
        &mut self,
        callback: T,
    ) -> &mut Self {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// Get a reference to the context's socket.
    pub async fn lock_socket(&self) -> MutexGuard<'_, IOBufStream> {
        self.socket.lock().await
    }

    /// Get a reference to the context's target.
    pub fn target(&self) -> TargetAddress {
        self.target.clone()
    }

    /// Set the context's target.
    pub fn set_target(&mut self, target: TargetAddress) -> &mut Self {
        self.target = target;
        self
    }
}

#[async_trait]
pub trait ContextRefOps {
    async fn target(&self) -> TargetAddress;
    // async fn lock_socket(&self) -> MutexGuard<'_, IOBufStream>;
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error>;
    async fn on_connect(&self);
    async fn on_error(&self, error: Error);
}

#[async_trait]
impl ContextRefOps for ContextRef {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error> {
        queue.send(self).await.context("enqueue")
    }
    async fn on_connect(&self) {
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_connect(self.clone()).await
        }
    }
    async fn on_error(&self, error: Error) {
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_error(self.clone(), error).await
        }
    }

    /// Get a reference to the context's target.
    async fn target(&self) -> TargetAddress {
        self.read().await.target()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        trace!("Context dropped: {}", self);
        CONTEXT_LIST.lock().unwrap().remove(&self.id);
    }
}

impl std::hash::Hash for Context {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.listener.hash(state);
        self.target.hash(state);
        self.source.hash(state);
    }
}

impl Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l={}, s={}, t={}",
            self.listener, self.source, self.target
        )
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "l={}, s={}, t={}",
            self.listener, self.source, self.target
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_address() {
        let a = TargetAddress::DomainPort("aaa".to_owned(), 100);
        let b = "aaa:100".parse().unwrap();
        assert_eq!(a, b);

        let a = TargetAddress::SocketAddr(SocketAddr::V4(SocketAddrV4::new(
            "1.2.3.4".parse().unwrap(),
            100,
        )));
        let b = (0x01020304u32, 100).into();
        assert_eq!(a, b);
    }
}
// use async_trait::async_trait;
// #[async_trait]
// pub trait AsyncInit {
//     async fn init(&mut self) -> Result<(), Error>;
// }
