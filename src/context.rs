use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{ser::SerializeStruct, Serialize};
use std::{
    collections::{HashMap, LinkedList},
    fmt::{Debug, Display},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Weak,
    },
    time::{Duration, SystemTime},
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

impl Serialize for TargetAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
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

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq, Serialize)]
pub enum ContextStatus {
    ClientConnected,
    ClientRequested,
    ServerConnecting,
    Connected,
    // ShutdowningDown,
    Terminated,
    ErrorOccured,
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct ContextStatusLog {
    status: ContextStatus,
    time: SystemTime,
}

impl Serialize for ContextStatusLog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("ContextStatusLog", 2)?;
        st.serialize_field("status", &self.status)?;
        st.serialize_field(
            "time",
            &self
                .time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )?;
        st.end()
    }
}

impl From<(ContextStatus, SystemTime)> for ContextStatusLog {
    fn from((status, time): (ContextStatus, SystemTime)) -> Self {
        Self { status, time }
    }
}

// this is the value object of Context, chould be used in filter evaluation or stored after Context is terminated, for statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ContextProps {
    pub id: u64,
    pub status: Vec<ContextStatusLog>,
    pub listener: String,
    pub source: SocketAddr,
    pub target: TargetAddress,
    pub client_sent: Arc<AtomicUsize>,
    pub server_sent: Arc<AtomicUsize>,
}

impl std::hash::Hash for ContextProps {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for ContextProps {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Default for ContextProps {
    fn default() -> Self {
        Self {
            id: Default::default(),
            status: Default::default(),
            listener: Default::default(),
            source: ([0, 0, 0, 0], 0).into(),
            target: TargetAddress::Unknown,
            client_sent: Default::default(),
            server_sent: Default::default(),
        }
    }
}

const CONTEXT_HISTORY_LENGTH: usize = 100;

use std::sync::Mutex as StdMutex;

#[derive(Default)]
pub struct GlobalState {
    next_id: AtomicU64,
    pub alive: Mutex<HashMap<u64, ContextWeakRef>>,
    pub terminated: Mutex<LinkedList<Arc<ContextProps>>>,
    // use std Mutex here because Drop is not async
    pub gc_list: StdMutex<Vec<Arc<ContextProps>>>,
}
impl GlobalState {
    pub async fn create_context(
        self: &Arc<Self>,
        listener: String,
        source: SocketAddr,
    ) -> ContextRef {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let props = Arc::new(ContextProps {
            id,
            listener,
            source,
            status: vec![(ContextStatus::ClientConnected, SystemTime::now()).into()],
            ..Default::default()
        });
        let ret = Arc::new(RwLock::new(Context {
            props,
            client: None,
            server: None,
            callback: None,
            state: self.clone(),
        }));
        self.alive.lock().await.insert(id, Arc::downgrade(&ret));
        ret
    }

    pub async fn drop_context(&self, props: Arc<ContextProps>) {
        self.alive.lock().await.remove(&props.id).unwrap();
        let mut list = self.terminated.lock().await;
        list.push_back(props);
        if list.len() > CONTEXT_HISTORY_LENGTH {
            list.pop_front();
        }
    }

    pub fn gc_thread(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let list: Vec<_> = self.gc_list.lock().unwrap().drain(..).collect();
                if !list.is_empty() {
                    trace!("context gc: {}", list.len());
                    for x in list {
                        self.drop_context(x).await;
                    }
                }
            }
        });
    }
}

pub struct Context {
    props: Arc<ContextProps>,
    client: Option<Arc<Mutex<IOBufStream>>>,
    server: Option<Arc<Mutex<IOBufStream>>>,
    callback: Option<Arc<dyn ContextCallback + Send + Sync>>,
    state: Arc<GlobalState>,
}

pub type ContextRef = Arc<RwLock<Context>>;
pub type ContextWeakRef = Weak<RwLock<Context>>;

#[allow(dead_code)]
impl Context {
    /// Set the context's callback.
    pub fn set_callback<T: ContextCallback + Send + Sync + 'static>(
        &mut self,
        callback: T,
    ) -> &mut Self {
        self.callback = Some(Arc::new(callback));
        self
    }

    /// Set the context's client stream.
    pub fn set_client_stream(&mut self, stream: IOBufStream) -> &mut Self {
        self.client = Some(Arc::new(Mutex::new(stream)));
        self
    }

    /// Set the context's server stream.
    pub fn set_server_stream(&mut self, stream: IOBufStream) -> &mut Self {
        self.server = Some(Arc::new(Mutex::new(stream)));
        self
    }

    /// Get a locked reference to the context's client stream.
    pub async fn get_client_stream(&self) -> MutexGuard<'_, IOBufStream> {
        self.client.as_ref().unwrap().lock().await
    }

    /// Get a locked reference to the context's server stream.
    pub async fn get_server_stream(&self) -> MutexGuard<'_, IOBufStream> {
        self.server.as_ref().unwrap().lock().await
    }

    /// Get a clone to the context's target.
    pub fn target(&self) -> TargetAddress {
        self.props.target.clone()
    }

    /// Set the context's target.
    pub fn set_target(&mut self, target: TargetAddress) -> &mut Self {
        Arc::make_mut(&mut self.props).target = target;
        self
    }

    // Get status of the context.
    pub fn status(&self) -> ContextStatus {
        self.props.status.last().unwrap().status
    }

    /// Set the context's status.
    pub fn set_status(&mut self, status: ContextStatus) -> &mut Self {
        Arc::make_mut(&mut self.props)
            .status
            .push((status, SystemTime::now()).into());
        // trace!("set_status: {:?}", self.props.status);
        self
    }

    /// Get a reference to the context's properties.
    pub fn props(&self) -> &Arc<ContextProps> {
        &self.props
    }
}

// a set of opreations that aquires write lock
#[async_trait]
pub trait ContextRefOps {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error>;
    async fn on_connect(&self);
    async fn on_error(&self, error: Error);
}

#[async_trait]
impl ContextRefOps for ContextRef {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error> {
        self.write()
            .await
            .set_status(ContextStatus::ClientRequested);
        queue.send(self).await.context("enqueue")
    }
    async fn on_connect(&self) {
        self.write().await.set_status(ContextStatus::Connected);
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_connect(self.clone()).await
        }
    }
    async fn on_error(&self, error: Error) {
        self.write().await.set_status(ContextStatus::ErrorOccured);
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_error(self.clone(), error).await
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        trace!("Context dropped: {}", self);
        self.state.gc_list.lock().unwrap().push(self.props.clone());
    }
}

impl std::hash::Hash for Context {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.props.hash(state);
    }
}

impl Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id={} l={}, s={}, t={}",
            self.props.id, self.props.listener, self.props.source, self.props.target
        )
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
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
