use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use log::trace;
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Serialize};
use std::{
    collections::{HashMap, LinkedList},
    fmt::{Debug, Display},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::DerefMut,
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
    pub fn host(&self) -> String {
        match self {
            Self::DomainPort(x, _) => x.to_owned(),
            Self::SocketAddr(x) => x.ip().to_string(),
            Self::Unknown => "unknown".to_owned(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Self::DomainPort(_, x) => *x,
            Self::SocketAddr(x) => x.port(),
            Self::Unknown => 0,
        }
    }
    pub fn r#type(&self) -> &str {
        match self {
            Self::DomainPort(_, _) => "domain",
            Self::SocketAddr(x) => {
                if x.is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                }
            }
            Self::Unknown => "unknown",
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

struct TargetAddressVisitor;
impl<'de> Visitor<'de> for TargetAddressVisitor {
    type Value = TargetAddress;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("ip:port or domain:port")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse()
            .map_err(|e: InvalidAddress| serde::de::Error::custom(e.to_string()))
    }
}

impl<'de> Deserialize<'de> for TargetAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(TargetAddressVisitor)
    }
}

trait UnixTimestamp {
    fn unix_timestamp(&self) -> u64;
}

impl UnixTimestamp for SystemTime {
    fn unix_timestamp(&self) -> u64 {
        self.duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
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
pub enum ContextState {
    ClientConnected,
    ClientRequested,
    ServerConnecting,
    Connected,
    // ShutdowningDown,
    Terminated,
    ErrorOccured,
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq)]
pub struct ContextStateLog {
    state: ContextState,
    time: SystemTime,
}

impl Serialize for ContextStateLog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("ContextStateLog", 2)?;
        st.serialize_field("state", &self.state)?;
        st.serialize_field("time", &self.time.unix_timestamp())?;
        st.end()
    }
}

impl From<(ContextState, SystemTime)> for ContextStateLog {
    fn from((state, time): (ContextState, SystemTime)) -> Self {
        Self { state, time }
    }
}

// this is the value object of Context, chould be used in filter evaluation or stored after Context is terminated, for statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ContextProps {
    pub id: u64,
    pub state: Vec<ContextStateLog>,
    pub listener: String,
    pub connector: Option<String>,
    pub source: SocketAddr,
    pub target: TargetAddress,
    pub error: Option<String>,
    pub client_stat: Arc<ContextStatistics>,
    pub server_stat: Arc<ContextStatistics>,
    pub extra: HashMap<String, String>,
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
            state: Default::default(),
            listener: Default::default(),
            connector: Default::default(),
            source: ([0, 0, 0, 0], 0).into(),
            target: TargetAddress::Unknown,
            error: Default::default(),
            client_stat: Default::default(),
            server_stat: Default::default(),
            extra: Default::default(),
        }
    }
}

#[derive(Default, Serialize, Debug)]
pub struct ContextStatistics {
    read_bytes: AtomicUsize,
    last_read: AtomicU64,
}

impl ContextStatistics {
    pub fn incr_sent_bytes(&self, cnt: usize) {
        self.read_bytes.fetch_add(cnt, Ordering::Relaxed);
        self.last_read
            .store(SystemTime::now().unix_timestamp(), Ordering::Relaxed)
    }
}

use std::sync::Mutex as StdMutex;

#[derive(Default)]
pub struct GlobalState {
    pub history_size: usize,
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
            state: vec![(ContextState::ClientConnected, SystemTime::now()).into()],
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

    pub fn gc_thread(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut list = Default::default();
                std::mem::swap(self.gc_list.lock().unwrap().deref_mut(), &mut list);
                if !list.is_empty() {
                    trace!("context gc: {}", list.len());
                    let mut terminated = self.terminated.lock().await;
                    let mut alive = self.alive.lock().await;
                    for props in list {
                        alive.remove(&props.id).unwrap();
                        terminated.push_front(props);
                    }
                    while terminated.len() > self.history_size {
                        terminated.pop_back();
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

    fn clear_callback(&mut self) {
        self.callback = None;
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

    /// Set the connector name.
    pub fn set_connector(&mut self, connector: String) -> &mut Self {
        Arc::make_mut(&mut self.props).connector = Some(connector);
        self
    }

    /// Set the error message.
    pub fn set_error(&mut self, error: String) -> &mut Self {
        Arc::make_mut(&mut self.props).error = Some(error);
        self
    }

    // Get state of the context.
    pub fn state(&self) -> ContextState {
        self.props.state.last().unwrap().state
    }

    /// Set the context's state.
    pub fn set_state(&mut self, state: ContextState) -> &mut Self {
        Arc::make_mut(&mut self.props)
            .state
            .push((state, SystemTime::now()).into());
        // trace!("set_state: {:?}", self.props.state);
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
    async fn to_string(&self) -> String;
}

#[async_trait]
impl ContextRefOps for ContextRef {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error> {
        self.write().await.set_state(ContextState::ClientRequested);
        queue.send(self).await.context("enqueue")
    }
    async fn on_connect(&self) {
        self.write().await.set_state(ContextState::Connected);
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_connect(self.clone()).await
        }
        self.write().await.clear_callback();
    }
    async fn on_error(&self, error: Error) {
        self.write()
            .await
            .set_state(ContextState::ErrorOccured)
            .set_error(format!("{} cause: {:?}", error, error.cause));
        if let Some(cb) = self.read().await.callback.clone() {
            cb.on_error(self.clone(), error).await
        }
        self.write().await.clear_callback();
    }
    async fn to_string(&self) -> String {
        self.read().await.to_string()
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
