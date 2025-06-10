use crate::{access_log::AccessLog, common::frames::FrameIO};
use async_trait::async_trait;
use easy_error::{Error, ResultExt};
use serde::{Deserialize, Serialize, de::Visitor, ser::SerializeStruct};
use std::{
    any::Any,
    collections::{HashMap, LinkedList},
    fmt::{Debug, Display},
    io::Error as IoError,
    io::Result as IoResult,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::DerefMut,
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, BufWriter},
    net::lookup_host,
    sync::{Mutex, RwLock, mpsc::Sender},
};
use tracing::trace;

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
    // pub async fn connect_tcp(&self) -> std::io::Result<TcpStream> {
    //     match self {
    //         Self::DomainPort(host, port) => TcpStream::connect((host.as_str(), *port)).await,
    //         Self::SocketAddr(addr) => TcpStream::connect(addr).await,
    //         _ => unreachable!(),
    //     }
    // }
    #[allow(dead_code)]
    pub async fn resolve(&self) -> IoResult<SocketAddr> {
        match self {
            Self::DomainPort(host, port) => {
                let addr = format!("{}:{}", host, port);
                let mut ret = lookup_host(addr.as_str()).await?;
                ret.next().ok_or_else(|| IoError::other("DNS Error"))
            }
            Self::SocketAddr(addr) => Ok(*addr),
            _ => unreachable!(),
        }
    }
    #[allow(dead_code)]
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::SocketAddr(x) => Some(*x),
            _ => None,
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

impl From<SocketAddr> for TargetAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }
}

impl From<(Ipv4Addr, u16)> for TargetAddress {
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        let a = SocketAddrV4::new(ip, port);
        Self::SocketAddr(SocketAddr::V4(a))
    }
}

impl From<(Ipv6Addr, u16)> for TargetAddress {
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        let a = SocketAddrV6::new(ip, port, 0, 0);
        Self::SocketAddr(SocketAddr::V6(a))
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

impl From<(String, u16)> for TargetAddress {
    fn from((host, port): (String, u16)) -> Self {
        Self::DomainPort(host, port)
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
impl Visitor<'_> for TargetAddressVisitor {
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

#[allow(dead_code)]
pub trait IOStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn as_any(&self) -> &dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T> IOStream for T
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // used to check if underlying stream is TcpStream, since specialization is unstable, we have to use dyn Any instead.
    // TODO: should use specialization when it's ready.
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
pub type IOBufStream = BufReader<BufWriter<Box<dyn IOStream>>>;

pub fn make_buffered_stream<T: IOStream + 'static>(stream: T) -> IOBufStream {
    BufReader::new(BufWriter::new(Box::new(stream)))
}

#[async_trait]
pub trait ContextCallback: Send + Sync {
    async fn on_connect(&self, _ctx: &mut Context) {}
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {}
    async fn on_finish(&self, _ctx: &mut Context) {}
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq, Serialize)]
pub enum ContextState {
    ClientConnected,
    ClientRequested,
    ServerConnecting,
    Connected,
    ServerShutdown,
    ClientShutdown,
    Terminated,
    ErrorOccured,
}

impl ContextState {
    #[cfg(feature = "metrics")]
    fn as_str(&self) -> &'static str {
        match self {
            Self::ClientConnected => "ClientConnected",
            Self::ClientRequested => "ClientRequested",
            Self::ServerConnecting => "ServerConnecting",
            Self::Connected => "Connected",
            Self::ClientShutdown => "ClientShutdown",
            Self::ServerShutdown => "ServerShutdown",
            Self::Terminated => "Terminated",
            Self::ErrorOccured => "ErrorOccured",
        }
    }
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
    pub local_addr: SocketAddr,
    pub server_addr: SocketAddr,
    pub error: Option<String>,
    pub client_stat: Arc<ContextStatistics>,
    pub server_stat: Arc<ContextStatistics>,
    pub extra: HashMap<String, String>,
    pub request_feature: Feature,
    pub idle_timeout: u64,
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
            local_addr: ([0, 0, 0, 0], 0).into(),
            server_addr: ([0, 0, 0, 0], 0).into(),
            error: Default::default(),
            client_stat: Default::default(),
            server_stat: Default::default(),
            extra: Default::default(),
            request_feature: Default::default(),
            idle_timeout: Default::default(),
        }
    }
}

impl Display for ContextProps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id={} l={} c={} s={} t={} f={}",
            self.id,
            self.listener,
            self.connector.as_deref().unwrap_or("<null>"),
            self.source,
            self.target,
            self.request_feature,
        )
    }
}

#[derive(Serialize, Debug)]
pub struct ContextStatistics {
    read_bytes: AtomicUsize,
    read_frames: AtomicUsize,
    last_read: AtomicU64,
}

impl Default for ContextStatistics {
    fn default() -> Self {
        Self {
            read_bytes: AtomicUsize::new(0),
            read_frames: AtomicUsize::new(0),
            last_read: AtomicU64::new(SystemTime::now().unix_timestamp()),
        }
    }
}

impl ContextStatistics {
    pub fn incr_sent_bytes(&self, cnt: usize) {
        self.read_bytes.fetch_add(cnt, Ordering::Relaxed);
        self.last_read
            .store(SystemTime::now().unix_timestamp(), Ordering::Relaxed)
    }
    pub fn incr_sent_frames(&self, cnt: usize) {
        self.read_frames.fetch_add(cnt, Ordering::Relaxed);
        self.last_read
            .store(SystemTime::now().unix_timestamp(), Ordering::Relaxed)
    }
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        if timeout.is_zero() {
            return false;
        }
        let last_read = self.last_read.load(Ordering::Relaxed);
        let now = SystemTime::now().unix_timestamp();
        now - last_read > timeout.as_millis() as u64
    }
}

#[cfg(feature = "metrics")]
lazy_static::lazy_static! {
    static ref CONTEXT_STATUS: prometheus::HistogramVec = prometheus::register_histogram_vec!(
        "context_state_time",
        "Time of context in this state.",
        &["state","listener","connector"],
        vec![
            0.001, 0.0025, 0.005, 0.0075,
            0.010, 0.025, 0.050, 0.075,
            0.100, 0.250, 0.500, 0.750,
            1.0,   2.5,   5.0,   7.5,
            10.0,  25.0,  50.0,  75.0,
        ]
    )
    .unwrap();
    static ref CONTEXT_GC_COUNT: prometheus::IntCounter = prometheus::register_int_counter!(
        "context_gc_count",
        "Number of garbbage collected contexts."
    )
    .unwrap();
    static ref CONTEXT_GC_TIME: prometheus::Histogram = prometheus::register_histogram!(
        "context_gc_time",
        "Context GC time in seconds.",
        vec![
            0.000_001, 0.000_002, 0.000_005, 0.000_007,
            0.000_010, 0.000_025, 0.000_050, 0.000_075,
            0.000_100, 0.000_250, 0.000_500, 0.001_000
        ]
    )
    .unwrap();
}

#[derive(Default)]
pub struct GlobalState {
    pub history_size: usize,
    next_id: AtomicU64,
    pub alive: Mutex<HashMap<u64, ContextWeakRef>>,
    pub terminated: Mutex<LinkedList<Arc<ContextProps>>>,
    // use std Mutex here because Drop is not async
    pub gc_list: StdMutex<Vec<Arc<ContextProps>>>,
    pub access_log: Option<AccessLog>,
    pub default_timeout: u64,
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
            idle_timeout: self.default_timeout,
            state: vec![(ContextState::ClientConnected, SystemTime::now()).into()],
            ..Default::default()
        });
        let ret = Arc::new(RwLock::new(Context {
            props,
            client_stream: None,
            server_stream: None,
            client_frames: None,
            server_frames: None,
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
                    #[cfg(feature = "metrics")]
                    let timer = {
                        CONTEXT_GC_COUNT.inc_by(list.len() as u64);
                        CONTEXT_GC_TIME.start_timer()
                    };
                    if let Some(log) = &self.access_log {
                        for props in list.iter().cloned() {
                            log.write(props).await.unwrap();
                        }
                    }
                    let mut terminated = self.terminated.lock().await;
                    let mut alive = self.alive.lock().await;
                    for props in list {
                        alive.remove(&props.id).unwrap();
                        terminated.push_front(props);
                    }
                    while terminated.len() > self.history_size {
                        terminated.pop_back();
                    }
                    #[cfg(feature = "metrics")]
                    timer.stop_and_record();
                }
            }
        });
    }
}

pub struct Context {
    props: Arc<ContextProps>,
    client_stream: Option<IOBufStream>,
    server_stream: Option<IOBufStream>,
    client_frames: Option<FrameIO>,
    server_frames: Option<FrameIO>,
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

    pub fn set_feature(&mut self, feature: Feature) -> &mut Self {
        Arc::make_mut(&mut self.props).request_feature = feature;
        self
    }

    pub fn feature(&self) -> Feature {
        self.props.request_feature
    }

    /// Set the context's client stream.
    pub fn set_client_stream(&mut self, stream: IOBufStream) -> &mut Self {
        self.client_stream = Some(stream);
        self
    }

    /// Set the context's server stream.
    pub fn set_server_stream(&mut self, stream: IOBufStream) -> &mut Self {
        self.server_stream = Some(stream);
        self
    }

    pub fn borrow_client_stream(&mut self) -> Option<&mut IOBufStream> {
        self.client_stream.as_mut()
    }

    pub fn take_client_stream(&mut self) -> IOBufStream {
        self.client_stream.take().unwrap()
    }

    pub fn take_streams(&mut self) -> Option<(IOBufStream, IOBufStream)> {
        if self.client_stream.is_none() || self.server_stream.is_none() {
            return None;
        }
        Some((
            self.client_stream.take().unwrap(),
            self.server_stream.take().unwrap(),
        ))
    }

    pub fn set_client_frames(&mut self, frames: FrameIO) -> &mut Self {
        self.client_frames = Some(frames);
        self
    }

    pub fn set_server_frames(&mut self, frames: FrameIO) -> &mut Self {
        self.server_frames = Some(frames);
        self
    }

    pub fn take_frames(&mut self) -> Option<(FrameIO, FrameIO)> {
        if self.client_frames.is_none() || self.server_frames.is_none() {
            return None;
        }
        Some((
            self.client_frames.take().unwrap(),
            self.server_frames.take().unwrap(),
        ))
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

    /// Get a clone to the context's remote_addr.
    pub fn server_addr(&self) -> SocketAddr {
        self.props.server_addr
    }

    /// Set the context's remote_addr.
    pub fn set_server_addr(&mut self, server_addr: SocketAddr) -> &mut Self {
        Arc::make_mut(&mut self.props).server_addr = server_addr;
        self
    }

    /// Get a clone to the context's remote_addr.
    pub fn local_addr(&self) -> SocketAddr {
        self.props.local_addr
    }

    /// Set the context's remote_addr.
    pub fn set_local_addr(&mut self, local_addr: SocketAddr) -> &mut Self {
        Arc::make_mut(&mut self.props).local_addr = local_addr;
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

    pub fn set_extra(&mut self, key: impl ToString, val: impl ToString) -> &mut Self {
        Arc::make_mut(&mut self.props)
            .extra
            .insert(key.to_string(), val.to_string());
        self
    }

    pub fn extra(&self, key: &str) -> Option<&str> {
        self.props.extra.get(key).map(|v| v.as_str())
    }

    // Get state of the context.
    pub fn state(&self) -> ContextState {
        self.props.state.last().unwrap().state
    }

    /// Set the context's state.
    pub fn set_state(&mut self, state: ContextState) -> &mut Self {
        #[cfg(feature = "metrics")]
        if let Some(last) = self.props.state.last() {
            let t = last.time.elapsed().unwrap().as_secs_f64();
            CONTEXT_STATUS
                .with_label_values(&[
                    last.state.as_str(),
                    self.props.listener.as_str(),
                    self.props.connector.as_deref().unwrap_or("null"),
                ])
                .observe(t);
        }
        Arc::make_mut(&mut self.props)
            .state
            .push((state, SystemTime::now()).into());
        tracing::debug!("set_state: ctx={} state={:?}", self.props, state);
        self
    }

    /// Get a reference to the context's properties.
    pub fn props(&self) -> &Arc<ContextProps> {
        &self.props
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.props.idle_timeout)
    }

    pub fn set_idle_timeout(&mut self, timeout: u64) -> &mut Self {
        Arc::make_mut(&mut self.props).idle_timeout = timeout;
        self
    }
}

// a set of opreations that aquires write lock
#[async_trait]
pub trait ContextRefOps {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error>;
    async fn on_connect(&self);
    async fn on_error(&self, error: Error);
    async fn on_finish(&self);
    async fn to_string(&self) -> String;
}

#[async_trait]
impl ContextRefOps for ContextRef {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<(), Error> {
        self.write().await.set_state(ContextState::ClientRequested);
        queue.send(self).await.context("enqueue")
    }
    async fn on_connect(&self) {
        let mut inner = self.write().await;
        inner.set_state(ContextState::Connected);
        if let Some(cb) = inner.callback.clone() {
            cb.on_connect(&mut inner).await
        }
        // self.write().await.clear_callback();
    }
    async fn on_error(&self, error: Error) {
        let mut inner = self.write().await;
        inner
            .set_state(ContextState::ErrorOccured)
            .set_error(format!("{} cause: {:?}", error, error.cause));
        if let Some(cb) = inner.callback.clone() {
            cb.on_error(&mut inner, error).await
        }
        // self.write().await.clear_callback();
    }
    async fn on_finish(&self) {
        let mut inner = self.write().await;
        if let Some(cb) = inner.callback.clone() {
            cb.on_finish(&mut inner).await
        }
        // self.write().await.clear_callback();
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
        Display::fmt(&self.props, f)
    }
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.props, f)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum Feature {
    // 1-to-1 connection
    #[default]
    TcpForward,
    // 1-to-any listening (one shot only)
    TcpBind,
    // 1-to-1 connection
    UdpForward,
    // 1-to-many listening
    UdpBind,
    // maybe we should add tap/tun support in the future
}

impl Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
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
