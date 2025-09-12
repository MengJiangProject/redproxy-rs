use crate::{
    HttpRequest,
    access_log::AccessLog,
    common::{frames::FrameIO, http::HttpRequestV1},
    config::IoParams,
    copy::copy_bidi,
    protocols::http::http_context::HttpContext,
};
use anyhow::{Context as AnyhowContext, Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::Visitor, ser::SerializeStruct};
use std::{
    collections::{HashMap, LinkedList},
    fmt::{Debug, Display},
    io::{Error as IoError, Result as IoResult},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::DerefMut,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    net::lookup_host,
    sync::{Mutex, Notify, RwLock, mpsc::Sender},
};
use tracing::{error, trace, warn};

pub use crate::io::*; //re-export for compatibility

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
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis() as u64
    }
}

#[async_trait]
pub trait ContextCallback: Send + Sync {
    async fn on_connect(&self, _ctx: &mut Context) {}
    async fn on_error(&self, _ctx: &mut Context, _error: Error) {}
    async fn on_finish(&self, _ctx: &mut Context) {}

    // BIND-related callbacks
    async fn on_bind_listen(&self, _ctx: &mut Context, _bind_addr: SocketAddr) {}
    async fn on_bind_accept(&self, _ctx: &mut Context, _peer_addr: SocketAddr) {}
}

#[derive(Debug, Hash, Copy, Clone, Eq, PartialEq, Serialize, Default)]
pub enum ContextState {
    #[default]
    Invalid,
    ClientConnected,
    ClientRequested,
    ServerConnecting,
    Connected,
    BindWaiting,
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
            Self::BindWaiting => "BindWaiting",
            Self::ClientShutdown => "ClientShutdown",
            Self::ServerShutdown => "ServerShutdown",
            Self::Terminated => "Terminated",
            Self::ErrorOccured => "ErrorOccured",
            Self::Invalid => "Invalid",
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

    pub fn sent_bytes(&self) -> usize {
        self.read_bytes.load(Ordering::Relaxed)
    }

    pub fn sent_frames(&self) -> usize {
        self.read_frames.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "metrics")]
use std::sync::OnceLock;

#[cfg(feature = "metrics")]
struct ContextMetrics {
    status: prometheus::HistogramVec,
    gc_count: prometheus::IntCounter,
    gc_time: prometheus::Histogram,
}

#[cfg(feature = "metrics")]
impl ContextMetrics {
    fn new() -> Self {
        Self {
            status: prometheus::register_histogram_vec!(
                "context_state_time",
                "Time of context in this state.",
                &["state", "listener", "connector"],
                vec![
                    0.001, 0.0025, 0.005, 0.0075, 0.010, 0.025, 0.050, 0.075, 0.100, 0.250, 0.500,
                    0.750, 1.0, 2.5, 5.0, 7.5, 10.0, 25.0, 50.0, 75.0,
                ]
            )
            .unwrap(),
            gc_count: prometheus::register_int_counter!(
                "context_gc_count",
                "Number of garbbage collected contexts."
            )
            .unwrap(),
            gc_time: prometheus::register_histogram!(
                "context_gc_time",
                "Context GC time in seconds.",
                vec![
                    0.000_001, 0.000_002, 0.000_005, 0.000_007, 0.000_010, 0.000_025, 0.000_050,
                    0.000_075, 0.000_100, 0.000_250, 0.000_500, 0.001_000
                ]
            )
            .unwrap(),
        }
    }
}

#[cfg(feature = "metrics")]
static CONTEXT_METRICS: OnceLock<ContextMetrics> = OnceLock::new();

#[cfg(feature = "metrics")]
fn context_metrics() -> &'static ContextMetrics {
    CONTEXT_METRICS.get_or_init(ContextMetrics::new)
}

pub struct ContextManager {
    pub history_size: usize,
    next_id: AtomicU64,
    // Efficient atomic counter for alive contexts
    alive_count: AtomicUsize,
    pub alive: Mutex<HashMap<u64, ContextWeakRef>>,
    pub terminated: Mutex<LinkedList<Arc<ContextProps>>>,
    // use std Mutex here because Drop is not async
    pub gc_list: StdMutex<Vec<Arc<ContextProps>>>,
    pub access_log: Option<AccessLog>,
    pub default_timeout: u64,
    // Efficient notification for connection termination
    termination_notify: Arc<Notify>,
}

impl Default for ContextManager {
    fn default() -> Self {
        Self {
            history_size: Default::default(),
            next_id: Default::default(),
            alive_count: AtomicUsize::new(0),
            alive: Default::default(),
            terminated: Default::default(),
            gc_list: Default::default(),
            access_log: None,
            default_timeout: Default::default(),
            termination_notify: Arc::new(Notify::new()),
        }
    }
}

impl ContextManager {
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
            manager: self.clone(),
            http_context: None,
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            // Initialize BIND fields
            bind_task: None,
            io_loop: copy_bidi,
        }));

        // Increment atomic counter and add to alive map
        self.alive_count.fetch_add(1, Ordering::Relaxed);
        self.alive.lock().await.insert(id, Arc::downgrade(&ret));
        ret
    }

    pub fn gc_thread(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut list = Default::default();
                if let Ok(mut gc_list) = self.gc_list.lock() {
                    std::mem::swap(gc_list.deref_mut(), &mut list);
                } else {
                    error!("Failed to acquire GC list lock");
                    continue;
                }
                if !list.is_empty() {
                    trace!("context gc: {}", list.len());
                    #[cfg(feature = "metrics")]
                    let timer = {
                        context_metrics().gc_count.inc_by(list.len() as u64);
                        context_metrics().gc_time.start_timer()
                    };
                    if let Some(log) = &self.access_log {
                        for props in list.iter().cloned() {
                            if let Err(e) = log.write(props).await {
                                error!("Failed to write access log: {}", e);
                            }
                        }
                    }
                    let mut terminated = self.terminated.lock().await;
                    let mut alive = self.alive.lock().await;
                    for props in list {
                        if alive.remove(&props.id).is_none() {
                            warn!("Context {} was not found in alive list during GC", props.id);
                        }
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

    /// Get the count of alive contexts
    pub fn alive_count(&self) -> usize {
        self.alive_count.load(Ordering::Relaxed)
    }

    /// Wait for all contexts to terminate with a timeout using efficient notification
    pub async fn wait_for_termination(&self, timeout_duration: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout_duration;

        loop {
            if self.alive_count() == 0 {
                return true;
            }

            let notified = self.termination_notify.notified();
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                // Timeout occurred, check one last time for race conditions
                return self.alive_count() == 0;
            }
            // If notified, the loop continues to check alive_count again
        }
    }

    /// Abort all remaining contexts with robust error handling and forced termination
    pub async fn abort_all_contexts(&self) {
        let alive = self.alive.lock().await;
        let mut aborted_count = 0;
        let mut failed_aborts = Vec::new();

        // Collect all strong references that need to be aborted
        let contexts_to_abort: Vec<_> = alive
            .values()
            .filter_map(|weak_ref| weak_ref.upgrade())
            .collect();

        drop(alive); // Release lock early

        tracing::info!(
            "Attempting to abort {} active contexts",
            contexts_to_abort.len()
        );

        for (index, ctx_ref) in contexts_to_abort.iter().enumerate() {
            match self.abort_single_context(ctx_ref, index).await {
                Ok(()) => aborted_count += 1,
                Err(e) => {
                    failed_aborts.push((index, e));
                }
            }
        }

        if !failed_aborts.is_empty() {
            tracing::warn!(
                "Failed to abort {} contexts: {:?}",
                failed_aborts.len(),
                failed_aborts
            );
        }

        tracing::info!(
            "Successfully aborted {}/{} contexts",
            aborted_count,
            contexts_to_abort.len()
        );

        // Notify waiters that termination state has changed
        self.termination_notify.notify_waiters();
    }

    /// Signal a single context to shut down gracefully using cancellation token
    async fn abort_single_context(&self, ctx_ref: &ContextRef, index: usize) -> Result<(), String> {
        // Try to acquire read lock with timeout to access cancellation token
        let ctx = match tokio::time::timeout(Duration::from_millis(100), ctx_ref.read()).await {
            Ok(guard) => guard,
            Err(_) => {
                return Err(format!("Context {} lock acquisition timeout", index));
            }
        };

        // Signal cancellation
        ctx.cancellation_token.cancel();

        tracing::debug!("Context {} cancellation signal sent", index);
        Ok(())
    }
}

// Type alias for the BIND task handle
pub type BindTask = tokio::task::JoinHandle<Result<()>>;

/// IO loop function signature - same as copy_bidi
pub type IOLoopFn = fn(
    ContextRef,
    &IoParams,
) -> Pin<
    Box<dyn futures_util::Future<Output = std::result::Result<(), anyhow::Error>> + Send>,
>;

pub struct Context {
    props: Arc<ContextProps>,
    client_stream: Option<IOBufStream>,
    server_stream: Option<IOBufStream>,
    client_frames: Option<FrameIO>,
    server_frames: Option<FrameIO>,
    callback: Option<Arc<dyn ContextCallback + Send + Sync>>,
    manager: Arc<ContextManager>,
    http_context: Option<HttpContext>,
    cancellation_token: tokio_util::sync::CancellationToken,
    // BIND-related fields - using JoinHandle for spawned task
    bind_task: Option<BindTask>,
    io_loop: IOLoopFn,
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

    pub fn take_client_stream(&mut self) -> Option<IOBufStream> {
        self.client_stream.take()
    }

    pub fn take_server_stream(&mut self) -> Option<IOBufStream> {
        self.server_stream.take()
    }

    pub fn take_streams(&mut self) -> Option<(IOBufStream, IOBufStream)> {
        if self.client_stream.is_none() || self.server_stream.is_none() {
            return None;
        }
        match (self.client_stream.take(), self.server_stream.take()) {
            (Some(client), Some(server)) => Some((client, server)),
            _ => {
                error!("Cannot take both client and server streams - one or both unavailable");
                None
            }
        }
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
        match (self.client_frames.take(), self.server_frames.take()) {
            (Some(client), Some(server)) => Some((client, server)),
            _ => {
                error!("Cannot take both client and server frames - one or both unavailable");
                None
            }
        }
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
        self.props.state.last().map(|s| s.state).unwrap_or_default()
    }

    /// Set the context's state.
    pub fn set_state(&mut self, state: ContextState) -> &mut Self {
        #[cfg(feature = "metrics")]
        if let Some(last) = self.props.state.last() {
            let t = last.time.elapsed().unwrap_or_default().as_secs_f64();
            context_metrics()
                .status
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

    pub fn set_http_request_v1(&mut self, request: HttpRequestV1) -> &mut Self {
        self.set_http_request(request.into())
    }

    pub fn http_request_v1(&self) -> Option<Arc<HttpRequestV1>> {
        self.http()
            .and_then(|h| h.request.as_ref())
            .map(|req| Arc::new(req.as_ref().clone().into()))
    }

    pub fn set_http_request(&mut self, request: HttpRequest) -> &mut Self {
        // Store only in HttpContext - single source of truth
        self.http_mut().set_request(request);
        self
    }

    pub fn http_request(&self) -> Option<Arc<HttpRequest>> {
        // Get from HttpContext
        self.http().and_then(|h| h.request.clone())
    }

    /// Get mutable HTTP context, creating if needed
    pub fn http_mut(&mut self) -> &mut HttpContext {
        self.http_context.get_or_insert_with(HttpContext::new)
    }

    /// Get HTTP context (read-only)
    pub fn http(&self) -> Option<&HttpContext> {
        self.http_context.as_ref()
    }

    /// Set HTTP context
    pub fn set_http_context(&mut self, context: HttpContext) -> &mut Self {
        self.http_context = Some(context);
        self
    }

    /// Take HTTP context (for ownership transfer)
    pub fn take_http_context(&mut self) -> Option<HttpContext> {
        self.http_context.take()
    }

    pub fn cancellation_token(&self) -> &tokio_util::sync::CancellationToken {
        &self.cancellation_token
    }

    /// Set up BIND operation with a task handle for waiting
    pub fn set_bind_task(&mut self, task: BindTask) -> &mut Self {
        self.bind_task = Some(task);
        self
    }

    /// Take the BIND task handle for waiting
    pub fn take_bind_task(&mut self) -> Option<BindTask> {
        self.bind_task.take()
    }
    /// Set the IO loop function for this context
    pub fn set_io_loop(&mut self, io_loop: IOLoopFn) -> &mut Self {
        self.io_loop = io_loop;
        self
    }

    /// Get the IO loop function, or None if using default copy_bidi
    pub fn io_loop(&self) -> IOLoopFn {
        self.io_loop
    }
}

// a set of opreations that aquires write lock
#[async_trait]
pub trait ContextRefOps {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<()>;
    async fn on_connect(&self);
    async fn on_error(&self, error: Error);
    async fn on_finish(&self);
    async fn to_string(&self) -> String;
    // BIND-related operations
    async fn on_bind_listen(&self, bind_addr: SocketAddr);
    async fn on_bind_accept(&self, peer_addr: SocketAddr);
    async fn wait_for_bind(&self) -> Result<()>;
}

#[async_trait]
impl ContextRefOps for ContextRef {
    async fn enqueue(self, queue: &Sender<ContextRef>) -> Result<()> {
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
            .set_error(format!("{} cause: {:?}", error, error.source()));
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

    async fn on_bind_listen(&self, bind_addr: SocketAddr) {
        let mut inner = self.write().await;
        inner.set_state(ContextState::BindWaiting);
        if let Some(cb) = inner.callback.clone() {
            cb.on_bind_listen(&mut inner, bind_addr).await
        }
    }

    async fn on_bind_accept(&self, peer_addr: SocketAddr) {
        let mut inner = self.write().await;
        if let Some(cb) = inner.callback.clone() {
            cb.on_bind_accept(&mut inner, peer_addr).await
        }
    }

    async fn wait_for_bind(&self) -> Result<()> {
        let (task, cancellation_token) = {
            let mut inner = self.write().await;
            let task = inner.take_bind_task();
            let token = inner.cancellation_token().clone();
            (task, token)
        };

        if let Some(task) = task {
            // Wait for either the BIND task to complete or cancellation
            tokio::select! {
                result = task => {
                    // Task completed (either success or error)
                    result
                        .map_err(|e| anyhow::anyhow!("BIND task panicked: {}", e))
                        .and_then(|result| result)
                }
                _ = cancellation_token.cancelled() => {
                    // Shutdown requested - abort waiting
                    Err(anyhow::anyhow!("BIND wait cancelled during shutdown"))
                }
            }
        } else {
            Err(anyhow::anyhow!("No BIND task available"))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        trace!("Context dropped: {}", self);

        // Decrement atomic counter immediately
        self.manager.alive_count.fetch_sub(1, Ordering::Relaxed);

        if let Ok(mut gc_list) = self.manager.gc_list.lock() {
            gc_list.push(self.props.clone());
        } else {
            error!("Failed to acquire GC list lock during context drop");
        }

        // Notify waiters that a context has been dropped
        self.manager.termination_notify.notify_waiters();
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

    #[tokio::test]
    async fn test_context_http_integration() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx_ref = manager.create_context("test".to_string(), source).await;

        let request = crate::HttpRequest {
            method: crate::protocols::http::HttpMethod::Get,
            uri: "/api/test".to_string(),
            version: crate::protocols::http::HttpVersion::Http1_1,
            headers: vec![("Host".to_string(), "example.com".to_string())],
        };

        // Test setting HTTP request through Context API
        {
            let mut ctx = ctx_ref.write().await;
            ctx.set_http_request(request.clone());
        }

        // Test retrieving HTTP request
        let retrieved = {
            let ctx = ctx_ref.read().await;
            ctx.http_request()
        };

        assert!(retrieved.is_some());
        let retrieved_req = retrieved.unwrap();
        assert_eq!(retrieved_req.uri, "/api/test");
        assert_eq!(
            retrieved_req.method,
            crate::protocols::http::HttpMethod::Get
        );

        // Test HttpContext direct access
        let ctx = ctx_ref.read().await;
        let http_ctx = ctx.http().unwrap();
        assert!(http_ctx.request.is_some());

        // Verify single source of truth - same Arc instance
        let direct_req = http_ctx.request.as_ref().unwrap();
        assert!(Arc::ptr_eq(&retrieved_req, direct_req));
    }

    #[tokio::test]
    async fn test_context_http_backward_compatibility() {
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx_ref = manager.create_context("test".to_string(), source).await;

        // Test old HttpRequestV1 compatibility
        let old_request = crate::common::http::HttpRequestV1 {
            method: "POST".to_string(),
            resource: "/submit".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        };

        {
            let mut ctx = ctx_ref.write().await;
            ctx.set_http_request_v1(old_request.clone());
        }

        // Should be accessible through both old and new APIs
        let ctx = ctx_ref.read().await;

        // New API
        let new_req = ctx.http_request().unwrap();
        assert_eq!(new_req.uri, "/submit");
        assert_eq!(new_req.method, crate::protocols::http::HttpMethod::Post);

        // Old API compatibility
        let old_req = ctx.http_request_v1().unwrap();
        assert_eq!(old_req.resource, "/submit");
        assert_eq!(old_req.method, "POST");
    }

    #[tokio::test]
    async fn test_context_http_properties_integration() {
        use crate::protocols::http::context_ext::HttpContextExt;

        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();
        let ctx_ref = manager.create_context("test".to_string(), source).await;

        {
            let mut ctx = ctx_ref.write().await;
            ctx.set_http_protocol("h2")
                .set_http_forward_proxy(true)
                .set_http_keep_alive(false)
                .set_http_proxy_auth("user:secret")
                .set_http_max_requests(50);
        }

        let ctx = ctx_ref.read().await;
        assert_eq!(ctx.http_protocol(), Some("h2"));
        assert!(ctx.http_forward_proxy());
        assert!(!ctx.http_keep_alive());
        assert_eq!(ctx.http_proxy_auth(), Some("user:secret"));
        assert_eq!(ctx.http_max_requests(), Some(50));

        // Verify HttpContext internal structure
        let http_ctx = ctx.http().unwrap();
        assert_eq!(http_ctx.protocol.as_deref(), Some("h2"));
        assert!(http_ctx.forward_proxy);
        assert!(!http_ctx.keep_alive);
        assert_eq!(http_ctx.max_requests, Some(50));

        // Verify ProxyAuth structure
        let auth = http_ctx.proxy_auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "secret");
        assert_eq!(auth.original_credentials, "user:secret");
    }

    #[test]
    fn test_context_http_lazy_initialization() {
        // Test that HttpContext is only created when needed
        let manager = Arc::new(ContextManager::default());
        let source = "127.0.0.1:1234".parse().unwrap();

        // This is a synchronous test to avoid async complexity
        let props = Arc::new(ContextProps {
            id: 1,
            source,
            listener: "test".to_string(),
            ..Default::default()
        });

        let mut context = Context {
            props,
            client_stream: None,
            server_stream: None,
            client_frames: None,
            server_frames: None,
            callback: None,
            manager: manager.clone(),
            http_context: None,
            cancellation_token: tokio_util::sync::CancellationToken::new(),
            bind_task: None,
            io_loop: crate::copy::copy_bidi,
        };

        // Initially no HttpContext
        assert!(context.http().is_none());

        // Accessing http_mut() creates it
        let _http = context.http_mut();
        assert!(context.http().is_some());

        // Verify default values
        let http_ctx = context.http().unwrap();
        assert!(http_ctx.keep_alive);
        assert!(!http_ctx.forward_proxy);
        assert_eq!(http_ctx.protocol(), "http/1.1");
    }
}
