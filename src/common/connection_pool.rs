use crate::context::ContextRef;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Generic connection manager trait (inspired by deadpool and bb8)
#[async_trait]
pub trait ConnectionManager: Send + Sync + Clone + 'static {
    type Connection: Send + Sync + 'static;
    type Key: Clone + Hash + Eq + Send + Sync + 'static;

    /// Create a new connection
    async fn create(&self, key: &Self::Key, ctx: ContextRef) -> Result<Self::Connection>;

    /// Check if a connection is still valid/healthy
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<bool>;

    /// Prepare connection for reuse (cleanup, reset state, etc.)
    async fn recycle(&self, conn: &mut Self::Connection) -> Result<()>;

    /// Check if connection can be reused (multiplexing support, etc.)
    fn is_reusable(&self, conn: &Self::Connection) -> bool;

    /// Get maximum requests per connection (for protocols with request limits)
    fn max_requests_per_connection(&self, _conn: &Self::Connection) -> Option<u32> {
        None
    }
}

/// Pooled connection with metadata
#[derive(Debug)]
pub struct PooledConnection<T> {
    pub connection: T,
    pub created_at: Instant,
    pub last_used: Instant,
    pub request_count: u32,
    pub max_requests: Option<u32>,
}

impl<T> PooledConnection<T> {
    pub fn new(connection: T) -> Self {
        let now = Instant::now();
        Self {
            connection,
            created_at: now,
            last_used: now,
            request_count: 0,
            max_requests: None,
        }
    }

    pub fn with_max_requests(mut self, max_requests: u32) -> Self {
        self.max_requests = Some(max_requests);
        self
    }

    pub fn is_expired(&self, max_idle: Duration, max_lifetime: Duration) -> bool {
        let now = Instant::now();

        // Check idle timeout
        if now.duration_since(self.last_used) > max_idle {
            return true;
        }

        // Check lifetime timeout
        if now.duration_since(self.created_at) > max_lifetime {
            return true;
        }

        // Check request count limit
        if let Some(max_req) = self.max_requests
            && self.request_count >= max_req
        {
            return true;
        }

        false
    }

    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.request_count += 1;
    }
}

/// Connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections per pool key
    pub max_connections_per_host: u32,
    /// Maximum total connections across all hosts
    pub max_total_connections: u32,
    /// Maximum idle time before connection is closed
    pub max_idle_time: Duration,
    /// Maximum connection lifetime
    pub max_lifetime: Duration,
    /// Interval for cleanup of expired connections
    pub cleanup_interval: Duration,
    /// Maximum number of requests per connection (for protocols with limits)
    pub max_requests_per_connection: Option<u32>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 10,
            max_total_connections: 100,
            max_idle_time: Duration::from_secs(90),
            max_lifetime: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
            max_requests_per_connection: Some(100),
        }
    }
}

/// Statistics for connection pool
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub total_connections: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub connections_created: u64,
    pub connections_closed: u64,
    pub cleanup_runs: u64,
}

/// Generic connection pool trait
#[async_trait]
pub trait ConnectionPool<M: ConnectionManager>: Send + Sync {
    /// Get a connection from the pool or create a new one
    async fn get(&self, key: &M::Key, ctx: ContextRef) -> Result<M::Connection>;

    /// Return a connection to the pool for reuse
    async fn put(&self, key: &M::Key, connection: M::Connection) -> Result<()>;

    /// Remove all connections for a specific key
    async fn invalidate(&self, key: &M::Key) -> Result<()>;

    /// Clear all connections from the pool
    async fn clear(&self) -> Result<()>;

    /// Get pool statistics
    async fn stats(&self) -> PoolStats;

    /// Run cleanup to remove expired connections
    async fn cleanup(&self) -> Result<u32>;
}

/// Type aliases to reduce complexity
type ConnectionPools<M> = Arc<
    RwLock<
        HashMap<
            <M as ConnectionManager>::Key,
            Vec<PooledConnection<<M as ConnectionManager>::Connection>>,
        >,
    >,
>;
type SharedStats = Arc<RwLock<PoolStats>>;

/// Default implementation of generic connection pool
pub struct DefaultConnectionPool<M: ConnectionManager> {
    config: PoolConfig,
    pools: ConnectionPools<M>,
    stats: SharedStats,
    manager: M,
}

impl<M: ConnectionManager> DefaultConnectionPool<M> {
    pub fn new(config: PoolConfig, manager: M) -> Self {
        Self {
            config,
            pools: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PoolStats::default())),
            manager,
        }
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        let interval = self.config.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                if let Err(e) = pool.cleanup().await {
                    tracing::warn!("Connection pool cleanup failed: {}", e);
                }
            }
        })
    }

    async fn get_pooled_connection(&self, key: &M::Key) -> Option<M::Connection> {
        // First check if the key exists with a read lock only
        {
            let pools = self.pools.read().await;
            if !pools.contains_key(key) {
                return None;
            }
        }

        // Then acquire write lock for actual connection retrieval
        let mut pools = self.pools.write().await;
        let connections = pools.get_mut(key)?;

        // Find a reusable connection that's not expired
        let pos = connections.iter().position(|conn| {
            !conn.is_expired(self.config.max_idle_time, self.config.max_lifetime)
        })?;

        let mut conn = connections.remove(pos);
        conn.mark_used();

        // Update stats
        let mut stats = self.stats.write().await;
        stats.cache_hits += 1;
        stats.active_connections += 1;
        stats.idle_connections = stats.idle_connections.saturating_sub(1);

        Some(conn.connection)
    }

    async fn create_new_connection(&self, key: &M::Key, ctx: ContextRef) -> Result<M::Connection> {
        let connection = self.manager.create(key, ctx).await?;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.cache_misses += 1;
        stats.connections_created += 1;
        stats.active_connections += 1;

        Ok(connection)
    }
}

impl<M: ConnectionManager> Clone for DefaultConnectionPool<M> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            pools: Arc::clone(&self.pools),
            stats: Arc::clone(&self.stats),
            manager: self.manager.clone(),
        }
    }
}

#[async_trait]
impl<M: ConnectionManager> ConnectionPool<M> for DefaultConnectionPool<M> {
    async fn get(&self, key: &M::Key, ctx: ContextRef) -> Result<M::Connection> {
        // Try to get from pool first
        if let Some(connection) = self.get_pooled_connection(key).await {
            return Ok(connection);
        }

        // Create new connection
        self.create_new_connection(key, ctx).await
    }

    async fn put(&self, key: &M::Key, mut connection: M::Connection) -> Result<()> {
        // Recycle connection (cleanup, reset state)
        self.manager.recycle(&mut connection).await?;

        // Only pool reusable connections
        if !self.manager.is_reusable(&connection) {
            let mut stats = self.stats.write().await;
            stats.active_connections = stats.active_connections.saturating_sub(1);
            stats.connections_closed += 1;
            return Ok(());
        }

        let mut pools = self.pools.write().await;
        let connections = pools.entry(key.clone()).or_insert_with(Vec::new);

        // Check pool limits
        if connections.len() >= self.config.max_connections_per_host as usize {
            let mut stats = self.stats.write().await;
            stats.active_connections = stats.active_connections.saturating_sub(1);
            stats.connections_closed += 1;
            return Ok(());
        }

        // Add to pool
        let mut pooled_conn = PooledConnection::new(connection);
        if let Some(max_req) = self
            .manager
            .max_requests_per_connection(&pooled_conn.connection)
            && max_req > 0
        {
            pooled_conn = pooled_conn.with_max_requests(max_req);
        }

        connections.push(pooled_conn);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.active_connections = stats.active_connections.saturating_sub(1);
        stats.idle_connections += 1;

        Ok(())
    }

    async fn invalidate(&self, key: &M::Key) -> Result<()> {
        let mut pools = self.pools.write().await;
        if let Some(connections) = pools.remove(key) {
            let mut stats = self.stats.write().await;
            stats.idle_connections = stats
                .idle_connections
                .saturating_sub(connections.len() as u32);
            stats.connections_closed += connections.len() as u64;
        }
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut pools = self.pools.write().await;
        let total_connections: u32 = pools.values().map(|v| v.len() as u32).sum();
        pools.clear();

        let mut stats = self.stats.write().await;
        stats.idle_connections = 0;
        stats.connections_closed += total_connections as u64;

        Ok(())
    }

    async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    async fn cleanup(&self) -> Result<u32> {
        let mut pools = self.pools.write().await;
        let mut cleaned_count = 0u32;

        pools.retain(|_key, connections| {
            let original_len = connections.len();
            connections.retain(|conn| {
                !conn.is_expired(self.config.max_idle_time, self.config.max_lifetime)
            });
            cleaned_count += original_len.saturating_sub(connections.len()) as u32;
            !connections.is_empty()
        });

        // Update stats
        let mut stats = self.stats.write().await;
        stats.idle_connections = stats.idle_connections.saturating_sub(cleaned_count);
        stats.connections_closed += cleaned_count as u64;
        stats.cleanup_runs += 1;

        Ok(cleaned_count)
    }
}

/// Pool builder pattern (inspired by deadpool/bb8)
pub struct PoolBuilder<M: ConnectionManager> {
    config: PoolConfig,
    manager: Option<M>,
}

impl<M: ConnectionManager> PoolBuilder<M> {
    pub fn new() -> Self {
        Self {
            config: PoolConfig::default(),
            manager: None,
        }
    }

    pub fn manager(mut self, manager: M) -> Self {
        self.manager = Some(manager);
        self
    }

    pub fn max_size(mut self, max_size: u32) -> Self {
        self.config.max_connections_per_host = max_size;
        self
    }

    pub fn max_total(mut self, max_total: u32) -> Self {
        self.config.max_total_connections = max_total;
        self
    }

    pub fn max_idle_time(mut self, max_idle_time: Duration) -> Self {
        self.config.max_idle_time = max_idle_time;
        self
    }

    pub fn max_lifetime(mut self, max_lifetime: Duration) -> Self {
        self.config.max_lifetime = max_lifetime;
        self
    }

    pub fn build(self) -> Result<DefaultConnectionPool<M>, String> {
        let manager = self.manager.ok_or("Manager is required")?;
        Ok(DefaultConnectionPool::new(self.config, manager))
    }
}

impl<M: ConnectionManager> Default for PoolBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}
