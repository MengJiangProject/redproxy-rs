use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use hickory_resolver::{
    Resolver,
    config::{
        CLOUDFLARE, ConnectionConfig, GOOGLE, NameServerConfig, ResolverConfig, ResolverOpts,
    },
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
};
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsConfig {
    pub servers: String,
    #[serde(default)]
    pub family: AddressFamily,
    #[serde(skip)]
    resolver: Option<Arc<Resolver<TokioRuntimeProvider>>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: "system".to_string(),
            family: Default::default(),
            resolver: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default)]
pub enum AddressFamily {
    V4Only,
    V6Only,
    V4First,
    #[default]
    V6First,
}

impl DnsConfig {
    pub fn init(&mut self) -> Result<()> {
        let config = Self::parse_servers(&self.servers)?;
        self.resolver = Some(Arc::new(
            Resolver::builder_with_config(config.0, TokioRuntimeProvider::default())
                .with_options(config.1)
                .build()
                .context("Failed to build DNS resolver")?,
        ));
        Ok(())
    }

    fn parse_servers(servers: &str) -> Result<(ResolverConfig, ResolverOpts)> {
        // println!("servers: {}", servers);
        if servers == "system" {
            read_system_conf().context("Failed to read system configuration")
        } else if servers == "google" {
            Ok((
                ResolverConfig::udp_and_tcp(&GOOGLE),
                ResolverOpts::default(),
            ))
        } else if servers == "cloudflare" {
            Ok((
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                ResolverOpts::default(),
            ))
        } else {
            let mut name_servers = Vec::new();
            for server in servers.split(',') {
                let socket_addr = server
                    .parse::<IpAddr>()
                    .map(|addr| SocketAddr::new(addr, 53))
                    .or_else(|_| server.parse::<SocketAddr>())
                    .with_context(|| format!("Failed to parse DNS server address: {}", server))?;
                let mut connection = ConnectionConfig::udp();
                connection.port = socket_addr.port();
                name_servers.push(NameServerConfig::new(
                    socket_addr.ip(),
                    true,
                    vec![connection],
                ));
            }
            Ok((
                ResolverConfig::from_parts(None, Vec::new(), name_servers),
                ResolverOpts::default(),
            ))
        }
    }
    pub async fn lookup_host(&self, host: &str, port: u16) -> Result<SocketAddr> {
        let resolver = self.resolver.as_ref().unwrap();
        let addr = match self.family {
            AddressFamily::V4Only => resolver
                .lookup_ip(host)
                .await
                .context("lookup_ip")?
                .iter()
                .filter(|a| a.is_ipv4())
                .choose(&mut rand::rng())
                .ok_or_else(|| anyhow!("No IPv4 address found for {}", host))?,
            AddressFamily::V6Only => resolver
                .lookup_ip(host)
                .await
                .context("lookup_ip")?
                .iter()
                .filter(|a| a.is_ipv6())
                .choose(&mut rand::rng())
                .ok_or_else(|| anyhow!("No IPv6 address found for {}", host))?,
            AddressFamily::V4First => {
                let (v4, v6): (Vec<_>, Vec<_>) = resolver
                    .lookup_ip(host)
                    .await
                    .context("lookup_ip")?
                    .iter()
                    .partition(|a| a.is_ipv4());
                v4.into_iter()
                    .choose(&mut rand::rng())
                    .or_else(|| v6.into_iter().choose(&mut rand::rng()))
                    .ok_or_else(|| anyhow!("No address found for {}", host))?
            }
            AddressFamily::V6First => {
                let (v4, v6): (Vec<_>, Vec<_>) = resolver
                    .lookup_ip(host)
                    .await
                    .context("lookup_ip")?
                    .iter()
                    .partition(|a| a.is_ipv4());
                v6.into_iter()
                    .choose(&mut rand::rng())
                    .or_else(|| v4.into_iter().choose(&mut rand::rng()))
                    .ok_or_else(|| anyhow!("No address found for {}", host))?
            }
        };
        Ok(SocketAddr::new(addr, port))
    }
}
