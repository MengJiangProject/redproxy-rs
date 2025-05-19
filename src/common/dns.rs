use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use easy_error::{err_msg, Error, ResultExt};
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    system_conf::read_system_conf,
    AsyncResolver,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsConfig {
    pub servers: String,
    #[serde(default)]
    pub family: AddressFamily,
    #[serde(skip)]
    resolver:
        Option<Arc<AsyncResolver<TokioConnectionProvider>>>,
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum AddressFamily {
    V4Only,
    V6Only,
    V4First,
    V6First,
}

impl Default for AddressFamily {
    fn default() -> Self {
        AddressFamily::V6First
    }
}

impl DnsConfig {
    pub fn init(&mut self) -> Result<(), Error> {
        let config = Self::parse_servers(&self.servers)?;
        self.resolver = Some(Arc::new(AsyncResolver::tokio(config.0, config.1)));
        Ok(())
    }

    fn parse_servers(servers: &str) -> Result<(ResolverConfig, ResolverOpts), Error> {
        // println!("servers: {}", servers);
        if servers == "system" {
            read_system_conf().context("Failed to read system configuration")
        } else if servers == "google" {
            Ok((ResolverConfig::google(), ResolverOpts::default()))
        } else if servers == "cloudflare" {
            Ok((ResolverConfig::cloudflare(), ResolverOpts::default()))
        } else {
            let mut config = ResolverConfig::new();
            for server in servers.split(',') {
                let socket_addr = server
                    .parse::<IpAddr>()
                    .map(|addr| SocketAddr::new(addr, 53))
                    .or_else(|_| server.parse::<SocketAddr>())
                    .with_context(|| format!("Failed to parse DNS server address: {}", server))?;
                config.add_name_server(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    bind_addr: None,
                    trust_negative_responses: true,
                });
            }
            Ok((config, ResolverOpts::default()))
        }
    }
    pub async fn lookup_host(&self, host: &str, port: u16) -> Result<SocketAddr, Error> {
        let resolver = self.resolver.as_ref().unwrap();
        let addr = match self.family {
            AddressFamily::V4Only => resolver
                .ipv4_lookup(host)
                .await
                .context("ipv4_lookup")?
                .into_iter()
                .choose(&mut rand::rng())
                .ok_or_else(|| err_msg(format!("No IPv4 address found for {}", host)))
                .map(|a| IpAddr::V4(Ipv4Addr::from(a.octets())))?,
            AddressFamily::V6Only => resolver
                .ipv6_lookup(host)
                .await
                .context("ipv6_lookup")?
                .into_iter()
                .choose(&mut rand::rng())
                .ok_or_else(|| err_msg(format!("No IPv6 address found for {}", host)))
                .map(|a| IpAddr::V6(Ipv6Addr::from(a.octets())))?,
            AddressFamily::V4First => {
                let (v4, v6): (Vec<_>, Vec<_>) = resolver
                    .lookup_ip(host)
                    .await
                    .context("lookup_ip")?
                    .into_iter()
                    .partition(|a| a.is_ipv4());
                v4.into_iter()
                    .choose(&mut rand::rng())
                    .or_else(|| v6.into_iter().choose(&mut rand::rng()))
                    .ok_or_else(|| err_msg(format!("No address found for {}", host)))?
            }
            AddressFamily::V6First => {
                let (v4, v6): (Vec<_>, Vec<_>) = resolver
                    .lookup_ip(host)
                    .await
                    .context("lookup_ip")?
                    .into_iter()
                    .partition(|a| a.is_ipv4());
                v6.into_iter()
                    .choose(&mut rand::rng())
                    .or_else(|| v4.into_iter().choose(&mut rand::rng()))
                    .ok_or_else(|| err_msg(format!("No address found for {}", host)))?
            }
        };
        Ok(SocketAddr::new(addr, port))
    }
}
