use std::net::{IpAddr, SocketAddr};

use easy_error::{err_msg, Error, ResultExt};
use serde::{Deserialize, Serialize};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    system_conf::read_system_conf,
    AsyncResolver,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct DnsConfig {
    pub servers: String,
    #[serde(default)]
    pub family: AddressFamily,
    #[serde(skip)]
    resolver: Option<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>,
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
        self.resolver = Some(AsyncResolver::tokio(config.0, config.1).unwrap());
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
                    trust_nx_responses: true,
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
                .next()
                .ok_or_else(|| err_msg(format!("No IPv4 address found for {}", host)))
                .map(IpAddr::V4)?,
            AddressFamily::V6Only => resolver
                .ipv6_lookup(host)
                .await
                .context("ipv6_lookup")?
                .into_iter()
                .next()
                .ok_or_else(|| err_msg(format!("No IPv6 address found for {}", host)))
                .map(IpAddr::V6)?,
            AddressFamily::V4First => resolver
                .lookup_ip(host)
                .await
                .context("lookup_ip")?
                .into_iter()
                .reduce(|a, b| if a.is_ipv4() { a } else { b })
                .ok_or_else(|| err_msg(format!("No address found for {}", host)))?,
            AddressFamily::V6First => resolver
                .lookup_ip(host)
                .await
                .context("lookup_ip")?
                .into_iter()
                .reduce(|a, b| if a.is_ipv6() { a } else { b })
                .ok_or_else(|| err_msg(format!("No address found for {}", host)))?,
        };
        Ok(SocketAddr::new(addr, port))
    }
}
