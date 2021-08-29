[![Rust Build and Test](https://github.com/bearice/redproxy-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/bearice/redproxy-rs/actions/workflows/rust.yml)

# redproxy-rs
Proxy routing tool. It can translate from one protocol to another, or select destnation proxy by policy

Protocol supported:
- HTTP CONNECT with mTLS
- HTTP CONNECT over QUIC
- SOCKS v4,v4a,v5 with mTLS (TCP CONNECT ONLY)
- TPROXY on linux, used with iptables REDIRECT, that is where the name comes from: RED(irect)PROXY

## Config example

see [config.yaml](config.yaml)

## why would you build such things?
Just because I am feeling boring. 
I had a [TypeScript version of this](https://github.com/bearice/redproxy) running on my router for years, and I just wanted to replace it with something nicer.
