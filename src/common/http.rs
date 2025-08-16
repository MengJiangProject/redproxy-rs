use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tracing::trace;

type Reader<'a> = &'a mut (dyn AsyncBufRead + Send + Unpin);
type Writer<'a> = &'a mut (dyn AsyncWrite + Send + Unpin);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub resource: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn new<T1: ToString, T2: ToString>(method: T1, resource: T2) -> Self {
        Self {
            version: "HTTP/1.1".to_owned(),
            method: method.to_string(),
            resource: resource.to_string(),
            headers: Vec::new(),
        }
    }
    pub fn with_header<T1: ToString, T2: ToString>(mut self, k: T1, v: T2) -> Self {
        let k = k.to_string();
        let v = v.to_string();
        if !v.is_empty() {
            self.headers.push((k, v));
        }
        self
    }
    pub async fn read_from(socket: Reader<'_>) -> Result<Self> {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        let a: Vec<&str> = buf.split_ascii_whitespace().collect();
        trace!("request={}", buf);
        let mut ret = if a.len() == 3 && a[2].starts_with("HTTP/") {
            let method = a[0].into();
            let resource = a[1].into();
            let version = a[2].into();
            Self {
                method,
                resource,
                version,
                headers: vec![],
            }
        } else {
            return Err(anyhow!("bad request"));
        };
        read_headers(&mut ret.headers, socket).await?;
        Ok(ret)
    }
    pub async fn write_to(&self, socket: Writer<'_>) -> Result<()> {
        let buf = format!("{} {} {}\r\n", self.method, self.resource, self.version);
        socket.write(buf.as_bytes()).await.context("write error")?;
        for (k, v) in &self.headers {
            socket
                .write(format!("{}: {}\r\n", k, v).as_bytes())
                .await
                .context("write error")?;
        }
        socket
            .write("\r\n".as_bytes())
            .await
            .context("write error")?;
        socket.flush().await.context("flush")
    }
    pub fn header<'a, 'b: 'a>(&'a self, name: &str, def: &'b str) -> &'a str {
        self.headers
            .iter()
            .find_map(|x| {
                if x.0.eq_ignore_ascii_case(name) {
                    Some(x.1.as_str())
                } else {
                    None
                }
            })
            .unwrap_or(def)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: String,
    pub code: u16,
    pub status: String,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn new<T: ToString>(code: u16, status: T) -> Self {
        Self {
            version: "HTTP/1.1".to_owned(),
            code,
            status: status.to_string(),
            headers: Vec::new(),
        }
    }
    #[allow(dead_code)]
    pub fn with_header<T1: ToString, T2: ToString>(mut self, k: T1, v: T2) -> Self {
        let k = k.to_string();
        let v = v.to_string();
        if !v.is_empty() {
            self.headers.push((k, v));
        }
        self
    }
    pub async fn read_from(socket: Reader<'_>) -> Result<Self> {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        let a: Vec<&str> = buf.splitn(3, ' ').collect();
        trace!("response={}", buf);
        let mut ret = if a.len() == 3 && a[0].starts_with("HTTP/") {
            let version = a[0].into();
            let code = a[1].parse().context("failed to parse response code")?;
            let status = a[2].into();
            Self {
                version,
                code,
                status,
                headers: vec![],
            }
        } else {
            return Err(anyhow!("bad response"));
        };
        read_headers(&mut ret.headers, socket).await?;
        Ok(ret)
    }
    pub async fn write_to(&self, socket: Writer<'_>) -> Result<()> {
        let buf = format!("{} {} {}\r\n", self.version, self.code, self.status);
        socket.write(buf.as_bytes()).await.context("write error")?;
        for (k, v) in &self.headers {
            socket
                .write(format!("{}: {}\r\n", k, v).as_bytes())
                .await
                .context("write error")?;
        }
        socket
            .write("\r\n".as_bytes())
            .await
            .context("write error")?;
        socket.flush().await.context("flush")
    }
    pub async fn write_with_body(&self, socket: Writer<'_>, body: &[u8]) -> Result<()> {
        self.write_to(socket).await?;
        socket.write(body).await.context("write error")?;
        Ok(())
    }
    pub fn header<'a, 'b: 'a>(&'a self, name: &str, def: &'b str) -> &'a str {
        self.headers
            .iter()
            .find_map(|x| {
                if x.0.eq_ignore_ascii_case(name) {
                    Some(x.1.as_str())
                } else {
                    None
                }
            })
            .unwrap_or(def)
    }
}

async fn read_headers(headers: &mut Vec<(String, String)>, socket: Reader<'_>) -> Result<()> {
    loop {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        trace!("header={:?}", buf);
        if buf.is_empty() {
            return Ok(());
        };
        let a = buf
            .split_once(": ")
            .ok_or_else(|| anyhow!("bad response: {:?}", buf))?;
        headers.push((a.0.to_owned(), a.1.to_owned()))
    }
}

async fn read_line(s: Reader<'_>) -> Result<String> {
    let mut buf = String::with_capacity(256);
    let sz = s.read_line(&mut buf).await.context("readline")?;
    match sz {
        0 => Err(anyhow!("EOF")),
        _ => Ok(buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use tokio::io::BufReader;
    use tokio_test::io::Builder;
    #[test(tokio::test)]
    async fn parse_request() {
        let input = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        let output = HttpRequest {
            method: "GET".into(),
            resource: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![("Host".into(), "test".into())],
        };
        let stream = Builder::new().read(input.as_bytes()).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(HttpRequest::read_from(&mut stream).await.unwrap(), output);
    }
    #[test(tokio::test)]
    async fn parse_response() {
        let input = "HTTP/1.1 200 OK\r\nHost: test\r\n\r\n";
        let output = HttpResponse {
            version: "HTTP/1.1".into(),
            code: 200,
            status: "OK".into(),
            headers: vec![("Host".into(), "test".into())],
        };
        let stream = Builder::new().read(input.as_bytes()).build();
        let mut stream = BufReader::new(stream);
        assert_eq!(HttpResponse::read_from(&mut stream).await.unwrap(), output);
    }
}
