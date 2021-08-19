use easy_error::{err_msg, Error, ResultExt};
use log::trace;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

type Reader<'a> = &'a mut (dyn AsyncBufRead + Send + Unpin);
#[derive(Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub resource: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    pub async fn new(socket: Reader<'_>) -> Result<Self, Error> {
        let mut ret = Self::read(socket).await?;
        read_headers(&mut ret.headers, socket).await?;
        Ok(ret)
    }
    async fn read(socket: Reader<'_>) -> Result<Self, Error> {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        let a: Vec<&str> = buf.split_ascii_whitespace().collect();
        trace!("request={}", buf);
        if a.len() == 3 && a[2].starts_with("HTTP/") {
            let method = a[0].into();
            let resource = a[1].into();
            let version = a[2].into();
            Ok(Self {
                method,
                resource,
                version,
                headers: vec![],
            })
        } else {
            Err(err_msg("bad request"))
        }
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
    pub async fn new(socket: Reader<'_>) -> Result<Self, Error> {
        let mut ret = Self::read(socket).await?;
        read_headers(&mut ret.headers, socket).await?;
        Ok(ret)
    }
    async fn read(socket: Reader<'_>) -> Result<Self, Error> {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        let a: Vec<&str> = buf.splitn(3, ' ').collect();
        trace!("response={}", buf);
        if a.len() == 3 && a[0].starts_with("HTTP/") {
            let version = a[0].into();
            let code = a[1].parse().context("failed to parse response code")?;
            let status = a[2].into();
            Ok(Self {
                version,
                code,
                status,
                headers: vec![],
            })
        } else {
            Err(err_msg("bad response"))
        }
    }
}

async fn read_headers(
    headers: &mut Vec<(String, String)>,
    socket: Reader<'_>,
) -> Result<(), Error> {
    loop {
        let buf = read_line(socket).await?;
        let buf = buf.trim_end();
        trace!("header={}", buf);
        if buf.is_empty() {
            return Ok(());
        };
        let a = buf.split_once(": ").ok_or(err_msg("bad response"))?;
        headers.push((a.0.to_owned(), a.1.to_owned()))
    }
}

async fn read_line(s: Reader<'_>) -> Result<String, Error> {
    let mut buf = String::with_capacity(256);
    let sz = s.read_line(&mut buf).await.context("readline")?;
    match sz {
        0 => Err(err_msg("EOF")),
        _ => Ok(buf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_env_log::test;
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
        assert_eq!(HttpRequest::new(&mut stream).await.unwrap(), output);
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
        assert_eq!(HttpResponse::new(&mut stream).await.unwrap(), output);
    }
}
