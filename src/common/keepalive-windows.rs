use easy_error::Error;
use tokio::net::TcpStream;
pub fn set_keepalive(stream: &TcpStream) -> Result<(), Error> {
    Ok(())
}
