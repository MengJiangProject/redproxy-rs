use easy_error::Error; // For Result<(), Error>

#[cfg(target_os = "linux")]
pub fn fwmark_direct_socket<T: std::os::unix::prelude::AsFd>(sk: &T, mark: Option<u32>) -> Result<(), Error> {
    use easy_error::ResultExt; // For .context()
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::Mark;
    if mark.is_none() {
        return Ok(());
    }
    let mark_val = mark.unwrap(); // Use a different name to avoid conflict
    setsockopt(sk, Mark, &mark_val).context("setsockopt Mark failed")?; // Added context message
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn fwmark_direct_socket_stub<T>(_sk: &T, _mark: Option<u32>) -> Result<(), Error> {
    tracing::warn!("fwmark not supported on this platform, using stub");
    Ok(())
}
