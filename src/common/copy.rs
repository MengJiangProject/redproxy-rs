use crate::context::ContextRef;
use easy_error::{Error, ResultExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub async fn copy_stream<T: AsyncRead + AsyncWrite>(
    mut r: ReadHalf<T>,
    rn: &str,
    mut w: WriteHalf<T>,
    wn: &str,
) -> Result<(), Error> {
    let mut buf = [0u8; 65536];
    loop {
        let len = r
            .read(&mut buf)
            .await
            .with_context(|| format!("read from {}", rn))?;
        if len > 0 {
            let mut pos = 0;
            while pos < len {
                let n = w
                    .write(&buf[pos..len])
                    .await
                    .with_context(|| format!("write to {}", wn))?;
                pos += n;
            }
            w.flush()
                .await
                .with_context(|| format!("flush {} buffer", wn))?;
        } else {
            break;
        }
    }
    w.shutdown()
        .await
        .with_context(|| format!("shutdown {}", wn))?;
    Ok(())
}
pub async fn copy_bidi(ctx: ContextRef) -> Result<(), Error> {
    let ctx = ctx.read().await;
    let mut client = ctx.get_client_stream().await;
    let mut server = ctx.get_server_stream().await;
    let (cread, cwrite) = tokio::io::split(client.get_mut());
    let (sread, swrite) = tokio::io::split(server.get_mut());
    let copy_a_to_b = copy_stream(cread, "client", swrite, "server");
    let copy_b_to_a = copy_stream(sread, "server", cwrite, "client");
    tokio::try_join!(copy_a_to_b, copy_b_to_a)?;
    Ok(())
}
