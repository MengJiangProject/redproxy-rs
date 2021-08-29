use crate::context::IOBufStream;
use easy_error::{Error, ResultExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

pub async fn copy_stream<T: AsyncRead + AsyncWrite>(
    mut r: ReadHalf<T>,
    mut w: WriteHalf<T>,
    (rn, wn): (&str, &str),
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
pub async fn copy_bidi(
    a: &mut IOBufStream,
    b: &mut IOBufStream,
    (an, bn): (&str, &str),
) -> Result<(), Error> {
    let (ra, wa) = tokio::io::split(a);
    let (rb, wb) = tokio::io::split(b);
    let copy_a_to_b = copy_stream(ra, wb, (an, bn));
    let copy_b_to_a = copy_stream(rb, wa, (bn, an));
    tokio::try_join!(copy_a_to_b, copy_b_to_a)?;
    Ok(())
}
