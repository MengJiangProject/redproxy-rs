use crate::{
    common::frames::FrameIO,
    config::IoParams,
    context::{ContextRef, ContextState, ContextStatistics},
};
use anyhow::{Context, Result, anyhow};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

#[cfg(feature = "metrics")]
use std::sync::OnceLock;

#[cfg(feature = "metrics")]
pub struct IoMetrics {
    pub client_bytes: prometheus::IntCounterVec,
    pub server_bytes: prometheus::IntCounterVec,
}

#[cfg(feature = "metrics")]
impl IoMetrics {
    fn new() -> Self {
        Self {
            client_bytes: prometheus::register_int_counter_vec!(
                "io_client_bytes",
                "Number of bytes sent from client to server.",
                &["listener"]
            )
            .expect("Failed to register IO client bytes counter metric"),
            server_bytes: prometheus::register_int_counter_vec!(
                "io_server_bytes",
                "Number of bytes sent from server to client.",
                &["connector"]
            )
            .expect("Failed to register IO server bytes counter metric"),
        }
    }
}
#[cfg(feature = "metrics")]
type MerticCounter = prometheus::core::GenericCounter<prometheus::core::AtomicU64>;
#[cfg(feature = "metrics")]
static IO_METRICS: OnceLock<IoMetrics> = OnceLock::new();

#[cfg(feature = "metrics")]
pub fn io_metrics() -> &'static IoMetrics {
    IO_METRICS.get_or_init(IoMetrics::new)
}

/// Bidirectional copy for frame-based communication (QUIC, etc.)
async fn copy_frames_bidi(
    (client_frames, server_frames): (FrameIO, FrameIO),
    (client_stat, server_stat): (Arc<ContextStatistics>, Arc<ContextStatistics>),
    idle_timeout: Duration,
    cancellation_token: tokio_util::sync::CancellationToken,
    #[cfg(feature = "metrics")] (client_counter, server_counter): (MerticCounter, MerticCounter),
) -> Result<()> {
    let (mut client_reader, mut client_writer) = client_frames;
    let (mut server_reader, mut server_writer) = server_frames;

    let interval = tokio::time::interval(Duration::from_secs(1));
    tokio::pin!(interval);

    loop {
        tokio::select! {
            biased;
            // Client -> Server frame copy
            frame_result = client_reader.read() => {
                match frame_result? {
                    Some(frame) => {
                        let len = server_writer.write(frame).await
                            .context("Failed to write frame to server")?;
                        client_stat.incr_sent_bytes(len);
                        client_stat.incr_sent_frames(1);
                        #[cfg(feature = "metrics")]
                        client_counter.inc_by(len as u64);
                    }
                    None => {
                        tracing::debug!("Client frame reader EOF");
                        break;
                    }
                }
            }
            // Server -> Client frame copy
            frame_result = server_reader.read() => {
                match frame_result? {
                    Some(frame) => {
                        let len = client_writer.write(frame).await
                            .context("Failed to write frame to client")?;
                        server_stat.incr_sent_bytes(len);
                        server_stat.incr_sent_frames(1);
                        #[cfg(feature = "metrics")]
                        server_counter.inc_by(len as u64);
                    }
                    None => {
                        tracing::debug!("Server frame reader EOF");
                        break;
                    }
                }
            }
            // Idle timeout check
            _ = interval.tick() => {
                if server_stat.is_timeout(idle_timeout) && client_stat.is_timeout(idle_timeout) {
                    return Err(anyhow::anyhow!("idle timeout"));
                }
            }
            // Cancellation
            _ = cancellation_token.cancelled() => {
                tracing::info!("Frame copy cancelled");
                return Err(anyhow::anyhow!("cancelled"));
            }
        }
    }

    // Shutdown writers
    client_writer
        .shutdown()
        .await
        .context("Failed to shutdown client frame writer")?;
    server_writer
        .shutdown()
        .await
        .context("Failed to shutdown server frame writer")?;

    Ok(())
}

pub fn copy_bidi(
    ctx: ContextRef,
    params: &IoParams,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    let params = params.clone();
    Box::pin(async move {
        let mut ctx_lock = ctx.write().await;
        let idle_timeout = ctx_lock.idle_timeout();
        let streams = ctx_lock.take_streams();
        let frames = ctx_lock.take_frames();
        let client_stat = ctx_lock.props().client_stat.clone();
        let server_stat = ctx_lock.props().server_stat.clone();
        let cancellation_token = ctx_lock.cancellation_token().clone();
        #[cfg(feature = "metrics")]
        let client_label = ctx_lock.props().listener.clone();
        #[cfg(feature = "metrics")]
        let server_label = ctx_lock
            .props()
            .connector
            .as_ref()
            .ok_or_else(|| anyhow!("No connector information available"))?
            .clone();
        drop(ctx_lock);

        // Create futures for available transports
        let mut tasks = Vec::new();

        let server_counter = io_metrics()
            .server_bytes
            .with_label_values(&[server_label.as_str()]);
        let client_counter = io_metrics()
            .client_bytes
            .with_label_values(&[client_label.as_str()]);
        // Add stream copy task if streams exist
        if let Some((client_stream, server_stream)) = streams {
            let client_counter = client_counter.clone();
            let server_counter = server_counter.clone();
            let stream_task =
                crate::io::BufferedStream::copy_bidirectional(client_stream, server_stream)
                    .with_io_params(&params)
                    .idle_timeout(idle_timeout)
                    .cancellation_token(cancellation_token.clone())
                    .with_stats(
                        {
                            let client_stat = client_stat.clone();
                            #[cfg(feature = "metrics")]
                            move |bytes| {
                                client_stat.incr_sent_bytes(bytes);
                                #[cfg(feature = "metrics")]
                                client_counter.inc_by(bytes as u64);
                            }
                        },
                        {
                            let server_stat = server_stat.clone();
                            #[cfg(feature = "metrics")]
                            move |bytes| {
                                server_stat.incr_sent_bytes(bytes);
                                #[cfg(feature = "metrics")]
                                server_counter.inc_by(bytes as u64);
                            }
                        },
                    )
                    .execute();
            tasks.push(Box::pin(async move {
                let result = stream_task.await.context("Stream copy failed")?;
                tracing::debug!(
                    "Stream copy completed: {} bytes C->S, {} bytes S->C",
                    result.0,
                    result.1
                );
                Ok::<(), anyhow::Error>(())
            })
                as Pin<Box<dyn Future<Output = Result<()>> + Send>>);
        }

        // Add frame copy task if frames exist
        if let Some((client_frames, server_frames)) = frames {
            let frame_task = copy_frames_bidi(
                (client_frames, server_frames),
                (client_stat.clone(), server_stat.clone()),
                idle_timeout,
                cancellation_token.clone(),
                #[cfg(feature = "metrics")]
                (
                    io_metrics()
                        .client_bytes
                        .with_label_values(&[client_label.as_str()]),
                    io_metrics()
                        .server_bytes
                        .with_label_values(&[server_label.as_str()]),
                ),
            );
            tasks.push(Box::pin(async move {
                frame_task.await.context("Frame copy failed")?;
                tracing::debug!("Frame copy completed");
                Ok::<(), anyhow::Error>(())
            })
                as Pin<Box<dyn Future<Output = Result<()>> + Send>>);
        }

        // Run all tasks concurrently
        if !tasks.is_empty() {
            futures::future::try_join_all(tasks).await?;
        }

        ctx.write().await.set_state(ContextState::ClientShutdown);

        Ok(())
    })
}
