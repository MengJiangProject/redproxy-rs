use anyhow::{Context, Result, ensure};
use milu::{
    parser::parse,
    script::{Evaluatable, ScriptContext, Type, Value},
};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc::{Receiver, Sender, channel},
};
use tracing::{error, info};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

use crate::{context::ContextProps, rules::script_ext::create_context};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
enum Format {
    Json,
    Script(String),
}
impl Format {
    async fn create(&self) -> Result<Box<dyn Formater>> {
        match self {
            Self::Json => Ok(Box::new(JsonFormater)),
            Self::Script(s) => Ok(Box::new(ScriptFormater::new(s).await?)),
            // _ => bail!("not implemented"),
        }
    }
}

#[async_trait::async_trait]
trait Formater: Send + Sync {
    async fn to_string(&self, e: Arc<ContextProps>) -> Result<String>;
}

struct JsonFormater;
#[async_trait::async_trait]
impl Formater for JsonFormater {
    async fn to_string(&self, e: Arc<ContextProps>) -> Result<String> {
        serde_json::to_string(&e).context("deserializer failure")
    }
}

struct ScriptFormater(Value);
impl ScriptFormater {
    async fn new(s: &str) -> Result<Self> {
        let value = parse(s).context("fail to compile")?;
        let ctx: Arc<ScriptContext> = create_context(Default::default()).into();
        let rtype = value.type_of(ctx.clone()).await?;
        ensure!(
            rtype == Type::String,
            "log script type mismatch: required string, got {}\nsnippet: {}",
            rtype,
            s
        );
        value.value_of(ctx).await?;
        Ok(Self(value))
    }
}
#[async_trait::async_trait]
impl Formater for ScriptFormater {
    async fn to_string(&self, e: Arc<ContextProps>) -> Result<String> {
        let ctx = create_context(e);
        self.0
            .value_of(ctx.into())
            .await?
            .try_into()
            .map_err(|e| anyhow::anyhow!("{}", e))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccessLog {
    path: PathBuf,
    #[serde(with = "serde_yaml_ng::with::singleton_map_recursive")]
    format: Format,
    #[serde(skip)]
    tx: Option<Sender<Option<Arc<ContextProps>>>>,
}

impl AccessLog {
    pub async fn init(&mut self) -> Result<()> {
        let path = self.path.to_owned();
        drop(log_open(&path).await?);
        let (tx, rx) = channel(100);
        self.tx = Some(tx.clone());
        let format = self.format.create().await?;
        tokio::spawn(async move {
            if let Err(e) = log_thread(format, rx, path).await {
                error!("Access log thread failed: {} cause: {:?}", e, e.source());
            }
        });
        tokio::spawn(signal_watch(tx));
        Ok(())
    }

    #[cfg(feature = "metrics")]
    pub async fn reopen(&self) -> Result<()> {
        self.tx
            .as_ref()
            .unwrap()
            .send(None)
            .await
            .context("enqueue log")
    }

    pub async fn write(&self, e: Arc<ContextProps>) -> Result<()> {
        self.tx
            .as_ref()
            .unwrap()
            .send(Some(e))
            .await
            .context("enqueue log")
    }
}

async fn log_open(path: &Path) -> Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .await
        .with_context(|| format!("failed to log open file: {}", path.display()))
}

async fn log_thread(
    format: Box<dyn Formater>,
    mut rx: Receiver<Option<Arc<ContextProps>>>,
    path: PathBuf,
) -> Result<()> {
    let mut stream = BufWriter::new(log_open(&path).await?);
    loop {
        let e = rx.recv().await.ok_or_else(|| anyhow::anyhow!("dequeue"))?;
        if let Some(e) = e {
            let mut line = format.to_string(e).await.context("deserializer error")?;
            line += "\r\n";
            stream
                .write(line.as_bytes())
                .await
                .context("log write error")?;
        } else {
            info!("log rotate");
            stream.flush().await.context("flush")?;
            stream.shutdown().await.context("shutdown")?;
            stream = BufWriter::new(log_open(&path).await?);
        }
    }
}

#[cfg(target_os = "windows")]
async fn signal_watch(_tx: Sender<Option<Arc<ContextProps>>>) {}

#[cfg(not(target_os = "windows"))]
async fn signal_watch(tx: Sender<Option<Arc<ContextProps>>>) {
    let mut stream = signal(SignalKind::user_defined1()).unwrap();
    loop {
        let e = stream.recv().await;
        if e.is_some() {
            tx.send(None).await.unwrap();
        } else {
            error!("signal watch ends");
            return;
        }
    }
}
