use axum::{
    body::Body,
    extract::Extension,
    handler::{get, Handler},
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::BoxRoute,
    Json, Router,
};
use easy_error::{ensure, Error};
use futures::StreamExt;
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Weak},
};
use tower_http::add_extension::AddExtensionLayer;
use tower_http::services::ServeDir;

use crate::GlobalState;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetricsServer {
    bind: SocketAddr,

    #[serde(default = "default_prefix")]
    prefix: String,

    #[serde(default = "default_ui_source")]
    ui: Option<String>,

    #[serde(default = "default_history_size")]
    pub history_size: usize,
}

fn default_prefix() -> String {
    "/".into()
}

#[cfg(feature = "embedded-ui")]
fn default_ui_source() -> Option<String> {
    Some("<embedded>".into())
}
#[cfg(not(feature = "embedded-ui"))]
fn default_ui_source() -> Option<String> {
    None
}

fn default_history_size() -> usize {
    100
}

impl MetricsServer {
    pub fn init(&mut self) -> Result<(), Error> {
        if let Some(ui) = &self.ui {
            #[cfg(feature = "embedded-ui")]
            if ui == "<embedded>" {
                return Ok(());
            }
            let path = std::path::Path::new(ui);
            ensure!(path.is_dir(), "not an accessible directory: {}", ui);
        }
        Ok(())
    }

    pub async fn listen(self: Arc<Self>, state: Arc<GlobalState>) -> Result<(), Error> {
        let api = Router::new()
            .route("/contexts", get(get_alive))
            .route("/history", get(get_history))
            .layer(AddExtensionLayer::new(state))
            .check_infallible();

        let root = Router::new().nest(&self.prefix, api);
        let root = if let Some(ui) = &self.ui {
            root.nest("/", ui_service(ui)?).boxed()
        } else {
            root.boxed()
        };
        let root = root.or(not_found.into_service());

        tokio::spawn(async move {
            info!("metrics server listening on {}", self.bind);
            axum::Server::bind(&self.bind)
                .serve(root.into_make_service())
                .await
                .unwrap();
        });

        // tokio::spawn(async move {
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(10)).await;
        //         let len = state.contexts.alive.lock().await.len();
        //         info!("We have {} client alive now.", len);
        //     }
        // });
        Ok(())
    }
}

fn ui_service(ui_source: &str) -> Result<Router<BoxRoute>, Error> {
    #[cfg(feature = "embedded-ui")]
    if ui_source == "<embedded>" {
        return Ok(embedded_ui::app());
    }
    Ok(Router::new()
        .nest(
            "/",
            axum::service::get(ServeDir::new(ui_source)).handle_error(|error: std::io::Error| {
                Ok::<_, Infallible>((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unhandled internal error: {}", error),
                ))
            }),
        )
        .boxed())
}

async fn get_alive(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    Json(
        futures::stream::iter(
            state
                .contexts
                .alive
                .lock()
                .await
                .values()
                .filter_map(Weak::upgrade),
        )
        .then(|x| async move { x.read().await.props().clone() })
        .collect::<Vec<_>>()
        .await,
    )
}

async fn get_history(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    Json(
        state
            .contexts
            .terminated
            .lock()
            .await
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "not found")
}

struct MyError(Error);

impl IntoResponse for MyError {
    type Body = Body;

    type BodyError = <Self::Body as axum::body::HttpBody>::Error;

    fn into_response(self) -> axum::http::Response<Self::Body> {
        let body = Body::from(format!("{} cause: {:?}", self.0, self.0.cause));
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(body)
            .unwrap()
    }
}

#[cfg(feature = "embedded-ui")]
mod embedded_ui {
    include!(concat!(env!("OUT_DIR"), "/embedded-ui.rs"));
}
