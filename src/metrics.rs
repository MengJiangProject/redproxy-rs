use axum::{
    body::Body,
    extract::Extension,
    handler::get,
    http::{Response, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use easy_error::Error;
use futures::StreamExt;
use log::info;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
};
use tower_http::add_extension::AddExtensionLayer;

use crate::GlobalState;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetricsServer {
    bind: SocketAddr,

    #[serde(default = "default_prefix")]
    prefix: String,

    // location of static files to serve
    static_resource: Option<String>,

    #[serde(default = "default_history_size")]
    pub history_size: usize,
}

fn default_prefix() -> String {
    "/".into()
}

fn default_history_size() -> usize {
    100
}

impl MetricsServer {
    pub fn init(&mut self) {}
    pub async fn listen(self: Arc<Self>, state: Arc<GlobalState>) -> Result<(), Error> {
        tokio::spawn(async move {
            let api = Router::new()
                .route("/contexts", get(get_alive))
                .route("/history", get(get_history))
                .layer(AddExtensionLayer::new(state))
                .check_infallible();
            let root = Router::new().nest(&self.prefix, api);
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
