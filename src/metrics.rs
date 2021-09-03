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
}

fn default_prefix() -> String {
    "/".into()
}

impl MetricsServer {
    pub fn init(&mut self) {}
    pub async fn listen(self: Arc<Self>, state: Arc<GlobalState>) -> Result<(), Error> {
        tokio::spawn(async move {
            let app = Router::new()
                .route("/", get(root))
                .route("/contexts", get(get_alive))
                .route("/history", get(get_history))
                .layer(AddExtensionLayer::new(state))
                .check_infallible();

            info!("metrics server listening on {}", self.bind);
            axum::Server::bind(&self.bind)
                .serve(app.into_make_service())
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

async fn root() -> &'static str {
    "Hello, World!"
}

async fn get_alive(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    let ret = futures::stream::iter(
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
    .await;
    Json(ret)
}

async fn get_history(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    let ctxs = state.contexts.terminated.lock().await;
    let ret = ctxs.iter().cloned().collect::<Vec<_>>();
    Json(ret)
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
