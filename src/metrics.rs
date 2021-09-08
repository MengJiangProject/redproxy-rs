use crate::{rules::Rule, GlobalState};
use axum::{
    body::Body,
    extract::Extension,
    handler::{get, Handler},
    http::{
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE},
        HeaderValue, Response, StatusCode,
    },
    response::IntoResponse,
    routing::BoxRoute,
    Json, Router,
};
use easy_error::{ensure, Error};
use futures::StreamExt;
use log::info;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec, IntCounterVec,
    TextEncoder,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Weak},
};
use tower_http::services::ServeDir;
use tower_http::{add_extension::AddExtensionLayer, set_header::SetResponseHeaderLayer};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetricsServer {
    bind: SocketAddr,

    #[serde(default = "default_prefix")]
    api_prefix: String,

    #[serde(default = "default_ui_source")]
    ui: Option<String>,

    #[serde(default = "default_history_size")]
    pub history_size: usize,

    #[serde(default = "default_cors")]
    cors: String,
}

fn default_prefix() -> String {
    "/api".into()
}

fn default_cors() -> String {
    "*".into()
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
            .route("/live", get(get_alive))
            .route("/history", get(get_history))
            .route("/rules", get(get_rules).post(post_rules))
            .route("/metrics", get(get_metrics))
            .layer(AddExtensionLayer::new(state))
            .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ))
            .check_infallible();

        let root = if let Some(ui) = &self.ui {
            ui_service(ui)?
        } else {
            Router::new().boxed()
        };

        let root = root
            .nest(&self.api_prefix, api)
            .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
                ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(&self.cors).unwrap(),
            ))
            .layer(SetResponseHeaderLayer::<_, Body>::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ))
            .or(not_found.into_service());

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

lazy_static::lazy_static! {
    static ref HTTP_COUNTER: IntCounterVec = register_int_counter_vec!(
        "http_requests_total",
        "Number of HTTP requests made.",
        &["handler"]
    )
    .unwrap();
    static ref HTTP_REQ_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["handler"],
        vec![
            0.001, 0.0025, 0.005, 0.0075,
            0.010, 0.025, 0.050, 0.075,
            0.100, 0.250, 0.500, 0.750,
        ]
    )
    .unwrap();
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
    HTTP_COUNTER.with_label_values(&["get_alive"]).inc();
    let timer = HTTP_REQ_HISTOGRAM
        .with_label_values(&["get_alive"])
        .start_timer();
    let ret = Json(
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
    );
    timer.stop_and_record();
    ret
}

async fn get_history(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    HTTP_COUNTER.with_label_values(&["get_history"]).inc();
    let timer = HTTP_REQ_HISTOGRAM
        .with_label_values(&["get_history"])
        .start_timer();
    let ret = Json(
        state
            .contexts
            .terminated
            .lock()
            .await
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    );
    timer.stop_and_record();
    ret
}

async fn get_rules(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    HTTP_COUNTER.with_label_values(&["get_rules"]).inc();
    let timer = HTTP_REQ_HISTOGRAM
        .with_label_values(&["get_rules"])
        .start_timer();
    let ret = Json(state.rules().await.clone());
    timer.stop_and_record();
    ret
}

async fn post_rules(
    state: Extension<Arc<GlobalState>>,
    rules: Json<Vec<Arc<Rule>>>,
) -> Result<impl IntoResponse, MyError> {
    HTTP_COUNTER.with_label_values(&["post_rules"]).inc();
    let timer = HTTP_REQ_HISTOGRAM
        .with_label_values(&["post_rules"])
        .start_timer();
    state.set_rules(rules.0).await.map_err(MyError)?;
    let ret = Json(state.rules().await.clone());
    timer.stop_and_record();
    Ok(ret)
}

async fn get_metrics() -> impl IntoResponse {
    HTTP_COUNTER.with_label_values(&["get_metrics"]).inc();
    let timer = HTTP_REQ_HISTOGRAM
        .with_label_values(&["get_metrics"])
        .start_timer();
    let encoder = TextEncoder::new();
    let data = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&data, &mut buffer).unwrap();
    let ret = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    timer.stop_and_record();
    ret
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
