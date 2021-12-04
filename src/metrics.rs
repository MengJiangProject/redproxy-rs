use crate::{rules::Rule, GlobalState, VERSION};
use axum::{
    body::Body,
    error_handling::HandleErrorExt,
    extract::Extension,
    handler::Handler,
    http::{
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE},
        HeaderValue, Response, StatusCode,
    },
    response::IntoResponse,
    routing::service_method_routing as service,
    routing::{get, post},
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
            .route("/status", get(get_status))
            .route("/live", get(get_alive))
            .route("/history", get(get_history))
            .route("/rules", get(get_rules).post(post_rules))
            .route("/metrics", get(get_metrics))
            .route("/logrotate", post(post_logrotate))
            .layer(AddExtensionLayer::new(state))
            .layer(SetResponseHeaderLayer::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ));

        let root = ui_service(self.ui.as_deref())?
            .nest(&self.api_prefix, api)
            .layer(SetResponseHeaderLayer::if_not_present(
                ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(&self.cors).unwrap(),
            ))
            .layer(SetResponseHeaderLayer::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ))
            .fallback(not_found.into_service());

        tokio::spawn(async move {
            info!("metrics server listening on {}", self.bind);
            axum::Server::bind(&self.bind)
                .serve(root.into_make_service())
                .await
                .unwrap();
        });

        Ok(())
    }
}

fn ui_service(ui: Option<&str>) -> Result<Router, Error> {
    if let Some(ui) = ui {
        #[cfg(feature = "embedded-ui")]
        if ui == "<embedded>" {
            return Ok(embedded_ui::app());
        }
        Ok(Router::new().nest(
            "/",
            service::get(ServeDir::new(".")).handle_error(|error: std::io::Error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unhandled internal error: {}", error),
                )
            }),
        ))
    } else {
        Ok(Router::new())
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

macro_rules! handler {
    ( $name:ident ( $($aname:ident : $atype:ty),* ) -> $rtype:ty $body:block ) => {
        async fn $name ($($aname : $atype),*) -> $rtype {
            HTTP_COUNTER.with_label_values(&[stringify!($name)]).inc();
            let timer = HTTP_REQ_HISTOGRAM
                .with_label_values(&[stringify!($name)])
                .start_timer();
            let ret = { $body };
            timer.stop_and_record();
            ret
        }
    };
}

handler!(get_status(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Status {
        version: String,
        listeners: Vec<String>,
        connectors: Vec<String>,
    }
    Json(
        Status {
            version: VERSION.to_string(),
            listeners: state.listeners.keys().cloned().collect(),
            connectors: state.connectors.keys().cloned().collect(),
        }
    )
});

handler!(get_alive(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
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
});

handler!(get_history(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
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
});

handler!(get_rules(state: Extension<Arc<GlobalState>>) -> impl IntoResponse {
    Json(state.rules().await.clone())
});

handler!(post_rules(
    state: Extension<Arc<GlobalState>>,
    rules: Json<Vec<Arc<Rule>>>
) -> Result<impl IntoResponse, MyError> {
    state.set_rules(rules.0).await.map_err(MyError)?;
    Ok(Json(state.rules().await.clone()))
});

handler!(get_metrics() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let data = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&data, &mut buffer).unwrap();
    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap()
});

handler!(post_logrotate(state: Extension<Arc<GlobalState>>) -> Result<(), MyError> {
    if let Some(log) = &state.contexts.access_log {
        log.reopen().await.map_err(MyError)
    } else {
        Ok(())
    }
});

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
