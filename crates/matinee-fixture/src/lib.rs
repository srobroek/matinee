//! Deterministic local fixture for the Matinee MVP demonstration.
//!
//! Spec: `specs/006.5-demonstrable-browser-mvp/spec.md` FR-055.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::{net::TcpListener, sync::Mutex};

#[derive(Clone)]
struct AppState {
    alpha: Arc<Mutex<RouteState>>,
    beta: Arc<Mutex<RouteState>>,
}

#[derive(Default)]
struct RouteState {
    counter: u64,
    last_text: String,
    stalled: bool,
}

impl AppState {
    fn route(&self, route: &str) -> Option<Arc<Mutex<RouteState>>> {
        match route {
            "alpha" => Some(Arc::clone(&self.alpha)),
            "beta" => Some(Arc::clone(&self.beta)),
            _ => None,
        }
    }
}

/// Builds the deterministic two-route fixture application.
///
/// The returned router has no external dependencies and owns independent state
/// for `/alpha` and `/beta`. Its controls are intended for deterministic
/// integration tests and the MVP demonstration.
pub fn build_router() -> Router {
    let state = AppState {
        alpha: Arc::new(Mutex::new(RouteState::default())),
        beta: Arc::new(Mutex::new(RouteState::default())),
    };

    Router::new()
        .route("/{route}", get(page))
        .route("/{route}/counter", get(counter))
        .route("/{route}/increment", post(increment))
        .route("/control/stall", post(stall))
        .route("/control/resume", post(resume))
        .route("/control/state", get(control_state))
        .with_state(state)
}

/// Binds the fixture to loopback on `port` and starts serving it.
///
/// Port `0` asks the operating system for an ephemeral port. The returned
/// address is the actual bound loopback address; the join handle completes
/// when the server exits or reports its serving error.
pub async fn bind_and_serve(
    port: u16,
) -> Result<(SocketAddr, JoinHandle<Result<(), std::io::Error>>), std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move { axum::serve(listener, build_router()).await });
    Ok((address, handle))
}

async fn page(State(state): State<AppState>, Path(route): Path<String>) -> Response {
    let Some(route_state) = state.route(&route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let snapshot = route_state.lock().await;
    let route_escaped = escape_html(&route);
    let text_escaped = escape_html(&snapshot.last_text);
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Matinee {route_escaped} fixture</title></head><body><main><h1>{route_escaped} fixture</h1><form action=\"/{route_escaped}/increment\" method=\"post\"><label for=\"{route_escaped}-text\">Text</label><input id=\"{route_escaped}-text\" name=\"text\" type=\"text\"><button id=\"{route_escaped}-increment\" type=\"submit\">Increment {route_escaped}</button></form><p id=\"{route_escaped}-status\">Counter: <span id=\"{route_escaped}-counter\">{}</span>; Last text: <span id=\"{route_escaped}-last-text\">{text_escaped}</span></p></main></body></html>",
        snapshot.counter
    ))
    .into_response()
}

async fn counter(State(state): State<AppState>, Path(route): Path<String>) -> Response {
    let Some(route_state) = state.route(&route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let snapshot = route_state.lock().await;
    Json(CounterResponse {
        route,
        counter: snapshot.counter,
    })
    .into_response()
}

#[derive(Deserialize)]
struct IncrementForm {
    #[serde(default)]
    text: String,
}

async fn increment(
    State(state): State<AppState>,
    Path(route): Path<String>,
    Form(form): Form<IncrementForm>,
) -> Response {
    let Some(route_state) = state.route(&route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut snapshot = route_state.lock().await;
    if snapshot.stalled {
        // Deliberately leave this request unresolved. A caller can observe a
        // real in-flight effect rather than a timer-based approximation.
        drop(snapshot);
        std::future::pending::<()>().await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    snapshot.counter += 1;
    snapshot.last_text = form.text;
    drop(snapshot);
    page(State(state), Path(route)).await
}

#[derive(Deserialize)]
struct RouteQuery {
    route: String,
}

async fn stall(State(state): State<AppState>, Query(query): Query<RouteQuery>) -> Response {
    let Some(route_state) = state.route(&query.route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    route_state.lock().await.stalled = true;
    Json(ControlResponse {
        route: query.route,
        stalled: true,
    })
    .into_response()
}

async fn resume(State(state): State<AppState>, Query(query): Query<RouteQuery>) -> Response {
    let Some(route_state) = state.route(&query.route) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    route_state.lock().await.stalled = false;
    Json(ControlResponse {
        route: query.route,
        stalled: false,
    })
    .into_response()
}

async fn control_state(State(state): State<AppState>) -> Json<ControlState> {
    let alpha = state.alpha.lock().await;
    let beta = state.beta.lock().await;
    Json(ControlState {
        alpha: RouteSnapshot::from(&*alpha),
        beta: RouteSnapshot::from(&*beta),
    })
}

#[derive(Serialize)]
struct CounterResponse {
    route: String,
    counter: u64,
}

#[derive(Serialize)]
struct ControlResponse {
    route: String,
    stalled: bool,
}

#[derive(Serialize)]
struct ControlState {
    alpha: RouteSnapshot,
    beta: RouteSnapshot,
}

#[derive(Serialize)]
struct RouteSnapshot {
    counter: u64,
    last_text: String,
    stalled: bool,
}

impl From<&RouteState> for RouteSnapshot {
    fn from(state: &RouteState) -> Self {
        Self {
            counter: state.counter,
            last_text: state.last_text.clone(),
            stalled: state.stalled,
        }
    }
}
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    fn request(address: SocketAddr, method: &str, path: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("fixture listener");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
    }

    fn response_body(response: &str) -> &str {
        response.split_once("\r\n\r\n").expect("HTTP response").1
    }

    #[test]
    fn html_escaping_covers_markup_delimiters() {
        assert_eq!(escape_html("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn routes_are_independent_and_stall_is_in_flight() {
        let (address, server) = bind_and_serve(0).await.expect("bind fixture");
        let alpha = tokio::task::spawn_blocking(move || request(address, "GET", "/alpha", ""))
            .await
            .expect("alpha request");
        let beta = tokio::task::spawn_blocking(move || request(address, "GET", "/beta", ""))
            .await
            .expect("beta request");
        assert!(alpha.contains("<title>Matinee alpha fixture</title>"));
        assert!(alpha.contains("id=\"alpha-text\""));
        assert!(alpha.contains("id=\"alpha-increment\""));
        assert!(beta.contains("<title>Matinee beta fixture</title>"));
        assert!(beta.contains("id=\"beta-text\""));
        assert!(beta.contains("id=\"beta-increment\""));

        tokio::task::spawn_blocking({
            move || request(address, "POST", "/alpha/increment", "text=only-alpha")
        })
        .await
        .expect("alpha increment");
        let beta_counter =
            tokio::task::spawn_blocking(move || request(address, "GET", "/beta/counter", ""))
                .await
                .expect("beta counter");
        assert_eq!(
            response_body(&beta_counter),
            r#"{"route":"beta","counter":0}"#
        );
        let alpha_page = tokio::task::spawn_blocking(move || request(address, "GET", "/alpha", ""))
            .await
            .expect("alpha page");
        assert!(alpha_page.contains("Counter: <span id=\"alpha-counter\">1</span>"));
        assert!(alpha_page.contains("only-alpha"));
        assert!(!alpha_page.contains("beta"));

        tokio::task::spawn_blocking({
            move || request(address, "POST", "/control/stall?route=alpha", "")
        })
        .await
        .expect("stall control");
        let stalled = tokio::task::spawn_blocking(move || {
            let mut stream = TcpStream::connect(address).expect("fixture listener");
            let request = format!(
                "POST /alpha/increment HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\nConnection: close\r\n\r\ntext="
            );
            stream
                .write_all(request.as_bytes())
                .expect("write stalled request");
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("set timeout");
            let mut bytes = [0_u8; 1];
            let error = stream.read(&mut bytes).expect_err("stalled response");
            error.kind()
        });
        assert_eq!(
            stalled.await.expect("stalled request"),
            std::io::ErrorKind::WouldBlock
        );
        let state =
            tokio::task::spawn_blocking(move || request(address, "GET", "/alpha/counter", ""))
                .await
                .expect("alpha counter");
        assert_eq!(response_body(&state), r#"{"route":"alpha","counter":1}"#);
        tokio::task::spawn_blocking({
            move || request(address, "POST", "/control/resume?route=alpha", "")
        })
        .await
        .expect("resume control");
        server.abort();
    }
}
