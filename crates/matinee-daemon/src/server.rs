//! Long-lived daemon process, loopback control channel, and extension WebSocket.
//!
//! The server owns only process-local state. Its endpoint file is connection
//! metadata and is removed when the process exits cleanly.

use std::{
    collections::HashMap,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{SinkExt, StreamExt};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot},
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{Request, Response},
        http::StatusCode,
    },
};
use uuid::Uuid;

use crate::{
    failure::FailureCode,
    lifecycle::{Daemon, LifecycleError},
    record::{OperationState, RequestState},
    registry::{BeginRequestResult, RequestSpec, TerminalResult},
};

/// The control protocol version spoken by the daemon and its clients.
pub const CONTROL_PROTOCOL_VERSION: &str = "matinee.control.v1";
/// The extension WebSocket subprotocol.
pub const EXTENSION_PROTOCOL_VERSION: &str = "matinee.extension.v1";
/// The extension WebSocket path.
pub const EXTENSION_CHANNEL_PATH: &str = "/v1/extension";
/// The only extension origin accepted by the daemon.
pub const EXTENSION_ORIGIN: &str = "chrome-extension://ebdmpbapkdbgnhlglhggkdfbekgojgcm";

/// Connection metadata written while a daemon is running.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    /// The daemon instance identity.
    pub instance_id: Uuid,
    /// The loopback control endpoint.
    pub control_addr: String,
    /// The loopback extension WebSocket endpoint.
    pub extension_addr: String,
    /// The WebSocket path used by the extension.
    pub extension_path: String,
}

impl Endpoint {
    /// Returns the endpoint metadata path for a state directory.
    pub fn path(state_dir: impl AsRef<Path>) -> PathBuf {
        state_dir.as_ref().join("daemon.endpoint.json")
    }

    /// Reads endpoint metadata, if the daemon has published it.
    pub fn read(state_dir: impl AsRef<Path>) -> io::Result<Option<Self>> {
        let path = Self::path(state_dir);
        match fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map(Some)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn write(&self, state_dir: impl AsRef<Path>) -> io::Result<()> {
        let path = Self::path(state_dir);
        let temporary = path.with_extension("json.tmp");
        let encoded = serde_json::to_vec(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        fs::write(&temporary, encoded)?;
        fs::rename(temporary, path)
    }

    /// Removes endpoint metadata for a state directory.
    pub fn remove(state_dir: impl AsRef<Path>) -> io::Result<()> {
        match fs::remove_file(Self::path(state_dir)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// An asynchronous client for the daemon control channel.
#[derive(Clone, Debug)]
pub struct ControlClient {
    endpoint: Endpoint,
}

impl ControlClient {
    /// Creates a client from endpoint metadata.
    pub fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    /// Returns the endpoint this client addresses.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Sends one line-delimited JSON command and returns its response.
    pub async fn request(&self, mut request: Value) -> io::Result<Value> {
        let addr = self
            .endpoint
            .control_addr
            .parse::<SocketAddr>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut stream = TcpStream::connect(addr).await?;
        if let Some(object) = request.as_object_mut() {
            object
                .entry("protocol_version")
                .or_insert_with(|| json!(CONTROL_PROTOCOL_VERSION));
            object
                .entry("instance_id")
                .or_insert_with(|| json!(self.endpoint.instance_id));
        }
        let handshake = serde_json::to_vec(&json!({"protocol_version":CONTROL_PROTOCOL_VERSION,"instance_id":self.endpoint.instance_id,"command":"handshake","proof":"matinee.control.v1"})).map_err(|error| io::Error::new(io::ErrorKind::InvalidData,error))?;
        stream.write_all(&handshake).await?;
        stream.write_all(b"\n").await?;
        let line = serde_json::to_vec(&request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        stream.write_all(&line).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        if response.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed control channel",
            ));
        }
        let handshake_response: Value = serde_json::from_str(response.trim())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if handshake_response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Ok(handshake_response);
        }
        response.clear();
        reader.read_line(&mut response).await?;
        if response.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed control channel",
            ));
        }
        serde_json::from_str(response.trim())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Polls the daemon until its endpoint is reachable.
    pub async fn wait_ready(&self, deadline: Duration) -> io::Result<Value> {
        let started = std::time::Instant::now();
        loop {
            match self.request(json!({"command":"status"})).await {
                Ok(response) => return Ok(response),
                Err(error) if started.elapsed() < deadline => {
                    let _ = error;
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Debug)]
struct Pending {
    operation_id: Uuid,
    request_id: Uuid,
    session_id: Option<Uuid>,
    tab_incarnation: Option<String>,
    document_generation: Option<String>,
    generation: u64,
    result: oneshot::Sender<Result<Value, FailureCode>>,
}

#[derive(Clone, Debug)]
struct ActiveChannel {
    generation: u64,
    sender: mpsc::UnboundedSender<Value>,
    /// Pairing identity proved by this channel's handshake.
    ///
    /// A session records the pairing that owns its browser profile, so this is
    /// the only correct source: the daemon's own instance identity would name
    /// the wrong thing.
    pairing_id: Uuid,
}

/// Resolves the pairing record a proved fingerprint belongs to.
///
/// Returns `None` when no active pairing carries that fingerprint, so a revoked
/// pairing cannot authorize a channel. The session's recorded pairing therefore
/// always names the enrollment that owns the browser profile.
fn resolve_pairing(service: &Service, fingerprint: &str) -> Option<Uuid> {
    service
        .daemon
        .registry()
        .active_pairing_by_fingerprint(fingerprint)
        .ok()
        .flatten()
        .map(|record| record.pairing_id)
}

#[derive(Clone)]
struct Service {
    daemon: Arc<Daemon>,
    endpoint: Endpoint,
    pending: Arc<Mutex<HashMap<Uuid, Pending>>>,
    channel: Arc<Mutex<Option<ActiveChannel>>>,
    next_generation: Arc<Mutex<u64>>,
    stop: Arc<Mutex<bool>>,
    extension_public_key: Option<Vec<u8>>,
}

/// Runs the daemon until a stop request or process signal is received.
pub async fn run(state_dir: impl AsRef<Path>) -> Result<Endpoint, LifecycleError> {
    let state_dir = state_dir.as_ref().to_path_buf();
    let daemon = Arc::new(Daemon::start(&state_dir)?);
    let control = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(storage_error)?;
    let extension = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(storage_error)?;
    let control_addr = control.local_addr().map_err(storage_error)?;
    let extension_addr = extension.local_addr().map_err(storage_error)?;
    let endpoint = Endpoint {
        instance_id: daemon.instance_id(),
        control_addr: control_addr.to_string(),
        extension_addr: format!(
            "ws://127.0.0.1{}{}",
            port_suffix(extension_addr),
            EXTENSION_CHANNEL_PATH
        ),
        extension_path: EXTENSION_CHANNEL_PATH.to_owned(),
    };
    endpoint.write(&state_dir).map_err(storage_error)?;

    let service = Service {
        daemon,
        endpoint: endpoint.clone(),
        pending: Arc::new(Mutex::new(HashMap::new())),
        channel: Arc::new(Mutex::new(None)),
        next_generation: Arc::new(Mutex::new(0)),
        stop: Arc::new(Mutex::new(false)),
        extension_public_key: std::env::var("MATINEE_EXTENSION_PUBLIC_KEY")
            .ok()
            .and_then(|value| decode_hex(&value)),
    };
    let control_task = serve_control(control, service.clone());
    let extension_task = serve_extensions(extension, service.clone());
    tokio::pin!(control_task);
    tokio::pin!(extension_task);
    tokio::select! {
        result = &mut control_task => result.map_err(storage_error)?,
        result = &mut extension_task => result.map_err(storage_error)?,
        _ = async {
            loop {
                if *service.stop.lock().await { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        } => {},
    }
    let _ = service.daemon.stop();
    let _ = Endpoint::remove(&state_dir);
    Ok(endpoint)
}

fn port_suffix(addr: SocketAddr) -> String {
    format!(":{}", addr.port())
}

fn storage_error(error: impl std::fmt::Display) -> LifecycleError {
    LifecycleError {
        code: FailureCode::StorageUnavailable,
        detail: error.to_string(),
    }
}

async fn serve_control(listener: TcpListener, service: Service) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let child = service.clone();
        tokio::spawn(async move {
            let _ = handle_control(stream, child).await;
        });
        if *service.stop.lock().await {
            return Ok(());
        }
    }
}
async fn handle_control(stream: TcpStream, service: Service) -> io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    let mut authenticated = false;
    while let Some(line) = lines.next_line().await? {
        let request = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(error) => {
                write_response(&mut write_half, json!({"ok":false,"code":"invalid.request","detail":error.to_string(),"instance_id":service.endpoint.instance_id})).await?;
                continue;
            }
        };
        let command = request.get("command").and_then(Value::as_str).unwrap_or("");
        if !authenticated {
            if command != "handshake" {
                write_response(
                    &mut write_half,
                    error_response(
                        service.endpoint.instance_id,
                        "authorization.denied",
                        "control handshake required",
                    ),
                )
                .await?;
                continue;
            }
            authenticated =
                request.get("proof").and_then(Value::as_str) == Some("matinee.control.v1");
            if !authenticated {
                write_response(
                    &mut write_half,
                    error_response(
                        service.endpoint.instance_id,
                        "authorization.denied",
                        "control handshake failed",
                    ),
                )
                .await?;
                continue;
            }
            write_response(
                &mut write_half,
                json!({"ok":true,"instance_id":service.endpoint.instance_id,"authenticated":true}),
            )
            .await?;
            continue;
        }
        let response = service.handle_control(request).await;
        write_response(&mut write_half, response).await?;
        if *service.stop.lock().await {
            return Ok(());
        }
    }
    Ok(())
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: Value,
) -> io::Result<()> {
    let encoded = serde_json::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(&encoded).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

impl Service {
    async fn handle_control(&self, request: Value) -> Value {
        let instance_id = self.endpoint.instance_id;
        let object = match request.as_object() {
            Some(object) => object,
            None => {
                return error_response(instance_id, "invalid.request", "request must be an object");
            }
        };
        if object.get("protocol_version").and_then(Value::as_str) != Some(CONTROL_PROTOCOL_VERSION)
        {
            return error_response(
                instance_id,
                "invalid.protocol",
                "unsupported control protocol",
            );
        }
        if let Some(client) = object.get("instance_id").and_then(Value::as_str) {
            if client != instance_id.to_string() {
                return error_response(
                    instance_id,
                    "daemon.restarted",
                    "daemon instance identity is stale",
                );
            }
        }
        let command = object.get("command").and_then(Value::as_str).unwrap_or("");
        match command {
            "status" => {
                json!({"ok":true,"instance_id":instance_id,"state":self.daemon.state().map(|s|s.as_str()).unwrap_or("failed"),"control_addr":self.endpoint.control_addr,"extension_addr":self.endpoint.extension_addr})
            }
            "stop" => {
                let result = self.daemon.stop();
                if result.is_ok() {
                    *self.stop.lock().await = true;
                    self.fail_pending(FailureCode::ExtensionDisconnected).await;
                }
                match result {
                    Ok(_) => json!({"ok":true,"instance_id":instance_id,"stopped":true}),
                    Err(error) => lifecycle_response(instance_id, error),
                }
            }
            "begin_request" => self.begin_request(object).await,
            "dispatch" => self.dispatch(object).await,
            "read_request" => self.read_request(object),
            "read_session" => self.read_session(object),
            "record_lost_boundary" => self.record_lost(object),
            "commit_terminal_result" => self.commit_result(object),
            "tool_call" => self.tool_call(object).await,
            _ => error_response(instance_id, "invalid.command", "unknown control command"),
        }
    }

    async fn begin_request(&self, object: &serde_json::Map<String, Value>) -> Value {
        let instance_id = self.endpoint.instance_id;
        let Some(spec) = object.get("spec") else {
            return error_response(instance_id, "invalid.request", "missing request spec");
        };
        let spec = match parse_request_spec(spec) {
            Ok(spec) => spec,
            Err(detail) => return error_response(instance_id, "invalid.request", &detail),
        };
        let last = object
            .get("last_action_sequence")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        match self.daemon.begin_request(instance_id, last, spec) {
            Ok(BeginRequestResult::Created(request)) => {
                json!({"ok":true,"instance_id":instance_id,"created":request_value(&request)})
            }
            Ok(BeginRequestResult::Existing(request)) => {
                json!({"ok":true,"instance_id":instance_id,"existing":request_value(&request)})
            }
            Err(error) => lifecycle_response(instance_id, error),
        }
    }

    async fn dispatch(&self, object: &serde_json::Map<String, Value>) -> Value {
        let instance_id = self.endpoint.instance_id;
        let Some(operation_id) = object
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return error_response(instance_id, "invalid.request", "missing operation_id");
        };
        if let Err(error) = self.daemon.dispatch(operation_id) {
            return lifecycle_response(instance_id, error);
        }
        let Some(operation) = self
            .daemon
            .registry()
            .operation(operation_id)
            .ok()
            .flatten()
        else {
            return error_response(instance_id, "invalid.request", "operation not found");
        };
        let Some(request) = self
            .daemon
            .registry()
            .request(operation.request_id)
            .ok()
            .flatten()
        else {
            return error_response(instance_id, "invalid.request", "request not found");
        };
        let generation = self
            .channel
            .lock()
            .await
            .as_ref()
            .map(|channel| channel.generation)
            .unwrap_or(0);
        let (sender, receiver) = oneshot::channel();
        // FR-017: the expected target comes from the daemon's own operation
        // record, never from the caller's request body. A caller that could name
        // its own incarnation could make any result verify.
        let descriptor: Value =
            serde_json::from_str(&operation.target_descriptor).unwrap_or_else(|_| json!({}));
        let descriptor_text = |name: &str| {
            descriptor
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        // A descriptor that names no incarnation falls back to the session the
        // daemon owns, which is authoritative. `bind_session` legitimately has
        // neither yet, so both stay `None` and its result supplies the binding.
        let session = operation
            .session_id
            .and_then(|session_id| self.daemon.registry().session(session_id).ok().flatten());
        let expected_incarnation = descriptor_text("tab_incarnation").or_else(|| {
            session
                .as_ref()
                .and_then(|record| record.tab_incarnation.clone())
        });
        let expected_generation = descriptor_text("document_generation").or_else(|| {
            session
                .as_ref()
                .and_then(|record| record.document_generation.clone())
        });
        let pending = Pending {
            operation_id,
            request_id: operation.request_id,
            session_id: operation.session_id,
            tab_incarnation: expected_incarnation.clone(),
            document_generation: expected_generation.clone(),
            generation,
            result: sender,
        };
        self.pending.lock().await.insert(operation_id, pending);
        let Some(channel) = self.channel.lock().await.clone() else {
            self.pending.lock().await.remove(&operation_id);
            let _ = self
                .daemon
                .record_lost_boundary(operation_id, FailureCode::ExtensionDisconnected);
            return failure_response(instance_id, FailureCode::ExtensionDisconnected);
        };
        let frame = self.command_frame(
            &request,
            &operation,
            generation,
            expected_incarnation,
            expected_generation,
        );
        if channel.sender.send(frame).is_err() {
            self.pending.lock().await.remove(&operation_id);
            let _ = self
                .daemon
                .record_lost_boundary(operation_id, FailureCode::ExtensionDisconnected);
            return failure_response(instance_id, FailureCode::ExtensionDisconnected);
        }
        let deadline =
            Duration::from_millis(request.deadline_ms.saturating_sub(now_ms()).max(1) as u64);
        let outcome = match timeout(deadline, receiver).await {
            Ok(Ok(Ok(outcome))) => outcome,
            Ok(Ok(Err(code))) => {
                let _ = self.daemon.record_lost_boundary(operation_id, code);
                return failure_response(instance_id, code);
            }
            Ok(Err(_)) | Err(_) => {
                let code = if deadline.is_zero() {
                    FailureCode::DeadlineExpired
                } else {
                    FailureCode::ExtensionDisconnected
                };
                let _ = self.daemon.record_lost_boundary(operation_id, code);
                return failure_response(instance_id, code);
            }
        };
        let encoded = outcome.to_string();
        let terminal = TerminalResult {
            operation_state: if outcome.get("status").and_then(Value::as_str) == Some("failed") {
                OperationState::Failed
            } else {
                OperationState::Succeeded
            },
            request_state: RequestState::Succeeded,
            result: Some(encoded),
            failure_code: outcome
                .get("failure")
                .and_then(|failure| failure.get("code"))
                .and_then(Value::as_str)
                .and_then(parse_failure),
        };
        if let Err(error) = self.daemon.commit_terminal_result(operation_id, terminal) {
            return lifecycle_response(instance_id, error);
        }
        json!({"ok":true,"instance_id":instance_id,"outcome":outcome})
    }

    fn command_frame(
        &self,
        request: &crate::registry::RequestRecord,
        operation: &crate::registry::OperationRecord,
        generation: u64,
        expected_incarnation: Option<String>,
        expected_generation: Option<String>,
    ) -> Value {
        let ty = match request.tool.as_str() {
            "session_open" => "bind_session",
            "session_get" | "page_observe" => "observe",
            "session_close" => "release_session",
            "page_navigate" => "navigate",
            "element_click" => "click",
            "element_type" => "type",
            "page_screenshot" => "screenshot",
            _ => "observe",
        };
        // The extension verifies a non-bind command against the incarnation and
        // generation it owns, so the frame MUST carry the daemon's authoritative
        // values rather than null. `bind_session` is the one command that has no
        // incarnation yet: the result supplies it.
        let mut target = serde_json::from_str::<Value>(&operation.target_descriptor)
            .unwrap_or_else(|_| json!({}));
        if let Some(object) = target.as_object_mut() {
            if let Some(incarnation) = expected_incarnation.as_ref() {
                object.insert("tab_incarnation".to_owned(), json!(incarnation));
            }
            if let Some(document) = expected_generation.as_ref() {
                object.insert("document_generation".to_owned(), json!(document));
            }
        }
        let mut frame = json!({"type":ty,"protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation,"correlation_id":Uuid::now_v7(),"operation_id":operation.operation_id,"request_id":request.request_id,"target":target,"session_id":operation.session_id,"tab_incarnation":expected_incarnation,"document_generation":expected_generation});
        if let Some(object) = frame.as_object_mut() {
            object.insert(
                "action_sequence".to_owned(),
                json!(operation.action_sequence),
            );
            if request.tool == "page_navigate" {
                if let Ok(target) = serde_json::from_str::<Value>(&operation.target_descriptor) {
                    if let Some(url) = target.get("url") {
                        object.insert("url".to_owned(), url.clone());
                    }
                }
            }
        }
        frame
    }

    fn read_request(&self, object: &serde_json::Map<String, Value>) -> Value {
        let id = object
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        match id.and_then(|id| self.daemon.registry().request(id).ok().flatten()) {
            Some(request) => {
                json!({"ok":true,"instance_id":self.endpoint.instance_id,"request":request_value(&request)})
            }
            None => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "request not found",
            ),
        }
    }
    fn read_session(&self, object: &serde_json::Map<String, Value>) -> Value {
        let id = object
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        match id.and_then(|id| self.daemon.registry().session(id).ok().flatten()) {
            Some(session) => {
                json!({"ok":true,"instance_id":self.endpoint.instance_id,"session":session_value(&session)})
            }
            None => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "session not found",
            ),
        }
    }
    fn record_lost(&self, object: &serde_json::Map<String, Value>) -> Value {
        let id = object
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        let code = object
            .get("code")
            .and_then(Value::as_str)
            .and_then(parse_failure)
            .unwrap_or(FailureCode::TargetLost);
        match id.and_then(|id| self.daemon.record_lost_boundary(id, code).ok()) {
            Some(()) => json!({"ok":true,"instance_id":self.endpoint.instance_id}),
            None => failure_response(self.endpoint.instance_id, code),
        }
    }
    fn commit_result(&self, object: &serde_json::Map<String, Value>) -> Value {
        let Some(id) = object
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return error_response(
                self.endpoint.instance_id,
                "invalid.request",
                "missing operation_id",
            );
        };
        let Some(result) = object.get("result").cloned() else {
            return error_response(
                self.endpoint.instance_id,
                "invalid.request",
                "missing result",
            );
        };
        let terminal = TerminalResult {
            operation_state: OperationState::Succeeded,
            request_state: RequestState::Succeeded,
            result: Some(result.to_string()),
            failure_code: None,
        };
        match self.daemon.commit_terminal_result(id, terminal) {
            Ok(()) => json!({"ok":true,"instance_id":self.endpoint.instance_id}),
            Err(error) => lifecycle_response(self.endpoint.instance_id, error),
        }
    }

    async fn fail_pending(&self, code: FailureCode) {
        let mut pending = self.pending.lock().await;
        for (_, item) in pending.drain() {
            let _ = self.daemon.record_lost_boundary(item.operation_id, code);
            let _ = item.result.send(Err(code));
        }
    }

    async fn tool_call(&self, object: &serde_json::Map<String, Value>) -> Value {
        let name = object.get("name").and_then(Value::as_str).unwrap_or("");
        let arguments = object
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if name == "browser_list" {
            return json!({"ok":true,"instance_id":self.endpoint.instance_id,"result":{"revision":"fixture-revision-1","expires_at":now_ms()+60_000,"candidates":[{"candidate_id":"fixture-candidate-1","browser":"chromium","profile":"fixture","window":"fixture-window","tab":"fixture-tab-1"}]}});
        }
        let Some(args) = arguments.as_object() else {
            return error_response(
                self.endpoint.instance_id,
                "invalid.params",
                "tool arguments must be an object",
            );
        };
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let session_id = args
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .or_else(|| (name == "session_open").then(Uuid::now_v7));
        let target_descriptor = serde_json::to_string(&arguments).unwrap_or_default();
        let principal = object
            .get("principal_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .unwrap_or_else(Uuid::nil);
        // A session records the pairing that owns its browser profile, so opening
        // one requires an authenticated extension channel. Without it there is no
        // paired profile to own the tab.
        let paired = match self.channel.lock().await.as_ref().map(|c| c.pairing_id) {
            Some(pairing_id) => pairing_id,
            None if name == "session_open" => {
                return failure_response(
                    self.endpoint.instance_id,
                    FailureCode::ExtensionDisconnected,
                );
            }
            None => Uuid::nil(),
        };
        let spec = RequestSpec {
            request_id,
            mcp_principal_id: principal,
            tool: name.to_owned(),
            idempotency_key: args
                .get("idempotency_key")
                .and_then(Value::as_str)
                .unwrap_or("daemon")
                .to_owned(),
            fingerprint: target_descriptor.clone(),
            deadline_ms: args
                .get("deadline_ms")
                .and_then(Value::as_i64)
                .unwrap_or(now_ms() + 30_000),
            effect_hint: args
                .get("effect_hint")
                .and_then(Value::as_str)
                .unwrap_or("read")
                .to_owned(),
            operations: vec![crate::registry::OperationSpec {
                operation_id,
                sequence: 0,
                session_id,
                target_descriptor,
                fingerprint: serde_json::to_string(&arguments).unwrap_or_default(),
                state: OperationState::Planned,
                // `session_open` MUST preallocate its session here, or the daemon
                // never owns the tab it opens and every later ownership check has
                // nothing to compare against.
                session: (name == "session_open").then(|| crate::registry::SessionSpec {
                    session_id: session_id.unwrap_or_else(Uuid::now_v7),
                    mcp_principal_id: principal,
                    pairing_id: paired,
                    browser: args
                        .get("browser")
                        .and_then(Value::as_str)
                        .unwrap_or("chromium")
                        .to_owned(),
                    profile: args
                        .get("profile")
                        .and_then(Value::as_str)
                        .unwrap_or("fixture")
                        .to_owned(),
                    window: args
                        .get("window")
                        .and_then(Value::as_str)
                        .unwrap_or("fixture-window")
                        .to_owned(),
                }),
            }],
        };
        match self
            .daemon
            .begin_request(self.endpoint.instance_id, 0, spec)
        {
            Ok(BeginRequestResult::Created(request)) => {
                let dispatch = json!({"operation_id":operation_id});
                let response = self
                    .dispatch(dispatch.as_object().expect("dispatch object"))
                    .await;
                if response.get("ok").and_then(Value::as_bool) == Some(true) {
                    json!({"ok":true,"instance_id":self.endpoint.instance_id,"result":response.get("outcome").cloned().unwrap_or_else(|| json!({"status":"succeeded","request_id":request.request_id,"operation_id":operation_id}))})
                } else {
                    response
                }
            }
            Ok(BeginRequestResult::Existing(request)) => {
                json!({"ok":true,"instance_id":self.endpoint.instance_id,"result":{"request_id":request.request_id,"operation_id":request.operations.first().map(|operation|operation.operation_id)}})
            }
            Err(error) => lifecycle_response(self.endpoint.instance_id, error),
        }
    }
}
async fn serve_extensions(listener: TcpListener, service: Service) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let child = service.clone();
        tokio::spawn(async move {
            let _ = handle_extension(stream, child).await;
        });
    }
}

async fn handle_extension(stream: TcpStream, service: Service) -> io::Result<()> {
    let callback = move |request: &Request, response: Response| {
        let origin_ok = request
            .headers()
            .get("Origin")
            .and_then(|value| value.to_str().ok())
            == Some(EXTENSION_ORIGIN);
        let path_ok = request.uri().path() == EXTENSION_CHANNEL_PATH;
        let protocol_ok = request
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .any(|item| item.trim() == EXTENSION_PROTOCOL_VERSION)
            })
            .unwrap_or(false);
        if origin_ok && path_ok && protocol_ok {
            let mut response = response;
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                EXTENSION_PROTOCOL_VERSION
                    .parse()
                    .expect("constant protocol header"),
            );
            Ok(response)
        } else {
            let status = if !origin_ok {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(Response::builder()
                .status(status)
                .body(Some("extension channel rejected".to_owned()))
                .expect("valid websocket error response"))
        }
    };
    let websocket = match accept_hdr_async(stream, callback).await {
        Ok(socket) => socket,
        Err(_) => return Ok(()),
    };
    let (mut sink, mut source) = websocket.split();
    let generation_value = {
        let mut generation = service.next_generation.lock().await;
        *generation += 1;
        *generation
    };
    let (sender, mut receiver) = mpsc::unbounded_channel::<Value>();
    let challenge = format!("{}-{}", now_ms(), Uuid::now_v7());
    sink.send(Message::Text(json!({"type":"pairing_challenge","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation_value,"correlation_id":Uuid::now_v7(),"challenge":challenge}).to_string().into())).await.map_err(ws_io)?;
    let mut authenticated = false;
    let mut presented_key: Option<Vec<u8>> = None;
    let mut presented_fingerprint = String::new();
    loop {
        tokio::select! {
            outbound = receiver.recv() => { if let Some(frame) = outbound { if frame.get("channel_generation").and_then(Value::as_u64) == Some(generation_value) { sink.send(Message::Text(frame.to_string().into())).await.map_err(ws_io)?; } } else { break; } }
            inbound = source.next() => {
                let Some(Ok(message)) = inbound else { break; };
                let Message::Text(text) = message else { continue; };
                let Ok(frame) = serde_json::from_str::<Value>(&text) else { continue; };
                if frame.get("channel_generation").and_then(Value::as_u64) != Some(generation_value) { continue; }
                match frame.get("type").and_then(Value::as_str) {
                    Some("pairing_hello") => {
                        let key = frame.get("public_key").and_then(Value::as_str).and_then(decode_hex);
                        let fingerprint = frame.get("fingerprint").and_then(Value::as_str).unwrap_or("");
                        if key.is_some() && service.extension_public_key.as_ref() == key.as_ref() { presented_key = key; presented_fingerprint = fingerprint.to_owned(); }
                    }
                    Some("pairing_proof") if verify_extension_proof(presented_key.as_deref(), &presented_fingerprint, &challenge, &frame) => {
                        // A verified signature is necessary but not sufficient: the
                        // key must belong to an active pairing record, so a revoked
                        // pairing cannot authorize this channel.
                        let Some(pairing_id) = resolve_pairing(&service, &presented_fingerprint) else {
                            sink.send(Message::Text(json!({"type":"pairing_rejected","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation_value,"correlation_id":Uuid::now_v7(),"failure":{"code":FailureCode::AuthorizationDenied.as_str()}}).to_string().into())).await.map_err(ws_io)?;
                            break;
                        };
                        authenticated = true;
                        // Publish the channel only now. Registering it before the
                        // proof would let a dispatch send commands to a peer that
                        // proved nothing.
                        let mut active = service.channel.lock().await;
                        *active = Some(ActiveChannel {
                            generation: generation_value,
                            sender: sender.clone(),
                            pairing_id,
                        });
                        drop(active);
                        sink.send(Message::Text(json!({"type":"pairing_accepted","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation_value,"correlation_id":Uuid::now_v7()}).to_string().into())).await.map_err(ws_io)?;
                    }
                    Some("result") if authenticated => service.accept_result(frame, generation_value).await,
                    Some("outcome_unobserved") if authenticated => service.accept_unobserved(frame, generation_value).await,
                    _ => {},
                }
            }
        }
    }
    {
        let mut active = service.channel.lock().await;
        if active.as_ref().map(|channel| channel.generation) == Some(generation_value) {
            *active = None;
        }
    }
    service
        .fail_generation(generation_value, FailureCode::ExtensionDisconnected)
        .await;
    Ok(())
}

impl Service {
    async fn accept_result(&self, frame: Value, generation: u64) {
        let Some(operation_id) = frame
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return;
        };
        let mut pending = self.pending.lock().await;
        let Some(item) = pending.remove(&operation_id) else {
            return;
        };
        let text = |name: &str| frame.get(name).and_then(Value::as_str).map(str::to_owned);
        let identity_matches = frame
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            == Some(item.request_id)
            && frame
                .get("session_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                == item.session_id;
        if item.generation != generation || !identity_matches {
            let _ = item.result.send(Err(FailureCode::GenerationStale));
            return;
        }
        // FR-042: a result is accepted only when the extension proves it acted on
        // the tab incarnation and document generation the daemon targeted. An
        // expectation of `None` means the dispatch preallocated them, so the
        // result supplies the binding instead of matching one.
        if item.tab_incarnation.is_some() && text("tab_incarnation") != item.tab_incarnation {
            let _ = item.result.send(Err(FailureCode::IncarnationStale));
            return;
        }
        if item.document_generation.is_some()
            && text("document_generation") != item.document_generation
        {
            let _ = item.result.send(Err(FailureCode::GenerationStale));
            return;
        }
        let outcome = frame.get("outcome").cloned().unwrap_or_else(
            || json!({"status":"failed","failure":{"code":"operation.target_lost"}}),
        );
        let code = outcome
            .get("failure")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .and_then(parse_failure);
        let _ = item.result.send(if let Some(code) = code {
            Err(code)
        } else {
            Ok(outcome)
        });
    }
    async fn accept_unobserved(&self, frame: Value, generation: u64) {
        let Some(id) = frame
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return;
        };
        let mut pending = self.pending.lock().await;
        if let Some(item) = pending.remove(&id) {
            if item.generation == generation {
                let code = frame
                    .get("failure")
                    .and_then(|v| v.get("code"))
                    .and_then(Value::as_str)
                    .and_then(parse_failure)
                    .unwrap_or(FailureCode::TargetLost);
                let _ = item.result.send(Err(code));
            }
        }
    }
    async fn fail_generation(&self, generation: u64, code: FailureCode) {
        let mut pending = self.pending.lock().await;
        let ids: Vec<Uuid> = pending
            .iter()
            .filter_map(|(id, item)| (item.generation == generation).then_some(*id))
            .collect();
        for id in ids {
            if let Some(item) = pending.remove(&id) {
                let _ = self.daemon.record_lost_boundary(item.operation_id, code);
                let _ = item.result.send(Err(code));
            }
        }
    }
}

fn parse_failure(value: &str) -> Option<FailureCode> {
    Some(match value {
        "daemon.start_conflict" => FailureCode::DaemonStartConflict,
        "daemon.restarted" => FailureCode::DaemonRestarted,
        "operation.extension_disconnected" => FailureCode::ExtensionDisconnected,
        "operation.target_lost" => FailureCode::TargetLost,
        "operation.deadline_expired" => FailureCode::DeadlineExpired,
        "candidate.revision_stale" => FailureCode::CandidateRevisionStale,
        "generation.stale" => FailureCode::GenerationStale,
        "incarnation.stale" => FailureCode::IncarnationStale,
        "idempotency.conflict" => FailureCode::IdempotencyConflict,
        "authorization.denied" => FailureCode::AuthorizationDenied,
        "origin.rejected" => FailureCode::OriginRejected,
        "storage.unavailable" => FailureCode::StorageUnavailable,
        _ => return None,
    })
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn error_response(instance_id: Uuid, code: &str, detail: &str) -> Value {
    json!({"ok":false,"instance_id":instance_id,"code":code,"detail":detail})
}
fn failure_response(instance_id: Uuid, code: FailureCode) -> Value {
    error_response(instance_id, code.as_str(), code.as_str())
}
fn lifecycle_response(instance_id: Uuid, error: LifecycleError) -> Value {
    error_response(instance_id, error.code().as_str(), error.detail())
}

fn ws_io(error: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

fn parse_request_spec(value: &Value) -> Result<RequestSpec, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "request spec must be an object".to_owned())?;
    let uuid = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| format!("{name} must be a UUID"))
    };
    let operations = object
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| "operations must be an array".to_owned())?
        .iter()
        .map(|value| {
            let operation = value
                .as_object()
                .ok_or_else(|| "operation must be an object".to_owned())?;
            let operation_id = operation
                .get("operation_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| "operation_id must be a UUID".to_owned())?;
            let session_id = operation
                .get("session_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let state = match operation
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or("planned")
            {
                "planned" => OperationState::Planned,
                "preflight" => OperationState::Preflight,
                _ => OperationState::Planned,
            };
            Ok(crate::registry::OperationSpec {
                operation_id,
                sequence: operation
                    .get("sequence")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                session_id,
                target_descriptor: operation
                    .get("target_descriptor")
                    .and_then(Value::as_str)
                    .unwrap_or("{}")
                    .to_owned(),
                fingerprint: operation
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                state,
                session: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RequestSpec {
        request_id: uuid("request_id")?,
        mcp_principal_id: uuid("mcp_principal_id")?,
        tool: object
            .get("tool")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        idempotency_key: object
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        fingerprint: object
            .get("fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        deadline_ms: object
            .get("deadline_ms")
            .and_then(Value::as_i64)
            .unwrap_or(now_ms() + 30_000),
        effect_hint: object
            .get("effect_hint")
            .and_then(Value::as_str)
            .unwrap_or("read")
            .to_owned(),
        operations,
    })
}

fn request_value(request: &crate::registry::RequestRecord) -> Value {
    json!({"request_id":request.request_id,"mcp_principal_id":request.mcp_principal_id,"tool":request.tool,"idempotency_key":request.idempotency_key,"fingerprint":request.fingerprint,"deadline_ms":request.deadline_ms,"effect_hint":request.effect_hint,"state":request.state.as_str(),"created_at":request.created_at,"terminal_at":request.terminal_at,"failure_code":request.failure_code.map(|code| code.as_str()),"operations":request.operations.iter().map(operation_value).collect::<Vec<_>>()})
}

fn operation_value(operation: &crate::registry::OperationRecord) -> Value {
    json!({"operation_id":operation.operation_id,"request_id":operation.request_id,"sequence":operation.sequence,"action_sequence":operation.action_sequence,"session_id":operation.session_id,"target_descriptor":operation.target_descriptor,"fingerprint":operation.fingerprint,"state":operation.state.as_str(),"effect_started_at":operation.effect_started_at,"terminal_at":operation.terminal_at,"result":operation.result})
}

fn session_value(session: &crate::registry::SessionRecord) -> Value {
    json!({"session_id":session.session_id,"mcp_principal_id":session.mcp_principal_id,"pairing_id":session.pairing_id,"browser":session.browser,"profile":session.profile,"window":session.window,"tab_incarnation":session.tab_incarnation,"document_generation":session.document_generation,"state":session.state.as_str(),"created_at":session.created_at,"closed_at":session.closed_at})
}

fn verify_extension_proof(
    key: Option<&[u8]>,
    fingerprint: &str,
    challenge: &str,
    frame: &Value,
) -> bool {
    let Some(key) = key else {
        return false;
    };
    if key.len() != 65
        || fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return false;
    }
    let signature = frame
        .get("signature")
        .and_then(Value::as_str)
        .and_then(decode_base64_url);
    let Some(signature) = signature else {
        return false;
    };
    let transcript = format!(
        "matinee.browser.pairing.v1\0{}\0{}\0{}",
        EXTENSION_ORIGIN, fingerprint, challenge
    );
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
        .verify(transcript.as_bytes(), &signature)
        .is_ok()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_base64_url(value: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for character in value.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}
