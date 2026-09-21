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
use ring::{
    digest,
    signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
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

use matinee_security::{
    ClientHandshake, ClientHandshakeConfig, ConnectionId, SecurityEvent, SecurityEventSink,
    SecurityEventSinkResult,
};

use crate::{
    control_auth::{self, ControlAuth, ControlAuthError},
    failure::FailureCode,
    lifecycle::{Daemon, LifecycleError},
    record::{OperationState, RequestState},
    registry::{BeginRequestResult, PairingRecord, RequestSpec, TerminalResult},
};

/// The control protocol version spoken by the daemon and its clients.
pub const CONTROL_PROTOCOL_VERSION: &str = "matinee.control.v1";
/// The extension WebSocket subprotocol.
pub const EXTENSION_PROTOCOL_VERSION: &str = "matinee.extension.v1";
/// The extension WebSocket path.
pub const EXTENSION_CHANNEL_PATH: &str = "/v1/extension";
/// The only extension origin accepted by the daemon.
pub const EXTENSION_ORIGIN: &str = "chrome-extension://ebdmpbapkdbgnhlglhggkdfbekgojgcm";

/// How often the daemon heartbeats an authenticated extension channel.
///
/// Chrome stops an idle MV3 service worker after about thirty seconds, so this
/// stays comfortably below that.
const EXTENSION_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(15);

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
    /// The user-readable path of the local control credential handoff.
    pub credential_path: String,
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

    /// Sends one JSON command after one authenticated secure-channel handshake.
    pub async fn request(&self, mut request: Value) -> io::Result<Value> {
        let addr = self
            .endpoint
            .control_addr
            .parse::<SocketAddr>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mut stream = TcpStream::connect(addr).await?;
        let native = matches!(
            request.get("command").and_then(Value::as_str),
            Some("stop" | "pair_extension")
        );
        let (principal, epoch, principal_key, daemon_key, daemon_id, signer) =
            control_auth::ControlAuth::client_material(
                Path::new(&self.endpoint.credential_path),
                native,
            )?;
        let config = ClientHandshakeConfig::new(
            self.endpoint.control_addr.clone(),
            principal,
            principal_key,
            daemon_id,
            daemon_key,
            epoch,
            control_auth::CONTROL_CONTRACT_MIN,
            control_auth::CONTROL_CONTRACT_MAX,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let (pending, hello) = ClientHandshake::start(config)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        write_binary_frame(&mut stream, &hello).await?;
        let proof = match read_binary_frame_or_denial(&mut stream).await? {
            HandshakePayload::Proof(proof) => proof,
            HandshakePayload::Denied(response) => return Ok(response),
        };
        let mut sink = NoopSink;
        let (session, signature) = pending
            .finish(&proof, &signer, &mut sink)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "authorization.denied"))?;
        write_binary_frame(&mut stream, &signature).await?;
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
        if session.principal().get() != principal.get() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authorization.denied",
            ));
        }
        if let Some(object) = request.as_object_mut() {
            object
                .entry("protocol_version")
                .or_insert_with(|| json!(CONTROL_PROTOCOL_VERSION));
            object
                .entry("instance_id")
                .or_insert_with(|| json!(self.endpoint.instance_id));
        }
        let line = serde_json::to_vec(&request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let stream = reader.get_mut();
        stream.write_all(&line).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
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

#[derive(Clone)]
struct Service {
    daemon: Arc<Daemon>,
    auth: Arc<ControlAuth>,
    endpoint: Endpoint,
    pending: Arc<Mutex<HashMap<Uuid, Pending>>>,
    channel: Arc<Mutex<Option<ActiveChannel>>>,
    next_generation: Arc<Mutex<u64>>,
    stop: Arc<Mutex<bool>>,
}

#[derive(Clone, Copy, Debug)]
struct AuthenticatedControl {
    principal_id: Uuid,
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
    let auth = Arc::new(
        ControlAuth::create(&control_addr.to_string(), &state_dir).map_err(storage_error)?,
    );
    auth.register(daemon.registry()).map_err(storage_error)?;
    let endpoint = Endpoint {
        instance_id: daemon.instance_id(),
        control_addr: control_addr.to_string(),
        extension_addr: format!(
            "ws://127.0.0.1{}{}",
            port_suffix(extension_addr),
            EXTENSION_CHANNEL_PATH
        ),
        extension_path: EXTENSION_CHANNEL_PATH.to_owned(),
        credential_path: auth.handoff_path().display().to_string(),
    };
    endpoint.write(&state_dir).map_err(storage_error)?;

    let service = Service {
        daemon,
        auth: auth.clone(),
        endpoint: endpoint.clone(),
        pending: Arc::new(Mutex::new(HashMap::new())),
        channel: Arc::new(Mutex::new(None)),
        next_generation: Arc::new(Mutex::new(0)),
        stop: Arc::new(Mutex::new(false)),
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
    let _ = auth.remove_handoff();
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
    let (mut reader, mut writer) = stream.into_split();
    let connection = ConnectionId::new(Uuid::now_v7());
    let hello = match read_binary_frame(&mut reader).await {
        Ok(hello) => hello,
        Err(_) => {
            write_response(
                &mut writer,
                error_response(
                    service.endpoint.instance_id,
                    "authorization.denied",
                    "control handshake required",
                ),
            )
            .await?;
            return Ok(());
        }
    };
    let (pending, proof, _) = match service.auth.accept(
        &service.endpoint.control_addr,
        &hello,
        connection,
        service.daemon.registry(),
    ) {
        Ok(value) => value,
        Err(ControlAuthError::Denied) => {
            write_response(
                &mut writer,
                error_response(
                    service.endpoint.instance_id,
                    "authorization.denied",
                    "control handshake failed",
                ),
            )
            .await?;
            return Ok(());
        }
    };
    write_binary_frame(&mut writer, &proof).await?;
    let signature = match read_binary_frame(&mut reader).await {
        Ok(signature) => signature,
        Err(_) => {
            write_response(
                &mut writer,
                error_response(
                    service.endpoint.instance_id,
                    "authorization.denied",
                    "control handshake failed",
                ),
            )
            .await?;
            return Ok(());
        }
    };
    let mut sink = NoopSink;
    let session = match pending.finish(&signature, &mut sink) {
        Ok(session) => session,
        Err(_) => {
            write_response(
                &mut writer,
                error_response(
                    service.endpoint.instance_id,
                    "authorization.denied",
                    "control handshake failed",
                ),
            )
            .await?;
            return Ok(());
        }
    };
    let authenticated = AuthenticatedControl {
        principal_id: session.principal().get(),
    };
    write_response(
        &mut writer,
        json!({"ok":true,"instance_id":service.endpoint.instance_id,"authenticated":true}),
    )
    .await?;
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let request = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(error) => {
                write_response(&mut writer, json!({"ok":false,"code":"invalid.request","detail":error.to_string(),"instance_id":service.endpoint.instance_id})).await?;
                continue;
            }
        };
        let response = service.handle_control(request, authenticated).await;
        write_response(&mut writer, response).await?;
        if *service.stop.lock().await {
            return Ok(());
        }
    }
    Ok(())
}

const MAX_CONTROL_FRAME: usize = 4_096;

async fn read_binary_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_CONTROL_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds limit",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_binary_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "control frame exceeds limit"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

enum HandshakePayload {
    Proof(Vec<u8>),
    Denied(Value),
}

async fn read_binary_frame_or_denial(reader: &mut TcpStream) -> io::Result<HandshakePayload> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length <= MAX_CONTROL_FRAME {
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload).await?;
        return Ok(HandshakePayload::Proof(payload));
    }
    let mut line = prefix.to_vec();
    loop {
        let byte = reader.read_u8().await?;
        line.push(byte);
        if byte == b'\n' {
            break;
        }
        if line.len() > MAX_CONTROL_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control denial exceeds limit",
            ));
        }
    }
    let response = serde_json::from_slice::<Value>(&line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(HandshakePayload::Denied(response))
}

struct NoopSink;
impl SecurityEventSink for NoopSink {
    fn emit(&mut self, _event: SecurityEvent) -> SecurityEventSinkResult {
        SecurityEventSinkResult::Accepted
    }
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
    async fn handle_control(&self, request: Value, authenticated: AuthenticatedControl) -> Value {
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
            "evidence" => self.evidence(),
            "pair_extension" => {
                if authenticated.principal_id != self.auth.native.id().get() {
                    return error_response(
                        instance_id,
                        "authorization.denied",
                        "native principal required",
                    );
                }
                let details = match self.auth.extension_pairing_details() {
                    Ok(details) => details,
                    Err(_) => {
                        return error_response(
                            instance_id,
                            "authorization.denied",
                            "extension enrollment unavailable",
                        );
                    }
                };
                json!({
                    "ok": true,
                    "instance_id": instance_id,
                    "one_time_key": details.one_time_key,
                    "extension_addr": self.endpoint.extension_addr,
                    "origin": details.origin,
                    "created_at": details.created_at,
                    "expires_at": details.expires_at,
                })
            }
            "stop" => {
                if authenticated.principal_id != self.auth.native.id().get() {
                    return error_response(
                        instance_id,
                        "authorization.denied",
                        "native principal required",
                    );
                }
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
            "begin_request" => self.begin_request(object, authenticated).await,
            "dispatch" => self.dispatch(object, authenticated).await,
            "read_request" => self.read_request(object, authenticated),
            "read_session" => self.read_session(object, authenticated),
            "record_lost_boundary" => self.record_lost(object, authenticated),
            "commit_terminal_result" => self.commit_result(object, authenticated),
            "tool_call" => self.tool_call(object, authenticated).await,
            _ => error_response(instance_id, "invalid.command", "unknown control command"),
        }
    }
    /// Returns the sanitized, point-in-time evidence report for this daemon run.
    fn evidence(&self) -> Value {
        let snapshot = match self.daemon.registry().snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return error_response(
                    self.endpoint.instance_id,
                    "storage.unavailable",
                    error.detail(),
                );
            }
        };
        let state = self
            .daemon
            .state()
            .map(|state| state.as_str())
            .unwrap_or("failed");
        let report = evidence_report(self.daemon.instance_id(), state, snapshot);
        json!({"ok":true,"instance_id":self.endpoint.instance_id,"report":report})
    }

    async fn begin_request(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let instance_id = self.endpoint.instance_id;
        let Some(spec) = object.get("spec") else {
            return error_response(instance_id, "invalid.request", "missing request spec");
        };
        let spec = match parse_request_spec(spec) {
            Ok(spec) => spec,
            Err(detail) => return error_response(instance_id, "invalid.request", &detail),
        };
        if spec.mcp_principal_id != authenticated.principal_id {
            return error_response(
                instance_id,
                "authorization.denied",
                "principal does not match authenticated control peer",
            );
        }
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

    async fn dispatch(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let instance_id = self.endpoint.instance_id;
        let Some(operation_id) = object
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            return error_response(instance_id, "invalid.request", "missing operation_id");
        };
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
        if request.mcp_principal_id != authenticated.principal_id {
            return error_response(
                instance_id,
                "authorization.denied",
                "principal does not match authenticated control peer",
            );
        }
        // A session belongs to the pairing that owned the browser profile when it
        // opened. This MUST be checked before `dispatch`, which crosses the browser
        // effect boundary: after that the operation is already `dispatching`.
        let active_pairing = self
            .channel
            .lock()
            .await
            .as_ref()
            .map(|channel| channel.pairing_id);
        if let Some(session_id) = operation.session_id {
            let owning_pairing = self
                .daemon
                .registry()
                .session(session_id)
                .ok()
                .flatten()
                .map(|record| record.pairing_id);
            if let (Some(owning), Some(active)) = (owning_pairing, active_pairing) {
                if owning != active {
                    return failure_response(instance_id, FailureCode::AuthorizationDenied);
                }
            }
        }
        if let Err(error) = self.daemon.dispatch(operation_id) {
            return lifecycle_response(instance_id, error);
        }
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
                if self
                    .daemon
                    .record_lost_boundary(operation_id, code)
                    .is_err()
                {
                    let _ = self.daemon.record_rejected_operation(operation_id, code);
                }
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

    fn read_request(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let id = object
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        match id.and_then(|id| self.daemon.registry().request(id).ok().flatten()) {
            Some(request) if request.mcp_principal_id == authenticated.principal_id => {
                json!({"ok":true,"instance_id":self.endpoint.instance_id,"request":request_value(&request)})
            }
            Some(_) => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "request belongs to another principal",
            ),
            None => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "request not found",
            ),
        }
    }
    fn read_session(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let id = object
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        match id.and_then(|id| self.daemon.registry().session(id).ok().flatten()) {
            Some(session) if session.mcp_principal_id == authenticated.principal_id => {
                json!({"ok":true,"instance_id":self.endpoint.instance_id,"session":session_value(&session)})
            }
            Some(_) => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "session belongs to another principal",
            ),
            None => error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "session not found",
            ),
        }
    }
    fn record_lost(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let id = object
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok());
        let code = object
            .get("code")
            .and_then(Value::as_str)
            .and_then(parse_failure)
            .unwrap_or(FailureCode::TargetLost);
        if let Some(operation_id) = id {
            let owned = self
                .daemon
                .registry()
                .operation(operation_id)
                .ok()
                .flatten()
                .and_then(|operation| {
                    self.daemon
                        .registry()
                        .request(operation.request_id)
                        .ok()
                        .flatten()
                })
                .is_some_and(|request| request.mcp_principal_id == authenticated.principal_id);
            if !owned {
                return error_response(
                    self.endpoint.instance_id,
                    "authorization.denied",
                    "operation belongs to another principal",
                );
            }
        }
        match id.and_then(|id| self.daemon.record_lost_boundary(id, code).ok()) {
            Some(()) => json!({"ok":true,"instance_id":self.endpoint.instance_id}),
            None => failure_response(self.endpoint.instance_id, code),
        }
    }
    fn commit_result(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
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
        let owned = self
            .daemon
            .registry()
            .operation(id)
            .ok()
            .flatten()
            .and_then(|operation| {
                self.daemon
                    .registry()
                    .request(operation.request_id)
                    .ok()
                    .flatten()
            })
            .is_some_and(|request| request.mcp_principal_id == authenticated.principal_id);
        if !owned {
            return error_response(
                self.endpoint.instance_id,
                "authorization.denied",
                "operation belongs to another principal",
            );
        }
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

    async fn tool_call(
        &self,
        object: &serde_json::Map<String, Value>,
        authenticated: AuthenticatedControl,
    ) -> Value {
        let name = object.get("name").and_then(Value::as_str).unwrap_or("");
        let arguments = object
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(body_principal) = object
            .get("principal_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        {
            if body_principal != authenticated.principal_id {
                return error_response(
                    self.endpoint.instance_id,
                    "authorization.denied",
                    "principal does not match authenticated control peer",
                );
            }
        }
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
        let principal = authenticated.principal_id;
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
                    .dispatch(
                        dispatch.as_object().expect("dispatch object"),
                        authenticated,
                    )
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
    let mut presented_one_time_key: Option<String> = None;
    let mut presented_pairing_id: Option<Uuid> = None;
    // Chrome terminates an idle MV3 service worker after roughly thirty seconds,
    // and only an incoming event resets that timer. A worker's own timers do not,
    // so the daemon heartbeats the channel to keep the extension alive between
    // operations. Without this the channel dies and every dispatch reports a
    // disconnected extension.
    let mut heartbeat = tokio::time::interval(EXTENSION_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if authenticated {
                    sink.send(Message::Text(json!({"type":"keepalive","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation_value,"correlation_id":Uuid::now_v7()}).to_string().into())).await.map_err(ws_io)?;
                }
            }
            outbound = receiver.recv() => { if let Some(frame) = outbound { if frame.get("channel_generation").and_then(Value::as_u64) == Some(generation_value) { sink.send(Message::Text(frame.to_string().into())).await.map_err(ws_io)?; } } else { break; } }
            inbound = source.next() => {
                let Some(Ok(message)) = inbound else { break; };
                let Message::Text(text) = message else { continue; };
                let Ok(frame) = serde_json::from_str::<Value>(&text) else { continue; };
                if frame.get("channel_generation").and_then(Value::as_u64) != Some(generation_value) {
                    continue;
                }
                match frame.get("type").and_then(Value::as_str) {
                    Some("pairing_hello") => {
                        let origin = frame.get("origin").and_then(Value::as_str).unwrap_or("");
                        if origin != EXTENSION_ORIGIN {
                            sink.send(Message::Text(pairing_rejected(
                                generation_value,
                                FailureCode::OriginRejected,
                            ).to_string().into())).await.map_err(ws_io)?;
                            break;
                        }
                        let Some(key) = frame.get("public_key").and_then(Value::as_str).and_then(decode_key_material) else {
                            sink.send(Message::Text(pairing_rejected(
                                generation_value,
                                FailureCode::AuthorizationDenied,
                            ).to_string().into())).await.map_err(ws_io)?;
                            break;
                        };
                        let client_fingerprint = frame.get("fingerprint").and_then(Value::as_str).unwrap_or("");
                        let fingerprint = hex_digest(&key);
                        if client_fingerprint != fingerprint {
                            sink.send(Message::Text(pairing_rejected(
                                generation_value,
                                FailureCode::AuthorizationDenied,
                            ).to_string().into())).await.map_err(ws_io)?;
                            break;
                        }
                        if let Some(one_time_key) = frame.get("one_time_key").and_then(Value::as_str) {
                            match service.auth.validate_extension_pairing(one_time_key, origin, now_ms()) {
                                Ok(()) => {
                                    presented_one_time_key = Some(one_time_key.to_owned());
                                    presented_pairing_id = None;
                                }
                                Err(control_auth::ExtensionEnrollmentError::OriginRejected) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::OriginRejected,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                                Err(control_auth::ExtensionEnrollmentError::AuthorizationDenied) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::AuthorizationDenied,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                                Err(control_auth::ExtensionEnrollmentError::StorageUnavailable) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::StorageUnavailable,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                            }
                        } else {
                            let Some(record) = service
                                .daemon
                                .registry()
                                .active_pairing_by_fingerprint(&fingerprint)
                                .ok()
                                .flatten()
                                .filter(|record| record.public_key == key)
                            else {
                                sink.send(Message::Text(pairing_rejected(
                                    generation_value,
                                    FailureCode::AuthorizationDenied,
                                ).to_string().into())).await.map_err(ws_io)?;
                                break;
                            };
                            presented_one_time_key = None;
                            presented_pairing_id = Some(record.pairing_id);
                        }
                        presented_key = Some(key);
                        presented_fingerprint = fingerprint;
                    }
                    Some("pairing_proof") if verify_extension_proof(presented_key.as_deref(), &presented_fingerprint, &challenge, &frame) => {
                        let pairing_id = if let Some(pairing_id) = presented_pairing_id {
                            pairing_id
                        } else {
                            let Some(one_time_key) = presented_one_time_key.as_deref() else {
                                sink.send(Message::Text(pairing_rejected(
                                    generation_value,
                                    FailureCode::AuthorizationDenied,
                                ).to_string().into())).await.map_err(ws_io)?;
                                break;
                            };
                            let pairing_id = Uuid::now_v7();
                            let Some(key) = presented_key.as_ref() else {
                                sink.send(Message::Text(pairing_rejected(
                                    generation_value,
                                    FailureCode::AuthorizationDenied,
                                ).to_string().into())).await.map_err(ws_io)?;
                                break;
                            };
                            let record = PairingRecord {
                                pairing_id,
                                extension_identity_id: Uuid::now_v7(),
                                origin: EXTENSION_ORIGIN.to_owned(),
                                public_key: key.clone(),
                                fingerprint: presented_fingerprint.clone(),
                                development_allowance: true,
                                status: "active".to_owned(),
                                created_at: now_ms(),
                                rotated_at: None,
                            };
                            match service.auth.commit_extension_pairing(
                                one_time_key,
                                EXTENSION_ORIGIN,
                                now_ms(),
                                service.daemon.registry(),
                                record,
                            ) {
                                Ok(pairing_id) => pairing_id,
                                Err(control_auth::ExtensionEnrollmentError::OriginRejected) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::OriginRejected,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                                Err(control_auth::ExtensionEnrollmentError::AuthorizationDenied) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::AuthorizationDenied,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                                Err(control_auth::ExtensionEnrollmentError::StorageUnavailable) => {
                                    sink.send(Message::Text(pairing_rejected(
                                        generation_value,
                                        FailureCode::StorageUnavailable,
                                    ).to_string().into())).await.map_err(ws_io)?;
                                    break;
                                }
                            }
                        };
                        authenticated = true;
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
                    Some("generation_changed") if authenticated => service.accept_generation_changed(frame).await,
                    Some("incarnation_lost") if authenticated => service.accept_incarnation_lost(frame, generation_value).await,
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
        let request_matches = frame
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            == Some(item.request_id);
        let session_matches = frame
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            == item.session_id;
        if !request_matches || !session_matches {
            let _ = item.result.send(Err(FailureCode::AuthorizationDenied));
            return;
        }
        if item.generation != generation {
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
        if code.is_none() && item.tab_incarnation.is_none() && item.document_generation.is_none() {
            if let Some(session_id) = item.session_id {
                let Some(tab_incarnation) = text("tab_incarnation") else {
                    let _ = item.result.send(Err(FailureCode::IncarnationStale));
                    return;
                };
                let Some(document_generation) = text("document_generation") else {
                    let _ = item.result.send(Err(FailureCode::GenerationStale));
                    return;
                };
                if self
                    .daemon
                    .registry()
                    .bind_session(session_id, tab_incarnation, document_generation)
                    .is_err()
                {
                    let _ = item.result.send(Err(FailureCode::TargetLost));
                    return;
                }
            }
        }
        let _ = item.result.send(if let Some(code) = code {
            Err(code)
        } else {
            Ok(outcome)
        });
    }
    async fn accept_generation_changed(&self, frame: Value) {
        let Some(session_id) = frame
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return;
        };
        let Some(tab_incarnation) = frame.get("tab_incarnation").and_then(Value::as_str) else {
            return;
        };
        let Some(document_generation) = frame.get("document_generation").and_then(Value::as_str)
        else {
            return;
        };
        let _ = self.daemon.registry().update_document_generation(
            session_id,
            tab_incarnation,
            document_generation.to_owned(),
        );
    }

    async fn accept_incarnation_lost(&self, frame: Value, generation: u64) {
        let Some(session_id) = frame
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return;
        };
        let lost_incarnation = frame.get("tab_incarnation").and_then(Value::as_str);
        // The extension reports a lost incarnation for an idle tab with no
        // operation in flight, so `operation_id` is absent. FR-029 still requires
        // the session's stale control state to be invalidated, otherwise a closed
        // tab stays reusable.
        let Some(operation_id) = frame
            .get("operation_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            if let Some(tab_incarnation) = lost_incarnation {
                let _ = self
                    .daemon
                    .registry()
                    .fail_session_incarnation(session_id, tab_incarnation);
            }
            return;
        };
        let mut pending = self.pending.lock().await;
        let Some(item) = pending.remove(&operation_id) else {
            return;
        };
        let tab_matches = lost_incarnation == item.tab_incarnation.as_deref();
        if item.generation != generation || item.session_id != Some(session_id) || !tab_matches {
            let _ = item.result.send(Err(FailureCode::GenerationStale));
            return;
        }
        drop(pending);
        // The tab backing this session is gone, so the session must not stay
        // usable for a later operation (FR-029).
        if let Some(tab_incarnation) = lost_incarnation {
            let _ = self
                .daemon
                .registry()
                .fail_session_incarnation(session_id, tab_incarnation);
        }
        let _ = self
            .daemon
            .record_lost_boundary(operation_id, FailureCode::TargetLost);
        let _ = item.result.send(Err(FailureCode::TargetLost));
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

fn evidence_report(
    instance_id: Uuid,
    daemon_state: &str,
    snapshot: crate::registry::RegistrySnapshot,
) -> Value {
    let principal_fingerprints = snapshot
        .principals
        .iter()
        .map(|principal| {
            json!({
                "identity_id": principal.identity_id,
                "kind": safe_principal_kind(&principal.kind),
                "fingerprint": hex_digest(principal.identity_id.as_bytes()),
            })
        })
        .collect::<Vec<_>>();
    let pairing_fingerprints = snapshot
        .pairings
        .iter()
        .map(|pairing| {
            json!({
                "pairing_id": pairing.pairing_id,
                "extension_identity_id": pairing.extension_identity_id,
                "fingerprint": redacted_fingerprint(&pairing.fingerprint),
            })
        })
        .collect::<Vec<_>>();
    let sessions = snapshot
        .sessions
        .iter()
        .map(|session| {
            json!({
                "session_id": session.session_id,
                "pairing_id": session.pairing_id,
                "tab_incarnation": session.tab_incarnation,
                "document_generation": session.document_generation,
                "state": session.state.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let tabs = snapshot
        .sessions
        .iter()
        .filter_map(|session| {
            session.tab_incarnation.as_ref().map(|tab| {
                json!({
                    "session_id": session.session_id,
                    "tab_incarnation": tab,
                    "document_generation": session.document_generation,
                })
            })
        })
        .collect::<Vec<_>>();
    let requests = snapshot
        .requests
        .iter()
        .map(|request| {
            json!({
                "request_id": request.request_id,
                "principal_id": request.mcp_principal_id,
                "tool": safe_tool_name(&request.tool),
                "fingerprint": redacted_fingerprint(&request.fingerprint),
                "state": request.state.as_str(),
                "failure_code": request.failure_code.map(|code| code.as_str()),
                "operations": request.operations.iter().map(report_operation_value).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let operations = snapshot
        .operations
        .iter()
        .map(|operation| {
            let failure_code = snapshot
                .requests
                .iter()
                .find(|request| request.request_id == operation.request_id)
                .and_then(|request| request.failure_code)
                .filter(|_| operation.state == OperationState::Failed)
                .map(|code| code.as_str());
            json!({
                "operation_id": operation.operation_id,
                "request_id": operation.request_id,
                "session_id": operation.session_id,
                "sequence": operation.sequence,
                "action_sequence": operation.action_sequence,
                "fingerprint": redacted_fingerprint(&operation.fingerprint),
                "state": operation.state.as_str(),
                "failure_code": failure_code,
            })
        })
        .collect::<Vec<_>>();
    let screenshot_artifacts = snapshot
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == "screenshot")
        .map(|artifact| {
            json!({
                "artifact_id": artifact.artifact_id,
                "operation_id": artifact.operation_id,
                "digest": artifact_digest(&artifact.digest),
                "byte_length": artifact.byte_length,
            })
        })
        .collect::<Vec<_>>();
    let resource_reads = snapshot
        .operations
        .iter()
        .filter_map(|operation| {
            let request = snapshot
                .requests
                .iter()
                .find(|request| request.request_id == operation.request_id)?;
            if !is_resource_read_tool(&request.tool) {
                return None;
            }
            Some(json!({
                "request_id": request.request_id,
                "operation_id": operation.operation_id,
                "tool": safe_tool_name(&request.tool),
                "action_sequence": operation.action_sequence,
                "state": operation.state.as_str(),
                "result": (operation.state == OperationState::Succeeded).then_some(json!({"status":"available"})),
                "failure_code": request.failure_code.map(|code| code.as_str()).filter(|_| operation.state == OperationState::Failed),
            }))
        })
        .collect::<Vec<_>>();
    let lost_boundary_operations = snapshot
        .operations
        .iter()
        .filter_map(|operation| {
            if operation.state != OperationState::Failed {
                return None;
            }
            let request = snapshot
                .requests
                .iter()
                .find(|request| request.request_id == operation.request_id)?;
            let code = request
                .failure_code
                .filter(|code| is_lost_boundary(*code))?;
            Some(json!({
                "operation_id": operation.operation_id,
                "request_id": operation.request_id,
                "action_sequence": operation.action_sequence,
                "state": "failed",
                "boundary_code": code.as_str(),
            }))
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": 1,
        "component_versions": {
            "matinee_cli": env!("CARGO_PKG_VERSION"),
            "matinee_daemon": env!("CARGO_PKG_VERSION"),
            "matinee_mcp": env!("CARGO_PKG_VERSION"),
            "control_protocol": CONTROL_PROTOCOL_VERSION,
            "extension_protocol": EXTENSION_PROTOCOL_VERSION,
        },
        "identity_fingerprints": {
            "principals": principal_fingerprints,
            "pairings": pairing_fingerprints,
        },
        "daemon": {
            "instance_id": instance_id,
            "fingerprint": hex_digest(instance_id.as_bytes()),
            "state": daemon_state,
        },
        "sessions": sessions,
        "tabs": tabs,
        "requests": requests,
        "operations": operations,
        "artifacts": screenshot_artifacts,
        "resource_reads": resource_reads,
        "lost_boundary": {
            "observed": !lost_boundary_operations.is_empty(),
            "operations": lost_boundary_operations,
        },
    })
}

fn report_operation_value(operation: &crate::registry::OperationRecord) -> Value {
    json!({
        "operation_id": operation.operation_id,
        "session_id": operation.session_id,
        "sequence": operation.sequence,
        "action_sequence": operation.action_sequence,
        "state": operation.state.as_str(),
    })
}
fn safe_principal_kind(kind: &str) -> &'static str {
    match kind {
        "native" | "native_admin" => "native_admin",
        "mcp" | "mcp_client" => "mcp_client",
        "extension" => "extension",
        _ => "other",
    }
}

fn safe_tool_name(tool: &str) -> &'static str {
    match tool {
        "browser_list" => "browser_list",
        "session_open" => "session_open",
        "session_get" => "session_get",
        "session_close" => "session_close",
        "page_observe" => "page_observe",
        "page_navigate" => "page_navigate",
        "element_click" => "element_click",
        "element_type" => "element_type",
        "page_screenshot" => "page_screenshot",
        "request_get" => "request_get",
        _ => "other",
    }
}

fn is_resource_read_tool(tool: &str) -> bool {
    matches!(tool, "session_get" | "page_observe" | "request_get")
}

fn is_lost_boundary(code: FailureCode) -> bool {
    matches!(
        code,
        FailureCode::ExtensionDisconnected | FailureCode::TargetLost | FailureCode::DeadlineExpired
    )
}

fn redacted_fingerprint(value: &str) -> String {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        value.to_owned()
    } else {
        hex_digest(value.as_bytes())
    }
}

fn artifact_digest(value: &str) -> String {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return format!("sha256:{}", hex_digest(value.as_bytes()));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        value.to_owned()
    } else {
        format!("sha256:{}", hex_digest(value.as_bytes()))
    }
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

/// Length of an uncompressed P-256 public key, which both encodings must yield.
const RAW_P256_KEY_LEN: usize = 65;

/// Decodes an uncompressed P-256 public key from base64url or hex.
///
/// Every lowercase hex string is also valid base64url, so trying one then the
/// other silently produces the wrong bytes for a hex input. The two encodings of
/// a 65-byte key have different lengths, so the decoded length disambiguates
/// them: only a candidate that yields exactly 65 bytes is accepted.
///
/// The extension sends base64url. Hex is accepted because an operator may paste a
/// key that way.
fn decode_key_material(value: &str) -> Option<Vec<u8>> {
    let correct_length = |bytes: &Vec<u8>| bytes.len() == RAW_P256_KEY_LEN;
    decode_hex(value)
        .filter(correct_length)
        .or_else(|| decode_base64_url(value).filter(correct_length))
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

fn pairing_rejected(generation: u64, code: FailureCode) -> Value {
    json!({
        "type": "pairing_rejected",
        "protocol_version": EXTENSION_PROTOCOL_VERSION,
        "channel_generation": generation,
        "correlation_id": Uuid::now_v7(),
        "failure": {"code": code.as_str()},
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut encoded = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
#[cfg(test)]
mod tests {
    use super::{
        AuthenticatedControl, EXTENSION_CHANNEL_PATH, EXTENSION_ORIGIN, EXTENSION_PROTOCOL_VERSION,
        Service, decode_key_material, evidence_report, serve_extensions, verify_extension_proof,
    };
    use crate::lifecycle::Daemon;
    use crate::registry::{BeginRequestResult, OperationSpec, RequestSpec, SessionSpec};
    use futures_util::{SinkExt, StreamExt};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::Value;
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::tungstenite::{Message, http::Request as ClientRequest};
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
    use uuid::Uuid;

    fn base64_url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut encoded = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0_u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            let digits = chunk.len() + 1;
            for index in 0..digits {
                let shift = 18 - index * 6;
                encoded.push(ALPHABET[((value >> shift) & 0x3f) as usize] as char);
            }
        }
        encoded
    }

    /// The extension encodes its key and signature as base64url. A daemon that
    /// only parsed hex rejected every real handshake before verification, so this
    /// pins the wire encoding both sides actually use.
    #[test]
    fn a_base64url_extension_proof_verifies() {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate signing key");
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .expect("load signing key");
        let public_key = pair.public_key().as_ref().to_vec();
        assert_eq!(public_key.len(), 65, "raw P-256 keys are 65 bytes");

        let fingerprint = "a".repeat(64);
        let challenge = "1758400000000-01a0c000-0000-7000-8000-000000000000";
        let transcript = format!(
            "matinee.browser.pairing.v1\0{}\0{}\0{}",
            EXTENSION_ORIGIN, fingerprint, challenge
        );
        let signature = pair
            .sign(&rng, transcript.as_bytes())
            .expect("sign transcript");

        let encoded_key = base64_url(&public_key);
        assert_eq!(
            decode_key_material(&encoded_key).as_deref(),
            Some(public_key.as_slice()),
            "the daemon must decode the encoding the extension sends"
        );

        // Lowercase hex is also valid base64url, so a decoder that tried base64url
        // first would decode a hex key to the wrong bytes and never reach hex.
        let hex_key: String = public_key
            .iter()
            .flat_map(|byte| {
                const DIGITS: &[u8; 16] = b"0123456789abcdef";
                [
                    DIGITS[usize::from(byte >> 4)] as char,
                    DIGITS[usize::from(byte & 0x0f)] as char,
                ]
            })
            .collect();
        assert_eq!(
            decode_key_material(&hex_key).as_deref(),
            Some(public_key.as_slice()),
            "a 130-character lowercase hex key must decode to the same 65 bytes"
        );
        assert_eq!(hex_key.len(), 130, "65 bytes are 130 hex characters");
        assert_ne!(hex_key, encoded_key, "the two encodings differ");

        let frame = json!({"signature": base64_url(signature.as_ref())});
        assert!(verify_extension_proof(
            decode_key_material(&encoded_key).as_deref(),
            &fingerprint,
            challenge,
            &frame
        ));

        let wrong = json!({"signature": base64_url(&[7_u8; 64])});
        assert!(
            !verify_extension_proof(
                decode_key_material(&encoded_key).as_deref(),
                &fingerprint,
                challenge,
                &wrong
            ),
            "a wrong signature must not verify"
        );
    }
    #[test]
    fn failed_proof_leaves_enrollment_usable_and_unregistered() {
        let state_dir =
            std::env::temp_dir().join(format!("matinee-pairing-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&state_dir).expect("create state directory");
        let auth = super::control_auth::ControlAuth::create("127.0.0.1:0", &state_dir)
            .expect("create control auth");
        let registry = crate::registry::Registry::new();
        let details = auth
            .extension_pairing_details()
            .expect("enrollment details");
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate signing key");
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .expect("load signing key");
        let key = pair.public_key().as_ref().to_vec();
        let fingerprint = super::hex_digest(&key);
        let challenge = "test-challenge";
        let wrong = json!({"signature": base64_url(&[7_u8; 64])});
        assert!(!verify_extension_proof(
            Some(&key),
            &fingerprint,
            challenge,
            &wrong
        ));
        assert!(
            registry
                .active_pairing_by_fingerprint(&fingerprint)
                .expect("read pairings")
                .is_none()
        );
        auth.validate_extension_pairing(&details.one_time_key, EXTENSION_ORIGIN, i64::MIN)
            .expect("failed proof must not consume the token");
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn valid_proof_commits_enrollment_and_allows_reconnect_lookup() {
        let state_dir =
            std::env::temp_dir().join(format!("matinee-pairing-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&state_dir).expect("create state directory");
        let auth = super::control_auth::ControlAuth::create("127.0.0.1:0", &state_dir)
            .expect("create control auth");
        let registry = crate::registry::Registry::new();
        let details = auth
            .extension_pairing_details()
            .expect("enrollment details");
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate signing key");
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .expect("load signing key");
        let key = pair.public_key().as_ref().to_vec();
        let fingerprint = super::hex_digest(&key);
        let challenge = "test-challenge";
        let transcript = format!(
            "matinee.browser.pairing.v1\0{}\0{}\0{}",
            EXTENSION_ORIGIN, fingerprint, challenge
        );
        let signature = pair
            .sign(&rng, transcript.as_bytes())
            .expect("sign transcript");
        let proof = json!({"signature": base64_url(signature.as_ref())});
        assert!(verify_extension_proof(
            Some(&key),
            &fingerprint,
            challenge,
            &proof
        ));
        let pairing_id = Uuid::now_v7();
        let committed = auth
            .commit_extension_pairing(
                &details.one_time_key,
                EXTENSION_ORIGIN,
                i64::MIN,
                &registry,
                crate::registry::PairingRecord {
                    pairing_id,
                    extension_identity_id: Uuid::now_v7(),
                    origin: EXTENSION_ORIGIN.to_owned(),
                    public_key: key.clone(),
                    fingerprint: fingerprint.clone(),
                    development_allowance: true,
                    status: "active".to_owned(),
                    created_at: 0,
                    rotated_at: None,
                },
            )
            .expect("commit pairing after proof");
        assert_eq!(committed, pairing_id);
        assert_eq!(
            registry
                .active_pairing_by_fingerprint(&fingerprint)
                .expect("read pairings")
                .expect("committed pairing")
                .public_key,
            key
        );
        assert!(
            auth.validate_extension_pairing(&details.one_time_key, EXTENSION_ORIGIN, i64::MIN)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }
    #[tokio::test]
    async fn wrong_generation_cannot_enroll_or_authenticate() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::{connect_async, tungstenite::http::Request as ClientRequest};

        let state_dir =
            std::env::temp_dir().join(format!("matinee-generation-test-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&state_dir).expect("create state directory");
        let daemon =
            std::sync::Arc::new(crate::lifecycle::Daemon::start(&state_dir).expect("start daemon"));
        let auth = std::sync::Arc::new(
            super::control_auth::ControlAuth::create("127.0.0.1:0", &state_dir)
                .expect("create control auth"),
        );
        auth.register(daemon.registry()).expect("register controls");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind extension listener");
        let address = listener.local_addr().expect("extension address");
        let endpoint = super::Endpoint {
            instance_id: daemon.instance_id(),
            control_addr: "127.0.0.1:0".to_owned(),
            extension_addr: format!(
                "ws://127.0.0.1:{}{}",
                address.port(),
                super::EXTENSION_CHANNEL_PATH
            ),
            extension_path: super::EXTENSION_CHANNEL_PATH.to_owned(),
            credential_path: auth.handoff_path().display().to_string(),
        };
        let service = super::Service {
            daemon: daemon.clone(),
            auth: auth.clone(),
            endpoint,
            pending: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            channel: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            next_generation: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
            stop: std::sync::Arc::new(tokio::sync::Mutex::new(false)),
        };
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept extension");
            super::handle_extension(stream, server_service).await
        });
        let request = ClientRequest::builder()
            .uri(format!(
                "ws://127.0.0.1:{}{}",
                address.port(),
                super::EXTENSION_CHANNEL_PATH
            ))
            .header("Host", format!("127.0.0.1:{}", address.port()))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Origin", super::EXTENSION_ORIGIN)
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", super::EXTENSION_PROTOCOL_VERSION)
            .body(())
            .expect("websocket request");
        let (mut client, _) = connect_async(request).await.expect("connect extension");
        let Some(Ok(Message::Text(challenge))) = client.next().await else {
            panic!("daemon did not send challenge");
        };
        let challenge: Value = serde_json::from_str(&challenge).expect("challenge JSON");
        let generation = challenge
            .get("channel_generation")
            .and_then(Value::as_u64)
            .expect("challenge generation");
        let details = auth
            .extension_pairing_details()
            .expect("enrollment details");
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate signing key");
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                .expect("load signing key");
        let key = pair.public_key().as_ref().to_vec();
        let fingerprint = super::hex_digest(&key);
        let challenge_text = challenge
            .get("challenge")
            .and_then(Value::as_str)
            .expect("challenge text");
        let transcript = format!(
            "matinee.browser.pairing.v1\0{}\0{}\0{}",
            EXTENSION_ORIGIN, fingerprint, challenge_text
        );
        let signature = pair
            .sign(&rng, transcript.as_bytes())
            .expect("sign transcript");
        let stale_generation = generation + 1;
        let stale = json!({
            "type": "pairing_hello",
            "channel_generation": stale_generation,
            "origin": EXTENSION_ORIGIN,
            "one_time_key": details.one_time_key.clone(),
            "public_key": base64_url(&key),
            "fingerprint": fingerprint,
        });
        client
            .send(Message::Text(stale.to_string().into()))
            .await
            .expect("send stale hello");
        client
            .send(Message::Text(
                json!({
                    "type": "pairing_proof",
                    "channel_generation": stale_generation,
                    "signature": base64_url(signature.as_ref()),
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("send stale proof");
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            daemon
                .registry()
                .active_pairing_by_fingerprint(&fingerprint)
                .expect("read pairings")
                .is_none()
        );
        assert!(
            auth.validate_extension_pairing(&details.one_time_key, EXTENSION_ORIGIN, i64::MIN)
                .is_ok()
        );
        assert!(service.channel.lock().await.is_none());
        client.close(None).await.expect("close extension");
        server
            .await
            .expect("join extension server")
            .expect("serve extension");
        let _ = daemon.stop();
        let _ = std::fs::remove_dir_all(state_dir);
    }
    #[test]
    fn fresh_evidence_report_has_stable_empty_collections() {
        let report = evidence_report(
            Uuid::now_v7(),
            "ready",
            crate::registry::Registry::new()
                .snapshot()
                .expect("empty registry snapshot"),
        );
        assert_eq!(report.get("schema_version"), Some(&json!(1)));
        for field in [
            "sessions",
            "tabs",
            "requests",
            "operations",
            "artifacts",
            "resource_reads",
        ] {
            assert_eq!(
                report.get(field).and_then(Value::as_array).map(Vec::len),
                Some(0),
                "{field}"
            );
        }
        assert_eq!(
            report
                .get("lost_boundary")
                .and_then(|value| value.get("operations"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn evidence_report_redacts_seeded_secret_values() {
        let registry = crate::registry::Registry::new();
        let secret = "FR058-SECRET-MARKER";
        registry
            .insert_principal(crate::registry::PrincipalRecord {
                identity_id: Uuid::now_v7(),
                kind: "mcp_client".to_owned(),
                credential_reference: secret.to_owned(),
                epoch: 1,
                status: "active".to_owned(),
                created_at: 0,
            })
            .expect("insert principal");
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        registry
            .begin_request(crate::registry::RequestSpec {
                request_id,
                mcp_principal_id: Uuid::now_v7(),
                tool: secret.to_owned(),
                idempotency_key: secret.to_owned(),
                fingerprint: secret.to_owned(),
                deadline_ms: 1,
                effect_hint: secret.to_owned(),
                operations: vec![crate::registry::OperationSpec {
                    operation_id,
                    sequence: 0,
                    session_id: None,
                    target_descriptor: secret.to_owned(),
                    fingerprint: secret.to_owned(),
                    state: crate::record::OperationState::Planned,
                    session: None,
                }],
            })
            .expect("insert request");
        registry
            .prepare_dispatch(operation_id)
            .expect("prepare operation");
        registry
            .mark_dispatched(operation_id)
            .expect("dispatch operation");
        registry
            .commit_terminal_result(
                operation_id,
                crate::registry::TerminalResult {
                    operation_state: crate::record::OperationState::Succeeded,
                    request_state: crate::record::RequestState::Succeeded,
                    result: Some(secret.to_owned()),
                    failure_code: None,
                },
            )
            .expect("commit operation");
        let report = evidence_report(
            Uuid::now_v7(),
            "ready",
            registry.snapshot().expect("registry snapshot"),
        );
        assert!(!report.to_string().contains(secret));
    }

    #[test]
    fn lost_boundary_evidence_keeps_failed_operation_and_boundary_code() {
        let registry = crate::registry::Registry::new();
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        registry
            .begin_request(crate::registry::RequestSpec {
                request_id,
                mcp_principal_id: Uuid::now_v7(),
                tool: "element_click".to_owned(),
                idempotency_key: Uuid::now_v7().to_string(),
                fingerprint: "safe-fingerprint".to_owned(),
                deadline_ms: 1,
                effect_hint: "mutate".to_owned(),
                operations: vec![crate::registry::OperationSpec {
                    operation_id,
                    sequence: 0,
                    session_id: None,
                    target_descriptor: "{}".to_owned(),
                    fingerprint: "safe-operation-fingerprint".to_owned(),
                    state: crate::record::OperationState::Planned,
                    session: None,
                }],
            })
            .expect("insert request");
        registry
            .prepare_dispatch(operation_id)
            .expect("prepare operation");
        registry
            .mark_dispatched(operation_id)
            .expect("dispatch operation");
        registry
            .record_lost_boundary(
                operation_id,
                crate::failure::FailureCode::ExtensionDisconnected,
            )
            .expect("record lost boundary");
        let report = evidence_report(
            Uuid::now_v7(),
            "ready",
            registry.snapshot().expect("registry snapshot"),
        );
        let lost = report
            .get("lost_boundary")
            .and_then(|value| value.get("operations"))
            .and_then(Value::as_array)
            .expect("lost boundary operation list");
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].get("state"), Some(&json!("failed")));
        assert_eq!(
            lost[0].get("boundary_code"),
            Some(&json!("operation.extension_disconnected"))
        );
    }

    type TestSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

    struct TestExtensionClient {
        socket: TestSocket,
        generation: u64,
        bindings: HashMap<Uuid, (String, String)>,
    }

    impl TestExtensionClient {
        async fn connect(address: SocketAddr, auth: &super::control_auth::ControlAuth) -> Self {
            let request = ClientRequest::builder()
                .uri(format!(
                    "ws://127.0.0.1:{}{}",
                    address.port(),
                    EXTENSION_CHANNEL_PATH
                ))
                .header("Host", format!("127.0.0.1:{}", address.port()))
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Origin", EXTENSION_ORIGIN)
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Protocol", EXTENSION_PROTOCOL_VERSION)
                .body(())
                .expect("websocket request");
            let (mut socket, _) = connect_async(request).await.expect("connect extension");
            let challenge = loop {
                let message = socket
                    .next()
                    .await
                    .expect("challenge frame")
                    .expect("challenge message");
                if let Message::Text(text) = message {
                    break serde_json::from_str::<Value>(&text).expect("challenge JSON");
                }
            };
            let generation = challenge["channel_generation"]
                .as_u64()
                .expect("challenge generation");
            let challenge_text = challenge["challenge"].as_str().expect("challenge text");
            let details = auth
                .extension_pairing_details()
                .expect("enrollment details");
            let rng = SystemRandom::new();
            let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate key");
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                    .expect("load key");
            let key = pair.public_key().as_ref().to_vec();
            let fingerprint = super::hex_digest(&key);
            socket.send(Message::Text(json!({"type":"pairing_hello","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation,"origin":EXTENSION_ORIGIN,"one_time_key":details.one_time_key,"public_key":base64_url(&key),"fingerprint":fingerprint}).to_string().into())).await.expect("send hello");
            let transcript = format!(
                "matinee.browser.pairing.v1\0{}\0{}\0{}",
                EXTENSION_ORIGIN, fingerprint, challenge_text
            );
            let signature = pair
                .sign(&rng, transcript.as_bytes())
                .expect("sign transcript");
            socket.send(Message::Text(json!({"type":"pairing_proof","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":generation,"signature":base64_url(signature.as_ref())}).to_string().into())).await.expect("send proof");
            let accepted = loop {
                let message = socket
                    .next()
                    .await
                    .expect("pairing response")
                    .expect("pairing message");
                if let Message::Text(text) = message {
                    break serde_json::from_str::<Value>(&text).expect("pairing JSON");
                }
            };
            assert_eq!(accepted["type"], json!("pairing_accepted"));
            Self {
                socket,
                generation,
                bindings: HashMap::new(),
            }
        }
        /// Reads the next command, skipping heartbeats.
        ///
        /// The daemon heartbeats an authenticated channel to keep Chrome from
        /// stopping the extension's service worker, so a real client must
        /// tolerate those frames arriving between commands.
        async fn next_command(&mut self) -> Value {
            loop {
                let message = timeout(Duration::from_secs(5), self.socket.next())
                    .await
                    .expect("command timeout")
                    .expect("command frame")
                    .expect("command message");
                let Message::Text(text) = message else {
                    panic!("expected text command")
                };
                let frame: Value = serde_json::from_str(&text).expect("command JSON");
                if frame["type"] == json!("keepalive") {
                    continue;
                }
                return frame;
            }
        }
        async fn send(&mut self, frame: Value) {
            self.socket
                .send(Message::Text(frame.to_string().into()))
                .await
                .expect("send extension frame");
        }
        fn result_for(
            &self,
            command: &Value,
            session_id: Value,
            tab: Value,
            document: Value,
        ) -> Value {
            json!({"type":"result","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":self.generation,"correlation_id":command["correlation_id"],"operation_id":command["operation_id"],"request_id":command["request_id"],"session_id":session_id,"tab_incarnation":tab,"document_generation":document,"outcome":{"status":"succeeded","value":{"observed":true}}})
        }
        async fn reply_success(&mut self, command: &Value) {
            let session_id = command["session_id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok());
            let (tab, document) = if command["type"] == json!("bind_session") {
                let session_id = session_id.expect("bind session identity");
                self.bindings
                    .entry(session_id)
                    .or_insert_with(|| {
                        (
                            format!("incarnation-{session_id}"),
                            format!("document-{session_id}"),
                        )
                    })
                    .clone()
            } else {
                (
                    command["tab_incarnation"].as_str().unwrap_or("").to_owned(),
                    command["document_generation"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                )
            };
            let frame = self.result_for(
                command,
                command["session_id"].clone(),
                json!(tab),
                json!(document),
            );
            self.send(frame).await;
        }
    }

    struct TestHarness {
        daemon: Arc<Daemon>,
        auth: Arc<super::control_auth::ControlAuth>,
        service: Service,
        principal_id: Uuid,
        pairing_id: Uuid,
        client: TestExtensionClient,
        server: JoinHandle<io::Result<()>>,
        state_dir: std::path::PathBuf,
    }

    impl TestHarness {
        async fn new() -> Self {
            let state_dir =
                std::env::temp_dir().join(format!("matinee-extension-protocol-{}", Uuid::now_v7()));
            fs::create_dir_all(&state_dir).expect("create state directory");
            let daemon = Arc::new(Daemon::start(&state_dir).expect("start daemon"));
            let auth = Arc::new(
                super::control_auth::ControlAuth::create("127.0.0.1:0", &state_dir)
                    .expect("create control auth"),
            );
            auth.register(daemon.registry())
                .expect("register control principals");
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("bind extension listener");
            let address = listener.local_addr().expect("extension address");
            let service = Service {
                daemon: daemon.clone(),
                auth: auth.clone(),
                endpoint: super::Endpoint {
                    instance_id: daemon.instance_id(),
                    control_addr: "127.0.0.1:0".to_owned(),
                    extension_addr: format!(
                        "ws://127.0.0.1:{}{}",
                        address.port(),
                        EXTENSION_CHANNEL_PATH
                    ),
                    extension_path: EXTENSION_CHANNEL_PATH.to_owned(),
                    credential_path: auth.handoff_path().display().to_string(),
                },
                pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                channel: Arc::new(tokio::sync::Mutex::new(None)),
                next_generation: Arc::new(tokio::sync::Mutex::new(0)),
                stop: Arc::new(tokio::sync::Mutex::new(false)),
            };
            let server = tokio::spawn(serve_extensions(listener, service.clone()));
            let client = TestExtensionClient::connect(address, &auth).await;
            let pairing_id = daemon
                .registry()
                .snapshot()
                .expect("registry snapshot")
                .pairings[0]
                .pairing_id;
            Self {
                principal_id: auth.native.id().get(),
                daemon,
                auth,
                service,
                pairing_id,
                client,
                server,
                state_dir,
            }
        }
        async fn shutdown(&mut self) {
            let _ = self.client.socket.close(None).await;
            self.server.abort();
            let _ = (&mut self.server).await;
            let _ = self.daemon.stop();
            let _ = self.auth.remove_handoff();
            let _ = fs::remove_dir_all(&self.state_dir);
        }
    }

    fn admit_operation(
        harness: &TestHarness,
        session_id: Uuid,
        tool: &str,
        target: Value,
    ) -> (Uuid, Uuid) {
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let result = harness
            .daemon
            .registry()
            .begin_request(RequestSpec {
                request_id,
                mcp_principal_id: harness.principal_id,
                tool: tool.to_owned(),
                idempotency_key: request_id.to_string(),
                fingerprint: operation_id.to_string(),
                deadline_ms: super::now_ms() + 30_000,
                effect_hint: if tool == "element_click" {
                    "mutate"
                } else {
                    "read"
                }
                .to_owned(),
                operations: vec![OperationSpec {
                    operation_id,
                    sequence: 0,
                    session_id: Some(session_id),
                    target_descriptor: serde_json::to_string(&target).expect("target JSON"),
                    fingerprint: operation_id.to_string(),
                    state: crate::record::OperationState::Planned,
                    session: (tool == "session_open").then(|| SessionSpec {
                        session_id,
                        mcp_principal_id: harness.principal_id,
                        pairing_id: harness.pairing_id,
                        browser: "chromium".to_owned(),
                        profile: "fixture".to_owned(),
                        window: "fixture-window".to_owned(),
                    }),
                }],
            })
            .expect("admit operation");
        assert!(matches!(result, BeginRequestResult::Created(_)));
        (request_id, operation_id)
    }
    fn spawn_dispatch(harness: &TestHarness, operation_id: Uuid) -> JoinHandle<Value> {
        let service = harness.service.clone();
        let authenticated = AuthenticatedControl {
            principal_id: harness.principal_id,
        };
        tokio::spawn(async move {
            service
                .dispatch(
                    json!({"operation_id":operation_id}).as_object().unwrap(),
                    authenticated,
                )
                .await
        })
    }
    async fn bind(harness: &mut TestHarness, session_id: Uuid) {
        let (_, operation_id) = admit_operation(harness, session_id, "session_open", json!({}));
        let task = spawn_dispatch(harness, operation_id);
        let command = harness.client.next_command().await;
        assert_eq!(command["type"], json!("bind_session"));
        harness.client.reply_success(&command).await;
        assert_eq!(task.await.expect("bind dispatch")["ok"], json!(true));
    }

    #[tokio::test]
    async fn authenticated_extension_protocol_proves_session_aware_routing_and_boundaries() {
        let mut harness = TestHarness::new().await;
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        bind(&mut harness, a).await;
        bind(&mut harness, b).await;
        assert_ne!(harness.client.bindings[&a], harness.client.bindings[&b]);
        assert_eq!(
            harness.daemon.registry().session(a).unwrap().unwrap().state,
            crate::record::SessionState::Active
        );
        assert_eq!(
            harness.daemon.registry().session(b).unwrap().unwrap().state,
            crate::record::SessionState::Active
        );
        for index in 0..50 {
            let session_id = if index % 2 == 0 { a } else { b };
            let (_, operation_id) = admit_operation(
                &harness,
                session_id,
                "page_observe",
                json!({"reference":format!("ref-{index}")}),
            );
            let task = spawn_dispatch(&harness, operation_id);
            let command = harness.client.next_command().await;
            let session_text = session_id.to_string();
            let expected = &harness.client.bindings[&session_id];
            assert_eq!(command["session_id"].as_str(), Some(session_text.as_str()));
            assert_eq!(
                command["tab_incarnation"].as_str(),
                Some(expected.0.as_str())
            );
            assert_eq!(
                command["document_generation"].as_str(),
                Some(expected.1.as_str())
            );
            harness.client.reply_success(&command).await;
            assert_eq!(task.await.unwrap()["ok"], json!(true));
        }
        let c = Uuid::now_v7();
        let d = Uuid::now_v7();
        let e = Uuid::now_v7();
        bind(&mut harness, c).await;
        bind(&mut harness, d).await;
        bind(&mut harness, e).await;
        let (_, op_c) = admit_operation(&harness, c, "page_observe", json!({}));
        let task_c = spawn_dispatch(&harness, op_c);
        let command_c = harness.client.next_command().await;
        let cross = harness
            .client
            .result_for(&command_c, json!(d), json!("wrong"), json!("wrong"));
        harness.client.send(cross).await;
        assert_eq!(task_c.await.unwrap()["code"], json!("authorization.denied"));
        assert_eq!(
            harness
                .daemon
                .registry()
                .operation(op_c)
                .unwrap()
                .unwrap()
                .state,
            crate::record::OperationState::Failed
        );
        let (_, op_d) = admit_operation(&harness, d, "page_observe", json!({}));
        let task_d = spawn_dispatch(&harness, op_d);
        let command_d = harness.client.next_command().await;
        let stale_incarnation = harness.client.result_for(
            &command_d,
            json!(d),
            json!("superseded"),
            command_d["document_generation"].clone(),
        );
        harness.client.send(stale_incarnation).await;
        assert_eq!(task_d.await.unwrap()["code"], json!("incarnation.stale"));
        let (_, op_e) = admit_operation(&harness, e, "page_observe", json!({}));
        let task_e = spawn_dispatch(&harness, op_e);
        let command_e = harness.client.next_command().await;
        let stale_generation = harness.client.result_for(
            &command_e,
            json!(e),
            command_e["tab_incarnation"].clone(),
            json!("stale-document"),
        );
        harness.client.send(stale_generation).await;
        assert_eq!(task_e.await.unwrap()["code"], json!("generation.stale"));
        let f = Uuid::now_v7();
        let g = Uuid::now_v7();
        bind(&mut harness, f).await;
        bind(&mut harness, g).await;
        let old = harness.client.bindings[&f].1.clone();
        let new = format!("{old}-next");
        let f_tab = harness.client.bindings[&f].0.clone();
        harness.client.send(json!({"type":"generation_changed","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":harness.client.generation,"correlation_id":Uuid::now_v7(),"session_id":f,"tab_incarnation":f_tab,"previous_document_generation":old,"document_generation":new})).await;
        timeout(Duration::from_secs(5), async {
            loop {
                if harness
                    .daemon
                    .registry()
                    .session(f)
                    .unwrap()
                    .unwrap()
                    .document_generation
                    .as_deref()
                    == Some(new.as_str())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("generation update");
        harness.client.bindings.get_mut(&f).unwrap().1 = new.clone();
        let (_, op_f) =
            admit_operation(&harness, f, "element_click", json!({"reference":"old-ref"}));
        let task_f = spawn_dispatch(&harness, op_f);
        let command_f = harness.client.next_command().await;
        assert_eq!(command_f["document_generation"], json!(new));
        let stale_reference = harness.client.result_for(
            &command_f,
            json!(f),
            command_f["tab_incarnation"].clone(),
            json!(old),
        );
        harness.client.send(stale_reference).await;
        assert_eq!(task_f.await.unwrap()["code"], json!("generation.stale"));
        let (_, op_g) = admit_operation(&harness, g, "element_click", json!({}));
        let task_g = spawn_dispatch(&harness, op_g);
        let command_g = harness.client.next_command().await;
        harness.client.reply_success(&command_g).await;
        assert_eq!(task_g.await.unwrap()["ok"], json!(true));
        let h = Uuid::now_v7();
        let i = Uuid::now_v7();
        bind(&mut harness, h).await;
        bind(&mut harness, i).await;
        let (_, op_h) = admit_operation(&harness, h, "element_click", json!({}));
        let task_h = spawn_dispatch(&harness, op_h);
        let command_h = harness.client.next_command().await;
        harness.client.send(json!({"type":"incarnation_lost","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":harness.client.generation,"correlation_id":Uuid::now_v7(),"operation_id":op_h,"request_id":command_h["request_id"],"session_id":h,"tab_incarnation":command_h["tab_incarnation"],"document_generation":command_h["document_generation"],"boundary":"tab"})).await;
        assert_eq!(
            task_h.await.unwrap()["code"],
            json!("operation.target_lost")
        );
        let (_, op_i) = admit_operation(&harness, i, "element_click", json!({}));
        let task_i = spawn_dispatch(&harness, op_i);
        let command_i = harness.client.next_command().await;
        harness.client.reply_success(&command_i).await;
        assert_eq!(task_i.await.unwrap()["ok"], json!(true));
        let j = Uuid::now_v7();
        let k = Uuid::now_v7();
        bind(&mut harness, j).await;
        bind(&mut harness, k).await;
        let (_, op_j) = admit_operation(&harness, j, "element_click", json!({}));
        let (_, op_k) = admit_operation(&harness, k, "element_click", json!({}));
        let task_j = spawn_dispatch(&harness, op_j);
        let task_k = spawn_dispatch(&harness, op_k);
        let command_j = harness.client.next_command().await;
        let command_k = harness.client.next_command().await;
        assert_eq!(command_j["session_id"], json!(j));
        assert_eq!(command_k["session_id"], json!(k));
        let _ = harness.client.socket.close(None).await;
        assert_eq!(
            task_j.await.unwrap()["code"],
            json!("operation.extension_disconnected")
        );
        assert_eq!(
            task_k.await.unwrap()["code"],
            json!("operation.extension_disconnected")
        );
        assert_eq!(harness.daemon.registry().dispatching_count().unwrap(), 0);
        assert!(harness.daemon.registry().operation(op_j).unwrap().is_some());
        assert!(harness.daemon.registry().operation(op_k).unwrap().is_some());
        harness.server.abort();
        let _ = (&mut harness.server).await;
        let _ = harness.daemon.stop();
        let _ = harness.auth.remove_handoff();
        let _ = fs::remove_dir_all(&harness.state_dir);
        let mut second = TestHarness::new().await;
        let blocked = Uuid::now_v7();
        let healthy = Uuid::now_v7();
        bind(&mut second, blocked).await;
        bind(&mut second, healthy).await;
        let (_, boundary_op) = admit_operation(&second, blocked, "element_click", json!({}));
        let boundary_task = spawn_dispatch(&second, boundary_op);
        let boundary_command = second.client.next_command().await;
        second.client.send(json!({"type":"incarnation_lost","protocol_version":EXTENSION_PROTOCOL_VERSION,"channel_generation":second.client.generation,"correlation_id":Uuid::now_v7(),"operation_id":boundary_op,"request_id":boundary_command["request_id"],"session_id":blocked,"tab_incarnation":boundary_command["tab_incarnation"],"document_generation":boundary_command["document_generation"],"boundary":"tab"})).await;
        assert_eq!(
            boundary_task.await.unwrap()["code"],
            json!("operation.target_lost")
        );
        let request_id = Uuid::now_v7();
        let conflict_operation = Uuid::now_v7();
        let error = second
            .daemon
            .registry()
            .begin_request(RequestSpec {
                request_id,
                mcp_principal_id: second.principal_id,
                tool: "element_click".to_owned(),
                idempotency_key: request_id.to_string(),
                fingerprint: conflict_operation.to_string(),
                deadline_ms: super::now_ms() + 30_000,
                effect_hint: "mutate".to_owned(),
                operations: vec![OperationSpec {
                    operation_id: conflict_operation,
                    sequence: 0,
                    session_id: Some(blocked),
                    target_descriptor: "{}".to_owned(),
                    fingerprint: conflict_operation.to_string(),
                    state: crate::record::OperationState::Planned,
                    session: None,
                }],
            })
            .expect_err("blocked target");
        assert_eq!(error.code(), crate::failure::FailureCode::TargetLost);
        let (_, healthy_op) = admit_operation(&second, healthy, "element_click", json!({}));
        let healthy_task = spawn_dispatch(&second, healthy_op);
        let healthy_command = second.client.next_command().await;
        second.client.reply_success(&healthy_command).await;
        assert_eq!(healthy_task.await.unwrap()["ok"], json!(true));
        let report = evidence_report(
            second.daemon.instance_id(),
            "ready",
            second.daemon.registry().snapshot().unwrap(),
        );
        assert!(
            report["lost_boundary"]["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["operation_id"] == json!(boundary_op)
                    && entry["state"] == json!("failed")
                    && entry["boundary_code"] == json!("operation.target_lost"))
        );
        second.shutdown().await;
    }
}
