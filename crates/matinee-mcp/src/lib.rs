//! Newline-delimited JSON-RPC adapter for the Matinee MVP.
//!
//! The adapter deliberately implements the small MCP surface directly with
//! `serde_json`: the official SDK requires a newer Rust compiler than the
//! project's MSRV. Records remain owned by [`matinee_daemon::lifecycle::Daemon`];
//! this connection only supplies the authenticated MCP principal and protocol
//! framing.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use matinee_daemon::failure::FailureCode;
use matinee_daemon::lifecycle::{Daemon, LifecycleError};
use matinee_daemon::record::{OperationState, RequestState};
use matinee_daemon::registry::{
    ArtifactRecord, BeginRequestResult, OperationRecord, OperationSpec, RequestRecord, RequestSpec,
    SessionRecord, SessionSpec, TerminalResult,
};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

const PROTOCOL_VERSION: &str = "matinee.tools.v1";
const FIXTURE_REVISION: &str = "fixture-revision-1";
const FIXTURE_ORIGIN_PREFIX: &str = "http://127.0.0.1";
const MAX_ARTIFACT_BYTES: u64 = 32 * 1024 * 1024;

/// A connection-scoped MCP adapter backed by one daemon instance.
///
/// The adapter does not retain browser, request, operation, or artifact state.
/// Those records are always read from the supplied daemon registry.
pub struct Adapter {
    daemon: Arc<Daemon>,
    principal_id: Uuid,
}

impl Adapter {
    /// Creates an adapter for an authenticated MCP principal.
    pub fn new(daemon: Arc<Daemon>, principal_id: Uuid) -> Self {
        Self {
            daemon,
            principal_id,
        }
    }

    /// Returns the daemon instance identity advertised on every response.
    pub fn instance_id(&self) -> Uuid {
        self.daemon.instance_id()
    }

    /// Returns the principal authenticated for this connection.
    pub const fn principal_id(&self) -> Uuid {
        self.principal_id
    }

    /// Serves newline-delimited JSON-RPC requests until EOF.
    ///
    /// Malformed requests are answered with a JSON-RPC error and do not close
    /// the stream. Only protocol responses are written to `output`.
    pub async fn serve<R, W>(&self, input: R, output: W) -> io::Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut input = input;
        let mut output = output;
        let mut line = String::new();
        loop {
            line.clear();
            let read = input.read_line(&mut line).await?;
            if read == 0 {
                return Ok(());
            }
            let response = self.handle_line(&line);
            let encoded = serde_json::to_vec(&response)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            output.write_all(&encoded).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
    }

    /// Handles one protocol line without writing to either stream.
    pub fn handle_line(&self, line: &str) -> Value {
        let parsed = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(error) => {
                return error_response(
                    Value::Null,
                    -32700,
                    "Parse error",
                    Some(json!({"detail": safe_error_detail(&error.to_string())})),
                    self.instance_id(),
                );
            }
        };
        let Some(object) = parsed.as_object() else {
            return error_response(
                Value::Null,
                -32600,
                "Invalid Request",
                None,
                self.instance_id(),
            );
        };
        let id = object.get("id").cloned().unwrap_or(Value::Null);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return error_response(id, -32600, "Invalid Request", None, self.instance_id());
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return error_response(id, -32600, "Invalid Request", None, self.instance_id());
        };
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let params = merge_identity_params(params, object);
        match method {
            "initialize" => success_response(id, self.initialize_result(), self.instance_id()),
            "tools/list" => {
                success_response(id, json!({"tools": tool_definitions()}), self.instance_id())
            }
            "tools/call" => match self.tools_call(&params) {
                Ok(result) => success_response(id, result, self.instance_id()),
                Err(error) => error_response(
                    id,
                    error.rpc_code,
                    &error.message,
                    Some(json!({"failure": error.failure, "identifiers": error.identifiers})),
                    self.instance_id(),
                ),
            },
            "resources/read" => match self.resource_read(&params) {
                Ok(result) => success_response(id, result, self.instance_id()),
                Err(error) => error_response(
                    id,
                    error.rpc_code,
                    &error.message,
                    Some(json!({"failure": error.failure, "identifiers": error.identifiers})),
                    self.instance_id(),
                ),
            },
            _ => error_response(
                id,
                -32601,
                "Method not found",
                Some(json!({"method": method})),
                self.instance_id(),
            ),
        }
    }

    fn initialize_result(&self) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "matinee", "version": env!("CARGO_PKG_VERSION")},
            "daemon_instance_id": self.instance_id().to_string(),
        })
    }

    fn tools_call(&self, params: &Value) -> Result<Value, AdapterError> {
        let object = params
            .as_object()
            .ok_or_else(|| invalid_params("tools/call params must be an object"))?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_params("tools/call requires a tool name"))?;
        let arguments = object
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let arguments = arguments
            .as_object()
            .ok_or_else(|| invalid_params("tool arguments must be an object"))?;
        if !tool_names().contains(&name) {
            return Err(invalid_params("unknown tool"));
        }

        let incoming_instance = arguments
            .get("daemon_instance_id")
            .or_else(|| object.get("daemon_instance_id"))
            .map(parse_uuid)
            .transpose()?;
        let last_action_sequence = arguments
            .get("last_action_sequence")
            .or_else(|| object.get("last_action_sequence"))
            .and_then(Value::as_i64)
            .unwrap_or(0);

        if is_mutating(name) {
            validate_mutation_context(arguments)?;
            if require_i64(arguments, "deadline_ms")? <= now_ms() {
                return Err(self.failure_error(FailureCode::DeadlineExpired, BTreeMap::new()));
            }
        }
        self.daemon
            .validate_instance(
                incoming_instance.unwrap_or_else(|| self.instance_id()),
                last_action_sequence,
            )
            .map_err(|error| self.daemon_error(error, BTreeMap::new()))?;

        match name {
            "browser_list" => Ok(json!({
                "revision": FIXTURE_REVISION,
                "expires_at": now_ms() + 60_000,
                "candidates": [{
                    "candidate_id": "fixture-candidate-1",
                    "browser": "chromium",
                    "profile": "fixture",
                    "window": "fixture-window",
                    "tab": "fixture-tab-1"
                }]
            })),
            "session_open" => self.session_open(arguments),
            "session_get" => self.session_get(arguments),
            "session_close" => self.session_close(arguments),
            "page_observe" => self.page_observe(arguments),
            "page_navigate" => self.page_navigate(arguments),
            "element_click" => self.element_click(arguments),
            "element_type" => self.element_type(arguments),
            "page_screenshot" => self.page_screenshot(arguments),
            "request_get" => self.request_get(arguments),
            _ => Err(invalid_params("unknown tool")),
        }
    }

    fn session_open(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        require_string(arguments, "candidate_revision")?;
        if arguments.get("candidate_revision").and_then(Value::as_str) != Some(FIXTURE_REVISION) {
            return Err(self.failure_error(FailureCode::CandidateRevisionStale, BTreeMap::new()));
        }
        let selection = if let Some(candidate) = arguments.get("candidate_id") {
            let candidate = candidate
                .as_str()
                .ok_or_else(|| invalid_params("candidate_id must be a string"))?;
            if candidate != "fixture-candidate-1" {
                return Err(
                    self.failure_error(FailureCode::CandidateRevisionStale, BTreeMap::new())
                );
            }
            json!({"candidate_id": candidate})
        } else {
            let new_tab = arguments
                .get("new_tab")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid_params("session_open requires candidate_id or new_tab"))?;
            let url = new_tab
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_params("new_tab.url is required"))?;
            if !is_fixture_url(url) {
                return Err(self.failure_error(FailureCode::OriginRejected, BTreeMap::new()));
            }
            json!({"new_tab": {"url": url}})
        };
        self.execute_operation(
            "session_open",
            arguments,
            None,
            selection,
            Some(SessionSpec {
                session_id: Uuid::now_v7(),
                mcp_principal_id: self.principal_id,
                pairing_id: Uuid::nil(),
                browser: "chromium".to_owned(),
                profile: "fixture".to_owned(),
                window: "fixture-window".to_owned(),
            }),
            |request, operation, session| {
                json!({
                    "session_id": session.map(|s| s.session_id).unwrap_or_else(Uuid::nil).to_string(),
                    "state": session.map(|s| s.state.as_str()).unwrap_or("opening"),
                    "tab_incarnation": session.and_then(|s| s.tab_incarnation.clone()).unwrap_or_else(|| "tab-incarnation-1".to_owned()),
                    "document_generation": session.and_then(|s| s.document_generation.clone()).unwrap_or_else(|| "document-generation-1".to_owned()),
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn session_get(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = require_uuid(arguments, "session_id")?;
        let session = self.owned_session(session_id)?;
        self.execute_operation(
            "session_get",
            arguments,
            Some(session_id),
            json!({"session_id": session_id}),
            None,
            |request, operation, _| {
                json!({
                    "session": session_summary(&session),
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn session_close(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = require_uuid(arguments, "session_id")?;
        let session = self.owned_session(session_id)?;
        self.execute_operation(
            "session_close",
            arguments,
            Some(session_id),
            json!({"session_id": session_id, "close_tab": arguments.get("close_tab").and_then(Value::as_bool).unwrap_or(false)}),
            None,
            |request, operation, _| json!({
                "session_id": session.session_id.to_string(),
                "state": "closed",
                "request_id": request.request_id.to_string(),
                "operation_id": operation.operation_id.to_string(),
                "action_sequence": operation.action_sequence,
            }),
        )
    }

    fn page_observe(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = require_uuid(arguments, "session_id")?;
        let session = self.owned_session(session_id)?;
        self.execute_operation(
            "page_observe",
            arguments,
            Some(session_id),
            json!({"session_id": session_id, "document_generation": current_generation(&session)}),
            None,
            |request, operation, _| {
                json!({
                    "session_id": session_id.to_string(),
                    "document_generation": current_generation(&session),
                    "elements": [],
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn page_navigate(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = self.validate_page_target(arguments)?;
        let url = require_string(arguments, "url")?;
        if !is_fixture_url(url) {
            return Err(self.failure_error(FailureCode::OriginRejected, BTreeMap::new()));
        }
        self.execute_operation(
            "page_navigate",
            arguments,
            Some(session_id),
            json!({"session_id": session_id, "url": url}),
            None,
            |request, operation, _| {
                json!({
                    "url": url,
                    "document_generation": "document-generation-1",
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn element_click(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = self.validate_page_target(arguments)?;
        let element_ref = require_string(arguments, "element_ref")?;
        self.execute_operation(
            "element_click",
            arguments,
            Some(session_id),
            json!({"session_id": session_id, "element_ref": element_ref}),
            None,
            |request, operation, _| {
                json!({
                    "element_ref": element_ref,
                    "activated": true,
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn element_type(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = self.validate_page_target(arguments)?;
        let element_ref = require_string(arguments, "element_ref")?;
        let text = require_string(arguments, "text")?;
        self.execute_operation(
            "element_type",
            arguments,
            Some(session_id),
            json!({"session_id": session_id, "element_ref": element_ref, "text": text}),
            None,
            |request, operation, _| {
                json!({
                    "element_ref": element_ref,
                    "typed": true,
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                })
            },
        )
    }

    fn page_screenshot(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let session_id = self.validate_page_target(arguments)?;
        self.execute_operation_checked(
            "page_screenshot",
            arguments,
            Some(session_id),
            json!({"session_id": session_id}),
            None,
            |request, operation, _| {
                let artifact_id = Uuid::now_v7();
                let resource_uri = format!("matinee://artifact/{artifact_id}");
                let artifact = ArtifactRecord {
                    artifact_id,
                    operation_id: operation.operation_id,
                    kind: "screenshot".to_owned(),
                    digest: "sha256:redacted-empty-artifact".to_owned(),
                    byte_length: 0,
                    relative_path: None,
                    redaction_status: "redacted".to_owned(),
                    availability: "available".to_owned(),
                    created_at: now_ms(),
                };
                self.daemon
                    .registry()
                    .insert_artifact(artifact)
                    .map_err(|error| {
                        self.registry_error(
                            error,
                            identifiers(
                                request.request_id,
                                operation.operation_id,
                                Some(session_id),
                            ),
                        )
                    })?;
                Ok(json!({
                    "artifact_id": artifact_id.to_string(),
                    "digest": "sha256:redacted-empty-artifact",
                    "byte_length": 0,
                    "resource_uri": resource_uri,
                    "redaction_status": "redacted",
                    "request_id": request.request_id.to_string(),
                    "operation_id": operation.operation_id.to_string(),
                    "action_sequence": operation.action_sequence,
                }))
            },
        )
    }

    fn request_get(&self, arguments: &Map<String, Value>) -> Result<Value, AdapterError> {
        let request_id = require_uuid(arguments, "request_id")?;
        let request = self
            .daemon
            .registry()
            .request(request_id)
            .map_err(|error| self.registry_error(error, BTreeMap::new()))?
            .ok_or_else(|| self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()))?;
        if request.mcp_principal_id != self.principal_id {
            return Err(self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()));
        }
        Ok(json!({"request": request_summary(&request)}))
    }

    fn resource_read(&self, params: &Value) -> Result<Value, AdapterError> {
        let object = params
            .as_object()
            .ok_or_else(|| invalid_params("resources/read params must be an object"))?;
        let incoming_instance = object
            .get("daemon_instance_id")
            .map(parse_uuid)
            .transpose()?;
        let last_action_sequence = object
            .get("last_action_sequence")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        self.daemon
            .validate_instance(
                incoming_instance.unwrap_or_else(|| self.instance_id()),
                last_action_sequence,
            )
            .map_err(|error| self.daemon_error(error, BTreeMap::new()))?;
        let uri = object
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_params("resources/read requires uri"))?;
        let prefix = "matinee://artifact/";
        let id = uri
            .strip_prefix(prefix)
            .ok_or_else(|| invalid_params("unknown resource URI"))
            .and_then(|value| {
                Uuid::parse_str(value).map_err(|_| invalid_params("invalid artifact URI"))
            })?;
        let artifact = self
            .daemon
            .registry()
            .artifact(id)
            .map_err(|error| self.registry_error(error, BTreeMap::new()))?
            .ok_or_else(|| self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()))?;
        let operation = self
            .daemon
            .registry()
            .operation(artifact.operation_id)
            .map_err(|error| self.registry_error(error, BTreeMap::new()))?
            .ok_or_else(|| self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()))?;
        let request = self
            .daemon
            .registry()
            .request(operation.request_id)
            .map_err(|error| self.registry_error(error, BTreeMap::new()))?
            .ok_or_else(|| self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()))?;
        if request.mcp_principal_id != self.principal_id {
            return Err(self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()));
        }
        if artifact.byte_length > MAX_ARTIFACT_BYTES {
            return Err(self.failure_error(FailureCode::StorageUnavailable, BTreeMap::new()));
        }
        Ok(json!({
            "contents": [{"uri": uri, "mimeType": "image/png", "blob": ""}],
            "byte_length": artifact.byte_length,
        }))
    }

    fn validate_page_target(&self, arguments: &Map<String, Value>) -> Result<Uuid, AdapterError> {
        let session_id = require_uuid(arguments, "session_id")?;
        let session = self.owned_session(session_id)?;
        let expected = require_string(arguments, "expected_document_generation")?;
        if expected != current_generation(&session) {
            return Err(self.failure_error(FailureCode::GenerationStale, BTreeMap::new()));
        }
        Ok(session_id)
    }

    fn owned_session(&self, session_id: Uuid) -> Result<SessionRecord, AdapterError> {
        let session = self
            .daemon
            .registry()
            .session(session_id)
            .map_err(|error| self.registry_error(error, BTreeMap::new()))?
            .ok_or_else(|| self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()))?;
        if session.mcp_principal_id != self.principal_id {
            return Err(self.failure_error(FailureCode::AuthorizationDenied, BTreeMap::new()));
        }
        Ok(session)
    }

    fn execute_operation<F>(
        &self,
        tool: &str,
        arguments: &Map<String, Value>,
        session_id: Option<Uuid>,
        target: Value,
        session: Option<SessionSpec>,
        result_builder: F,
    ) -> Result<Value, AdapterError>
    where
        F: FnOnce(&RequestRecord, &OperationRecord, Option<&SessionRecord>) -> Value,
    {
        self.execute_operation_inner(
            tool,
            arguments,
            session_id,
            target,
            session,
            |request, operation, session| Ok(result_builder(request, operation, session)),
        )
    }

    fn execute_operation_checked<F>(
        &self,
        tool: &str,
        arguments: &Map<String, Value>,
        session_id: Option<Uuid>,
        target: Value,
        session: Option<SessionSpec>,
        result_builder: F,
    ) -> Result<Value, AdapterError>
    where
        F: FnOnce(
            &RequestRecord,
            &OperationRecord,
            Option<&SessionRecord>,
        ) -> Result<Value, AdapterError>,
    {
        self.execute_operation_inner(tool, arguments, session_id, target, session, result_builder)
    }

    fn execute_operation_inner<F>(
        &self,
        tool: &str,
        arguments: &Map<String, Value>,
        session_id: Option<Uuid>,
        target: Value,
        session: Option<SessionSpec>,
        result_builder: F,
    ) -> Result<Value, AdapterError>
    where
        F: FnOnce(
            &RequestRecord,
            &OperationRecord,
            Option<&SessionRecord>,
        ) -> Result<Value, AdapterError>,
    {
        let idempotency_key = require_string(arguments, "idempotency_key")?.to_owned();
        let deadline_ms = require_i64(arguments, "deadline_ms")?;
        let effect_hint = require_string(arguments, "effect_hint")?.to_owned();
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let session_id_for_result = session
            .as_ref()
            .map(|value| value.session_id)
            .or(session_id);
        let fingerprint = fingerprint(tool, arguments);
        let spec = RequestSpec {
            request_id,
            mcp_principal_id: self.principal_id,
            tool: tool.to_owned(),
            idempotency_key,
            fingerprint: fingerprint.clone(),
            deadline_ms,
            effect_hint,
            operations: vec![OperationSpec {
                operation_id,
                sequence: 0,
                session_id: session_id_for_result,
                target_descriptor: target.to_string(),
                fingerprint,
                state: OperationState::Planned,
                session,
            }],
        };
        let begun = self
            .daemon
            .begin_request(self.instance_id(), 0, spec)
            .map_err(|error| {
                self.daemon_error(error, identifiers(request_id, operation_id, session_id))
            })?;
        let request = match begun {
            BeginRequestResult::Existing(request) => return Ok(existing_result(&request)),
            BeginRequestResult::Created(request) => request,
        };
        let operation = request.operations.first().cloned().ok_or_else(|| {
            self.failure_error(
                FailureCode::StorageUnavailable,
                identifiers(request_id, operation_id, session_id),
            )
        })?;
        self.daemon
            .dispatch(operation.operation_id)
            .map_err(|error| {
                self.daemon_error(error, identifiers(request_id, operation_id, session_id))
            })?;
        let session_record =
            session_id_for_result.and_then(|id| self.daemon.registry().session(id).ok().flatten());
        let result = result_builder(&request, &operation, session_record.as_ref())?;
        self.daemon
            .commit_terminal_result(
                operation.operation_id,
                TerminalResult {
                    operation_state: OperationState::Succeeded,
                    request_state: RequestState::Succeeded,
                    result: Some(result.to_string()),
                    failure_code: None,
                },
            )
            .map_err(|error| {
                self.daemon_error(error, identifiers(request_id, operation_id, session_id))
            })?;
        Ok(operation_result(
            &self.daemon,
            operation.operation_id,
            result,
        ))
    }

    fn daemon_error(&self, error: LifecycleError, ids: BTreeMap<String, Value>) -> AdapterError {
        self.failure_error_with_detail(error.code(), error.detail(), ids)
    }

    fn registry_error(
        &self,
        error: matinee_daemon::registry::RegistryError,
        ids: BTreeMap<String, Value>,
    ) -> AdapterError {
        self.failure_error_with_detail(error.code(), error.detail(), ids)
    }

    fn failure_error(&self, code: FailureCode, ids: BTreeMap<String, Value>) -> AdapterError {
        self.failure_error_with_detail(code, "", ids)
    }

    fn failure_error_with_detail(
        &self,
        code: FailureCode,
        detail: &str,
        ids: BTreeMap<String, Value>,
    ) -> AdapterError {
        let mut failure = failure_envelope(code, detail);
        if let Value::Object(values) = &mut failure {
            values.insert("identifiers".to_owned(), json!(ids));
        }
        AdapterError {
            rpc_code: -32000,
            message: "Matinee operation failed".to_owned(),
            failure,
            identifiers: ids,
        }
    }
}

/// Runs an adapter on the process standard input and output.
pub async fn run_stdio(daemon: Arc<Daemon>, principal_id: Uuid) -> io::Result<()> {
    let adapter = Adapter::new(daemon, principal_id);
    let input = tokio::io::BufReader::new(tokio::io::stdin());
    let output = tokio::io::stdout();
    adapter.serve(input, output).await
}

/// Runs the stdio adapter as a client of a long-lived daemon.
pub async fn run_stdio_client(
    endpoint: matinee_daemon::server::Endpoint,
    principal_id: Uuid,
) -> io::Result<()> {
    let client = matinee_daemon::server::ControlClient::new(endpoint.clone());
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let parsed = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(error) => error_response(
                Value::Null,
                -32700,
                "Parse error",
                Some(json!({"detail": safe_error_detail(&error.to_string())})),
                endpoint.instance_id,
            ),
        };
        let response = if let Some(object) = parsed.as_object() {
            let id = object.get("id").cloned().unwrap_or(Value::Null);
            match object.get("method").and_then(Value::as_str) {
                Some("initialize") => success_response(
                    id,
                    json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"matinee","version":env!("CARGO_PKG_VERSION")},"daemon_instance_id":endpoint.instance_id.to_string()}),
                    endpoint.instance_id,
                ),
                Some("tools/list") => success_response(
                    id,
                    json!({"tools":tool_definitions()}),
                    endpoint.instance_id,
                ),
                Some("tools/call") => {
                    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
                    let mut request = json!({"command":"tool_call","principal_id":principal_id,"name":params.get("name").and_then(Value::as_str).unwrap_or(""),"arguments":params.get("arguments").cloned().unwrap_or_else(|| json!({}))});
                    if let Some(arguments) =
                        request.get_mut("arguments").and_then(Value::as_object_mut)
                    {
                        if let Some(instance) = object.get("daemon_instance_id") {
                            arguments.insert("daemon_instance_id".to_owned(), instance.clone());
                        }
                    }
                    match client.request(request).await {
                        Ok(result) if result.get("ok").and_then(Value::as_bool) == Some(true) => {
                            success_response(
                                id,
                                result.get("result").cloned().unwrap_or_else(|| json!({})),
                                endpoint.instance_id,
                            )
                        }
                        Ok(result) => error_response(
                            id,
                            -32000,
                            "Matinee operation failed",
                            Some(
                                json!({"failure":failure_envelope(parse_failure_code(result.get("code").and_then(Value::as_str).unwrap_or("operation.target_lost")), result.get("detail").and_then(Value::as_str).unwrap_or("daemon operation failed"))}),
                            ),
                            endpoint.instance_id,
                        ),
                        Err(error) => error_response(
                            id,
                            -32000,
                            "Daemon unavailable",
                            Some(json!({"detail":safe_error_detail(&error.to_string())})),
                            endpoint.instance_id,
                        ),
                    }
                }
                Some("resources/read") => error_response(
                    id,
                    -32000,
                    "Resource unavailable",
                    Some(
                        json!({"failure":failure_envelope(FailureCode::AuthorizationDenied,"resource reads require a daemon artifact" )}),
                    ),
                    endpoint.instance_id,
                ),
                _ => error_response(id, -32601, "Method not found", None, endpoint.instance_id),
            }
        } else {
            error_response(
                Value::Null,
                -32600,
                "Invalid Request",
                None,
                endpoint.instance_id,
            )
        };
        let encoded = serde_json::to_vec(&response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        output.write_all(&encoded).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
}

fn parse_failure_code(code: &str) -> FailureCode {
    match code {
        "daemon.start_conflict" => FailureCode::DaemonStartConflict,
        "daemon.restarted" => FailureCode::DaemonRestarted,
        "operation.extension_disconnected" => FailureCode::ExtensionDisconnected,
        "operation.deadline_expired" => FailureCode::DeadlineExpired,
        "candidate.revision_stale" => FailureCode::CandidateRevisionStale,
        "generation.stale" => FailureCode::GenerationStale,
        "incarnation.stale" => FailureCode::IncarnationStale,
        "idempotency.conflict" => FailureCode::IdempotencyConflict,
        "origin.rejected" => FailureCode::OriginRejected,
        _ => FailureCode::TargetLost,
    }
}

struct AdapterError {
    rpc_code: i64,
    message: String,
    failure: Value,
    identifiers: BTreeMap<String, Value>,
}

fn invalid_params(detail: &str) -> AdapterError {
    AdapterError {
        rpc_code: -32602,
        message: "Invalid params".to_owned(),
        failure: json!({"code": "invalid.params", "class": "input", "summary": detail, "failed_boundary": "request validation", "retryable": false, "identifiers": {}, "safe_next_actions": ["correct the request and retry"]}),
        identifiers: BTreeMap::new(),
    }
}
fn merge_identity_params(mut params: Value, request: &Map<String, Value>) -> Value {
    if let Value::Object(values) = &mut params {
        for key in ["daemon_instance_id", "last_action_sequence"] {
            if !values.contains_key(key) {
                if let Some(value) = request.get(key) {
                    values.insert(key.to_owned(), value.clone());
                }
            }
        }
    }
    params
}

fn parse_uuid(value: &Value) -> Result<Uuid, AdapterError> {
    let string = value
        .as_str()
        .ok_or_else(|| invalid_params("UUID must be a string"))?;
    Uuid::parse_str(string).map_err(|_| invalid_params("UUID is invalid"))
}

fn require_uuid(arguments: &Map<String, Value>, name: &str) -> Result<Uuid, AdapterError> {
    arguments
        .get(name)
        .ok_or_else(|| invalid_params(&format!("{name} is required")))
        .and_then(parse_uuid)
}

fn require_string<'a>(
    arguments: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, AdapterError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_params(&format!("{name} is required")))
}

fn require_i64(arguments: &Map<String, Value>, name: &str) -> Result<i64, AdapterError> {
    arguments
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid_params(&format!("{name} is required")))
}

fn validate_mutation_context(arguments: &Map<String, Value>) -> Result<(), AdapterError> {
    require_string(arguments, "idempotency_key")?;
    require_i64(arguments, "deadline_ms")?;
    let effect_hint = require_string(arguments, "effect_hint")?;
    if !matches!(effect_hint, "read" | "mutate") {
        return Err(invalid_params("effect_hint must be read or mutate"));
    }
    Ok(())
}

fn is_mutating(tool: &str) -> bool {
    !matches!(
        tool,
        "browser_list" | "session_get" | "page_observe" | "request_get"
    )
}

fn tool_names() -> [&'static str; 10] {
    [
        "browser_list",
        "session_open",
        "session_get",
        "session_close",
        "page_observe",
        "page_navigate",
        "element_click",
        "element_type",
        "page_screenshot",
        "request_get",
    ]
}

fn tool_definitions() -> Vec<Value> {
    tool_names()
        .into_iter()
        .map(|name| json!({"name": name, "description": format!("Matinee {name} operation"), "inputSchema": schema_for(name)}))
        .collect()
}

fn schema_for(name: &str) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    match name {
        "browser_list" => {}
        "session_open" => {
            mutation_schema(&mut properties, &mut required, false);
            properties.insert("candidate_revision".to_owned(), json!({"type": "string"}));
            properties.insert("candidate_id".to_owned(), json!({"type": "string"}));
            properties.insert("new_tab".to_owned(), json!({"type": "object", "properties": {"url": {"type": "string", "format": "uri"}}, "required": ["url"], "additionalProperties": false}));
            required.push("candidate_revision");
        }
        "session_get" => {
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            required.push("session_id");
        }
        "session_close" => {
            mutation_schema(&mut properties, &mut required, false);
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            properties.insert(
                "close_tab".to_owned(),
                json!({"type": "boolean", "default": false}),
            );
            required.push("session_id");
        }
        "page_observe" => {
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            required.push("session_id");
        }
        "page_navigate" => {
            mutation_schema(&mut properties, &mut required, true);
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            properties.insert(
                "expected_document_generation".to_owned(),
                json!({"type": "string"}),
            );
            properties.insert("url".to_owned(), json!({"type": "string", "format": "uri"}));
            required.extend(["session_id", "expected_document_generation", "url"]);
        }
        "element_click" => {
            mutation_schema(&mut properties, &mut required, true);
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            properties.insert(
                "expected_document_generation".to_owned(),
                json!({"type": "string"}),
            );
            properties.insert("element_ref".to_owned(), json!({"type": "string"}));
            required.extend(["session_id", "expected_document_generation", "element_ref"]);
        }
        "element_type" => {
            mutation_schema(&mut properties, &mut required, true);
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            properties.insert(
                "expected_document_generation".to_owned(),
                json!({"type": "string"}),
            );
            properties.insert("element_ref".to_owned(), json!({"type": "string"}));
            properties.insert("text".to_owned(), json!({"type": "string"}));
            required.extend([
                "session_id",
                "expected_document_generation",
                "element_ref",
                "text",
            ]);
        }
        "page_screenshot" => {
            mutation_schema(&mut properties, &mut required, true);
            properties.insert(
                "session_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            properties.insert(
                "expected_document_generation".to_owned(),
                json!({"type": "string"}),
            );
            required.extend(["session_id", "expected_document_generation"]);
        }
        "request_get" => {
            properties.insert(
                "request_id".to_owned(),
                json!({"type": "string", "format": "uuid"}),
            );
            required.push("request_id");
        }
        _ => unreachable!("tool names are exhaustive"),
    }
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

fn mutation_schema(
    properties: &mut Map<String, Value>,
    required: &mut Vec<&'static str>,
    page_target: bool,
) {
    properties.insert("idempotency_key".to_owned(), json!({"type": "string"}));
    properties.insert("deadline_ms".to_owned(), json!({"type": "integer"}));
    properties.insert(
        "effect_hint".to_owned(),
        json!({"type": "string", "enum": ["read", "mutate"]}),
    );
    required.extend(["idempotency_key", "deadline_ms", "effect_hint"]);
    if page_target {
        properties.insert(
            "session_id".to_owned(),
            json!({"type": "string", "format": "uuid"}),
        );
        properties.insert(
            "expected_document_generation".to_owned(),
            json!({"type": "string"}),
        );
    }
}

fn success_response(id: Value, result: Value, instance_id: Uuid) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result, "daemon_instance_id": instance_id.to_string()})
}

fn error_response(
    id: Value,
    code: i64,
    message: &str,
    data: Option<Value>,
    instance_id: Uuid,
) -> Value {
    let mut error = Map::new();
    error.insert("code".to_owned(), json!(code));
    error.insert("message".to_owned(), json!(message));
    if let Some(data) = data {
        error.insert("data".to_owned(), data);
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error, "daemon_instance_id": instance_id.to_string()})
}

fn operation_result(daemon: &Daemon, operation_id: Uuid, result: Value) -> Value {
    let operation = daemon.registry().operation(operation_id).ok().flatten();
    let request_id = operation.as_ref().map(|value| value.request_id.to_string());
    json!({
        "result": result,
        "request_id": request_id,
        "operation_id": operation_id.to_string(),
        "action_sequence": operation.map(|value| value.action_sequence).unwrap_or(0),
    })
}

fn existing_result(request: &RequestRecord) -> Value {
    let operation = request.operations.first();
    let value = operation
        .and_then(|operation| operation.result.as_deref())
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .unwrap_or_else(|| json!({"state": request.state.as_str()}));
    json!({
        "result": value,
        "request_id": request.request_id.to_string(),
        "operation_id": operation.map(|value| value.operation_id.to_string()),
        "action_sequence": operation.map(|value| value.action_sequence).unwrap_or(0),
    })
}

fn request_summary(request: &RequestRecord) -> Value {
    json!({
        "request_id": request.request_id.to_string(),
        "tool": request.tool,
        "state": request.state.as_str(),
        "failure_code": request.failure_code.map(FailureCode::as_str),
        "operations": request.operations.iter().map(operation_summary).collect::<Vec<_>>(),
    })
}

fn operation_summary(operation: &OperationRecord) -> Value {
    json!({
        "operation_id": operation.operation_id.to_string(),
        "request_id": operation.request_id.to_string(),
        "sequence": operation.sequence,
        "action_sequence": operation.action_sequence,
        "state": operation.state.as_str(),
        "result": operation.result.as_deref().and_then(|value| serde_json::from_str::<Value>(value).ok()),
    })
}

fn session_summary(session: &SessionRecord) -> Value {
    json!({
        "session_id": session.session_id.to_string(),
        "state": session.state.as_str(),
        "tab_incarnation": session.tab_incarnation.clone().unwrap_or_else(|| "tab-incarnation-1".to_owned()),
        "document_generation": current_generation(session),
    })
}

fn current_generation(session: &SessionRecord) -> String {
    session
        .document_generation
        .clone()
        .unwrap_or_else(|| "document-generation-1".to_owned())
}

fn fingerprint(tool: &str, arguments: &Map<String, Value>) -> String {
    json!({"tool": tool, "arguments": arguments}).to_string()
}

fn identifiers(
    request_id: Uuid,
    operation_id: Uuid,
    session_id: Option<Uuid>,
) -> BTreeMap<String, Value> {
    let mut ids = BTreeMap::from([
        ("request_id".to_owned(), json!(request_id.to_string())),
        ("operation_id".to_owned(), json!(operation_id.to_string())),
    ]);
    if let Some(session_id) = session_id {
        ids.insert("session_id".to_owned(), json!(session_id.to_string()));
    }
    ids
}

fn failure_envelope(code: FailureCode, detail: &str) -> Value {
    let (class, summary, boundary, actions) = match code {
        FailureCode::DaemonStartConflict => (
            "daemon",
            "another daemon owns the state directory",
            "daemon startup ownership",
            vec!["wait for the owning daemon or choose another state directory"],
        ),
        FailureCode::DaemonRestarted => (
            "daemon",
            "the daemon instance changed and the prior outcome is unobserved",
            "daemon instance validation",
            vec!["reconnect and inspect the prior request before retrying"],
        ),
        FailureCode::ExtensionDisconnected => (
            "operation",
            "the extension disconnected before the outcome was observed",
            "extension result observation",
            vec!["reconnect the extension and inspect the failed operation"],
        ),
        FailureCode::TargetLost => (
            "operation",
            "the operation target was lost before the outcome was observed",
            "target result observation",
            vec!["observe the target and create a new request"],
        ),
        FailureCode::DeadlineExpired => (
            "operation",
            "the operation deadline expired before the outcome was observed",
            "operation deadline",
            vec!["create a new request with a sufficient deadline"],
        ),
        FailureCode::CandidateRevisionStale => (
            "selection",
            "the browser candidate revision is stale",
            "candidate validation",
            vec!["call browser_list and use its current revision"],
        ),
        FailureCode::GenerationStale => (
            "target",
            "the document generation is stale",
            "document generation validation",
            vec!["observe the page and retry with its generation"],
        ),
        FailureCode::IncarnationStale => (
            "target",
            "the tab incarnation is stale",
            "tab incarnation validation",
            vec!["open or observe the current session"],
        ),
        FailureCode::IdempotencyConflict => (
            "request",
            "the idempotency key has a different request fingerprint",
            "idempotency validation",
            vec!["use the original arguments or a new idempotency key"],
        ),
        FailureCode::AuthorizationDenied => (
            "authorization",
            "the principal does not own the requested object",
            "ownership authorization",
            vec!["use an object owned by this principal"],
        ),
        FailureCode::OriginRejected => (
            "origin",
            "the origin is outside the pinned fixture",
            "origin validation",
            vec!["use the configured fixture origin"],
        ),
        FailureCode::StorageUnavailable => (
            "daemon",
            "the daemon could not access its in-memory registry",
            "daemon state access",
            vec!["reconnect to a ready daemon"],
        ),
    };
    let mut envelope = Map::new();
    envelope.insert("code".to_owned(), json!(code.as_str()));
    envelope.insert("class".to_owned(), json!(class));
    envelope.insert("summary".to_owned(), json!(summary));
    envelope.insert("failed_boundary".to_owned(), json!(boundary));
    envelope.insert("retryable".to_owned(), json!(code.retryable()));
    envelope.insert("safe_next_actions".to_owned(), json!(actions));
    if !detail.is_empty() {
        envelope.insert("detail".to_owned(), json!(safe_error_detail(detail)));
    }
    Value::Object(envelope)
}

fn safe_error_detail(detail: &str) -> String {
    detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

/// Reports whether a URL names the pinned fixture origin.
///
/// The extension manifest grants host access to `http://127.0.0.1/*` only, so
/// `localhost` is rejected here as well. Accepting it would let a navigation
/// pass this pre-dispatch check and then fail at the browser boundary.
fn is_fixture_url(url: &str) -> bool {
    let Some(remainder) = url.strip_prefix(FIXTURE_ORIGIN_PREFIX) else {
        return false;
    };
    remainder.is_empty()
        || remainder.starts_with('/')
        || remainder.starts_with(':')
        || remainder.starts_with('?')
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::is_fixture_url;

    /// The extension only holds host access to `http://127.0.0.1/*`, so any URL
    /// this accepts must be one the browser boundary can also act on.
    #[test]
    fn only_the_pinned_fixture_origin_is_accepted() {
        assert!(is_fixture_url("http://127.0.0.1:8787/alpha"));
        assert!(is_fixture_url("http://127.0.0.1/alpha"));
        assert!(is_fixture_url("http://127.0.0.1"));

        assert!(!is_fixture_url("http://localhost:8787/alpha"));
        assert!(!is_fixture_url("https://127.0.0.1:8787/alpha"));
        assert!(!is_fixture_url("http://127.0.0.1.example.com/alpha"));
        assert!(!is_fixture_url("http://127.0.0.10/alpha"));
        assert!(!is_fixture_url("http://example.com/alpha"));
    }
}
