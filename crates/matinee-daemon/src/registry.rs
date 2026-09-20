//! In-memory state for one running Matinee daemon.
//!
//! The registry is intentionally process-local. It has no file, database, or
//! recovery path; dropping the daemon drops every record it owns.

use crate::failure::FailureCode;
use crate::record::{OperationState, RequestState, SessionState};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// An error returned by an in-memory registry operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryError {
    code: FailureCode,
    detail: String,
}

impl RegistryError {
    fn invalid(detail: impl Into<String>) -> Self {
        Self {
            code: FailureCode::StorageUnavailable,
            detail: detail.into(),
        }
    }

    fn conflict() -> Self {
        Self {
            code: FailureCode::IdempotencyConflict,
            detail: "idempotency key fingerprint differs".to_owned(),
        }
    }

    fn blocked_target() -> Self {
        Self {
            code: FailureCode::TargetLost,
            detail: "target is blocked after an unobserved operation outcome".to_owned(),
        }
    }

    /// Returns the stable failure code for this error.
    pub const fn code(&self) -> FailureCode {
        self.code
    }

    /// Returns the stable failure code for this error.
    pub const fn failure_code(&self) -> FailureCode {
        self.code
    }

    /// Returns a local diagnostic detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for RegistryError {}

/// A public principal record without private key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRecord {
    /// Principal identity.
    pub identity_id: Uuid,
    /// Stable principal kind string.
    pub kind: String,
    /// Platform credential-store locator.
    pub credential_reference: String,
    /// Credential epoch.
    pub epoch: i64,
    /// `active` or `revoked`.
    pub status: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: i64,
}

/// A paired extension record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRecord {
    /// Pairing identity.
    pub pairing_id: Uuid,
    /// Extension principal identity.
    pub extension_identity_id: Uuid,
    /// Pinned extension origin.
    pub origin: String,
    /// Public key bytes or an encoded public key.
    pub public_key: Vec<u8>,
    /// Redaction-safe public-key fingerprint.
    pub fingerprint: String,
    /// Whether development pairing was explicitly allowed.
    pub development_allowance: bool,
    /// `active` or `revoked`.
    pub status: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: i64,
    /// Rotation timestamp, when applicable.
    pub rotated_at: Option<i64>,
}

/// A browser session owned by one MCP principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session identity.
    pub session_id: Uuid,
    /// Owning MCP principal.
    pub mcp_principal_id: Uuid,
    /// Pairing used for the browser connection.
    pub pairing_id: Uuid,
    /// Browser family.
    pub browser: String,
    /// Paired browser profile reference.
    pub profile: String,
    /// Browser window reference.
    pub window: String,
    /// Non-repeating daemon-issued tab incarnation.
    pub tab_incarnation: Option<String>,
    /// Current browser document generation.
    pub document_generation: Option<String>,
    /// Canonical session state.
    pub state: SessionState,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: i64,
    /// Close timestamp, when applicable.
    pub closed_at: Option<i64>,
}

/// A request and its ordered operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRecord {
    /// Request identity.
    pub request_id: Uuid,
    /// Authenticated MCP principal.
    pub mcp_principal_id: Uuid,
    /// Tool name.
    pub tool: String,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
    /// Stable request fingerprint.
    pub fingerprint: String,
    /// Caller deadline in Unix milliseconds.
    pub deadline_ms: i64,
    /// Caller effect hint.
    pub effect_hint: String,
    /// Canonical request state.
    pub state: RequestState,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: i64,
    /// Terminal timestamp, when applicable.
    pub terminal_at: Option<i64>,
    /// Stable failure code, when applicable.
    pub failure_code: Option<FailureCode>,
    /// Ordered operations owned by the request.
    pub operations: Vec<OperationRecord>,
}

/// A browser operation belonging to a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRecord {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Owning request identity.
    pub request_id: Uuid,
    /// Request-local order.
    pub sequence: i64,
    /// Daemon-assigned action sequence within the target session.
    pub action_sequence: i64,
    /// Optional target session.
    pub session_id: Option<Uuid>,
    /// Opaque JSON target descriptor.
    pub target_descriptor: String,
    /// Stable operation fingerprint.
    pub fingerprint: String,
    /// Canonical operation state.
    pub state: OperationState,
    /// Effect start timestamp, set at the dispatch boundary.
    pub effect_started_at: Option<i64>,
    /// Terminal timestamp, when applicable.
    pub terminal_at: Option<i64>,
    /// Opaque terminal result JSON.
    pub result: Option<String>,
}

/// The in-memory dispatch record for an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchRecord {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Request identity.
    pub request_id: Uuid,
    /// Whether the operation crossed the browser effect boundary.
    pub dispatched: bool,
    /// Dispatch timestamp, when applicable.
    pub dispatched_at: Option<i64>,
}

/// Metadata for an artifact produced during this daemon run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRecord {
    /// Artifact identity.
    pub artifact_id: Uuid,
    /// Operation that produced the artifact.
    pub operation_id: Uuid,
    /// Artifact kind, such as `screenshot`.
    pub kind: String,
    /// Content digest.
    pub digest: String,
    /// Artifact byte length.
    pub byte_length: u64,
    /// Run-local relative path, if one is used by the producer.
    pub relative_path: Option<String>,
    /// Redaction status.
    pub redaction_status: String,
    /// Availability status.
    pub availability: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at: i64,
}

/// A session to preallocate with a `session_open` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSpec {
    /// Session identity.
    pub session_id: Uuid,
    /// Owning MCP principal.
    pub mcp_principal_id: Uuid,
    /// Pairing identity.
    pub pairing_id: Uuid,
    /// Browser family.
    pub browser: String,
    /// Browser profile reference.
    pub profile: String,
    /// Browser window reference.
    pub window: String,
}

/// One operation to insert with a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    /// Operation identity.
    pub operation_id: Uuid,
    /// Request-local order.
    pub sequence: i64,
    /// Optional target session.
    pub session_id: Option<Uuid>,
    /// Opaque JSON target descriptor.
    pub target_descriptor: String,
    /// Stable operation fingerprint.
    pub fingerprint: String,
    /// Initial operation state.
    pub state: OperationState,
    /// Optional preallocated session.
    pub session: Option<SessionSpec>,
}

/// A request and its operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSpec {
    /// Request identity.
    pub request_id: Uuid,
    /// Authenticated MCP principal.
    pub mcp_principal_id: Uuid,
    /// Tool name.
    pub tool: String,
    /// Caller-provided idempotency key.
    pub idempotency_key: String,
    /// Stable request fingerprint.
    pub fingerprint: String,
    /// Caller deadline in Unix milliseconds.
    pub deadline_ms: i64,
    /// Caller effect hint.
    pub effect_hint: String,
    /// Operations inserted in sequence order.
    pub operations: Vec<OperationSpec>,
}

/// Result of an idempotent request insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeginRequestResult {
    /// A new request was inserted in memory.
    Created(RequestRecord),
    /// The existing request matched the supplied fingerprint.
    Existing(RequestRecord),
}

/// A terminal transition for one dispatched operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalResult {
    /// Canonical terminal operation state.
    pub operation_state: OperationState,
    /// Canonical terminal request state.
    pub request_state: RequestState,
    /// Opaque result JSON.
    pub result: Option<String>,
    /// Stable failure code, when the result is a failure.
    pub failure_code: Option<FailureCode>,
}

/// The process-local, single-owner registry for daemon state.
#[derive(Clone)]
pub struct Registry {
    inner: Arc<Mutex<RegistryInner>>,
}

struct RegistryInner {
    principals: HashMap<Uuid, PrincipalRecord>,
    pairings: HashMap<Uuid, PairingRecord>,
    sessions: HashMap<Uuid, SessionRecord>,
    requests: HashMap<Uuid, RequestRecord>,
    operations: HashMap<Uuid, OperationRecord>,
    idempotency: HashMap<(Uuid, String), (Uuid, String)>,
    dispatches: HashMap<Uuid, DispatchRecord>,
    artifacts: HashMap<Uuid, ArtifactRecord>,
    next_action_sequence: HashMap<Uuid, i64>,
    blocked_targets: HashSet<(Uuid, Option<String>)>,
}
/// A point-in-time copy of all in-memory records owned by one daemon run.
///
/// Report producers use this aggregate so they can build one stable snapshot
/// without exposing the registry's private maps or holding its mutex while
/// serializing JSON.
#[derive(Clone, Debug, Default)]
pub struct RegistrySnapshot {
    /// Registered native and MCP principals.
    pub principals: Vec<PrincipalRecord>,
    /// Extension pairings, including redaction-safe fingerprints.
    pub pairings: Vec<PairingRecord>,
    /// Browser sessions.
    pub sessions: Vec<SessionRecord>,
    /// Requests admitted during this run.
    pub requests: Vec<RequestRecord>,
    /// Operations admitted during this run.
    pub operations: Vec<OperationRecord>,
    /// Artifacts produced during this run.
    pub artifacts: Vec<ArtifactRecord>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Creates an empty registry for one daemon process.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RegistryInner {
                principals: HashMap::new(),
                pairings: HashMap::new(),
                sessions: HashMap::new(),
                requests: HashMap::new(),
                operations: HashMap::new(),
                idempotency: HashMap::new(),
                dispatches: HashMap::new(),
                artifacts: HashMap::new(),
                next_action_sequence: HashMap::new(),
                blocked_targets: HashSet::new(),
            })),
        }
    }
    /// Returns a deterministic point-in-time copy of every in-memory record.
    pub fn snapshot(&self) -> Result<RegistrySnapshot, RegistryError> {
        let inner = self.lock()?;
        let mut principals: Vec<_> = inner.principals.values().cloned().collect();
        let mut pairings: Vec<_> = inner.pairings.values().cloned().collect();
        let mut sessions: Vec<_> = inner.sessions.values().cloned().collect();
        let mut requests: Vec<_> = inner
            .requests
            .values()
            .cloned()
            .map(|mut request| {
                request.operations = request
                    .operations
                    .iter()
                    .filter_map(|operation| inner.operations.get(&operation.operation_id).cloned())
                    .collect();
                request
            })
            .collect();
        let mut operations: Vec<_> = inner.operations.values().cloned().collect();
        let mut artifacts: Vec<_> = inner.artifacts.values().cloned().collect();
        principals.sort_by_key(|record| record.identity_id);
        pairings.sort_by_key(|record| record.pairing_id);
        sessions.sort_by_key(|record| record.session_id);
        requests.sort_by_key(|record| record.request_id);
        operations.sort_by_key(|record| record.operation_id);
        artifacts.sort_by_key(|record| record.artifact_id);
        Ok(RegistrySnapshot {
            principals,
            pairings,
            sessions,
            requests,
            operations,
            artifacts,
        })
    }

    /// Returns a principal record, if it exists.
    pub fn principal(&self, identity_id: Uuid) -> Result<Option<PrincipalRecord>, RegistryError> {
        Ok(Some(self.lock()?.principals.get(&identity_id).cloned()).flatten())
    }

    /// Inserts a principal record.
    pub fn insert_principal(&self, record: PrincipalRecord) -> Result<(), RegistryError> {
        let mut inner = self.lock()?;
        if inner.principals.contains_key(&record.identity_id) {
            return Err(RegistryError::invalid("principal identity already exists"));
        }
        inner.principals.insert(record.identity_id, record);
        Ok(())
    }

    /// Inserts a pairing record.
    pub fn insert_pairing(&self, record: PairingRecord) -> Result<(), RegistryError> {
        let mut inner = self.lock()?;
        if inner.pairings.contains_key(&record.pairing_id) {
            return Err(RegistryError::invalid("pairing identity already exists"));
        }
        inner.pairings.insert(record.pairing_id, record);
        Ok(())
    }

    /// Resolves an active pairing by the fingerprint that proved possession.
    ///
    /// A channel that proves a key must be bound to the pairing record that owns
    /// the browser profile, so revocation and status govern it. Returns `None`
    /// when no pairing carries that fingerprint or when the pairing is not
    /// active.
    pub fn active_pairing_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<PairingRecord>, RegistryError> {
        let inner = self.lock()?;
        Ok(inner
            .pairings
            .values()
            .find(|record| record.fingerprint == fingerprint && record.status == "active")
            .cloned())
    }

    /// Begins a request, assigning action sequences and applying idempotency.
    pub fn begin_request(&self, spec: RequestSpec) -> Result<BeginRequestResult, RegistryError> {
        if spec.operations.is_empty() {
            return Err(RegistryError::invalid("request must contain an operation"));
        }
        let mut inner = self.lock()?;
        let key = (spec.mcp_principal_id, spec.idempotency_key.clone());
        if let Some((request_id, fingerprint)) = inner.idempotency.get(&key) {
            if fingerprint != &spec.fingerprint {
                return Err(RegistryError::conflict());
            }
            let mut request =
                inner.requests.get(request_id).cloned().ok_or_else(|| {
                    RegistryError::invalid("idempotency record points to no request")
                })?;
            request.operations = request
                .operations
                .iter()
                .filter_map(|operation| inner.operations.get(&operation.operation_id).cloned())
                .collect();
            return Ok(BeginRequestResult::Existing(request));
        }

        for operation in &spec.operations {
            if !is_read_only_tool(&spec.tool) {
                if let Some(session_id) = operation.session_id {
                    let key = (session_id, session_incarnation(&inner, session_id));
                    if inner.blocked_targets.contains(&key) {
                        return Err(RegistryError::blocked_target());
                    }
                }
            }
            if inner.operations.contains_key(&operation.operation_id) {
                return Err(RegistryError::invalid("operation identity already exists"));
            }
            if let Some(session) = &operation.session {
                if inner.sessions.contains_key(&session.session_id) {
                    return Err(RegistryError::invalid("session identity already exists"));
                }
            }
        }
        if inner.requests.contains_key(&spec.request_id) {
            return Err(RegistryError::invalid("request identity already exists"));
        }

        let created_at = now_ms();
        let mut operations = Vec::with_capacity(spec.operations.len());
        for operation in spec.operations {
            if let Some(session) = operation.session {
                inner.next_action_sequence.insert(session.session_id, 0);
                inner.sessions.insert(
                    session.session_id,
                    SessionRecord {
                        session_id: session.session_id,
                        mcp_principal_id: session.mcp_principal_id,
                        pairing_id: session.pairing_id,
                        browser: session.browser,
                        profile: session.profile,
                        window: session.window,
                        tab_incarnation: None,
                        document_generation: None,
                        state: SessionState::Opening,
                        created_at,
                        closed_at: None,
                    },
                );
            }
            let action_sequence = operation
                .session_id
                .map(|session_id| {
                    let next = inner.next_action_sequence.entry(session_id).or_insert(0);
                    let assigned = *next;
                    *next += 1;
                    assigned
                })
                .unwrap_or(operation.sequence);
            let record = OperationRecord {
                operation_id: operation.operation_id,
                request_id: spec.request_id,
                sequence: operation.sequence,
                action_sequence,
                session_id: operation.session_id,
                target_descriptor: operation.target_descriptor,
                fingerprint: operation.fingerprint,
                state: operation.state,
                effect_started_at: None,
                terminal_at: None,
                result: None,
            };
            inner.operations.insert(record.operation_id, record.clone());
            operations.push(record);
        }
        let request = RequestRecord {
            request_id: spec.request_id,
            mcp_principal_id: spec.mcp_principal_id,
            tool: spec.tool,
            idempotency_key: spec.idempotency_key,
            fingerprint: spec.fingerprint,
            deadline_ms: spec.deadline_ms,
            effect_hint: spec.effect_hint,
            state: RequestState::Accepted,
            created_at,
            terminal_at: None,
            failure_code: None,
            operations,
        };
        inner
            .idempotency
            .insert(key, (request.request_id, request.fingerprint.clone()));
        inner.requests.insert(request.request_id, request.clone());
        Ok(BeginRequestResult::Created(request))
    }

    /// Inserts an opening session outside a request.
    pub fn preallocate_session(&self, spec: SessionSpec) -> Result<SessionRecord, RegistryError> {
        let mut inner = self.lock()?;
        if inner.sessions.contains_key(&spec.session_id) {
            return Err(RegistryError::invalid("session identity already exists"));
        }
        let record = SessionRecord {
            session_id: spec.session_id,
            mcp_principal_id: spec.mcp_principal_id,
            pairing_id: spec.pairing_id,
            browser: spec.browser,
            profile: spec.profile,
            window: spec.window,
            tab_incarnation: None,
            document_generation: None,
            state: SessionState::Opening,
            created_at: now_ms(),
            closed_at: None,
        };
        inner.next_action_sequence.insert(record.session_id, 0);
        inner.sessions.insert(record.session_id, record.clone());
        Ok(record)
    }

    /// Reads one request and its current operations.
    pub fn request(&self, request_id: Uuid) -> Result<Option<RequestRecord>, RegistryError> {
        let inner = self.lock()?;
        Ok(inner.requests.get(&request_id).cloned().map(|mut request| {
            request.operations = request
                .operations
                .iter()
                .filter_map(|operation| inner.operations.get(&operation.operation_id).cloned())
                .collect();
            request
        }))
    }

    /// Reads one operation.
    pub fn operation(&self, operation_id: Uuid) -> Result<Option<OperationRecord>, RegistryError> {
        Ok(self.lock()?.operations.get(&operation_id).cloned())
    }

    /// Reads one session.
    pub fn session(&self, session_id: Uuid) -> Result<Option<SessionRecord>, RegistryError> {
        Ok(self.lock()?.sessions.get(&session_id).cloned())
    }

    /// Reads one in-memory dispatch record.
    pub fn dispatch(&self, operation_id: Uuid) -> Result<Option<DispatchRecord>, RegistryError> {
        Ok(self.lock()?.dispatches.get(&operation_id).cloned())
    }

    /// Registers a prepared operation before the effect boundary.
    pub fn prepare_dispatch(&self, operation_id: Uuid) -> Result<DispatchRecord, RegistryError> {
        let mut inner = self.lock()?;
        let operation = inner
            .operations
            .get_mut(&operation_id)
            .ok_or_else(|| RegistryError::invalid("operation not found"))?;
        if !matches!(
            operation.state,
            OperationState::Planned
                | OperationState::Queued
                | OperationState::AwaitingAttention
                | OperationState::Preflight
        ) {
            return Err(RegistryError::invalid("operation is not dispatchable"));
        }
        operation.state = OperationState::Preflight;
        let record = DispatchRecord {
            operation_id,
            request_id: operation.request_id,
            dispatched: false,
            dispatched_at: None,
        };
        inner.dispatches.insert(operation_id, record.clone());
        Ok(record)
    }

    /// Crosses the in-run browser effect boundary exactly once.
    pub fn mark_dispatched(&self, operation_id: Uuid) -> Result<DispatchRecord, RegistryError> {
        let mut inner = self.lock()?;
        let timestamp = now_ms();
        let operation_state = inner
            .operations
            .get(&operation_id)
            .ok_or_else(|| RegistryError::invalid("operation not found"))?
            .state;
        if operation_state != OperationState::Preflight {
            return Err(RegistryError::invalid("dispatch admission rejected"));
        }
        let dispatch = inner
            .dispatches
            .get_mut(&operation_id)
            .ok_or_else(|| RegistryError::invalid("dispatch was not prepared"))?;
        if dispatch.dispatched {
            return Err(RegistryError::invalid("operation was already dispatched"));
        }
        dispatch.dispatched = true;
        dispatch.dispatched_at = Some(timestamp);
        let result = dispatch.clone();
        let operation = inner
            .operations
            .get_mut(&operation_id)
            .expect("operation exists");
        operation.state = OperationState::Dispatching;
        operation.effect_started_at = Some(timestamp);
        Ok(result)
    }

    /// Commits an observed terminal result in memory.
    pub fn commit_terminal_result(
        &self,
        operation_id: Uuid,
        result: TerminalResult,
    ) -> Result<(), RegistryError> {
        if !matches!(
            result.operation_state,
            OperationState::Succeeded
                | OperationState::Failed
                | OperationState::Expired
                | OperationState::Cancelled
        ) || !result.request_state.terminal()
        {
            return Err(RegistryError::invalid(
                "terminal transition is not terminal",
            ));
        }
        let mut inner = self.lock()?;
        let (request_id, terminal_at) = {
            let operation = inner
                .operations
                .get_mut(&operation_id)
                .ok_or_else(|| RegistryError::invalid("operation not found"))?;
            if !matches!(
                operation.state,
                OperationState::Dispatching | OperationState::AwaitingAttention
            ) {
                return Err(RegistryError::invalid(
                    "operation terminal barrier rejected",
                ));
            }
            let terminal_at = now_ms();
            operation.state = result.operation_state;
            operation.terminal_at = Some(terminal_at);
            operation.result = result.result;
            (operation.request_id, terminal_at)
        };
        let request = inner
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| RegistryError::invalid("request not found"))?;
        request.state = result.request_state;
        request.terminal_at = Some(terminal_at);
        request.failure_code = result.failure_code;
        Ok(())
    }

    /// Fails a dispatched operation when the daemon loses its outcome boundary.
    pub fn record_lost_boundary(
        &self,
        operation_id: Uuid,
        failure_code: FailureCode,
    ) -> Result<(), RegistryError> {
        if !matches!(
            failure_code,
            FailureCode::ExtensionDisconnected
                | FailureCode::TargetLost
                | FailureCode::DeadlineExpired
        ) {
            return Err(RegistryError::invalid(
                "failure code does not name a lost boundary",
            ));
        }
        let mut inner = self.lock()?;
        let (request_id, session_id, terminal_at) = {
            let operation = inner
                .operations
                .get_mut(&operation_id)
                .ok_or_else(|| RegistryError::invalid("operation not found"))?;
            if !matches!(
                operation.state,
                OperationState::Dispatching | OperationState::AwaitingAttention
            ) {
                return Err(RegistryError::invalid(
                    "operation was not awaiting an outcome",
                ));
            }
            let terminal_at = now_ms();
            operation.state = OperationState::Failed;
            operation.terminal_at = Some(terminal_at);
            (operation.request_id, operation.session_id, terminal_at)
        };
        if let Some(session_id) = session_id {
            let key = (session_id, session_incarnation(&inner, session_id));
            inner.blocked_targets.insert(key);
        }
        let request = inner
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| RegistryError::invalid("request not found"))?;
        request.state = RequestState::Failed;
        request.terminal_at = Some(terminal_at);
        request.failure_code = Some(failure_code);
        Ok(())
    }

    /// Cancels operations that have not crossed the browser effect boundary.
    pub fn cancel_undispatched(&self) -> Result<usize, RegistryError> {
        let mut inner = self.lock()?;
        let mut cancelled = 0;
        let timestamp = now_ms();
        let ids: Vec<Uuid> = inner
            .operations
            .values()
            .filter(|operation| operation.state.before_dispatch())
            .map(|operation| operation.operation_id)
            .collect();
        for operation_id in ids {
            let operation = inner
                .operations
                .get_mut(&operation_id)
                .expect("collected operation exists");
            operation.state = OperationState::Cancelled;
            operation.terminal_at = Some(timestamp);
            let request_id = operation.request_id;
            if let Some(request) = inner.requests.get_mut(&request_id) {
                request.state = RequestState::Cancelled;
                request.terminal_at = Some(timestamp);
            }
            cancelled += 1;
        }
        Ok(cancelled)
    }

    /// Counts operations currently waiting for an observed terminal result.
    pub fn dispatching_count(&self) -> Result<usize, RegistryError> {
        Ok(self
            .lock()?
            .operations
            .values()
            .filter(|operation| operation.state == OperationState::Dispatching)
            .count())
    }

    /// Counts operations that crossed the browser effect boundary.
    pub fn dispatched_count(&self) -> Result<usize, RegistryError> {
        Ok(self
            .lock()?
            .dispatches
            .values()
            .filter(|dispatch| dispatch.dispatched)
            .count())
    }

    /// Inserts artifact metadata owned by this daemon run.
    pub fn insert_artifact(&self, record: ArtifactRecord) -> Result<(), RegistryError> {
        let mut inner = self.lock()?;
        if inner.artifacts.contains_key(&record.artifact_id) {
            return Err(RegistryError::invalid("artifact identity already exists"));
        }
        inner.artifacts.insert(record.artifact_id, record);
        Ok(())
    }

    /// Reads artifact metadata, if it exists in this run.
    pub fn artifact(&self, artifact_id: Uuid) -> Result<Option<ArtifactRecord>, RegistryError> {
        Ok(self.lock()?.artifacts.get(&artifact_id).cloned())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RegistryInner>, RegistryError> {
        self.inner
            .lock()
            .map_err(|_| RegistryError::invalid("registry mutex poisoned"))
    }
}

fn is_read_only_tool(tool: &str) -> bool {
    matches!(tool, "session_get" | "request_get")
}

fn session_incarnation(inner: &RegistryInner, session_id: Uuid) -> Option<String> {
    inner
        .sessions
        .get(&session_id)
        .and_then(|session| session.tab_incarnation.clone())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(
        principal: Uuid,
        request_id: Uuid,
        operation_id: Uuid,
        key: &str,
        fingerprint: &str,
        session_id: Option<Uuid>,
    ) -> RequestSpec {
        RequestSpec {
            request_id,
            mcp_principal_id: principal,
            tool: "element_click".to_owned(),
            idempotency_key: key.to_owned(),
            fingerprint: fingerprint.to_owned(),
            deadline_ms: 0,
            effect_hint: "mutate".to_owned(),
            operations: vec![OperationSpec {
                operation_id,
                sequence: 0,
                session_id,
                target_descriptor: "{\"element\":\"button\"}".to_owned(),
                fingerprint: "operation-fingerprint".to_owned(),
                state: OperationState::Planned,
                session: None,
            }],
        }
    }

    #[test]
    fn idempotency_conflict_does_not_dispatch_and_equal_retry_returns_original() {
        let registry = Registry::new();
        let principal = Uuid::now_v7();
        let request_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let created = match registry
            .begin_request(spec(
                principal,
                request_id,
                operation_id,
                "same-key",
                "one",
                None,
            ))
            .expect("created")
        {
            BeginRequestResult::Created(request) => request,
            BeginRequestResult::Existing(_) => panic!("new request was existing"),
        };
        registry.prepare_dispatch(operation_id).expect("prepared");
        registry.mark_dispatched(operation_id).expect("dispatched");
        registry
            .commit_terminal_result(
                operation_id,
                TerminalResult {
                    operation_state: OperationState::Succeeded,
                    request_state: RequestState::Succeeded,
                    result: Some("{\"ok\":true}".to_owned()),
                    failure_code: None,
                },
            )
            .expect("terminal");

        let existing = match registry
            .begin_request(spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "same-key",
                "one",
                None,
            ))
            .expect("equal retry")
        {
            BeginRequestResult::Existing(request) => request,
            BeginRequestResult::Created(_) => panic!("equal retry dispatched a new request"),
        };
        assert_eq!(existing.request_id, created.request_id);
        assert_eq!(existing.operations[0].operation_id, operation_id);
        assert_eq!(
            existing.operations[0].result.as_deref(),
            Some("{\"ok\":true}")
        );
        assert_eq!(registry.dispatched_count().expect("count"), 1);

        let conflict = registry
            .begin_request(spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "same-key",
                "two",
                None,
            ))
            .expect_err("different fingerprint");
        assert_eq!(conflict.code(), FailureCode::IdempotencyConflict);
        assert_eq!(registry.dispatched_count().expect("count"), 1);
        assert_eq!(
            registry
                .request(request_id)
                .expect("request")
                .expect("record")
                .request_id,
            request_id
        );
    }

    #[test]
    fn action_sequences_increase_per_session() {
        let registry = Registry::new();
        let principal = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        registry
            .preallocate_session(SessionSpec {
                session_id,
                mcp_principal_id: principal,
                pairing_id: Uuid::now_v7(),
                browser: "chromium".to_owned(),
                profile: "profile".to_owned(),
                window: "window".to_owned(),
            })
            .expect("session");
        let first = match registry
            .begin_request(spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "first",
                "one",
                Some(session_id),
            ))
            .expect("first")
        {
            BeginRequestResult::Created(request) => request.operations[0].action_sequence,
            BeginRequestResult::Existing(_) => panic!("first request existing"),
        };
        let second = match registry
            .begin_request(spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "second",
                "two",
                Some(session_id),
            ))
            .expect("second")
        {
            BeginRequestResult::Created(request) => request.operations[0].action_sequence,
            BeginRequestResult::Existing(_) => panic!("second request existing"),
        };
        assert_eq!((first, second), (0, 1));
    }

    #[test]
    fn lost_boundary_fails_operation_and_blocks_its_target() {
        let registry = Registry::new();
        let principal = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let request_id = Uuid::now_v7();
        registry
            .begin_request(spec(
                principal,
                request_id,
                operation_id,
                "first",
                "one",
                Some(session_id),
            ))
            .expect("request");
        registry.prepare_dispatch(operation_id).expect("prepared");
        registry.mark_dispatched(operation_id).expect("dispatched");
        registry
            .record_lost_boundary(operation_id, FailureCode::ExtensionDisconnected)
            .expect("lost boundary");
        let operation = registry
            .operation(operation_id)
            .expect("operation")
            .expect("record");
        assert_eq!(operation.state, OperationState::Failed);
        let request = registry
            .request(request_id)
            .expect("request")
            .expect("record");
        assert_eq!(request.state, RequestState::Failed);
        assert_eq!(
            request.failure_code,
            Some(FailureCode::ExtensionDisconnected)
        );
        let blocked = registry
            .begin_request(spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                "second",
                "two",
                Some(session_id),
            ))
            .expect_err("blocked target");
        assert_eq!(blocked.code(), FailureCode::TargetLost);
        assert_eq!(registry.dispatched_count().expect("count"), 1);
    }
    #[test]
    fn lost_tab_blocks_mutations_but_not_reads_or_other_tabs() {
        let registry = Registry::new();
        let principal = Uuid::now_v7();
        let tab_a = Uuid::now_v7();
        let tab_b = Uuid::now_v7();
        let failed_operation = Uuid::now_v7();
        let failed_request = Uuid::now_v7();
        registry
            .preallocate_session(SessionSpec {
                session_id: tab_a,
                mcp_principal_id: principal,
                pairing_id: Uuid::now_v7(),
                browser: "chromium".to_owned(),
                profile: "profile".to_owned(),
                window: "window-a".to_owned(),
            })
            .expect("tab A");
        registry
            .preallocate_session(SessionSpec {
                session_id: tab_b,
                mcp_principal_id: principal,
                pairing_id: Uuid::now_v7(),
                browser: "chromium".to_owned(),
                profile: "profile".to_owned(),
                window: "window-b".to_owned(),
            })
            .expect("tab B");
        registry
            .begin_request(spec(
                principal,
                failed_request,
                failed_operation,
                "failed",
                "failed",
                Some(tab_a),
            ))
            .expect("failed request");
        registry
            .prepare_dispatch(failed_operation)
            .expect("prepared");
        registry
            .mark_dispatched(failed_operation)
            .expect("dispatched");
        registry
            .record_lost_boundary(failed_operation, FailureCode::TargetLost)
            .expect("lost target");

        let mut other_a = spec(
            principal,
            Uuid::now_v7(),
            Uuid::now_v7(),
            "other-a",
            "other-a",
            Some(tab_a),
        );
        other_a.tool = "navigate".to_owned();
        assert_eq!(
            registry
                .begin_request(other_a)
                .expect_err("tab A mutation blocked")
                .code(),
            FailureCode::TargetLost
        );

        for (tool, key) in [
            ("element_click", "tab-b-click"),
            ("element_type", "tab-b-type"),
            ("session_get", "tab-b-observe"),
        ] {
            let mut request = spec(
                principal,
                Uuid::now_v7(),
                Uuid::now_v7(),
                key,
                key,
                Some(tab_b),
            );
            request.tool = tool.to_owned();
            assert!(matches!(
                registry.begin_request(request).expect("tab B request"),
                BeginRequestResult::Created(_)
            ));
        }
        let mut read_a = spec(
            principal,
            Uuid::now_v7(),
            Uuid::now_v7(),
            "tab-a-read",
            "tab-a-read",
            Some(tab_a),
        );
        read_a.tool = "session_get".to_owned();
        assert!(matches!(
            registry.begin_request(read_a).expect("tab A read"),
            BeginRequestResult::Created(_)
        ));
    }
}
