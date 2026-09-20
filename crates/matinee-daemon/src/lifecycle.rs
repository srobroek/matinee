//! Daemon ownership and lifecycle transitions.
//!
//! The state-directory lock is the only process-external resource. All daemon
//! records are held by the in-memory registry and disappear when the process
//! exits. [`Daemon::dispatch`] and [`Daemon::stop`] share one admission mutex,
//! so a stop cannot race an operation across the in-run dispatch boundary.

use crate::failure::FailureCode;
use crate::registry::{BeginRequestResult, Registry, RegistryError, RequestSpec, TerminalResult};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Lifecycle state of a running daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Ownership is held while the in-memory registry initializes.
    Starting,
    /// New requests and dispatch admission are accepted.
    Ready,
    /// New admission is closed while the process exits.
    Draining,
    /// Ownership or in-memory state failed and no work may be dispatched.
    Failed,
}

impl LifecycleState {
    /// Returns the stable lifecycle wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Draining => "draining",
            Self::Failed => "failed",
        }
    }
}

/// A lifecycle error with a stable public failure code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleError {
    code: FailureCode,
    detail: String,
}

impl LifecycleError {
    fn from_registry(error: RegistryError) -> Self {
        Self {
            code: error.code(),
            detail: error.detail().to_owned(),
        }
    }

    fn not_ready(detail: impl Into<String>) -> Self {
        Self {
            code: FailureCode::StorageUnavailable,
            detail: detail.into(),
        }
    }

    /// Returns the stable failure code.
    pub const fn code(&self) -> FailureCode {
        self.code
    }

    /// Returns the stable failure code.
    pub const fn failure_code(&self) -> FailureCode {
        self.code
    }

    /// Returns a local diagnostic detail.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for LifecycleError {}

/// The result of an authorized stop request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopResult {
    /// Admission closed and the daemon abandoned its in-memory work.
    Clean,
}

impl StopResult {
    /// Returns the failure code represented by this result, if any.
    pub const fn failure_code(self) -> Option<FailureCode> {
        match self {
            Self::Clean => None,
        }
    }
}

/// Exclusive ownership of a state directory for one daemon process.
#[derive(Debug)]
pub struct StateDirectoryLock {
    file: File,
    path: PathBuf,
}

impl StateDirectoryLock {
    /// Acquires exclusive ownership of `state_dir`.
    pub fn acquire(state_dir: impl AsRef<Path>) -> Result<Self, LifecycleError> {
        let state_dir = state_dir.as_ref();
        fs::create_dir_all(state_dir).map_err(|error| LifecycleError {
            code: FailureCode::StorageUnavailable,
            detail: error.to_string(),
        })?;
        let canonical = state_dir.canonicalize().map_err(|error| LifecycleError {
            code: FailureCode::StorageUnavailable,
            detail: error.to_string(),
        })?;
        let path = canonical.join(".daemon.lock");

        #[cfg(unix)]
        let file = {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|error| LifecycleError {
                    code: FailureCode::StorageUnavailable,
                    detail: error.to_string(),
                })?;
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                return Err(
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
                        LifecycleError {
                            code: FailureCode::DaemonStartConflict,
                            detail: "state directory is owned".to_owned(),
                        }
                    } else {
                        LifecycleError {
                            code: FailureCode::StorageUnavailable,
                            detail: std::io::Error::last_os_error().to_string(),
                        }
                    },
                );
            }
            file
        };

        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&path)
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        LifecycleError {
                            code: FailureCode::DaemonStartConflict,
                            detail: "state directory is owned".to_owned(),
                        }
                    } else {
                        LifecycleError {
                            code: FailureCode::StorageUnavailable,
                            detail: error.to_string(),
                        }
                    }
                })?
        };

        #[cfg(all(not(unix), not(windows)))]
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| LifecycleError {
                code: FailureCode::StorageUnavailable,
                detail: error.to_string(),
            })?;

        let mut lock = Self { file, path };
        lock.write_identity()?;
        Ok(lock)
    }

    /// Returns the lock-file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_identity(&mut self) -> Result<(), LifecycleError> {
        self.file.set_len(0).map_err(|error| LifecycleError {
            code: FailureCode::StorageUnavailable,
            detail: error.to_string(),
        })?;
        let identity = format!("pid={}\nstarted_at={}\n", std::process::id(), now_ms());
        self.file
            .write_all(identity.as_bytes())
            .map_err(|error| LifecycleError {
                code: FailureCode::StorageUnavailable,
                detail: error.to_string(),
            })?;
        self.file.sync_all().map_err(|error| LifecycleError {
            code: FailureCode::StorageUnavailable,
            detail: error.to_string(),
        })
    }
}

impl Drop for StateDirectoryLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// A running daemon with exclusive state ownership.
pub struct Daemon {
    registry: Registry,
    lock: StateDirectoryLock,
    lifecycle: Mutex<LifecycleState>,
    admission: Mutex<()>,
    instance_id: Uuid,
}

impl Daemon {
    /// Acquires ownership, creates an empty registry, and transitions to `ready`.
    pub fn start(state_dir: impl AsRef<Path>) -> Result<Self, LifecycleError> {
        let lock = StateDirectoryLock::acquire(state_dir)?;
        Ok(Self {
            registry: Registry::new(),
            lock,
            lifecycle: Mutex::new(LifecycleState::Ready),
            admission: Mutex::new(()),
            instance_id: Uuid::now_v7(),
        })
    }

    /// Returns the daemon's current lifecycle state.
    pub fn state(&self) -> Result<LifecycleState, LifecycleError> {
        Ok(*self.lifecycle_guard()?)
    }

    /// Returns the process-lifetime daemon instance identity.
    pub const fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    /// Returns the in-memory registry owned by this daemon.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Rejects a request from a daemon instance other than this one.
    pub fn validate_instance(
        &self,
        client_instance_id: Uuid,
        last_action_sequence: i64,
    ) -> Result<(), LifecycleError> {
        if client_instance_id == self.instance_id {
            return Ok(());
        }
        Err(LifecycleError {
            code: FailureCode::DaemonRestarted,
            detail: format!(
                "prior action sequence {last_action_sequence} outcome is unobserved; daemon retains no state"
            ),
        })
    }

    /// Begins an idempotent request after validating the client's instance pin.
    pub fn begin_request(
        &self,
        client_instance_id: Uuid,
        last_action_sequence: i64,
        spec: RequestSpec,
    ) -> Result<BeginRequestResult, LifecycleError> {
        let _admission = self.admission_guard()?;
        if *self.lifecycle_guard()? != LifecycleState::Ready {
            return Err(LifecycleError::not_ready(
                "daemon is not ready for new work",
            ));
        }
        self.validate_instance(client_instance_id, last_action_sequence)?;
        self.registry
            .begin_request(spec)
            .map_err(LifecycleError::from_registry)
    }

    /// Commits a terminal result while the daemon is ready or draining.
    pub fn commit_terminal_result(
        &self,
        operation_id: Uuid,
        result: TerminalResult,
    ) -> Result<(), LifecycleError> {
        let state = self.state()?;
        if state == LifecycleState::Failed || state == LifecycleState::Starting {
            return Err(LifecycleError::not_ready(
                "daemon is not accepting terminal results",
            ));
        }
        self.registry
            .commit_terminal_result(operation_id, result)
            .map_err(LifecycleError::from_registry)
    }

    /// Records a failed operation when its outcome boundary is lost.
    pub fn record_lost_boundary(
        &self,
        operation_id: Uuid,
        failure_code: FailureCode,
    ) -> Result<(), LifecycleError> {
        self.registry
            .record_lost_boundary(operation_id, failure_code)
            .map_err(LifecycleError::from_registry)
    }

    /// Atomically prepares and crosses dispatch admission for one operation.
    pub fn dispatch(&self, operation_id: Uuid) -> Result<(), LifecycleError> {
        let _admission = self.admission_guard()?;
        if *self.lifecycle_guard()? != LifecycleState::Ready {
            return Err(LifecycleError::not_ready(
                "daemon is not ready for dispatch",
            ));
        }
        self.registry
            .prepare_dispatch(operation_id)
            .map_err(LifecycleError::from_registry)?;
        self.registry
            .mark_dispatched(operation_id)
            .map_err(LifecycleError::from_registry)?;
        Ok(())
    }

    /// Alias using the protocol's preflight wording.
    pub fn preflight_to_dispatch(&self, operation_id: Uuid) -> Result<(), LifecycleError> {
        self.dispatch(operation_id)
    }

    /// Closes admission, abandons undispatched in-memory work, and returns.
    pub fn stop(&self) -> Result<StopResult, LifecycleError> {
        let _admission = self.admission_guard()?;
        {
            let mut state = self.lifecycle_guard()?;
            match *state {
                LifecycleState::Ready | LifecycleState::Draining => {
                    *state = LifecycleState::Draining
                }
                LifecycleState::Starting | LifecycleState::Failed => {
                    return Err(LifecycleError::not_ready(
                        "daemon cannot stop from current state",
                    ));
                }
            }
        }
        self.registry
            .cancel_undispatched()
            .map_err(LifecycleError::from_registry)?;
        Ok(StopResult::Clean)
    }

    /// Returns the lock identity held by the daemon.
    pub fn lock_path(&self) -> &Path {
        self.lock.path()
    }

    fn lifecycle_guard(&self) -> Result<MutexGuard<'_, LifecycleState>, LifecycleError> {
        self.lifecycle
            .lock()
            .map_err(|_| LifecycleError::not_ready("lifecycle mutex poisoned"))
    }

    fn admission_guard(&self) -> Result<MutexGuard<'_, ()>, LifecycleError> {
        self.admission
            .lock()
            .map_err(|_| LifecycleError::not_ready("admission mutex poisoned"))
    }
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
    use crate::record::OperationState;
    use crate::registry::{BeginRequestResult, OperationSpec};
    use std::fs;
    use std::sync::Arc;

    fn temp_state() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "matinee-lifecycle-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&path).expect("state");
        path
    }

    fn request(principal: Uuid) -> RequestSpec {
        RequestSpec {
            request_id: Uuid::now_v7(),
            mcp_principal_id: principal,
            tool: "element_click".to_owned(),
            idempotency_key: Uuid::now_v7().to_string(),
            fingerprint: "request-fingerprint".to_owned(),
            deadline_ms: 0,
            effect_hint: "mutate".to_owned(),
            operations: vec![OperationSpec {
                operation_id: Uuid::now_v7(),
                sequence: 0,
                session_id: None,
                target_descriptor: "{}".to_owned(),
                fingerprint: "operation-fingerprint".to_owned(),
                state: OperationState::Planned,
                session: None,
            }],
        }
    }

    #[test]
    fn ownership_conflict_returns_start_conflict() {
        let path = temp_state();
        let first = StateDirectoryLock::acquire(&path).expect("first lock");
        let second = StateDirectoryLock::acquire(&path).expect_err("conflict");
        assert_eq!(second.code(), FailureCode::DaemonStartConflict);
        drop(first);
        let released = StateDirectoryLock::acquire(&path).expect("released lock");
        drop(released);
        fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn stale_instance_names_unobserved_action_and_no_state() {
        let path = temp_state();
        let daemon = Daemon::start(&path).expect("daemon");
        let error = daemon
            .validate_instance(Uuid::now_v7(), 17)
            .expect_err("stale instance");
        assert_eq!(error.code(), FailureCode::DaemonRestarted);
        assert!(error.detail().contains("17"));
        assert!(error.detail().contains("outcome is unobserved"));
        assert!(error.detail().contains("daemon retains no state"));
        fs::remove_dir_all(path).expect("cleanup");
    }

    /// A stop racing a dispatch must resolve to exactly one winner. Either order
    /// is legal; what SC-016 forbids is a dispatch that proceeds after stop won.
    #[test]
    fn stop_and_dispatch_share_one_admission_boundary() {
        for _ in 0..64 {
            let path = temp_state();
            let daemon = Arc::new(Daemon::start(&path).expect("daemon"));
            let principal = Uuid::now_v7();
            let spec = request(principal);
            let operation_id = match daemon
                .begin_request(daemon.instance_id(), 0, spec)
                .expect("request")
            {
                BeginRequestResult::Created(request) => request.operations[0].operation_id,
                BeginRequestResult::Existing(_) => panic!("new request existing"),
            };
            let left = Arc::clone(&daemon);
            let right = Arc::clone(&daemon);
            let stop = std::thread::spawn(move || left.stop().expect("stop"));
            let dispatch = std::thread::spawn(move || right.dispatch(operation_id));
            assert_eq!(stop.join().expect("stop join"), StopResult::Clean);
            let dispatched = dispatch.join().expect("dispatch join").is_ok();
            let state = daemon
                .registry()
                .operation(operation_id)
                .expect("registry readable")
                .expect("operation survives the race")
                .state;
            if dispatched {
                assert_eq!(
                    state,
                    OperationState::Dispatching,
                    "a winning dispatch must leave the operation dispatching"
                );
            } else {
                assert_ne!(
                    state,
                    OperationState::Dispatching,
                    "a losing dispatch must not reach the browser"
                );
            }
            drop(daemon);
            fs::remove_dir_all(path).expect("cleanup");
        }
    }

    #[test]
    fn each_start_gets_a_fresh_instance_identity() {
        let path = temp_state();
        let first = Daemon::start(&path).expect("first daemon");
        let first_id = first.instance_id();
        drop(first);
        let second = Daemon::start(&path).expect("second daemon");
        assert_ne!(first_id, second.instance_id());
        drop(second);
        fs::remove_dir_all(path).expect("cleanup");
    }
}
