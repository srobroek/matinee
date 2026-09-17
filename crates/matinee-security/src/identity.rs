//! Typed identity and lifecycle values shared by the security boundary.
//!
//! This module deliberately contains identifiers and references only. Private key
//! bytes, enrollment secrets, and derived key material have no representation here.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct IdentityId(Uuid);
impl IdentityId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
    pub fn get(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ConnectionId(Uuid);
impl ConnectionId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
    pub fn get(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TransitionId(Uuid);
impl TransitionId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
    pub fn get(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(Uuid);
impl IdempotencyKey {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }
    pub fn get(self) -> Uuid {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint(String);
impl Fingerprint {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("fingerprint must be 64 lowercase hexadecimal bytes");
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey([u8; 65]);
impl PublicKey {
    pub fn from_uncompressed(bytes: [u8; 65]) -> Result<Self, &'static str> {
        if bytes[0] != 0x04 {
            return Err("public key must be uncompressed P-256");
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DaemonLifecycle {
    Staged,
    Active,
    Replaced,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrincipalKind {
    NativeAdmin,
    McpClient,
    BrowserExtension,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrincipalLifecycle {
    Pending,
    Active,
    Rotating,
    Revoked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EnrollmentLifecycle {
    Pending,
    Consumed,
    Closed,
    Expired,
    Revoked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConnectionLifecycle {
    Handshaking,
    Authenticated,
    Closing,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GrantLifecycle {
    Active,
    Closed,
    Revoked,
}

/// A non-secret locator. It is never a private-key container.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialReference {
    provider: String,
    key_locator: String,
    daemon: IdentityId,
    state_directory: IdentityId,
}
impl CredentialReference {
    pub fn new(
        provider: impl Into<String>,
        key_locator: impl Into<String>,
        daemon: IdentityId,
        state_directory: IdentityId,
    ) -> Result<Self, &'static str> {
        let provider = provider.into();
        let key_locator = key_locator.into();
        if provider.is_empty()
            || provider.len() > 64
            || key_locator.is_empty()
            || key_locator.len() > 256
        {
            return Err("credential reference is empty or exceeds its bound");
        }
        Ok(Self {
            provider,
            key_locator,
            daemon,
            state_directory,
        })
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn key_locator(&self) -> &str {
        &self.key_locator
    }
    pub fn daemon(&self) -> IdentityId {
        self.daemon
    }
    pub fn state_directory(&self) -> IdentityId {
        self.state_directory
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DaemonIdentity {
    id: IdentityId,
    public_key: PublicKey,
    fingerprint: Fingerprint,
    endpoint: String,
    contract_min: u16,
    contract_max: u16,
    credential: CredentialReference,
    lifecycle: DaemonLifecycle,
}
impl DaemonIdentity {
    pub fn new(
        id: IdentityId,
        public_key: PublicKey,
        fingerprint: Fingerprint,
        endpoint: impl Into<String>,
        contract_min: u16,
        contract_max: u16,
        credential: CredentialReference,
    ) -> Result<Self, &'static str> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() || contract_min > contract_max || credential.daemon() != id {
            return Err("invalid daemon identity binding");
        }
        Ok(Self {
            id,
            public_key,
            fingerprint,
            endpoint,
            contract_min,
            contract_max,
            credential,
            lifecycle: DaemonLifecycle::Staged,
        })
    }
    pub fn id(&self) -> IdentityId {
        self.id
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn lifecycle(&self) -> DaemonLifecycle {
        self.lifecycle
    }
    pub fn activate(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != DaemonLifecycle::Staged {
            return Err("daemon is not staged");
        }
        self.lifecycle = DaemonLifecycle::Active;
        Ok(())
    }
    pub fn replace(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != DaemonLifecycle::Active {
            return Err("daemon is not active");
        }
        self.lifecycle = DaemonLifecycle::Replaced;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    id: IdentityId,
    kind: PrincipalKind,
    public_key: PublicKey,
    fingerprint: Fingerprint,
    owner: IdentityId,
    ceiling: Vec<Capability>,
    lifecycle: PrincipalLifecycle,
    epoch: u64,
    credential: CredentialReference,
}
impl Principal {
    pub fn new(
        id: IdentityId,
        kind: PrincipalKind,
        public_key: PublicKey,
        fingerprint: Fingerprint,
        owner: IdentityId,
        ceiling: Vec<Capability>,
        credential: CredentialReference,
    ) -> Result<Self, &'static str> {
        if ceiling.is_empty() || credential.daemon() != owner {
            return Err("invalid principal binding");
        }
        Ok(Self {
            id,
            kind,
            public_key,
            fingerprint,
            owner,
            ceiling,
            lifecycle: PrincipalLifecycle::Pending,
            epoch: 0,
            credential,
        })
    }
    pub fn id(&self) -> IdentityId {
        self.id
    }
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }
    pub fn owner(&self) -> IdentityId {
        self.owner
    }
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn lifecycle(&self) -> PrincipalLifecycle {
        self.lifecycle
    }
    pub fn ceiling(&self) -> &[Capability] {
        &self.ceiling
    }
    pub fn activate(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != PrincipalLifecycle::Pending {
            return Err("principal is not pending");
        }
        self.lifecycle = PrincipalLifecycle::Active;
        Ok(())
    }
    pub fn begin_rotation(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != PrincipalLifecycle::Active {
            return Err("principal is not active");
        }
        self.lifecycle = PrincipalLifecycle::Rotating;
        Ok(())
    }
    pub fn complete_rotation(
        &mut self,
        fingerprint: Fingerprint,
        credential: CredentialReference,
    ) -> Result<(), &'static str> {
        if self.lifecycle != PrincipalLifecycle::Rotating || credential.daemon() != self.owner {
            return Err("rotation is not valid");
        }
        self.fingerprint = fingerprint;
        self.credential = credential;
        self.epoch = self.epoch.checked_add(1).ok_or("epoch exhausted")?;
        self.lifecycle = PrincipalLifecycle::Active;
        Ok(())
    }
    pub fn revoke(&mut self) {
        self.lifecycle = PrincipalLifecycle::Revoked;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CapabilityAction {
    Read,
    Write,
    Execute,
    Administer,
    ManagePrincipals,
    Rotate,
    Revoke,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    action: CapabilityAction,
    resource_scope: String,
}
impl Capability {
    pub fn new(action: CapabilityAction, scope: impl Into<String>) -> Result<Self, &'static str> {
        let scope = scope.into();
        if scope.is_empty() || scope.len() > 256 {
            return Err("invalid capability scope");
        }
        Ok(Self {
            action,
            resource_scope: scope,
        })
    }
    pub fn action(&self) -> &CapabilityAction {
        &self.action
    }
    pub fn resource_scope(&self) -> &str {
        &self.resource_scope
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionGrant {
    extension: IdentityId,
    owner: IdentityId,
    capabilities: Vec<Capability>,
    epoch: u64,
    lifecycle: GrantLifecycle,
}
impl ExtensionGrant {
    pub fn new(
        extension: IdentityId,
        owner: IdentityId,
        capabilities: Vec<Capability>,
        epoch: u64,
    ) -> Result<Self, &'static str> {
        if capabilities.is_empty() {
            return Err("grant must contain capabilities");
        }
        Ok(Self {
            extension,
            owner,
            capabilities,
            epoch,
            lifecycle: GrantLifecycle::Active,
        })
    }
    pub fn extension(&self) -> IdentityId {
        self.extension
    }
    pub fn owner(&self) -> IdentityId {
        self.owner
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
    pub fn lifecycle(&self) -> GrantLifecycle {
        self.lifecycle
    }
    pub fn revoke(&mut self) {
        self.lifecycle = GrantLifecycle::Revoked
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionEnrollment {
    id: TransitionId,
    origin: String,
    extension_metadata: String,
    daemon: IdentityId,
    endpoint: String,
    public_key_fingerprint: Fingerprint,
    expiry: ExpiryResult,
    failed_proofs: u8,
    lifecycle: EnrollmentLifecycle,
}
impl ExtensionEnrollment {
    pub fn new(
        id: TransitionId,
        origin: impl Into<String>,
        metadata: impl Into<String>,
        daemon: IdentityId,
        endpoint: impl Into<String>,
        fingerprint: Fingerprint,
        expiry: ExpiryResult,
    ) -> Result<Self, &'static str> {
        let origin = origin.into();
        let extension_metadata = metadata.into();
        let endpoint = endpoint.into();
        if origin.is_empty()
            || extension_metadata.is_empty()
            || endpoint.is_empty()
            || !expiry.is_valid()
        {
            return Err("invalid enrollment");
        };
        Ok(Self {
            id,
            origin,
            extension_metadata,
            daemon,
            endpoint,
            public_key_fingerprint: fingerprint,
            expiry,
            failed_proofs: 0,
            lifecycle: EnrollmentLifecycle::Pending,
        })
    }
    pub fn lifecycle(&self) -> EnrollmentLifecycle {
        self.lifecycle
    }
    pub fn failed_proofs(&self) -> u8 {
        self.failed_proofs
    }
    pub fn consume(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != EnrollmentLifecycle::Pending {
            return Err("enrollment is not pending");
        }
        self.lifecycle = EnrollmentLifecycle::Consumed;
        Ok(())
    }
    pub fn record_failed_proof(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != EnrollmentLifecycle::Pending {
            return Err("enrollment is not pending");
        }
        self.failed_proofs = self.failed_proofs.saturating_add(1);
        if self.failed_proofs >= 5 {
            self.lifecycle = EnrollmentLifecycle::Closed
        }
        Ok(())
    }
    pub fn expire(&mut self) {
        if self.lifecycle == EnrollmentLifecycle::Pending {
            self.lifecycle = EnrollmentLifecycle::Expired
        }
    }
    pub fn revoke(&mut self) {
        if self.lifecycle == EnrollmentLifecycle::Pending {
            self.lifecycle = EnrollmentLifecycle::Revoked
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    id: ConnectionId,
    principal: IdentityId,
    contract: u16,
    epoch: u64,
    client_nonce: [u8; 12],
    daemon_nonce: [u8; 12],
    client_key: Uuid,
    daemon_key: Uuid,
    send_counter: u64,
    receive_counter: u64,
    send_exhausted: bool,
    receive_exhausted: bool,
    lifecycle: ConnectionLifecycle,
}
impl Connection {
    pub fn new(
        id: ConnectionId,
        principal: IdentityId,
        contract: u16,
        epoch: u64,
        client_nonce: [u8; 12],
        daemon_nonce: [u8; 12],
        client_key: Uuid,
        daemon_key: Uuid,
    ) -> Self {
        Self {
            id,
            principal,
            contract,
            epoch,
            client_nonce,
            daemon_nonce,
            client_key,
            daemon_key,
            send_counter: 0,
            receive_counter: 0,
            send_exhausted: false,
            receive_exhausted: false,
            lifecycle: ConnectionLifecycle::Handshaking,
        }
    }
    pub fn id(&self) -> ConnectionId {
        self.id
    }
    pub fn principal(&self) -> IdentityId {
        self.principal
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn lifecycle(&self) -> ConnectionLifecycle {
        self.lifecycle
    }
    pub fn authenticate(&mut self) -> Result<(), &'static str> {
        if self.lifecycle != ConnectionLifecycle::Handshaking {
            return Err("connection is not handshaking");
        }
        self.lifecycle = ConnectionLifecycle::Authenticated;
        Ok(())
    }
    pub fn close(&mut self) {
        self.lifecycle = ConnectionLifecycle::Closed
    }
    pub fn next_send(&mut self) -> Option<u64> {
        if self.lifecycle != ConnectionLifecycle::Authenticated || self.send_exhausted {
            return None;
        }
        let n = self.send_counter;
        if n == u64::MAX {
            self.send_exhausted = true;
        } else {
            self.send_counter += 1;
        }
        Some(n)
    }
    pub fn next_receive(&mut self) -> Option<u64> {
        if self.lifecycle != ConnectionLifecycle::Authenticated || self.receive_exhausted {
            return None;
        }
        let n = self.receive_counter;
        if n == u64::MAX {
            self.receive_exhausted = true;
        } else {
            self.receive_counter += 1;
        }
        Some(n)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransitionOutcome {
    Committed,
    AlreadyCommitted,
    Rejected,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransitionOperation {
    Bootstrap,
    EnrollmentCreate,
    EnrollmentConsume,
    Rotation,
    Revocation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransitionInput {
    state_directory: IdentityId,
    transition: TransitionId,
    operation: TransitionOperation,
    idempotency: IdempotencyKey,
    prior_epoch: u64,
    outcome: TransitionOutcome,
}
impl TransitionInput {
    pub fn new(
        state_directory: IdentityId,
        transition: TransitionId,
        operation: TransitionOperation,
        idempotency: IdempotencyKey,
        prior_epoch: u64,
        outcome: TransitionOutcome,
    ) -> Self {
        Self {
            state_directory,
            transition,
            operation,
            idempotency,
            prior_epoch,
            outcome,
        }
    }
    pub fn outcome(&self) -> TransitionOutcome {
        self.outcome
    }
    pub fn is_fail_closed(&self) -> bool {
        matches!(self.outcome, TransitionOutcome::Unknown)
    }
    pub fn may_persist(&self) -> bool {
        matches!(
            self.outcome,
            TransitionOutcome::Committed | TransitionOutcome::AlreadyCommitted
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExpiryStatus {
    Valid,
    Expired,
    Uncertain,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpiryResult {
    status: ExpiryStatus,
    deadline_ms: u64,
}
impl ExpiryResult {
    pub fn valid(deadline_ms: u64) -> Result<Self, &'static str> {
        if deadline_ms == 0 {
            Err("deadline must be bounded and nonzero")
        } else {
            Ok(Self {
                status: ExpiryStatus::Valid,
                deadline_ms,
            })
        }
    }
    pub fn expired(deadline_ms: u64) -> Self {
        Self {
            status: ExpiryStatus::Expired,
            deadline_ms,
        }
    }
    pub fn uncertain(deadline_ms: u64) -> Self {
        Self {
            status: ExpiryStatus::Uncertain,
            deadline_ms,
        }
    }
    pub fn status(&self) -> ExpiryStatus {
        self.status
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub fn is_valid(&self) -> bool {
        matches!(self.status, ExpiryStatus::Valid)
    }
    pub fn is_security_valid(&self) -> bool {
        self.is_valid()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationTransition {
    idempotency: IdempotencyKey,
    principal: IdentityId,
    old_fingerprint: Fingerprint,
    new_fingerprint: Fingerprint,
    old_epoch: u64,
    new_epoch: u64,
    effective_boundary: u64,
    outcome: TransitionOutcome,
}
impl RotationTransition {
    pub fn new(
        idempotency: IdempotencyKey,
        principal: IdentityId,
        old_fingerprint: Fingerprint,
        new_fingerprint: Fingerprint,
        old_epoch: u64,
        new_epoch: u64,
        effective_boundary: u64,
        outcome: TransitionOutcome,
    ) -> Result<Self, &'static str> {
        if new_epoch != old_epoch.checked_add(1).ok_or("epoch exhausted")?
            || old_fingerprint == new_fingerprint
        {
            return Err("invalid rotation boundary");
        }
        Ok(Self {
            idempotency,
            principal,
            old_fingerprint,
            new_fingerprint,
            old_epoch,
            new_epoch,
            effective_boundary,
            outcome,
        })
    }
    pub fn outcome(&self) -> TransitionOutcome {
        self.outcome
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevocationTransition {
    idempotency: IdempotencyKey,
    principal: IdentityId,
    reason_class: String,
    epoch: u64,
    invalidated_channels: u32,
    invalidated_grants: u32,
    outcome: TransitionOutcome,
}
impl RevocationTransition {
    pub fn new(
        idempotency: IdempotencyKey,
        principal: IdentityId,
        reason: impl Into<String>,
        epoch: u64,
        channels: u32,
        grants: u32,
        outcome: TransitionOutcome,
    ) -> Result<Self, &'static str> {
        let reason_class = reason.into();
        if reason_class.is_empty() || reason_class.len() > 64 {
            return Err("invalid revocation reason");
        }
        Ok(Self {
            idempotency,
            principal,
            reason_class,
            epoch,
            invalidated_channels: channels,
            invalidated_grants: grants,
            outcome,
        })
    }
    pub fn outcome(&self) -> TransitionOutcome {
        self.outcome
    }
}
