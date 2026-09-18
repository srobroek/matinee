//! Typed identity and lifecycle values shared by the security boundary.
//!
//! This module deliberately contains identifiers and references only. Private key
//! bytes, enrollment secrets, and derived key material have no representation here.

use core::fmt;

use serde::de::{self, Visitor};
use serde::ser;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
            || !value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        { return Err("fingerprint must be 64 lowercase hexadecimal bytes"); }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str { &self.0 }

    /// Lowercase SHA-256 over exactly the 65 SEC1 public-key bytes.
    pub fn from_public_key(key: &PublicKey) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
        let mut text = String::with_capacity(64);
        for byte in digest.as_ref() { use core::fmt::Write; write!(&mut text, "{byte:02x}").unwrap(); }
        Self(text)
    }
}

/// Bytes in an uncompressed SEC1 P-256 point.
pub const UNCOMPRESSED_KEY_BYTES: usize = 65;
const UNCOMPRESSED_KEY_HEX: usize = UNCOMPRESSED_KEY_BYTES * 2;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// A public key. This is the only key representation in this module: no private,
/// one-time, or derived key byte has one here.
///
/// `serde` derives no array impl at this length, so the serialized form is the exact
/// lowercase-hex encoding of the 65 bytes. Deserialization accepts only that one
/// shape: a wrong length, a non-hex or uppercase character, or a missing `0x04`
/// prefix is rejected instead of being padded, truncated, or reinterpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; UNCOMPRESSED_KEY_BYTES]);
impl PublicKey {
    pub fn from_uncompressed(bytes: [u8; UNCOMPRESSED_KEY_BYTES]) -> Result<Self, &'static str> {
        if p256::PublicKey::from_sec1_bytes(&bytes).is_err() {
            return Err("public key must be a valid uncompressed P-256 point");
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; UNCOMPRESSED_KEY_BYTES] {
        &self.0
    }
    /// The exact serialized representation: lowercase-hex ASCII of the fixed 65 bytes.
    pub fn uncompressed_hex(&self) -> [u8; UNCOMPRESSED_KEY_HEX] {
        let mut hex = [0u8; UNCOMPRESSED_KEY_HEX];
        for (byte, digits) in self.0.iter().zip(hex.chunks_exact_mut(2)) {
            digits[0] = HEX_DIGITS[usize::from(byte >> 4)];
            digits[1] = HEX_DIGITS[usize::from(byte & 0x0f)];
        }
        hex
    }
    fn from_uncompressed_hex(text: &str) -> Result<Self, &'static str> {
        let hex = text.as_bytes();
        if hex.len() != UNCOMPRESSED_KEY_HEX {
            return Err("public key must be 130 lowercase hexadecimal characters");
        }
        let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
        for (digits, byte) in hex.chunks_exact(2).zip(bytes.iter_mut()) {
            let high = hex_digit(digits[0]).ok_or("public key is not lowercase hexadecimal")?;
            let low = hex_digit(digits[1]).ok_or("public key is not lowercase hexadecimal")?;
            *byte = (high << 4) | low;
        }
        Self::from_uncompressed(bytes)
    }
}

const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex = self.uncompressed_hex();
        let text = core::str::from_utf8(&hex).map_err(ser::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UncompressedHex;
        impl<'v> Visitor<'v> for UncompressedHex {
            type Value = PublicKey;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "130 lowercase hexadecimal characters encoding an uncompressed P-256 public key",
                )
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<PublicKey, E> {
                PublicKey::from_uncompressed_hex(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(UncompressedHex)
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
    pub(crate) fn client_nonce(&self) -> [u8; 12] { self.client_nonce }
    pub(crate) fn daemon_nonce(&self) -> [u8; 12] { self.daemon_nonce }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error as ValueError, StrDeserializer};
    fn public_key_bytes() -> [u8; UNCOMPRESSED_KEY_BYTES] {
        [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
            0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
            0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ]
    }

    fn public_key() -> PublicKey {
        PublicKey::from_uncompressed(public_key_bytes()).expect("uncompressed prefix")
    }

    fn deserialize_key(text: &str) -> Result<PublicKey, ValueError> {
        PublicKey::deserialize(StrDeserializer::<ValueError>::new(text))
    }

    fn daemon() -> DaemonIdentity {
        let id = IdentityId::new(Uuid::from_u128(1));
        let credential = CredentialReference::new("apple-keychain", "matinee/daemon", id, id)
            .expect("bounded credential reference");
        DaemonIdentity::new(
            id,
            public_key(),
            Fingerprint::new("a".repeat(64)).expect("64 lowercase hex digits"),
            "127.0.0.1:7777",
            1,
            1,
            credential,
        )
        .expect("valid daemon binding")
    }

    fn assert_serde<T: Serialize + serde::de::DeserializeOwned>() {}

    #[test]
    fn every_typed_identity_is_serde_compatible() {
        assert_serde::<PublicKey>();
        assert_serde::<Fingerprint>();
        assert_serde::<IdentityId>();
        assert_serde::<ConnectionId>();
        assert_serde::<TransitionId>();
        assert_serde::<IdempotencyKey>();
        assert_serde::<CredentialReference>();
        assert_serde::<DaemonIdentity>();
        assert_serde::<Principal>();
        assert_serde::<Capability>();
        assert_serde::<ExtensionGrant>();
        assert_serde::<ExtensionEnrollment>();
        assert_serde::<Connection>();
        assert_serde::<TransitionInput>();
        assert_serde::<ExpiryResult>();
        assert_serde::<RotationTransition>();
        assert_serde::<RevocationTransition>();
    }

    #[test]
    fn public_key_serialized_form_is_exactly_the_public_point() {
        let key = public_key();
        let hex = key.uncompressed_hex();
        let text = core::str::from_utf8(&hex).expect("hex is ascii");
        assert_eq!(text.len(), UNCOMPRESSED_KEY_BYTES * 2);
        assert!(text.starts_with("04"));
        assert_eq!(&text[2..6], "6b17");
        assert_eq!(deserialize_key(text).expect("round trip"), key);
    }

    #[test]
    fn wrong_length_or_malformed_public_key_is_rejected() {
        let key = public_key();
        let hex = key.uncompressed_hex();
        let canonical = core::str::from_utf8(&hex).expect("hex is ascii").to_owned();

        for rejected in [
            String::new(),
            canonical[..canonical.len() - 1].to_owned(),
            canonical[..canonical.len() - 2].to_owned(),
            format!("{canonical}00"),
            canonical.to_ascii_uppercase(),
            format!("zz{}", &canonical[2..]),
            format!("02{}", &canonical[2..]),
        ] {
            assert!(
                deserialize_key(&rejected).is_err(),
                "accepted a malformed key of {} characters",
                rejected.len()
            );
        }

        let mut compressed = public_key_bytes();
        compressed[0] = 0x02;
        assert!(PublicKey::from_uncompressed(compressed).is_err());
    }

    #[test]
    fn fingerprint_rejects_wrong_length_and_uppercase() {
        assert!(Fingerprint::new("a".repeat(63)).is_err());
        assert!(Fingerprint::new("a".repeat(65)).is_err());
        assert!(Fingerprint::new("A".repeat(64)).is_err());
        assert!(Fingerprint::new("g".repeat(64)).is_err());
    }

    #[test]
    fn public_material_accessors_borrow_instead_of_copying() {
        let daemon = daemon();
        let borrowed = &daemon;
        assert!(core::ptr::eq(
            borrowed.public_key().as_bytes().as_ptr(),
            daemon.public_key().as_bytes().as_ptr()
        ));
        assert!(core::ptr::eq(
            borrowed.fingerprint().as_str().as_ptr(),
            daemon.fingerprint().as_str().as_ptr()
        ));
        assert!(core::ptr::eq(
            borrowed.endpoint().as_ptr(),
            daemon.endpoint().as_ptr()
        ));
    }

    #[test]
    fn outcome_and_status_accessors_read_through_a_shared_reference() {
        let expiry = ExpiryResult::valid(1_000).expect("bounded deadline");
        let shared = &expiry;
        assert_eq!(shared.status(), ExpiryStatus::Valid);
        assert!(shared.is_valid());

        let id = IdentityId::new(Uuid::from_u128(2));
        let transition = TransitionInput::new(
            id,
            TransitionId::new(Uuid::from_u128(3)),
            TransitionOperation::Rotation,
            IdempotencyKey::new(Uuid::from_u128(4)),
            7,
            TransitionOutcome::Unknown,
        );
        let shared = &transition;
        assert_eq!(shared.outcome(), TransitionOutcome::Unknown);
        assert!(shared.is_fail_closed());
        assert!(!shared.may_persist());

        let rotation = RotationTransition::new(
            IdempotencyKey::new(Uuid::from_u128(5)),
            id,
            Fingerprint::new("a".repeat(64)).expect("64 lowercase hex digits"),
            Fingerprint::new("b".repeat(64)).expect("64 lowercase hex digits"),
            7,
            8,
            1_000,
            TransitionOutcome::Committed,
        )
        .expect("valid rotation boundary");
        let shared = &rotation;
        assert_eq!(shared.outcome(), TransitionOutcome::Committed);

        let revocation = RevocationTransition::new(
            IdempotencyKey::new(Uuid::from_u128(6)),
            id,
            "administrator",
            8,
            1,
            2,
            TransitionOutcome::AlreadyCommitted,
        )
        .expect("bounded revocation reason");
        let shared = &revocation;
        assert_eq!(shared.outcome(), TransitionOutcome::AlreadyCommitted);
    }

    #[test]
    fn rotation_requires_a_new_epoch_and_a_new_fingerprint() {
        let id = IdentityId::new(Uuid::from_u128(7));
        let same = Fingerprint::new("c".repeat(64)).expect("64 lowercase hex digits");
        assert!(RotationTransition::new(
            IdempotencyKey::new(Uuid::from_u128(8)),
            id,
            same.clone(),
            same,
            7,
            7,
            1_000,
            TransitionOutcome::Committed,
        )
        .is_err());
    }
}
