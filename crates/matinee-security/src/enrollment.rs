//! Closed, bounded enrollment creation and binding validation.

use core::fmt;
use std::collections::HashMap;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::SecureRandom;
use ring::signature::KeyPair;
use ring::{digest, rand, signature};

use crate::events::{
    emit_required, EndpointClass, EventBoundary, EventOutcome, EventTime, SafeNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink,
};
use crate::identity::{
    ConnectionId, EnrollmentLifecycle, ExpiryResult, ExpiryStatus, ExtensionEnrollment,
    Fingerprint, IdentityId, PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES,
};

const SECRET_BYTES: usize = 32;
const MAX_EXPIRY_MS: u64 = 10 * 60 * 1_000;
const MAX_ORIGIN_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnrollmentCreation {
    pub(crate) enrollment: TransitionId,
    pub(crate) origin: String,
    pub(crate) store_metadata: String,
    pub(crate) update_metadata: String,
    pub(crate) install_metadata: String,
    pub(crate) daemon: IdentityId,
    pub(crate) daemon_endpoint: String,
    pub(crate) expiry: ExpiryResult,
}

impl EnrollmentCreation {
    pub(crate) fn new(
        enrollment: TransitionId,
        origin: impl Into<String>,
        store_metadata: impl Into<String>,
        update_metadata: impl Into<String>,
        install_metadata: impl Into<String>,
        daemon: IdentityId,
        daemon_endpoint: impl Into<String>,
        expiry: ExpiryResult,
    ) -> Self {
        Self {
            enrollment,
            origin: origin.into(),
            store_metadata: store_metadata.into(),
            update_metadata: update_metadata.into(),
            install_metadata: install_metadata.into(),
            daemon,
            daemon_endpoint: daemon_endpoint.into(),
            expiry,
        }
    }
}

pub(crate) type EnrollmentCreationInput = EnrollmentCreation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentCreateError {
    EmptyOrOversizedOrigin,
    EmptyOrOversizedMetadata,
    EmptyOrOversizedEndpoint,
    InvalidOrigin,
    InvalidEndpoint,
    InvalidInstallMetadata,
    InvalidExpiry,
    KeyGenerationFailed,
    InvalidPublicKey,
    InvalidFingerprint,
}

impl fmt::Display for EnrollmentCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyOrOversizedOrigin | Self::InvalidOrigin => "invalid enrollment origin",
            Self::EmptyOrOversizedMetadata => "invalid enrollment metadata",
            Self::EmptyOrOversizedEndpoint | Self::InvalidEndpoint => "invalid enrollment endpoint",
            Self::InvalidInstallMetadata => "invalid enrollment install metadata",
            Self::InvalidExpiry => "invalid enrollment expiry",
            Self::KeyGenerationFailed => "enrollment key generation failed",
            Self::InvalidPublicKey => "invalid enrollment public key",
            Self::InvalidFingerprint => "invalid enrollment fingerprint",
        })
    }
}

/// A supplied occurrence time is deliberately distinct from the expiry deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnrollmentClock {
    occurrence_ms: u64,
    expiry: ExpiryResult,
}

impl EnrollmentClock {
    pub(crate) fn new(occurrence_ms: u64, expiry: ExpiryResult) -> Self {
        Self { occurrence_ms, expiry }
    }
    pub(crate) fn occurrence_ms(&self) -> u64 { self.occurrence_ms }
    pub(crate) fn expiry(&self) -> &ExpiryResult { &self.expiry }
    fn valid_for(&self, deadline_ms: u64) -> Result<(), EnrollmentConsumeError> {
        if !self.expiry.is_security_valid() {
            return Err(if self.expiry.status() == ExpiryStatus::Uncertain {
                EnrollmentConsumeError::UncertainExpiry
            } else {
                EnrollmentConsumeError::Expired
            });
        }
        if self.expiry.deadline_ms() != deadline_ms || self.occurrence_ms >= deadline_ms {
            return Err(EnrollmentConsumeError::Expired);
        }
        Ok(())
    }
}

pub struct EnrollmentBundle {
    enrollment: ExtensionEnrollment,
    enrollment_id: TransitionId,
    expiry_deadline_ms: u64,
    secret: [u8; SECRET_BYTES],
    one_time_public_key: PublicKey,
    one_time_public_key_fingerprint: Fingerprint,
    one_time_private_key_pkcs8: Option<Vec<u8>>,
    origin: String,
    store_metadata: String,
    update_metadata: String,
    install_metadata: String,
    daemon: IdentityId,
    daemon_endpoint: String,
}

impl fmt::Debug for EnrollmentBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentBundle")
            .field("enrollment", &self.enrollment)
            .field("origin", &self.origin)
            .field("store_metadata", &self.store_metadata)
            .field("update_metadata", &self.update_metadata)
            .field("install_metadata", &self.install_metadata)
            .field("daemon", &self.daemon)
            .field("daemon_endpoint", &self.daemon_endpoint)
            .field("one_time_public_key", &self.one_time_public_key)
            .field("one_time_public_key_fingerprint", &self.one_time_public_key_fingerprint)
            .field("secret", &"<redacted>")
            .field("one_time_private_key_pkcs8", &"<redacted>")
            .finish()
    }
}

impl EnrollmentBundle {
    pub(crate) fn create(input: EnrollmentCreation) -> Result<Self, EnrollmentCreateError> {
        validate_creation(&input)?;
        let rng = rand::SystemRandom::new();
        let mut secret = [0u8; SECRET_BYTES];
        rng.fill(&mut secret).map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng,
        ).map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng,
        ).map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
        let bytes = key_pair.public_key().as_ref();
        if bytes.len() != UNCOMPRESSED_KEY_BYTES { return Err(EnrollmentCreateError::InvalidPublicKey); }
        let mut public_bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
        public_bytes.copy_from_slice(bytes);
        let public_key = PublicKey::from_uncompressed(public_bytes)
            .map_err(|_| EnrollmentCreateError::InvalidPublicKey)?;
        let fingerprint = Fingerprint::new(hex_digest(&public_bytes))
            .map_err(|_| EnrollmentCreateError::InvalidFingerprint)?;
        let metadata = format!("store={};update={};install={}", input.store_metadata, input.update_metadata, input.install_metadata);
        let enrollment = ExtensionEnrollment::new(
            input.enrollment, input.origin.clone(), metadata, input.daemon,
            input.daemon_endpoint.clone(), fingerprint.clone(), input.expiry.clone(),
        ).map_err(|_| EnrollmentCreateError::InvalidExpiry)?;
        Ok(Self {
            enrollment,
            enrollment_id: input.enrollment,
            expiry_deadline_ms: input.expiry.deadline_ms(),
            secret,
            one_time_public_key: public_key,
            one_time_public_key_fingerprint: fingerprint,
            one_time_private_key_pkcs8: Some(pkcs8.as_ref().to_vec()),
            origin: input.origin,
            store_metadata: input.store_metadata,
            update_metadata: input.update_metadata,
            install_metadata: input.install_metadata,
            daemon: input.daemon,
            daemon_endpoint: input.daemon_endpoint,
        })
    }
    pub(crate) fn enrollment(&self) -> &ExtensionEnrollment { &self.enrollment }
    pub(crate) fn lifecycle(&self) -> EnrollmentLifecycle { self.enrollment.lifecycle() }
    pub(crate) fn secret(&self) -> &[u8; SECRET_BYTES] { &self.secret }
    pub(crate) fn one_time_public_key(&self) -> &PublicKey { &self.one_time_public_key }
    pub(crate) fn one_time_public_key_fingerprint(&self) -> &Fingerprint { &self.one_time_public_key_fingerprint }
    pub(crate) fn origin(&self) -> &str { &self.origin }
    pub(crate) fn store_metadata(&self) -> &str { &self.store_metadata }
    pub(crate) fn update_metadata(&self) -> &str { &self.update_metadata }
    pub(crate) fn install_metadata(&self) -> &str { &self.install_metadata }
    pub(crate) fn daemon(&self) -> IdentityId { self.daemon }
    pub(crate) fn daemon_endpoint(&self) -> &str { &self.daemon_endpoint }
    fn mark_failed_proof(&mut self) -> Result<u8, EnrollmentConsumeError> {
        self.enrollment.record_failed_proof().map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        Ok(self.enrollment.failed_proofs())
    }
    pub(crate) fn encrypted_private_key_output(
        &mut self, capability: &AuthenticatedOutputCapability,
    ) -> Result<EncryptedKeyOutput, EnrollmentCustodyError> {
        if !capability.active.load(Ordering::Acquire) { return Err(EnrollmentCustodyError::ChannelNotAuthenticated); }
        let key = self.one_time_private_key_pkcs8.as_ref().ok_or(EnrollmentCustodyError::AlreadyTransferred)?;
        let unbound = UnboundKey::new(&AES_256_GCM, &capability.key).map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        let sealing_key = LessSafeKey::new(unbound);
        let mut ciphertext = key.clone();
        sealing_key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(capability.nonce), Aad::empty(), &mut ciphertext,
        ).map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        self.one_time_private_key_pkcs8.take();
        Ok(EncryptedKeyOutput { connection: capability.connection, epoch: capability.epoch, nonce: capability.nonce, ciphertext })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentCustodyError { ChannelNotAuthenticated, AlreadyTransferred, EncryptionFailed }

pub(crate) struct AuthenticatedOutputCapability {
    connection: ConnectionId,
    epoch: u64,
    key: [u8; 32],
    nonce: [u8; 12],
    active: Arc<AtomicBool>,
}

impl AuthenticatedOutputCapability {
    pub(crate) fn from_authenticated_channel(connection: ConnectionId, epoch: u64, active: Arc<AtomicBool>) -> Result<Self, EnrollmentCustodyError> {
        let rng = rand::SystemRandom::new();
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key).map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        rng.fill(&mut nonce).map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        Ok(Self { connection, epoch, key, nonce, active })
    }
}

pub(crate) struct EncryptedKeyOutput {
    connection: ConnectionId,
    epoch: u64,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedKeyOutput {
    pub(crate) fn ciphertext(&self) -> &[u8] { &self.ciphertext }
    pub(crate) fn decrypt_for_channel(&self, capability: &AuthenticatedOutputCapability) -> Result<Vec<u8>, EnrollmentCustodyError> {
        if !capability.active.load(Ordering::Acquire) || capability.connection != self.connection || capability.epoch != self.epoch || capability.nonce != self.nonce {
            return Err(EnrollmentCustodyError::ChannelNotAuthenticated);
        }
        let unbound = UnboundKey::new(&AES_256_GCM, &capability.key).map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        let opening_key = LessSafeKey::new(unbound);
        let mut plaintext = self.ciphertext.clone();
        let bytes = opening_key.open_in_place(Nonce::assume_unique_for_key(self.nonce), Aad::empty(), &mut plaintext)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        Ok(bytes.to_vec())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnrollmentProof {
    pub(crate) identity: IdentityId,
    pub(crate) signature: Vec<u8>,
    pub(crate) long_term_public_key: PublicKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentConsumeError {
    Expired,
    UncertainExpiry,
    WrongIdentity,
    InvalidProof,
    AlreadyConsumed,
    EventUnavailable,
    InvalidPublicKey,
    RateLimited,
    ChannelClosed,
    CredentialMismatch,
    CapabilityRejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostAttemptResult { Allowed, RateLimited }

#[derive(Clone, Debug, Default)]
pub(crate) struct HostAttemptBudget { failures: u8, window_start_ms: Option<u64> }

impl HostAttemptBudget {
    pub(crate) fn failures(&self) -> u8 { self.failures }
    pub(crate) fn before_attempt(&self, occurrence_ms: u64) -> HostAttemptResult {
        let Some(start) = self.window_start_ms else { return HostAttemptResult::Allowed; };
        if occurrence_ms.saturating_sub(start) >= 60_000 || self.failures < 10 { HostAttemptResult::Allowed } else { HostAttemptResult::RateLimited }
    }
    pub(crate) fn record_failure(&mut self, occurrence_ms: u64) -> HostAttemptResult {
        if self.window_start_ms.is_none() || occurrence_ms.saturating_sub(self.window_start_ms.unwrap_or(occurrence_ms)) >= 60_000 {
            self.window_start_ms = Some(occurrence_ms);
            self.failures = 0;
        }
        if self.failures >= 10 { return HostAttemptResult::RateLimited; }
        self.failures = self.failures.saturating_add(1);
        HostAttemptResult::Allowed
    }
    pub(crate) fn reset_if_elapsed(&mut self, occurrence_ms: u64) {
        if self.window_start_ms.is_some_and(|start| occurrence_ms.saturating_sub(start) >= 60_000) {
            self.window_start_ms = None;
            self.failures = 0;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChromeCapability {
    origin: String,
    store_metadata: String,
    update_metadata: String,
    install_metadata: String,
    storage_local: bool,
    non_exportable: bool,
}

impl ChromeCapability {
    pub(crate) fn new(binding: &EnrollmentBinding<'_>) -> Result<Self, EnrollmentConsumeError> {
        if binding.origin.is_empty() || binding.store_metadata.is_empty() || binding.update_metadata.is_empty() || binding.install_metadata.is_empty()
            || !validate_origin(binding.origin) || !validate_metadata(binding.store_metadata, false)
            || !validate_metadata(binding.update_metadata, true) || !validate_metadata(binding.install_metadata, false) {
            return Err(EnrollmentConsumeError::CapabilityRejected);
        }
        Ok(Self { origin: binding.origin.to_string(), store_metadata: binding.store_metadata.to_string(), update_metadata: binding.update_metadata.to_string(), install_metadata: binding.install_metadata.to_string(), storage_local: true, non_exportable: true })
    }
    pub(crate) fn storage_local(&self) -> bool { self.storage_local }
    pub(crate) fn non_exportable(&self) -> bool { self.non_exportable }
    fn matches(&self, binding: &EnrollmentBinding<'_>) -> bool {
        self.origin == binding.origin && self.store_metadata == binding.store_metadata && self.update_metadata == binding.update_metadata && self.install_metadata == binding.install_metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChromeReconnectOutcome { Reconnected, Mismatch, Revoked }

#[derive(Clone, Debug)]
struct Registration {
    enrollment: TransitionId,
    key: [u8; UNCOMPRESSED_KEY_BYTES],
    fingerprint: Fingerprint,
    capability: ChromeCapability,
    generation: u64,
    revoked: bool,
}

#[derive(Debug, Default)]
struct ConsumptionState {
    registrations: HashMap<IdentityId, Registration>,
    consumed: HashMap<TransitionId, IdentityId>,
    host_budgets: HashMap<String, HostAttemptBudget>,
    quarantined: Vec<Fingerprint>,
}

#[derive(Debug, Default)]
pub(crate) struct EnrollmentConsumptionService { state: Mutex<ConsumptionState> }
pub(crate) type EnrollmentRegistry = EnrollmentConsumptionService;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentChannelState { Open, Closed }
#[derive(Debug)]
pub(crate) struct EnrollmentChannel { state: EnrollmentChannelState }
impl EnrollmentChannel {
    pub(crate) fn new() -> Self { Self { state: EnrollmentChannelState::Open } }
    pub(crate) fn close(&mut self) { self.state = EnrollmentChannelState::Closed; }
    pub(crate) fn state(&self) -> EnrollmentChannelState { self.state }
}

impl EnrollmentConsumptionService {
    pub(crate) fn registered_public_key(&self, identity: IdentityId) -> Option<PublicKey> {
        let bytes = self.state.lock().ok()?.registrations.get(&identity)?.key;
        PublicKey::from_uncompressed(bytes).ok()
    }
    pub(crate) fn registered_fingerprint(&self, identity: IdentityId) -> Option<Fingerprint> {
        self.state.lock().ok()?.registrations.get(&identity).map(|entry| entry.fingerprint.clone())
    }
    pub(crate) fn is_quarantined(&self, fingerprint: &Fingerprint) -> bool {
        self.state.lock().map(|state| state.quarantined.iter().any(|item| item == fingerprint)).unwrap_or(true)
    }
    pub(crate) fn host_failures(&self, endpoint: &str) -> u8 {
        host_key(endpoint).and_then(|key| self.state.lock().ok()?.host_budgets.get(&key).map(HostAttemptBudget::failures)).unwrap_or(0)
    }
    pub(crate) fn consume_proof<S: SecurityEventSink>(
        &self, bundle: &mut EnrollmentBundle, proof: &EnrollmentProof, expected_identity: IdentityId,
        clock: &EnrollmentClock, binding: &EnrollmentBinding<'_>, capability: &ChromeCapability,
        channel: &mut EnrollmentChannel, sink: Option<&mut S>,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        if !capability.matches(binding) || !capability.storage_local() || !capability.non_exportable() { return Err(EnrollmentConsumeError::CapabilityRejected); }
        if channel.state() == EnrollmentChannelState::Closed { return Err(EnrollmentConsumeError::ChannelClosed); }
        clock.valid_for(bundle.expiry_deadline_ms)?;
        let host = host_key(bundle.daemon_endpoint()).ok_or(EnrollmentConsumeError::InvalidProof)?;
        let mut state = self.state.lock().map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        if state.host_budgets.get(&host).is_some_and(|budget| budget.before_attempt(clock.occurrence_ms()) == HostAttemptResult::RateLimited) {
            let event = SecurityEvent::new(bundle.enrollment_id.get(), EventBoundary::Enrollment, SecurityCode::RateLimited, EventOutcome::Rejected, SafeNextAction::Wait, None, None, EndpointClass::Loopback, EventTime(clock.occurrence_ms()), bundle.daemon.get(), Vec::new()).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            channel.close();
            return Err(EnrollmentConsumeError::RateLimited);
        }
        if state.consumed.contains_key(&bundle.enrollment_id) || bundle.lifecycle() != EnrollmentLifecycle::Pending { return Err(EnrollmentConsumeError::AlreadyConsumed); }
        let expected = EnrollmentCreation::new(bundle.enrollment_id, bundle.origin.clone(), bundle.store_metadata.clone(), bundle.update_metadata.clone(), bundle.install_metadata.clone(), bundle.daemon, bundle.daemon_endpoint.clone(), clock.expiry().clone());
        let failure = validate_enrollment_binding(&expected, binding).err().map(|_| EnrollmentConsumeError::InvalidProof)
            .or_else(|| (proof.identity != expected_identity).then_some(EnrollmentConsumeError::WrongIdentity))
            .or_else(|| {
                let fingerprint = Fingerprint::new(hex_digest(proof.long_term_public_key.as_bytes())).ok()?;
                if state.registrations.contains_key(&expected_identity) || state.quarantined.iter().any(|item| item == &fingerprint) { Some(EnrollmentConsumeError::CredentialMismatch) } else { None }
            });
        let signature_valid = if failure.is_none() {
            let message = proof_message(bundle, &proof.long_term_public_key);
            let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, bundle.one_time_public_key.as_bytes());
            key.verify(&message, &proof.signature).is_ok()
        } else { false };
        if failure.is_some() || !signature_valid {
            let reason = failure.unwrap_or(EnrollmentConsumeError::InvalidProof);
            let event = SecurityEvent::new(bundle.enrollment_id.get(), EventBoundary::Enrollment, SecurityCode::ProofRejected, EventOutcome::Rejected, SafeNextAction::Reconnect, Some(expected_identity.get()), None, EndpointClass::Extension, EventTime(clock.occurrence_ms()), bundle.daemon.get(), Vec::new()).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            let _ = state.host_budgets.entry(host).or_default().record_failure(clock.occurrence_ms());
            bundle.mark_failed_proof()?;
            channel.close();
            return Err(reason);
        }
        let fingerprint = Fingerprint::new(hex_digest(proof.long_term_public_key.as_bytes())).map_err(|_| EnrollmentConsumeError::InvalidPublicKey)?;
        let event = SecurityEvent::new(bundle.enrollment_id.get(), EventBoundary::Enrollment, SecurityCode::EnrollmentAccepted, EventOutcome::Committed, SafeNextAction::Continue, Some(expected_identity.get()), None, EndpointClass::Extension, EventTime(clock.occurrence_ms()), bundle.daemon.get(), Vec::new()).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        bundle.enrollment.consume().map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        state.consumed.insert(bundle.enrollment_id, expected_identity);
        state.registrations.insert(expected_identity, Registration { enrollment: bundle.enrollment_id, key: *proof.long_term_public_key.as_bytes(), fingerprint: fingerprint.clone(), capability: capability.clone(), generation: 0, revoked: false });
        Ok(fingerprint)
    }
    pub(crate) fn reconnect(&self, identity: IdentityId, fingerprint: &Fingerprint) -> ChromeReconnectOutcome {
        let Ok(state) = self.state.lock() else { return ChromeReconnectOutcome::Mismatch; };
        let Some(registration) = state.registrations.get(&identity) else { return ChromeReconnectOutcome::Mismatch; };
        if registration.revoked { ChromeReconnectOutcome::Revoked } else if &registration.fingerprint == fingerprint { ChromeReconnectOutcome::Reconnected } else { ChromeReconnectOutcome::Mismatch }
    }
    pub(crate) fn update_custody(&self, identity: IdentityId, key: &PublicKey) -> Result<Fingerprint, EnrollmentConsumeError> {
        let mut state = self.state.lock().map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        let old_fingerprint = { let registration = state.registrations.get(&identity).ok_or(EnrollmentConsumeError::CredentialMismatch)?; if registration.revoked { return Err(EnrollmentConsumeError::CredentialMismatch); } registration.fingerprint.clone() };
        state.quarantined.push(old_fingerprint);
        let fingerprint = Fingerprint::new(hex_digest(key.as_bytes())).map_err(|_| EnrollmentConsumeError::InvalidPublicKey)?;
        let registration = state.registrations.get_mut(&identity).ok_or(EnrollmentConsumeError::CredentialMismatch)?;
        registration.key = *key.as_bytes(); registration.fingerprint = fingerprint.clone(); registration.generation = registration.generation.saturating_add(1);
        Ok(fingerprint)
    }
    pub(crate) fn revoke(&self, identity: IdentityId) -> Result<(), EnrollmentConsumeError> {
        let mut state = self.state.lock().map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        state.registrations.get_mut(&identity).ok_or(EnrollmentConsumeError::CredentialMismatch)?.revoked = true;
        Ok(())
    }
    pub(crate) fn quarantine_identity(&self, identity: IdentityId) -> Result<(), EnrollmentConsumeError> {
        let mut state = self.state.lock().map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        if let Some(registration) = state.registrations.remove(&identity) { state.quarantined.push(registration.fingerprint); }
        Ok(())
    }
}

pub(crate) fn boundary_ready(endpoint: &str) -> bool {
    let _ = host_key(endpoint);
    let mut channel = EnrollmentChannel::new();
    let channel_open = channel.state() == EnrollmentChannelState::Open;
    channel.close();
    let mut budget = HostAttemptBudget::default();
    let budget_open = budget.before_attempt(0) == HostAttemptResult::Allowed;
    budget.reset_if_elapsed(60_000);
    let _ = core::mem::size_of::<EnrollmentClock>();
    let _ = EnrollmentClock::new;
    let _ = ChromeCapability::new;
    let _ = ChromeCapability::storage_local;
    let _ = ChromeCapability::non_exportable;
    let _ = EnrollmentConsumptionService::registered_public_key;
    let _ = EnrollmentConsumptionService::registered_fingerprint;
    let _ = EnrollmentConsumptionService::is_quarantined;
    let _ = EnrollmentConsumptionService::consume_proof::<crate::events::AggregationState>;
    let _ = EnrollmentConsumptionService::reconnect;
    let _ = EnrollmentConsumptionService::update_custody;
    let _ = EnrollmentConsumptionService::revoke;
    let _ = EnrollmentConsumptionService::quarantine_identity;
    let _ = EnrollmentBundle::create;
    let _ = EnrollmentBundle::enrollment;
    let _ = EnrollmentBundle::lifecycle;
    let _ = EnrollmentBundle::encrypted_private_key_output;
    let _ = EncryptedKeyOutput::ciphertext;
    let _ = EncryptedKeyOutput::decrypt_for_channel;
    let _ = core::mem::size_of::<EnrollmentProof>();
    let _ = proof_message;
    let _ = enrollment_proof_message;
    let _ = validate_enrollment_binding;
    let _ = create_enrollment;
    channel_open && budget_open
}

fn host_key(endpoint: &str) -> Option<String> {
    let (host, port) = endpoint.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() { return None; }
    Some(host.to_string())
}

fn proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 16 + UNCOMPRESSED_KEY_BYTES * 2 + bundle.origin.len());
    message.extend_from_slice(b"matinee.enrollment.proof.v1\0");
    message.extend_from_slice(bundle.enrollment_id.get().as_bytes());
    message.extend_from_slice(bundle.one_time_public_key.as_bytes());
    message.extend_from_slice(long_term.as_bytes());
    message.extend_from_slice(bundle.origin.as_bytes());
    message
}

pub(crate) fn enrollment_proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> { proof_message(bundle, long_term) }

/// The values supplied by the browser during `/v1/pair`. This remains private;
/// callers receive only the typed validation result and never a policy bypass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnrollmentBinding<'a> {
    pub(crate) origin: &'a str,
    pub(crate) endpoint: &'a str,
    pub(crate) store_metadata: &'a str,
    pub(crate) update_metadata: &'a str,
    pub(crate) install_metadata: &'a str,
    pub(crate) development_allowance: DevelopmentIdentityAllowance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevelopmentIdentityAllowance {
    None,
    Explicit { warning_acknowledged: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentBindingError {
    Origin,
    Endpoint,
    Metadata,
    DevelopmentAllowance,
}

fn validate_origin(origin: &str) -> bool {
    let Some(id) = origin.strip_prefix("chrome-extension://") else {
        return false;
    };
    id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

fn validate_endpoint(endpoint: &str) -> bool {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let valid_host = host == "127.0.0.1" || host == "[::1]" || host == "::1";
    valid_host
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_printable_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn validate_metadata(value: &str, update: bool) -> bool {
    if !validate_printable_ascii(value) {
        return false;
    }
    if !update {
        return true;
    }

    let Some(authority_and_suffix) = value.strip_prefix("https://") else {
        return false;
    };
    let authority_end = authority_and_suffix.find(['/', '?', '#']).unwrap_or(authority_and_suffix.len());
    let authority = &authority_and_suffix[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (raw_host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    // A single terminal root dot is valid DNS presentation syntax. Normalize it
    // before applying label and total-length checks so the root separator does
    // not create an empty label or consume the hostname length budget.
    let host = raw_host.strip_suffix('.').unwrap_or(raw_host);
    let valid_host = host.len() <= 253
        && !host.is_empty()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    let valid_port = port.is_none_or(|port| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0)
    });
    if !valid_host || !valid_port {
        return false;
    }

    // Validate the entire suffix, not just the authority. Percent escapes are
    // the only encoded form accepted here and must always contain two hex digits.
    let suffix = &authority_and_suffix[authority_end..];
    let bytes = suffix.as_bytes();
    let mut index = 0;
    let mut in_fragment = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            if byte == b'#' {
                if in_fragment {
                    return false;
                }
                in_fragment = true;
            } else if !byte.is_ascii_alphanumeric()
                && !matches!(byte, b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@' | b'/' | b'?')
            {
                return false;
            }
            index += 1;
        }
    }
    true
}


pub(crate) fn validate_enrollment_binding(
    expected: &EnrollmentCreation,
    attempt: &EnrollmentBinding<'_>,
) -> Result<(), EnrollmentBindingError> {
    if !validate_origin(expected.origin.as_str()) || attempt.origin != expected.origin {
        return Err(EnrollmentBindingError::Origin);
    }
    if !validate_endpoint(expected.daemon_endpoint.as_str()) || attempt.endpoint != expected.daemon_endpoint {
        return Err(EnrollmentBindingError::Endpoint);
    }
    let metadata_matches = attempt.store_metadata == expected.store_metadata
        && attempt.update_metadata == expected.update_metadata
        && attempt.install_metadata == expected.install_metadata
        && validate_metadata(attempt.store_metadata, false)
        && validate_metadata(attempt.update_metadata, true)
        && validate_metadata(attempt.install_metadata, false);
    if !metadata_matches {
        return Err(EnrollmentBindingError::Metadata);
    }
    // `install_metadata` is the browser's identity classification. Production
    // pairing uses `normal`; every other install type is non-production and
    // requires the explicit, user-visible warning acknowledgement.
    let non_production_install = expected.install_metadata != "normal";
    if non_production_install
        && !matches!(
            attempt.development_allowance,
            DevelopmentIdentityAllowance::Explicit { warning_acknowledged: true }
        )
    {
        return Err(EnrollmentBindingError::DevelopmentAllowance);
    }
    Ok(())

}


pub(crate) fn create_enrollment(
    input: EnrollmentCreation,
) -> Result<EnrollmentBundle, EnrollmentCreateError> {
    EnrollmentBundle::create(input)
}

fn validate_creation(input: &EnrollmentCreation) -> Result<(), EnrollmentCreateError> {
    bounded(
        &input.origin,
        MAX_ORIGIN_BYTES,
        EnrollmentCreateError::EmptyOrOversizedOrigin,
    )?;
    if !validate_origin(&input.origin) {
        return Err(EnrollmentCreateError::InvalidOrigin);
    }
    for value in [
        &input.store_metadata,
        &input.update_metadata,
        &input.install_metadata,
    ] {
        bounded(
            value,
            MAX_METADATA_BYTES,
            EnrollmentCreateError::EmptyOrOversizedMetadata,
        )?;
    }
    if !validate_metadata(&input.store_metadata, false)
        || !validate_metadata(&input.update_metadata, true)
        || !validate_metadata(&input.install_metadata, false)
    {
        return Err(EnrollmentCreateError::InvalidInstallMetadata);
    }
    bounded(
        &input.daemon_endpoint,
        MAX_ENDPOINT_BYTES,
        EnrollmentCreateError::EmptyOrOversizedEndpoint,
    )?;
    if !validate_endpoint(&input.daemon_endpoint) {
        return Err(EnrollmentCreateError::InvalidEndpoint);
    }
    if !input.expiry.is_security_valid() || input.expiry.deadline_ms() > MAX_EXPIRY_MS {
        return Err(EnrollmentCreateError::InvalidExpiry);
    }
    Ok(())
}

fn bounded(
    value: &str,
    max: usize,
    error: EnrollmentCreateError,
) -> Result<(), EnrollmentCreateError> {
    if value.is_empty() || value.len() > max || !value.is_char_boundary(value.len()) {
        Err(error)
    } else {
        Ok(())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn input() -> EnrollmentCreation {
        EnrollmentCreation::new(
            TransitionId::new(Uuid::from_u128(1)),
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "stable",
            "https://updates.example.test/ext.xml",
            "normal",
            IdentityId::new(Uuid::from_u128(2)),
            "127.0.0.1:7777",
            ExpiryResult::valid(MAX_EXPIRY_MS).unwrap(),
        )
    }

    #[test]
    fn creates_bounded_redacted_one_use_bundle() {
        let mut bundle = create_enrollment(input()).unwrap();
        assert_eq!(bundle.secret().len(), SECRET_BYTES);
        assert_eq!(bundle.one_time_public_key_fingerprint().as_str().len(), 64);
        assert!(format!("{bundle:?}").contains("<redacted>"));
    }

    #[test]
    fn creates_with_printable_non_url_metadata_containing_spaces() {
        let mut spaced = input();
        spaced.store_metadata = "Chrome Web Store".into();
        spaced.install_metadata = "Chrome Web Store".into();
        assert!(create_enrollment(spaced).is_ok());
    }

    #[test]
    fn uncertain_and_oversized_expiry_fail_closed() {
        let mut uncertain = input();
        uncertain.expiry = ExpiryResult::uncertain(MAX_EXPIRY_MS);
        assert!(matches!(
            create_enrollment(uncertain),
            Err(EnrollmentCreateError::InvalidExpiry)
        ));
        let mut oversized = input();
        oversized.expiry = ExpiryResult::valid(MAX_EXPIRY_MS + 1).unwrap();
        assert!(matches!(
            create_enrollment(oversized),
            Err(EnrollmentCreateError::InvalidExpiry)
        ));
    }

    fn binding() -> EnrollmentBinding<'static> {
        EnrollmentBinding {
            origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            endpoint: "127.0.0.1:7777",
            store_metadata: "stable",
            update_metadata: "https://updates.example.test/ext.xml",
            install_metadata: "normal",
            development_allowance: DevelopmentIdentityAllowance::None,
        }
    }

    #[test]
    fn binding_rejects_origin_endpoint_and_metadata_mutations() {
        let expected = input();
        assert_eq!(validate_enrollment_binding(&expected, &binding()), Ok(()));
        let mut wrong = binding();
        wrong.origin = "chrome-extension://abcdefghijklmnox";
        assert_eq!(validate_enrollment_binding(&expected, &wrong), Err(EnrollmentBindingError::Origin));
        let mut wrong = binding();
        wrong.endpoint = "localhost:7777";
        assert_eq!(validate_enrollment_binding(&expected, &wrong), Err(EnrollmentBindingError::Endpoint));
        let mut wrong = binding();
        wrong.update_metadata = "http://updates.example.test/ext.xml";
        assert_eq!(validate_enrollment_binding(&expected, &wrong), Err(EnrollmentBindingError::Metadata));
    }

    #[test]
    fn development_install_requires_explicit_acknowledged_allowance() {
        let mut expected = input();
        expected.install_metadata = "development".into();
        let mut attempt = binding();
        attempt.install_metadata = "development";
        assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::DevelopmentAllowance));
        attempt.development_allowance = DevelopmentIdentityAllowance::Explicit { warning_acknowledged: true };
        assert_eq!(validate_enrollment_binding(&expected, &attempt), Ok(()));
    }

    #[test]
    fn sideload_install_requires_explicit_acknowledged_allowance() {
        let mut expected = input();
        expected.install_metadata = "sideload".into();
        let mut attempt = binding();
        attempt.install_metadata = "sideload";
        assert_eq!(
            validate_enrollment_binding(&expected, &attempt),
            Err(EnrollmentBindingError::DevelopmentAllowance)
        );
        attempt.development_allowance = DevelopmentIdentityAllowance::Explicit {
            warning_acknowledged: true,
        };
        assert_eq!(validate_enrollment_binding(&expected, &attempt), Ok(()));
    }


    #[test]
    fn binding_accepts_matching_printable_non_url_metadata_containing_spaces() {
        let mut expected = input();
        expected.store_metadata = "Chrome Web Store".into();
        expected.install_metadata = "Chrome Web Store".into();
        let mut attempt = binding();
        attempt.store_metadata = "Chrome Web Store";
        attempt.install_metadata = "Chrome Web Store";
        attempt.development_allowance = DevelopmentIdentityAllowance::Explicit {
            warning_acknowledged: true,
        };
        assert_eq!(validate_enrollment_binding(&expected, &attempt), Ok(()));
    }

    #[test]
    fn malformed_private_binding_values_fail_closed() {
        assert!(!validate_origin("chrome-extension://abcdefghijklmnop"));
        assert!(!validate_origin("chrome-extension://abcdefghijklmnopabcdefghijklmnox"));
        assert!(!validate_metadata("https://", true));
        assert!(validate_metadata("Chrome Web Store", false));
        for invalid in ["contains\nnewline", "contains\x7fdelete", "contains café"] {
            assert!(!validate_metadata(invalid, false));
            assert!(!validate_metadata(invalid, true));
        }
        assert!(!validate_metadata("http://updates.example.test/ext.xml", true));
        assert!(!validate_metadata("https://updates.example.test/a b", true));
        assert!(!validate_metadata("https://updates.example.test/%zz", true));
        assert!(!validate_metadata("https://bad_host.example/ext.xml", true));
        assert!(!validate_metadata("https://updates..example/ext.xml", true));
        assert!(!validate_metadata("https://updates.example../ext.xml", true));
        assert!(!validate_metadata("https://updates.example.test../ext.xml", true));
        assert!(validate_metadata(
            "https://updates.example.test./ext.xml",
            true
        ));
        let overlong_label = format!("https://{}.example/ext.xml", "a".repeat(64));
        assert!(!validate_metadata(&overlong_label, true));
        let max_hostname = format!(
            "https://{}.{}.{}.{}./ext.xml",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(validate_metadata(&max_hostname, true));
        let overlong_hostname = max_hostname.replace(&"d".repeat(61), &"d".repeat(62));
        assert!(!validate_metadata(&overlong_hostname, true));
        assert!(validate_metadata(
            "https://updates.example.test:443/a%20b?channel=stable#release",
            true
        ));
    }
}
