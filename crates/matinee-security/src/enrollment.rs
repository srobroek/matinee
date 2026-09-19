//! Closed, bounded enrollment creation and binding validation.

// The complete enrollment boundary is owned here for downstream wiring: Spec 008 owns
// the extension and pairing caller, and Spec 007 owns the daemon transition actor that
// drives creation. Spec 006 has no such caller, while contract tests exercise the seam.
#![cfg_attr(not(test), allow(dead_code))]
use core::fmt;
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::SecureRandom;
use ring::signature::KeyPair;
use ring::{digest, rand, signature};

use crate::events::{
    AggregationState, EndpointClass, EventBoundary, EventOutcome, EventTime, SafeNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink, emit_required,
};
use crate::identity::{
    ConnectionId, EnrollmentLifecycle, ExpiryResult, ExpiryStatus, ExtensionEnrollment,
    Fingerprint, IdentityId, PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES,
};
use uuid::Uuid;

const SEALED_KEY_AAD_PREFIX: &[u8; 26] = b"matinee.enrollment.key.v1\0";
/// FR-007 fixes one ten-minute figure for an enrollment deadline: it is both the window
/// an administrator gets by naming no deadline and the widest window a named deadline may
/// span from the instant the enrollment is created, so a caller can neither widen the
/// window nor be handed a wider one. It is a duration; a deadline is an instant.
const TEN_MINUTE_EXPIRY_MS: u64 = 10 * 60 * 1_000;
const MAX_EXPIRY_MS: u64 = TEN_MINUTE_EXPIRY_MS;
const MAX_ORIGIN_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 256;
/// `65535.65535.65535.65535` is the longest Chrome manifest version.
const MAX_VERSION_BYTES: usize = 23;

/// One extension version, in Chrome manifest form: one to four dot-separated integers in
/// `0..=65535`, each written without a leading zero. Missing trailing components are zero,
/// so `3` and `3.0.0.0` are one version and order alongside `3.0.1` exactly as Chrome
/// orders them.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtensionVersion([u16; 4]);

impl ExtensionVersion {
    pub fn parse(value: &str) -> Result<Self, ExtensionVersionError> {
        if value.is_empty() || value.len() > MAX_VERSION_BYTES {
            return Err(ExtensionVersionError::Malformed);
        }
        let mut components = [0u16; 4];
        for (count, part) in value.split('.').enumerate() {
            if count == components.len() {
                return Err(ExtensionVersionError::Malformed);
            }
            if part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(ExtensionVersionError::Malformed);
            }
            components[count] = part
                .parse::<u16>()
                .map_err(|_| ExtensionVersionError::Malformed)?;
        }
        Ok(Self(components))
    }
}

impl fmt::Display for ExtensionVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch, build] = self.0;
        write!(f, "{major}.{minor}.{patch}.{build}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionVersionError {
    Malformed,
    InvertedRange,
}

impl fmt::Display for ExtensionVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed extension version",
            Self::InvertedRange => "inverted supported extension version range",
        })
    }
}

/// The inclusive range of extension versions this daemon pairs with.
///
/// FR-019 makes a supported version a production pairing requirement, so the range is
/// pinned into the enrollment at creation and enforced when the browser presents its
/// version. A range can only be built minimum-first, so no enrollment can carry a range
/// that admits nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportedExtensionVersions {
    minimum: ExtensionVersion,
    maximum: ExtensionVersion,
}

impl SupportedExtensionVersions {
    pub fn new(
        minimum: ExtensionVersion,
        maximum: ExtensionVersion,
    ) -> Result<Self, ExtensionVersionError> {
        if minimum > maximum {
            return Err(ExtensionVersionError::InvertedRange);
        }
        Ok(Self { minimum, maximum })
    }

    /// Parse both bounds from their Chrome manifest spellings.
    pub fn parse(minimum: &str, maximum: &str) -> Result<Self, ExtensionVersionError> {
        Self::new(
            ExtensionVersion::parse(minimum)?,
            ExtensionVersion::parse(maximum)?,
        )
    }

    pub fn minimum(&self) -> ExtensionVersion {
        self.minimum
    }

    pub fn maximum(&self) -> ExtensionVersion {
        self.maximum
    }

    /// Both bounds are inclusive: the oldest and the newest supported build both pair.
    pub fn contains(&self, version: ExtensionVersion) -> bool {
        self.minimum <= version && version <= self.maximum
    }
}

/// The deadline an administrator asked for, before any instant is known.
///
/// FR-007 makes the ten-minute expiry a default rather than the only choice, so an
/// administrator may name an absolute deadline instead. Neither form carries a creation
/// instant: the width of the window is only definable against the instant the enrollment
/// is actually created, and that instant belongs to whoever holds the clock, never to the
/// caller describing the enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentExpiry {
    /// The ten minutes FR-007 applies when an administrator names no deadline, counted
    /// from the trusted creation instant.
    Default,
    /// An absolute deadline on the same clock the creating host reads. It is accepted
    /// only when it falls within ten minutes after the trusted creation instant.
    Deadline(ExpiryResult),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCreation {
    pub enrollment: TransitionId,
    pub origin: String,
    pub store_metadata: String,
    pub update_metadata: String,
    pub install_metadata: String,
    pub supported_versions: SupportedExtensionVersions,
    pub daemon: IdentityId,
    pub daemon_endpoint: String,
    pub expiry: EnrollmentExpiry,
}

impl EnrollmentCreation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        enrollment: TransitionId,
        origin: impl Into<String>,
        store_metadata: impl Into<String>,
        update_metadata: impl Into<String>,
        install_metadata: impl Into<String>,
        supported_versions: SupportedExtensionVersions,
        daemon: IdentityId,
        daemon_endpoint: impl Into<String>,
        expiry: EnrollmentExpiry,
    ) -> Self {
        Self {
            enrollment,
            origin: origin.into(),
            store_metadata: store_metadata.into(),
            update_metadata: update_metadata.into(),
            install_metadata: install_metadata.into(),
            supported_versions,
            daemon,
            daemon_endpoint: daemon_endpoint.into(),
            expiry,
        }
    }

    /// The same enrollment an administrator opens without naming a deadline.
    ///
    /// FR-007 requires the expiry to be ten minutes by default, so the default is
    /// resolved by the creating host against its own clock rather than left to a caller:
    /// there is no way to reach the creation path with an absent deadline and no way to
    /// reach it with a deadline nobody chose.
    #[allow(clippy::too_many_arguments)]
    pub fn with_default_expiry(
        enrollment: TransitionId,
        origin: impl Into<String>,
        store_metadata: impl Into<String>,
        update_metadata: impl Into<String>,
        install_metadata: impl Into<String>,
        supported_versions: SupportedExtensionVersions,
        daemon: IdentityId,
        daemon_endpoint: impl Into<String>,
    ) -> Self {
        Self::new(
            enrollment,
            origin,
            store_metadata,
            update_metadata,
            install_metadata,
            supported_versions,
            daemon,
            daemon_endpoint,
            EnrollmentExpiry::Default,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentCreateError {
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
pub struct EnrollmentClock {
    occurrence_ms: u64,
    expiry: ExpiryResult,
}

impl EnrollmentClock {
    pub fn new(occurrence_ms: u64, expiry: ExpiryResult) -> Self {
        Self {
            occurrence_ms,
            expiry,
        }
    }
    pub fn occurrence_ms(&self) -> u64 {
        self.occurrence_ms
    }
    pub fn expiry(&self) -> &ExpiryResult {
        &self.expiry
    }
    /// Is this proof inside the window the enrollment was actually opened for?
    ///
    /// The window is the half-open interval from the trusted creation instant up to the
    /// deadline, and both bounds are checked. Checking only the deadline would accept a
    /// proof whose occurrence time precedes the creation instant, which is an occurrence
    /// the enrollment did not exist for, and it would leave the width of the real window
    /// unstated at the one place a proof is measured against it.
    fn valid_for(&self, created_ms: u64, deadline_ms: u64) -> Result<(), EnrollmentConsumeError> {
        // The host-held deadline and host-observed occurrence decide conclusive expiry before
        // the caller's status label is considered. A caller cannot turn an already-expired
        // attempt into `TransitionUnknown` by reporting `uncertain`.
        if self.occurrence_ms < created_ms || self.occurrence_ms >= deadline_ms {
            return Err(EnrollmentConsumeError::Expired);
        }
        if self.expiry.deadline_ms() != deadline_ms {
            return Err(EnrollmentConsumeError::Expired);
        }
        if !self.expiry.is_security_valid() {
            return Err(if self.expiry.status() == ExpiryStatus::Uncertain {
                EnrollmentConsumeError::UncertainExpiry
            } else {
                EnrollmentConsumeError::Expired
            });
        }
        Ok(())
    }
}

pub struct EnrollmentBundle {
    enrollment: ExtensionEnrollment,
    enrollment_id: TransitionId,
    /// The trusted instant this enrollment was created at, as the creating host's own
    /// clock read it. Every bound the enrollment carries is measured from it, so it is
    /// restated exactly when a proof is checked against those bounds.
    created_ms: u64,
    expiry_deadline_ms: u64,
    one_time_public_key: PublicKey,
    one_time_public_key_fingerprint: Fingerprint,
    one_time_private_key_pkcs8: Option<Vec<u8>>,
    origin: String,
    store_metadata: String,
    update_metadata: String,
    install_metadata: String,
    supported_versions: SupportedExtensionVersions,
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
            .field("supported_versions", &self.supported_versions)
            .field("daemon", &self.daemon)
            .field("daemon_endpoint", &self.daemon_endpoint)
            .field("one_time_public_key", &self.one_time_public_key)
            .field(
                "one_time_public_key_fingerprint",
                &self.one_time_public_key_fingerprint,
            )
            .field("one_time_private_key_pkcs8", &"<redacted>")
            .finish()
    }
}

impl EnrollmentBundle {
    /// Open one bounded enrollment at the instant the creating host's clock reports.
    ///
    /// `created_ms` is that instant, and it is the only creation instant in the system:
    /// the described enrollment carries none, so no caller can name a second one for the
    /// window to be measured against. That is what bounds real validity. FR-007's ten
    /// minutes is a window between two instants, and a window a caller could anchor at a
    /// freely chosen instant is no bound at all: an anchor ten minutes wide but placed a
    /// year ahead keeps an enrollment live for a year. Anchored here, the deadline is at
    /// most ten minutes after the clock reading this host actually took, and
    /// [`EnrollmentClock::valid_for`] measures a proof against that same pair of instants.
    pub fn create(
        input: EnrollmentCreation,
        created_ms: u64,
    ) -> Result<Self, EnrollmentCreateError> {
        let expiry = validate_creation(&input, created_ms)?;
        let rng = rand::SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
        let bytes = key_pair.public_key().as_ref();
        if bytes.len() != UNCOMPRESSED_KEY_BYTES {
            return Err(EnrollmentCreateError::InvalidPublicKey);
        }
        let mut public_bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
        public_bytes.copy_from_slice(bytes);
        let public_key = PublicKey::from_uncompressed(public_bytes)
            .map_err(|_| EnrollmentCreateError::InvalidPublicKey)?;
        let fingerprint = Fingerprint::new(hex_digest(&public_bytes))
            .map_err(|_| EnrollmentCreateError::InvalidFingerprint)?;
        let metadata = format!(
            "store={};update={};install={}",
            input.store_metadata, input.update_metadata, input.install_metadata
        );
        let enrollment = ExtensionEnrollment::new(
            input.enrollment,
            input.origin.clone(),
            metadata,
            input.daemon,
            input.daemon_endpoint.clone(),
            fingerprint.clone(),
            expiry.clone(),
        )
        .map_err(|_| EnrollmentCreateError::InvalidExpiry)?;
        Ok(Self {
            enrollment,
            enrollment_id: input.enrollment,
            created_ms,
            expiry_deadline_ms: expiry.deadline_ms(),
            one_time_public_key: public_key,
            one_time_public_key_fingerprint: fingerprint,
            one_time_private_key_pkcs8: Some(pkcs8.as_ref().to_vec()),
            origin: input.origin,
            store_metadata: input.store_metadata,
            update_metadata: input.update_metadata,
            install_metadata: input.install_metadata,
            supported_versions: input.supported_versions,
            daemon: input.daemon,
            daemon_endpoint: input.daemon_endpoint,
        })
    }
    pub fn enrollment(&self) -> &ExtensionEnrollment {
        &self.enrollment
    }
    pub fn enrollment_id(&self) -> TransitionId {
        self.enrollment_id
    }
    pub fn expiry_deadline_ms(&self) -> u64 {
        self.expiry_deadline_ms
    }
    pub fn lifecycle(&self) -> EnrollmentLifecycle {
        self.enrollment.lifecycle()
    }
    pub fn one_time_public_key(&self) -> &PublicKey {
        &self.one_time_public_key
    }
    pub fn one_time_public_key_fingerprint(&self) -> &Fingerprint {
        &self.one_time_public_key_fingerprint
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn store_metadata(&self) -> &str {
        &self.store_metadata
    }
    pub fn update_metadata(&self) -> &str {
        &self.update_metadata
    }
    pub fn install_metadata(&self) -> &str {
        &self.install_metadata
    }
    /// The inclusive extension version range production pairing requires.
    pub fn supported_versions(&self) -> SupportedExtensionVersions {
        self.supported_versions
    }
    pub fn daemon(&self) -> IdentityId {
        self.daemon
    }
    pub fn daemon_endpoint(&self) -> &str {
        &self.daemon_endpoint
    }
    /// Revoke this enrollment when its owner is revoked. A consumed, closed, or expired
    /// enrollment is already terminal and is left exactly as it is.
    pub(crate) fn revoke(&mut self) {
        self.enrollment.revoke();
    }
    fn mark_failed_proof(&mut self) -> Result<u8, EnrollmentConsumeError> {
        self.enrollment
            .record_failed_proof()
            .map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        Ok(self.enrollment.failed_proofs())
    }
    pub(crate) fn encrypted_private_key_output(
        &mut self,
        capability: &AuthenticatedOutputCapability,
    ) -> Result<EncryptedKeyOutput, EnrollmentCustodyError> {
        if !capability.active.load(Ordering::Acquire) {
            return Err(EnrollmentCustodyError::ChannelNotAuthenticated);
        }
        let key = self
            .one_time_private_key_pkcs8
            .as_ref()
            .ok_or(EnrollmentCustodyError::AlreadyTransferred)?;
        let nonce = capability.next_nonce()?;
        let aad = sealed_key_aad(self.enrollment_id, capability.connection, capability.epoch);
        let unbound = UnboundKey::new(&AES_256_GCM, &capability.key)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        let sealing_key = LessSafeKey::new(unbound);
        let mut ciphertext = key.clone();
        sealing_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        self.one_time_private_key_pkcs8.take();
        Ok(EncryptedKeyOutput {
            enrollment: self.enrollment_id,
            connection: capability.connection,
            epoch: capability.epoch,
            nonce,
            ciphertext,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentCustodyError {
    ChannelNotAuthenticated,
    AlreadyTransferred,
    EncryptionFailed,
}

pub struct AuthenticatedOutputCapability {
    connection: ConnectionId,
    epoch: u64,
    key: [u8; 32],
    nonce_prefix: [u8; 4],
    nonce_sequence: AtomicU64,
    active: Arc<AtomicBool>,
}

impl AuthenticatedOutputCapability {
    pub(crate) fn from_authenticated_channel(
        connection: ConnectionId,
        epoch: u64,
        active: Arc<AtomicBool>,
    ) -> Result<Self, EnrollmentCustodyError> {
        let rng = rand::SystemRandom::new();
        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 4];
        rng.fill(&mut key)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        rng.fill(&mut nonce_prefix)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        Ok(Self {
            connection,
            epoch,
            key,
            nonce_prefix,
            nonce_sequence: AtomicU64::new(0),
            active,
        })
    }

    fn next_nonce(&self) -> Result<[u8; 12], EnrollmentCustodyError> {
        let sequence = self
            .nonce_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        Ok(nonce)
    }
}

impl fmt::Debug for AuthenticatedOutputCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedOutputCapability")
            .field("connection", &self.connection)
            .field("epoch", &self.epoch)
            .field("key", &"<redacted>")
            .field(
                "nonce_sequence",
                &self.nonce_sequence.load(Ordering::Relaxed),
            )
            .finish()
    }
}

pub struct EncryptedKeyOutput {
    enrollment: TransitionId,
    connection: ConnectionId,
    epoch: u64,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedKeyOutput {
    pub fn enrollment(&self) -> TransitionId {
        self.enrollment
    }
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub(crate) fn decrypt_for_channel(
        &self,
        capability: &AuthenticatedOutputCapability,
        expected_enrollment: TransitionId,
    ) -> Result<Vec<u8>, EnrollmentCustodyError> {
        if !capability.active.load(Ordering::Acquire)
            || capability.connection != self.connection
            || capability.epoch != self.epoch
            || self.enrollment != expected_enrollment
        {
            return Err(EnrollmentCustodyError::ChannelNotAuthenticated);
        }
        let aad = sealed_key_aad(self.enrollment, self.connection, self.epoch);
        let unbound = UnboundKey::new(&AES_256_GCM, &capability.key)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        let opening_key = LessSafeKey::new(unbound);
        let mut plaintext = self.ciphertext.clone();
        let bytes = opening_key
            .open_in_place(
                Nonce::assume_unique_for_key(self.nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        Ok(bytes.to_vec())
    }
}

fn sealed_key_aad(enrollment: TransitionId, connection: ConnectionId, epoch: u64) -> [u8; 66] {
    let mut aad = [0u8; 66];
    aad[..26].copy_from_slice(SEALED_KEY_AAD_PREFIX);
    aad[26..42].copy_from_slice(enrollment.get().as_bytes());
    aad[42..58].copy_from_slice(connection.get().as_bytes());
    aad[58..].copy_from_slice(&epoch.to_be_bytes());
    aad
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentProof {
    pub identity: IdentityId,
    pub signature: Vec<u8>,
    pub long_term_public_key: PublicKey,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentConsumeError {
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
pub(crate) enum HostAttemptResult {
    Allowed,
    RateLimited,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HostAttemptBudget {
    failures: u8,
    window_start_ms: Option<u64>,
}

impl HostAttemptBudget {
    pub(crate) fn before_attempt(&self, occurrence_ms: u64) -> HostAttemptResult {
        let Some(start) = self.window_start_ms else {
            return HostAttemptResult::Allowed;
        };
        if occurrence_ms.saturating_sub(start) >= 60_000 || self.failures < 10 {
            HostAttemptResult::Allowed
        } else {
            HostAttemptResult::RateLimited
        }
    }
    pub(crate) fn record_failure(&mut self, occurrence_ms: u64) -> HostAttemptResult {
        if self.window_start_ms.is_none()
            || occurrence_ms.saturating_sub(self.window_start_ms.unwrap_or(occurrence_ms)) >= 60_000
        {
            self.window_start_ms = Some(occurrence_ms);
            self.failures = 0;
        }
        if self.failures >= 10 {
            return HostAttemptResult::RateLimited;
        }
        self.failures = self.failures.saturating_add(1);
        HostAttemptResult::Allowed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChromeCapability {
    origin: String,
    store_metadata: String,
    update_metadata: String,
    install_metadata: String,
    storage_local: bool,
    non_exportable: bool,
}

impl ChromeCapability {
    /// The capability the browser reported for one pairing attempt.
    ///
    /// `storage_local` and `non_exportable` are observations, never assumptions: a
    /// browser that cannot preserve `chrome.storage.local` persistence or a
    /// non-exportable WebCrypto key reports `false`, and consumption then refuses.
    pub fn reported(
        binding: &EnrollmentBinding<'_>,
        storage_local: bool,
        non_exportable: bool,
    ) -> Result<Self, EnrollmentConsumeError> {
        if binding.origin.is_empty()
            || binding.store_metadata.is_empty()
            || binding.update_metadata.is_empty()
            || binding.install_metadata.is_empty()
            || !validate_origin(binding.origin)
            || !validate_metadata(binding.store_metadata, false)
            || !validate_metadata(binding.update_metadata, true)
            || !validate_metadata(binding.install_metadata, false)
        {
            return Err(EnrollmentConsumeError::CapabilityRejected);
        }
        Ok(Self {
            origin: binding.origin.to_string(),
            store_metadata: binding.store_metadata.to_string(),
            update_metadata: binding.update_metadata.to_string(),
            install_metadata: binding.install_metadata.to_string(),
            storage_local,
            non_exportable,
        })
    }
    pub fn storage_local(&self) -> bool {
        self.storage_local
    }
    pub fn non_exportable(&self) -> bool {
        self.non_exportable
    }
    pub(crate) fn canonical_fields(&self) -> (&str, &str, &str, &str, bool, bool) {
        (
            &self.origin,
            &self.store_metadata,
            &self.update_metadata,
            &self.install_metadata,
            self.storage_local,
            self.non_exportable,
        )
    }
    fn matches(&self, binding: &EnrollmentBinding<'_>) -> bool {
        self.origin == binding.origin
            && self.store_metadata == binding.store_metadata
            && self.update_metadata == binding.update_metadata
            && self.install_metadata == binding.install_metadata
    }
    fn permits(&self, current: &Self) -> bool {
        self.storage_local
            && self.non_exportable
            && current.storage_local
            && current.non_exportable
            && self.origin == current.origin
            && self.store_metadata == current.store_metadata
            && self.update_metadata == current.update_metadata
            && self.install_metadata == current.install_metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChromeReconnectOutcome {
    Reconnected,
    Mismatch,
    Revoked,
}

#[derive(Clone, Debug)]
struct Registration {
    key: [u8; UNCOMPRESSED_KEY_BYTES],
    fingerprint: Fingerprint,
    capability: ChromeCapability,
    revoked: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct CustodyUpdate {
    identity: IdentityId,
    key: [u8; UNCOMPRESSED_KEY_BYTES],
    fingerprint: Fingerprint,
    capability: ChromeCapability,
    retired_fingerprint: Fingerprint,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct CustodyRevocation {
    identity: IdentityId,
}

#[derive(Debug, Default)]
struct ConsumptionState {
    registrations: HashMap<IdentityId, Registration>,
    consumed: HashMap<TransitionId, IdentityId>,
    host_budgets: HashMap<String, HostAttemptBudget>,
    quarantined: Vec<Fingerprint>,
    #[cfg(test)]
    fail_next_custody_validation: bool,
    #[cfg(test)]
    fail_next_custody_revocation: bool,
}

/// The process-lifetime registry, host budgets, quarantine set, and required-event
/// sink for enrollment consumption.
///
/// One instance serves every connection of a host process: replacing a connection
/// replaces its channel only, never the registrations or the host attempt budgets.
#[derive(Debug, Default)]
pub struct EnrollmentConsumptionService {
    state: Mutex<ConsumptionState>,
    events: Mutex<AggregationState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentChannelState {
    Open,
    Closed,
}

/// One authenticated native channel to a pairing peer.
///
/// The channel owns the only sealing capability for its connection. Closing it
/// destroys the ability to seal one-time key material on that connection; key
/// opening belongs to the remote peer and has no production host API.
#[derive(Debug)]
pub struct EnrollmentChannel {
    state: EnrollmentChannelState,
    capability: AuthenticatedOutputCapability,
    active: Arc<AtomicBool>,
}
impl EnrollmentChannel {
    /// Open the channel for one authenticated connection at its current epoch.
    pub fn open(connection: ConnectionId, epoch: u64) -> Result<Self, EnrollmentCustodyError> {
        let active = Arc::new(AtomicBool::new(true));
        let capability = AuthenticatedOutputCapability::from_authenticated_channel(
            connection,
            epoch,
            Arc::clone(&active),
        )?;
        Ok(Self {
            state: EnrollmentChannelState::Open,
            capability,
            active,
        })
    }
    pub fn connection(&self) -> ConnectionId {
        self.capability.connection
    }
    pub fn epoch(&self) -> u64 {
        self.capability.epoch
    }
    pub fn is_open(&self) -> bool {
        self.state == EnrollmentChannelState::Open
    }
    pub fn close(&mut self) {
        self.state = EnrollmentChannelState::Closed;
        self.active.store(false, Ordering::Release);
    }
    pub(crate) fn state(&self) -> EnrollmentChannelState {
        self.state
    }
    /// Seal the bundle's one-time PKCS#8 key for this channel's peer.
    ///
    /// This is the only operation that moves that key out of the bundle, and it
    /// succeeds once: a second call reports `AlreadyTransferred`.
    pub fn seal_one_time_key(
        &self,
        bundle: &mut EnrollmentBundle,
    ) -> Result<EncryptedKeyOutput, EnrollmentCustodyError> {
        bundle.encrypted_private_key_output(&self.capability)
    }
    #[cfg(test)]
    pub(crate) fn open_sealed_for_test(
        &self,
        expected_enrollment: TransitionId,
        sealed: &EncryptedKeyOutput,
    ) -> Result<Vec<u8>, EnrollmentCustodyError> {
        sealed.decrypt_for_channel(&self.capability, expected_enrollment)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn sign_sealed_for_test(
        &self,
        expected_enrollment: TransitionId,
        sealed: &EncryptedKeyOutput,
        message: &[u8],
    ) -> Result<Vec<u8>, EnrollmentCustodyError> {
        let pkcs8 = sealed.decrypt_for_channel(&self.capability, expected_enrollment)?;
        let rng = rand::SystemRandom::new();
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &pkcs8,
            &rng,
        )
        .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?;
        Ok(key
            .sign(&rng, message)
            .map_err(|_| EnrollmentCustodyError::EncryptionFailed)?
            .as_ref()
            .to_vec())
    }
}

impl EnrollmentConsumptionService {
    pub fn registered_public_key(&self, identity: IdentityId) -> Option<PublicKey> {
        let bytes = self.state.lock().ok()?.registrations.get(&identity)?.key;
        PublicKey::from_uncompressed(bytes).ok()
    }

    pub fn registered_fingerprint(&self, identity: IdentityId) -> Option<Fingerprint> {
        self.state
            .lock()
            .ok()?
            .registrations
            .get(&identity)
            .map(|entry| entry.fingerprint.clone())
    }

    #[cfg(test)]
    pub(crate) fn is_revoked(&self, identity: IdentityId) -> Option<bool> {
        Some(
            self.state
                .lock()
                .ok()?
                .registrations
                .get(&identity)?
                .revoked,
        )
    }

    pub fn is_quarantined(&self, fingerprint: &Fingerprint) -> bool {
        self.state
            .lock()
            .map(|state| state.quarantined.iter().any(|item| item == fingerprint))
            .unwrap_or(true)
    }

    /// The refusals decided before an identifier is resolved.
    ///
    /// Both consumption paths run exactly this, so neither reported custody refusal
    /// depends on whether the presented identifier named a pending enrollment.
    fn precheck_attempt(
        binding: &EnrollmentBinding<'_>,
        capability: &ChromeCapability,
        channel: &EnrollmentChannel,
    ) -> Result<(), EnrollmentConsumeError> {
        if !capability.matches(binding)
            || !capability.storage_local()
            || !capability.non_exportable()
        {
            return Err(EnrollmentConsumeError::CapabilityRejected);
        }
        if channel.state() == EnrollmentChannelState::Closed {
            return Err(EnrollmentConsumeError::ChannelClosed);
        }
        Ok(())
    }

    /// Consume one pairing proof against the enrollment it bound to.
    // Pairing proof fields are contract-fixed; keep this boundary explicit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consume_proof<S: SecurityEventSink + ?Sized>(
        &self,
        bundle: &mut EnrollmentBundle,
        proof: &EnrollmentProof,
        expected_identity: IdentityId,
        clock: &EnrollmentClock,
        binding: &EnrollmentBinding<'_>,
        capability: &ChromeCapability,
        channel: &mut EnrollmentChannel,
        mut sink: Option<&mut S>,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        Self::precheck_attempt(binding, capability, channel)?;
        // An elapsed deadline is a proof presented against an enrollment that is no
        // longer live, which `transition::consume_rejection` reports as a replay, so the
        // replay fact is owed before the refusal is returned. An uncertain deadline
        // decides nothing and is therefore no outcome to state.
        if let Err(error) = clock.valid_for(bundle.created_ms, bundle.expiry_deadline_ms) {
            if error == EnrollmentConsumeError::Expired {
                let host = host_key(bundle.daemon_endpoint())
                    .ok_or(EnrollmentConsumeError::InvalidProof)?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
                let rate_limited = state.host_budgets.get(&host).is_some_and(|budget| {
                    budget.before_attempt(clock.occurrence_ms()) == HostAttemptResult::RateLimited
                });
                if rate_limited {
                    require_rate_limit_fact(&mut sink, bundle, clock)?;
                    channel.close();
                    return Err(EnrollmentConsumeError::RateLimited);
                }
                // A decided replay/expiry refusal is still a failed host attempt. Charge it
                // only after its required fact is accepted, so an unavailable sink cannot
                // mutate the budget while refusing to admit the attempt.
                require_replay_fact(&mut sink, bundle, clock, expected_identity)?;
                match state
                    .host_budgets
                    .entry(host)
                    .or_default()
                    .record_failure(clock.occurrence_ms())
                {
                    HostAttemptResult::Allowed => {}
                    HostAttemptResult::RateLimited => {
                        require_rate_limit_fact(&mut sink, bundle, clock)?;
                        channel.close();
                        return Err(EnrollmentConsumeError::RateLimited);
                    }
                }
            }
            return Err(error);
        }
        let host =
            host_key(bundle.daemon_endpoint()).ok_or(EnrollmentConsumeError::InvalidProof)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        let rate_limited = state.host_budgets.get(&host).is_some_and(|budget| {
            budget.before_attempt(clock.occurrence_ms()) == HostAttemptResult::RateLimited
        });
        if rate_limited {
            require_rate_limit_fact(&mut sink, bundle, clock)?;
            channel.close();
            return Err(EnrollmentConsumeError::RateLimited);
        }
        // A second proof against an enrollment already spent, closed, expired, or revoked
        // is the other replay this boundary owes a fact for.
        if state.consumed.contains_key(&bundle.enrollment_id)
            || bundle.lifecycle() != EnrollmentLifecycle::Pending
        {
            require_replay_fact(&mut sink, bundle, clock, expected_identity)?;
            return Err(EnrollmentConsumeError::AlreadyConsumed);
        }
        let expected = EnrollmentCreation::new(
            bundle.enrollment_id,
            bundle.origin.clone(),
            bundle.store_metadata.clone(),
            bundle.update_metadata.clone(),
            bundle.install_metadata.clone(),
            bundle.supported_versions,
            bundle.daemon,
            bundle.daemon_endpoint.clone(),
            EnrollmentExpiry::Deadline(clock.expiry().clone()),
        );
        let binding_error = validate_enrollment_binding(&expected, binding).err();
        let failure = binding_error
            .map(|_| EnrollmentConsumeError::InvalidProof)
            .or_else(|| {
                (proof.identity != expected_identity)
                    .then_some(EnrollmentConsumeError::WrongIdentity)
            })
            .or_else(|| {
                let fingerprint =
                    Fingerprint::new(hex_digest(proof.long_term_public_key.as_bytes())).ok()?;
                if state.registrations.contains_key(&expected_identity)
                    || state.quarantined.iter().any(|item| item == &fingerprint)
                {
                    Some(EnrollmentConsumeError::CredentialMismatch)
                } else {
                    None
                }
            });
        let signature_valid = if failure.is_none() {
            let message = proof_message(bundle, &proof.long_term_public_key);
            let key = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                bundle.one_time_public_key.as_bytes(),
            );
            key.verify(&message, &proof.signature).is_ok()
        } else {
            false
        };
        if failure.is_some() || !signature_valid {
            let reason = failure.unwrap_or(EnrollmentConsumeError::InvalidProof);
            let event = SecurityEvent::new(
                bundle.enrollment_id.get(),
                EventBoundary::Enrollment,
                // `contracts/failures-events.md` requires a rejected Origin to be its own
                // fact. Only the emitted fact distinguishes it: the returned error stays
                // `InvalidProof`, so a caller still cannot tell which bound it missed.
                if binding_error == Some(EnrollmentBindingError::Origin) {
                    SecurityCode::OriginRejected
                } else {
                    SecurityCode::ProofRejected
                },
                EventOutcome::Rejected,
                SafeNextAction::Reconnect,
                Some(expected_identity.get()),
                None,
                EndpointClass::Extension,
                EventTime(clock.occurrence_ms()),
                bundle.daemon.get(),
                Vec::new(),
            )
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            if bundle.mark_failed_proof().is_err() {
                return Err(EnrollmentConsumeError::AlreadyConsumed);
            }
            state
                .host_budgets
                .entry(host)
                .or_default()
                .record_failure(clock.occurrence_ms());
            channel.close();
            return Err(reason);
        }
        let fingerprint = Fingerprint::new(hex_digest(proof.long_term_public_key.as_bytes()))
            .map_err(|_| EnrollmentConsumeError::InvalidPublicKey)?;
        let event = SecurityEvent::new(
            bundle.enrollment_id.get(),
            EventBoundary::Enrollment,
            SecurityCode::EnrollmentAccepted,
            EventOutcome::Committed,
            SafeNextAction::Continue,
            Some(expected_identity.get()),
            None,
            EndpointClass::Extension,
            EventTime(clock.occurrence_ms()),
            bundle.daemon.get(),
            Vec::new(),
        )
        .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        bundle
            .enrollment
            .consume()
            .map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        state
            .consumed
            .insert(bundle.enrollment_id, expected_identity);
        state.registrations.insert(
            expected_identity,
            Registration {
                key: *proof.long_term_public_key.as_bytes(),
                fingerprint: fingerprint.clone(),
                capability: capability.clone(),
                revoked: false,
            },
        );
        Ok(fingerprint)
    }

    /// Charge and refuse one pairing attempt that bound to no pending enrollment.
    ///
    /// `contracts/enrollment-bootstrap.md` states that a malformed or unknown
    /// envelope cannot bind to a pending enrollment, so it counts only against the
    /// host budget: there is no enrollment whose five-proof budget could hold it.
    /// The refusal is the same `InvalidProof` a bound proof returns when it misses a
    /// bound, and the channel closes exactly as it does there, so neither the code
    /// nor the channel tells a caller whether the identifier was pending.
    ///
    /// The owed fact is emitted before the budget moves, so an unavailable sink
    /// leaves the budget untouched and admits nothing.
    pub(crate) fn consume_unbound_proof<S: SecurityEventSink + ?Sized>(
        &self,
        clock: &EnrollmentClock,
        binding: &EnrollmentBinding<'_>,
        capability: &ChromeCapability,
        channel: &mut EnrollmentChannel,
        sink: Option<&mut S>,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        Self::precheck_attempt(binding, capability, channel)?;
        let host = unbound_attempt_host_key(binding.endpoint);
        let mut state = self
            .state
            .lock()
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        let rate_limited = state.host_budgets.get(&host).is_some_and(|budget| {
            budget.before_attempt(clock.occurrence_ms()) == HostAttemptResult::RateLimited
        });
        // An exhausted host window refuses before proof work on the bound path, and an
        // unbound attempt is no different: it owes the rate-limit fact and the bounded
        // wait action rather than a second charge.
        let (code, outcome, action, refusal) = if rate_limited {
            (
                SecurityCode::RateLimited,
                EventOutcome::Rejected,
                SafeNextAction::Wait,
                EnrollmentConsumeError::RateLimited,
            )
        } else {
            (
                SecurityCode::MalformedInput,
                EventOutcome::Failed,
                SafeNextAction::Discard,
                EnrollmentConsumeError::InvalidProof,
            )
        };
        // No enrollment bound, so the fact carries no enrollment and no principal: the
        // presented identifiers name nothing this host holds, and leaving them out also
        // keeps every unbound attempt in one aggregation bucket.
        let event = SecurityEvent::new(
            Uuid::nil(),
            EventBoundary::Enrollment,
            code,
            outcome,
            action,
            None,
            None,
            EndpointClass::Extension,
            EventTime(clock.occurrence_ms()),
            Uuid::nil(),
            Vec::new(),
        )
        .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        if !rate_limited {
            state
                .host_budgets
                .entry(host)
                .or_default()
                .record_failure(clock.occurrence_ms());
        }
        channel.close();
        Err(refusal)
    }
    /// Consume one pairing proof against this service's own required-event sink.
    ///
    /// This is the boundary a host process calls. The sink lives as long as the
    /// service, so rate-limit and rejection facts aggregate across connections
    /// instead of restarting with every channel.
    ///
    /// A host passes `None` for an identifier it holds no pending enrollment for,
    /// rather than refusing it itself, so that attempt is budgeted and stated here
    /// and cannot become an existence oracle at the route.
    // Host pairing fields are contract-fixed at the public security boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_pairing_proof(
        &self,
        bundle: Option<&mut EnrollmentBundle>,
        proof: &EnrollmentProof,
        expected_identity: IdentityId,
        clock: &EnrollmentClock,
        binding: &EnrollmentBinding<'_>,
        capability: &ChromeCapability,
        channel: &mut EnrollmentChannel,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        match bundle {
            Some(bundle) => self.consume_proof(
                bundle,
                proof,
                expected_identity,
                clock,
                binding,
                capability,
                channel,
                Some(&mut *events),
            ),
            None => {
                self.consume_unbound_proof(clock, binding, capability, channel, Some(&mut *events))
            }
        }
    }

    pub fn reconnect(
        &self,
        identity: IdentityId,
        fingerprint: &Fingerprint,
        current_capability: &ChromeCapability,
    ) -> ChromeReconnectOutcome {
        let Ok(state) = self.state.lock() else {
            return ChromeReconnectOutcome::Mismatch;
        };
        let Some(registration) = state.registrations.get(&identity) else {
            return ChromeReconnectOutcome::Mismatch;
        };
        if registration.revoked {
            ChromeReconnectOutcome::Revoked
        } else if &registration.fingerprint == fingerprint
            && registration.capability.permits(current_capability)
        {
            ChromeReconnectOutcome::Reconnected
        } else {
            ChromeReconnectOutcome::Mismatch
        }
    }

    pub fn update_custody(
        &self,
        identity: IdentityId,
        key: &PublicKey,
        current_capability: &ChromeCapability,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        let update = Self::validate_custody_update(&state, identity, key, current_capability)?;
        let fingerprint = update.fingerprint.clone();
        Self::commit_validated_custody_update(&mut state, update);
        Ok(fingerprint)
    }

    pub(crate) fn prepare_custody_update(
        &mut self,
        identity: IdentityId,
        key: &PublicKey,
        current_capability: &ChromeCapability,
    ) -> Result<CustodyUpdate, EnrollmentConsumeError> {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        if core::mem::take(&mut state.fail_next_custody_validation) {
            return Err(EnrollmentConsumeError::EventUnavailable);
        }
        Self::validate_custody_update(state, identity, key, current_capability)
    }

    pub(crate) fn commit_custody_update(&mut self, update: CustodyUpdate) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::commit_validated_custody_update(state, update);
    }

    pub(crate) fn prepare_custody_revocation(
        &mut self,
        identity: IdentityId,
    ) -> Result<Option<CustodyRevocation>, EnrollmentConsumeError> {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(test)]
        if core::mem::take(&mut state.fail_next_custody_revocation) {
            return Err(EnrollmentConsumeError::EventUnavailable);
        }
        Ok(Self::validate_custody_revocation(state, identity))
    }

    pub(crate) fn commit_custody_revocation(&mut self, revocation: CustodyRevocation) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::commit_validated_custody_revocation(state, revocation);
    }

    fn validate_custody_update(
        state: &ConsumptionState,
        identity: IdentityId,
        key: &PublicKey,
        current_capability: &ChromeCapability,
    ) -> Result<CustodyUpdate, EnrollmentConsumeError> {
        let registration = state
            .registrations
            .get(&identity)
            .ok_or(EnrollmentConsumeError::CredentialMismatch)?;
        if registration.revoked {
            return Err(EnrollmentConsumeError::CredentialMismatch);
        }
        if !registration.capability.permits(current_capability) {
            return Err(EnrollmentConsumeError::CapabilityRejected);
        }
        let fingerprint = Fingerprint::new(hex_digest(key.as_bytes()))
            .map_err(|_| EnrollmentConsumeError::InvalidPublicKey)?;
        if registration.key == *key.as_bytes()
            || state
                .quarantined
                .iter()
                .any(|retired| retired == &fingerprint)
        {
            return Err(EnrollmentConsumeError::CredentialMismatch);
        }
        Ok(CustodyUpdate {
            identity,
            key: *key.as_bytes(),
            fingerprint,
            capability: current_capability.clone(),
            retired_fingerprint: registration.fingerprint.clone(),
        })
    }

    fn commit_validated_custody_update(state: &mut ConsumptionState, update: CustodyUpdate) {
        state.quarantined.push(update.retired_fingerprint);
        let registration = state
            .registrations
            .get_mut(&update.identity)
            .expect("validated custody registration remains present");
        registration.key = update.key;
        registration.fingerprint = update.fingerprint;
        registration.capability = update.capability;
    }

    fn validate_custody_revocation(
        state: &ConsumptionState,
        identity: IdentityId,
    ) -> Option<CustodyRevocation> {
        state
            .registrations
            .contains_key(&identity)
            .then_some(CustodyRevocation { identity })
    }

    fn commit_validated_custody_revocation(
        state: &mut ConsumptionState,
        revocation: CustodyRevocation,
    ) {
        state
            .registrations
            .get_mut(&revocation.identity)
            .expect("validated custody registration remains present")
            .revoked = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_next_custody_validation(&mut self) {
        self.state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_next_custody_validation = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_next_custody_revocation(&mut self) {
        self.state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_next_custody_revocation = true;
    }

    pub fn revoke(&self, identity: IdentityId) -> Result<(), EnrollmentConsumeError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        let revocation = Self::validate_custody_revocation(&state, identity)
            .ok_or(EnrollmentConsumeError::CredentialMismatch)?;
        Self::commit_validated_custody_revocation(&mut state, revocation);
        Ok(())
    }
}
/// The host-budget bucket for one endpoint, one bucket per loopback address.
///
/// FR-009 budgets failed pairing attempts per loopback address, and
/// `validate_endpoint` admits the IPv6 loopback in two spellings. Collapsing them
/// keeps one bucket per address, so rewriting the presented spelling reaches no
/// second budget.
fn host_key(endpoint: &str) -> Option<String> {
    let (host, port) = endpoint.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some(match host {
        "[::1]" => "::1".to_owned(),
        other => other.to_owned(),
    })
}

/// The bucket charged for an attempt that bound to no pending enrollment.
///
/// Only the presented endpoint attributes such an attempt, and a presented endpoint
/// that is not a valid loopback endpoint attributes it to no address at all. Those
/// charge one reserved bucket rather than none: `host_key` never yields an empty
/// host, so no presentable endpoint can reach that bucket or split it, and an
/// unattributable attempt still costs its host attempt instead of being free.
fn unbound_attempt_host_key(endpoint: &str) -> String {
    if validate_endpoint(endpoint) {
        host_key(endpoint).unwrap_or_default()
    } else {
        String::new()
    }
}

fn proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(32 + 16 + UNCOMPRESSED_KEY_BYTES * 2 + bundle.origin.len());
    message.extend_from_slice(b"matinee.enrollment.proof.v1\0");
    message.extend_from_slice(bundle.enrollment_id.get().as_bytes());
    message.extend_from_slice(bundle.one_time_public_key.as_bytes());
    message.extend_from_slice(long_term.as_bytes());
    message.extend_from_slice(bundle.origin.as_bytes());
    message
}

/// The exact bytes a pairing client signs with the one-time key.
///
/// The daemon publishes this transcript for one pending enrollment and one offered
/// long-term public key, so the client signs what consumption verifies and neither
/// side reimplements the format.
pub fn enrollment_proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
    proof_message(bundle, long_term)
}

/// The values supplied by the browser during `/v1/pair`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentBinding<'a> {
    pub origin: &'a str,
    pub endpoint: &'a str,
    pub store_metadata: &'a str,
    pub update_metadata: &'a str,
    pub install_metadata: &'a str,
    /// The version the browser reports for the pairing extension, in Chrome manifest form.
    pub version: &'a str,
    pub development_allowance: DevelopmentIdentityAllowance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevelopmentIdentityAllowance {
    None,
    Explicit { warning_acknowledged: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnrollmentBindingError {
    Origin,
    Endpoint,
    Metadata,
    Version,
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
    let authority_end = authority_and_suffix
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_suffix.len());
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
                && !matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b':'
                        | b'@'
                        | b'/'
                        | b'?'
                )
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
    if !validate_endpoint(expected.daemon_endpoint.as_str())
        || attempt.endpoint != expected.daemon_endpoint
    {
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
    // FR-019: a supported version is a pairing requirement, not advice. An unparsable
    // version and a version outside the pinned inclusive range both fail closed here,
    // before the development allowance is consulted, so an allowed development install
    // still has to be a build this daemon supports.
    let Ok(version) = ExtensionVersion::parse(attempt.version) else {
        return Err(EnrollmentBindingError::Version);
    };
    if !expected.supported_versions.contains(version) {
        return Err(EnrollmentBindingError::Version);
    }
    // `install_metadata` is the browser's identity classification. Production
    // pairing uses `normal`; every other install type is non-production and
    // requires the explicit, user-visible warning acknowledgement.
    let non_production_install = expected.install_metadata != "normal";
    if non_production_install
        && !matches!(
            attempt.development_allowance,
            DevelopmentIdentityAllowance::Explicit {
                warning_acknowledged: true
            }
        )
    {
        return Err(EnrollmentBindingError::DevelopmentAllowance);
    }
    Ok(())
}

/// Validate one described enrollment against the instant its host is creating it at, and
/// resolve the deadline that instant fixes.
///
/// The creation instant is a parameter rather than a field of the description, so the
/// window FR-007 bounds is measured from the clock reading the host actually took. A
/// description that carried its own instant could satisfy a width check while placing the
/// whole window arbitrarily far ahead, which bounds the width and nothing else.
fn validate_creation(
    input: &EnrollmentCreation,
    created_ms: u64,
) -> Result<ExpiryResult, EnrollmentCreateError> {
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
    // FR-007's ten minutes is a window between two instants, so the ceiling is the width
    // from the trusted creation instant to the deadline: a deadline at or before that
    // instant opens an enrollment already expired, and one further than ten minutes past
    // it is the window no caller may widen. Comparing the deadline itself against ten
    // minutes would instead refuse every enrollment created later than ten minutes into
    // the clock's epoch.
    let expiry = match &input.expiry {
        EnrollmentExpiry::Default => default_expiry(created_ms),
        EnrollmentExpiry::Deadline(requested) => requested.clone(),
    };
    let window_ms = expiry
        .deadline_ms()
        .checked_sub(created_ms)
        .unwrap_or_default();
    if !expiry.is_security_valid() || window_ms == 0 || window_ms > MAX_EXPIRY_MS {
        return Err(EnrollmentCreateError::InvalidExpiry);
    }
    Ok(expiry)
}

/// The ten-minute deadline FR-007 applies when an administrator names none, counted
/// from the instant the enrollment is created.
///
/// `ExpiryResult::valid` refuses exactly one value, zero, and the constant is checked
/// against it at compile time, so the sum cannot be zero and the default cannot degrade
/// into an uncertain or rejected deadline at runtime. A clock close enough to its own
/// ceiling to saturate yields a shorter window, never a wider one.
fn default_expiry(created_ms: u64) -> ExpiryResult {
    const { assert!(TEN_MINUTE_EXPIRY_MS != 0) }
    ExpiryResult::valid(created_ms.saturating_add(TEN_MINUTE_EXPIRY_MS))
        .expect("a nonzero deadline is a valid expiry")
}

/// Require the replay fact a proof against a spent or elapsed enrollment owes.
///
/// FR-027 and `contracts/failures-events.md` list a replay among the outcomes this
/// module must state, and `transition::consume_rejection` reports both an elapsed
/// deadline and an already-consumed enrollment as `replay.detected`, so one fact answers
/// for both. It is required before the refusal is returned, exactly as the rejected-proof
/// and rate-limit facts are: an unavailable sink fails closed with `EventUnavailable`, and
/// there is nothing to undo, because both refusals precede the consumption, the
/// registration, and every charge against the proof budget.
fn require_replay_fact<S: SecurityEventSink + ?Sized>(
    sink: &mut Option<&mut S>,
    bundle: &EnrollmentBundle,
    clock: &EnrollmentClock,
    identity: IdentityId,
) -> Result<(), EnrollmentConsumeError> {
    let event = SecurityEvent::new(
        bundle.enrollment_id.get(),
        EventBoundary::Enrollment,
        SecurityCode::ReplayDetected,
        EventOutcome::Rejected,
        SafeNextAction::Discard,
        Some(identity.get()),
        None,
        EndpointClass::Extension,
        EventTime(clock.occurrence_ms()),
        bundle.daemon.get(),
        Vec::new(),
    )
    .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
    emit_required(sink.as_deref_mut(), event)
        .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
    Ok(())
}

fn require_rate_limit_fact<S: SecurityEventSink + ?Sized>(
    sink: &mut Option<&mut S>,
    bundle: &EnrollmentBundle,
    clock: &EnrollmentClock,
) -> Result<(), EnrollmentConsumeError> {
    let event = SecurityEvent::new(
        bundle.enrollment_id.get(),
        EventBoundary::Enrollment,
        SecurityCode::RateLimited,
        EventOutcome::Rejected,
        SafeNextAction::Wait,
        None,
        None,
        EndpointClass::Loopback,
        EventTime(clock.occurrence_ms()),
        bundle.daemon.get(),
        Vec::new(),
    )
    .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
    emit_required(sink.as_deref_mut(), event)
        .map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
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

    /// A realistic wall-clock creation instant in Unix epoch milliseconds, which is the
    /// clock a daemon actually reads. A fixture created at zero cannot tell a ten-minute
    /// window from a deadline ten minutes after the epoch began.
    const CREATED_MS: u64 = 1_763_000_000_000;

    /// Far enough ahead of any trusted instant that no ten-minute window reaches it.
    const YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

    fn input() -> EnrollmentCreation {
        EnrollmentCreation::new(
            TransitionId::new(Uuid::from_u128(1)),
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            "stable",
            "https://updates.example.test/ext.xml",
            "normal",
            SupportedExtensionVersions::parse("1.0", "2.5.1").unwrap(),
            IdentityId::new(Uuid::from_u128(2)),
            "127.0.0.1:7777",
            EnrollmentExpiry::Default,
        )
    }

    fn asking_for(expiry: EnrollmentExpiry) -> EnrollmentCreation {
        let mut creation = input();
        creation.expiry = expiry;
        creation
    }

    fn deadline_at(deadline_ms: u64) -> EnrollmentExpiry {
        EnrollmentExpiry::Deadline(ExpiryResult::valid(deadline_ms).expect("a nonzero deadline"))
    }

    #[test]
    fn creates_bounded_redacted_one_use_bundle() {
        let bundle = EnrollmentBundle::create(input(), CREATED_MS).unwrap();
        assert_eq!(bundle.one_time_public_key_fingerprint().as_str().len(), 64);
        assert!(format!("{bundle:?}").contains("<redacted>"));
    }

    #[test]
    fn creates_with_printable_non_url_metadata_containing_spaces() {
        let mut spaced = input();
        spaced.store_metadata = "Chrome Web Store".into();
        spaced.install_metadata = "Chrome Web Store".into();
        assert!(EnrollmentBundle::create(spaced, CREATED_MS).is_ok());
    }

    #[test]
    fn uncertain_and_oversized_expiry_fail_closed() {
        let uncertain = asking_for(EnrollmentExpiry::Deadline(ExpiryResult::uncertain(
            CREATED_MS + MAX_EXPIRY_MS,
        )));
        assert!(matches!(
            EnrollmentBundle::create(uncertain, CREATED_MS),
            Err(EnrollmentCreateError::InvalidExpiry)
        ));
        let oversized = asking_for(deadline_at(CREATED_MS + MAX_EXPIRY_MS + 1));
        assert!(matches!(
            EnrollmentBundle::create(oversized, CREATED_MS),
            Err(EnrollmentCreateError::InvalidExpiry)
        ));
    }

    /// The property FR-007's ten minutes actually asserts: whatever an administrator asks
    /// for, an enrollment that opens is live for at most ten minutes after the instant its
    /// host created it at, and for a nonzero span.
    ///
    /// Asserted as that relation rather than against a literal deadline, because a
    /// literal-deadline check is satisfied by a window of the right width anchored at the
    /// wrong instant, which is a window of unbounded real validity.
    #[test]
    fn accepted_validity_never_outlasts_ten_minutes_after_the_trusted_instant() {
        // The earliest instant is 2, not 0 or 1: `deadline_at(trusted_ms - 1)` below has to
        // name a real deadline, and `ExpiryResult::valid` refuses zero.
        for trusted_ms in [2, TEN_MINUTE_EXPIRY_MS, CREATED_MS, CREATED_MS + YEAR_MS] {
            for requested in [
                EnrollmentExpiry::Default,
                deadline_at(trusted_ms + 1),
                deadline_at(trusted_ms + MAX_EXPIRY_MS),
                deadline_at(trusted_ms + MAX_EXPIRY_MS + 1),
                deadline_at(trusted_ms + YEAR_MS + MAX_EXPIRY_MS),
                deadline_at(trusted_ms),
                deadline_at(trusted_ms - 1),
            ] {
                match EnrollmentBundle::create(asking_for(requested.clone()), trusted_ms) {
                    Ok(bundle) => {
                        let window_ms = bundle
                            .expiry_deadline_ms()
                            .checked_sub(trusted_ms)
                            .expect("an accepted deadline is after the creation instant");
                        assert!(
                            window_ms > 0 && window_ms <= MAX_EXPIRY_MS,
                            "{requested:?} created at {trusted_ms} stayed live for {window_ms}ms"
                        );
                    }
                    Err(error) => assert_eq!(error, EnrollmentCreateError::InvalidExpiry),
                }
            }
        }
    }

    /// SEC-005: a deadline ten minutes after an instant far ahead of the trusted one is
    /// refused. The width of that request is exactly the ten minutes FR-007 allows, so a
    /// creation path that measured only the width — from a creation instant the caller
    /// also supplied — accepted it and stayed live for a year.
    #[test]
    fn a_ten_minute_window_anchored_ahead_of_the_trusted_instant_is_refused() {
        let future_anchor = CREATED_MS + YEAR_MS;
        let asked = deadline_at(future_anchor + TEN_MINUTE_EXPIRY_MS);
        assert_eq!(
            EnrollmentBundle::create(asking_for(asked), CREATED_MS)
                .expect_err("a window anchored a year ahead opens nothing"),
            EnrollmentCreateError::InvalidExpiry
        );
        // The same deadline is exactly what that instant's own host may open.
        let bundle = EnrollmentBundle::create(
            asking_for(deadline_at(future_anchor + TEN_MINUTE_EXPIRY_MS)),
            future_anchor,
        )
        .expect("ten minutes from the instant it is created at");
        assert_eq!(
            bundle.expiry_deadline_ms() - future_anchor,
            TEN_MINUTE_EXPIRY_MS
        );
    }

    /// A deadline anchored behind the trusted instant shortens the window or opens
    /// nothing; it never extends validity. An enrollment whose ten minutes have already
    /// run out by the time it is created is refused rather than opened spent.
    #[test]
    fn a_window_anchored_behind_the_trusted_instant_never_extends_validity() {
        let past_anchor = CREATED_MS - TEN_MINUTE_EXPIRY_MS;
        assert_eq!(
            EnrollmentBundle::create(
                asking_for(deadline_at(past_anchor + TEN_MINUTE_EXPIRY_MS)),
                CREATED_MS,
            )
            .expect_err("a window that has already run out opens nothing"),
            EnrollmentCreateError::InvalidExpiry
        );
        let overlapping = EnrollmentBundle::create(
            asking_for(deadline_at(past_anchor + TEN_MINUTE_EXPIRY_MS + 1)),
            CREATED_MS,
        )
        .expect("a deadline one millisecond ahead still opens");
        assert_eq!(overlapping.expiry_deadline_ms() - CREATED_MS, 1);
    }

    /// The default path still yields exactly the ten minutes FR-007 names, counted from the
    /// trusted instant, at any instant a real clock reports.
    #[test]
    fn the_default_expiry_is_ten_minutes_after_the_trusted_instant() {
        for trusted_ms in [0, 1, TEN_MINUTE_EXPIRY_MS, CREATED_MS] {
            let default = default_expiry(trusted_ms);
            assert_eq!(default.status(), ExpiryStatus::Valid);
            assert_eq!(default.deadline_ms(), trusted_ms + TEN_MINUTE_EXPIRY_MS);
            let bundle = EnrollmentBundle::create(input(), trusted_ms)
                .expect("an administrator naming no deadline gets the default");
            assert_eq!(
                bundle.expiry_deadline_ms(),
                trusted_ms + TEN_MINUTE_EXPIRY_MS
            );
        }
        // A clock at its own ceiling shortens the window instead of wrapping it.
        let saturated = default_expiry(u64::MAX);
        assert_eq!(saturated.deadline_ms(), u64::MAX);
    }

    /// The interval a proof is measured against is half-open, from the trusted creation
    /// instant up to the deadline: the last millisecond before the deadline still pairs,
    /// the deadline instant itself does not, and neither does an occurrence from before
    /// the enrollment existed.
    #[test]
    fn consumption_pairs_on_the_last_valid_millisecond_and_refuses_both_bounds() {
        let deadline_ms = CREATED_MS + TEN_MINUTE_EXPIRY_MS;
        let expiry = ExpiryResult::valid(deadline_ms).expect("a nonzero deadline");
        let at = |occurrence_ms: u64| {
            EnrollmentClock::new(occurrence_ms, expiry.clone()).valid_for(CREATED_MS, deadline_ms)
        };
        assert_eq!(at(CREATED_MS), Ok(()));
        assert_eq!(at(deadline_ms - 1), Ok(()));
        assert_eq!(at(deadline_ms), Err(EnrollmentConsumeError::Expired));
        assert_eq!(at(CREATED_MS - 1), Err(EnrollmentConsumeError::Expired));
    }

    fn binding() -> EnrollmentBinding<'static> {
        EnrollmentBinding {
            origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
            endpoint: "127.0.0.1:7777",
            store_metadata: "stable",
            update_metadata: "https://updates.example.test/ext.xml",
            install_metadata: "normal",
            version: "1.4.2",
            development_allowance: DevelopmentIdentityAllowance::None,
        }
    }

    #[test]
    fn binding_rejects_origin_endpoint_and_metadata_mutations() {
        let expected = input();
        assert_eq!(validate_enrollment_binding(&expected, &binding()), Ok(()));
        let mut wrong = binding();
        wrong.origin = "chrome-extension://abcdefghijklmnox";
        assert_eq!(
            validate_enrollment_binding(&expected, &wrong),
            Err(EnrollmentBindingError::Origin)
        );
        let mut wrong = binding();
        wrong.endpoint = "localhost:7777";
        assert_eq!(
            validate_enrollment_binding(&expected, &wrong),
            Err(EnrollmentBindingError::Endpoint)
        );
        let mut wrong = binding();
        wrong.update_metadata = "http://updates.example.test/ext.xml";
        assert_eq!(
            validate_enrollment_binding(&expected, &wrong),
            Err(EnrollmentBindingError::Metadata)
        );
    }

    #[test]
    fn development_install_requires_explicit_acknowledged_allowance() {
        let mut expected = input();
        expected.install_metadata = "development".into();
        let mut attempt = binding();
        attempt.install_metadata = "development";
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
        assert!(!validate_origin(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnox"
        ));
        assert!(!validate_metadata("https://", true));
        assert!(validate_metadata("Chrome Web Store", false));
        for invalid in ["contains\nnewline", "contains\x7fdelete", "contains café"] {
            assert!(!validate_metadata(invalid, false));
            assert!(!validate_metadata(invalid, true));
        }
        assert!(!validate_metadata(
            "http://updates.example.test/ext.xml",
            true
        ));
        assert!(!validate_metadata("https://updates.example.test/a b", true));
        assert!(!validate_metadata("https://updates.example.test/%zz", true));
        assert!(!validate_metadata("https://bad_host.example/ext.xml", true));
        assert!(!validate_metadata("https://updates..example/ext.xml", true));
        assert!(!validate_metadata(
            "https://updates.example../ext.xml",
            true
        ));
        assert!(!validate_metadata(
            "https://updates.example.test../ext.xml",
            true
        ));
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
