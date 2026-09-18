//! The process-lifetime enrollment host over the private security boundary.
//!
//! One host owns the enrollment registry, the host attempt budgets, the quarantine
//! set, and the pending one-time enrollments for a whole process. Connections come
//! and go: each one derives its own channel from this host, so replacing a
//! connection never resets a registration and never refills a host budget.

use std::collections::HashMap;
use std::fmt;
use std::sync::{LazyLock, Mutex};

use matinee_security::{
    ChromeCapability, EncryptedKeyOutput, EnrollmentBundle, EnrollmentChannel, EnrollmentClock,
    EnrollmentConsumptionService, enrollment_proof_message,
};

/// The security-boundary values a consumer of this host names directly.
pub use matinee_security::{
    ChromeReconnectOutcome, ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding,
    EnrollmentConsumeError, EnrollmentCreateError, EnrollmentCreation, EnrollmentCustodyError,
    EnrollmentProof, ExpiryResult, Fingerprint, IdentityId, PublicKey, TransitionId,
    UNCOMPRESSED_KEY_BYTES,
};

static ENROLLMENT_HOST: LazyLock<EnrollmentHost> = LazyLock::new(EnrollmentHost::new);

/// The one enrollment host owned by this process.
///
/// Every caller receives the same host, so a pairing committed through one
/// connection is visible to every later connection in the process.
pub fn enrollment_host() -> &'static EnrollmentHost {
    &ENROLLMENT_HOST
}

/// The enrollment state a host process keeps for its whole lifetime.
#[derive(Debug)]
pub struct EnrollmentHost {
    service: EnrollmentConsumptionService,
    pending: Mutex<HashMap<TransitionId, EnrollmentBundle>>,
}

impl EnrollmentHost {
    fn new() -> Self {
        Self {
            service: EnrollmentConsumptionService::default(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Open one bounded, one-time enrollment and keep its bundle in host custody.
    ///
    /// The returned ticket carries only ceremony-safe facts. The 32-byte secret and
    /// the one-time private key never leave this host except as sealed channel
    /// output. A second creation under a live enrollment identifier is refused
    /// rather than replacing it, because replacement would refill that
    /// enrollment's failed-proof budget.
    pub fn create_pairing(
        &self,
        creation: EnrollmentCreation,
    ) -> Result<PairingTicket, EnrollmentFailure> {
        let enrollment = creation.enrollment;
        let bundle = EnrollmentBundle::create(creation)?;
        let ticket = PairingTicket {
            enrollment: bundle.enrollment_id(),
            one_time_public_key: bundle.one_time_public_key().clone(),
            one_time_public_key_fingerprint: bundle.one_time_public_key_fingerprint().clone(),
            origin: bundle.origin().to_owned(),
            daemon: bundle.daemon(),
            daemon_endpoint: bundle.daemon_endpoint().to_owned(),
            expiry_deadline_ms: bundle.expiry_deadline_ms(),
        };
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        if pending.contains_key(&enrollment) {
            return Err(EnrollmentFailure::DuplicateEnrollment);
        }
        pending.insert(enrollment, bundle);
        Ok(ticket)
    }

    /// The exact bytes a client signs with the one-time key for this enrollment and
    /// the long-term public key it offers.
    pub fn proof_challenge(
        &self,
        enrollment: TransitionId,
        long_term_public_key: &PublicKey,
    ) -> Result<Vec<u8>, EnrollmentFailure> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        let bundle = pending
            .get(&enrollment)
            .ok_or(EnrollmentFailure::UnknownEnrollment)?;
        Ok(enrollment_proof_message(bundle, long_term_public_key))
    }

    /// Derive one pairing session for an authenticated connection.
    ///
    /// The session owns only its channel; the registry and the host budgets stay
    /// with this host.
    pub fn session(
        &self,
        connection: ConnectionId,
        epoch: u64,
    ) -> Result<PairingSession<'_>, EnrollmentFailure> {
        Ok(PairingSession {
            host: self,
            channel: EnrollmentChannel::open(connection, epoch)?,
        })
    }

    /// Whether a registered principal may resume on a presented key fingerprint.
    pub fn reconnect(
        &self,
        identity: IdentityId,
        fingerprint: &Fingerprint,
    ) -> ChromeReconnectOutcome {
        self.service.reconnect(identity, fingerprint)
    }

    /// Replace a registered principal's key, quarantining the stale fingerprint.
    pub fn update_custody(
        &self,
        identity: IdentityId,
        key: &PublicKey,
    ) -> Result<Fingerprint, EnrollmentFailure> {
        Ok(self.service.update_custody(identity, key)?)
    }

    /// Revoke a registered principal terminally.
    pub fn revoke(&self, identity: IdentityId) -> Result<(), EnrollmentFailure> {
        Ok(self.service.revoke(identity)?)
    }

    /// The registered fingerprint for a principal, when one is registered.
    pub fn registered_fingerprint(&self, identity: IdentityId) -> Option<Fingerprint> {
        self.service.registered_fingerprint(identity)
    }

    /// The registered long-term public key for a principal, when one is registered.
    pub fn registered_key(&self, identity: IdentityId) -> Option<PublicKey> {
        self.service.registered_public_key(identity)
    }

    /// Whether a fingerprint was quarantined by a custody update.
    pub fn is_quarantined(&self, fingerprint: &Fingerprint) -> bool {
        self.service.is_quarantined(fingerprint)
    }
}

/// The ceremony-safe projection of one pending enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingTicket {
    enrollment: TransitionId,
    one_time_public_key: PublicKey,
    one_time_public_key_fingerprint: Fingerprint,
    origin: String,
    daemon: IdentityId,
    daemon_endpoint: String,
    expiry_deadline_ms: u64,
}

impl PairingTicket {
    /// The identifier of the pending enrollment.
    pub fn enrollment(&self) -> TransitionId {
        self.enrollment
    }

    /// The one-time public key the daemon verifies the pairing proof against.
    pub fn one_time_public_key(&self) -> &PublicKey {
        &self.one_time_public_key
    }

    /// The fingerprint of that one-time public key.
    pub fn one_time_public_key_fingerprint(&self) -> &Fingerprint {
        &self.one_time_public_key_fingerprint
    }

    /// The expected extension Origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The daemon identity that owns the enrollment.
    pub fn daemon(&self) -> IdentityId {
        self.daemon
    }

    /// The bound loopback endpoint.
    pub fn daemon_endpoint(&self) -> &str {
        &self.daemon_endpoint
    }

    /// The enrollment deadline in the caller's own time base.
    pub fn expiry_deadline_ms(&self) -> u64 {
        self.expiry_deadline_ms
    }
}

/// The sealed one-time key as it travels over the authenticated native channel.
pub struct SealedOneTimeKey(EncryptedKeyOutput);

impl SealedOneTimeKey {
    /// The AEAD ciphertext. A transport capture contains only these bytes.
    pub fn ciphertext(&self) -> &[u8] {
        self.0.ciphertext()
    }
}

impl fmt::Debug for SealedOneTimeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedOneTimeKey")
            .field("ciphertext_bytes", &self.0.ciphertext().len())
            .finish()
    }
}

/// One pairing attempt presented on one authenticated channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingCompletion<'a> {
    /// The pending enrollment being consumed.
    pub enrollment: TransitionId,
    /// The principal the administrator expects this pairing to register.
    pub expected_identity: IdentityId,
    /// The proof the client signed with the one-time key.
    pub proof: &'a EnrollmentProof,
    /// The Origin, endpoint, and install metadata the client presented.
    pub binding: EnrollmentBinding<'a>,
    /// The caller's occurrence time for this attempt.
    pub occurrence_ms: u64,
    /// The caller's typed expiry observation for this attempt.
    pub expiry: ExpiryResult,
    /// Whether the browser reported durable `chrome.storage.local` custody.
    pub storage_local: bool,
    /// Whether the browser reported a non-exportable long-term key.
    pub non_exportable: bool,
}

/// The principal one pairing registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairedPrincipal {
    identity: IdentityId,
    fingerprint: Fingerprint,
}

impl PairedPrincipal {
    /// The registered principal.
    pub fn identity(&self) -> IdentityId {
        self.identity
    }

    /// The fingerprint of its registered long-term public key.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
}

/// One connection's pairing session, derived from the process-lifetime host.
#[derive(Debug)]
pub struct PairingSession<'a> {
    host: &'a EnrollmentHost,
    channel: EnrollmentChannel,
}

impl PairingSession<'_> {
    /// The connection this session serves.
    pub fn connection(&self) -> ConnectionId {
        self.channel.connection()
    }

    /// The epoch this session was opened at.
    pub fn epoch(&self) -> u64 {
        self.channel.epoch()
    }

    /// Whether the channel still carries custody.
    pub fn is_open(&self) -> bool {
        self.channel.is_open()
    }

    /// Close the channel. Sealed output already on the wire becomes unreadable.
    pub fn close(&mut self) {
        self.channel.close();
    }

    /// Seal one pending enrollment's one-time key for this channel's peer.
    ///
    /// The key leaves host custody exactly once, and only as ciphertext bound to
    /// this channel.
    pub fn deliver_one_time_key(
        &mut self,
        enrollment: TransitionId,
    ) -> Result<SealedOneTimeKey, EnrollmentFailure> {
        let mut pending = self
            .host
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        let bundle = pending
            .get_mut(&enrollment)
            .ok_or(EnrollmentFailure::UnknownEnrollment)?;
        Ok(SealedOneTimeKey(self.channel.seal_one_time_key(bundle)?))
    }

    /// The peer half of this channel: recover a sealed one-time key.
    pub fn open_sealed(&self, sealed: &SealedOneTimeKey) -> Result<Vec<u8>, EnrollmentFailure> {
        Ok(self.channel.open_sealed(&sealed.0)?)
    }

    /// Consume one pairing proof and register its long-term key.
    ///
    /// Success removes the enrollment from host custody: it is one-use. A failure
    /// leaves it pending so that its own failed-proof budget, and the shared host
    /// budget, keep counting.
    pub fn complete_pairing(
        &mut self,
        completion: &PairingCompletion<'_>,
    ) -> Result<PairedPrincipal, EnrollmentFailure> {
        let capability = ChromeCapability::reported(
            &completion.binding,
            completion.storage_local,
            completion.non_exportable,
        )?;
        let clock = EnrollmentClock::new(completion.occurrence_ms, completion.expiry.clone());
        let mut pending = self
            .host
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        let bundle = pending
            .get_mut(&completion.enrollment)
            .ok_or(EnrollmentFailure::UnknownEnrollment)?;
        let fingerprint = self.host.service.consume_pairing_proof(
            bundle,
            completion.proof,
            completion.expected_identity,
            &clock,
            &completion.binding,
            &capability,
            &mut self.channel,
        )?;
        pending.remove(&completion.enrollment);
        Ok(PairedPrincipal {
            identity: completion.expected_identity,
            fingerprint,
        })
    }
}

/// The closed set of enrollment-boundary failures a consumer observes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentFailure {
    /// The enrollment could not be created from the supplied values.
    Create(EnrollmentCreateError),
    /// The pairing proof was refused.
    Consume(EnrollmentConsumeError),
    /// One-time key custody was refused.
    Custody(EnrollmentCustodyError),
    /// No enrollment with that identifier is pending in this host.
    UnknownEnrollment,
    /// An enrollment with that identifier is already pending.
    DuplicateEnrollment,
    /// The host's own state could not be reached, so the call fails closed.
    HostUnavailable,
}

impl From<EnrollmentCreateError> for EnrollmentFailure {
    fn from(error: EnrollmentCreateError) -> Self {
        Self::Create(error)
    }
}

impl From<EnrollmentConsumeError> for EnrollmentFailure {
    fn from(error: EnrollmentConsumeError) -> Self {
        Self::Consume(error)
    }
}

impl From<EnrollmentCustodyError> for EnrollmentFailure {
    fn from(error: EnrollmentCustodyError) -> Self {
        Self::Custody(error)
    }
}

impl fmt::Display for EnrollmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create(error) => write!(formatter, "enrollment creation refused: {error}"),
            Self::Consume(error) => write!(formatter, "pairing proof refused: {error:?}"),
            Self::Custody(error) => write!(formatter, "one-time key custody refused: {error:?}"),
            Self::UnknownEnrollment => formatter.write_str("no such pending enrollment"),
            Self::DuplicateEnrollment => formatter.write_str("enrollment is already pending"),
            Self::HostUnavailable => formatter.write_str("enrollment host state is unavailable"),
        }
    }
}

impl std::error::Error for EnrollmentFailure {}
