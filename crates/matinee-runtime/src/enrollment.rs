//! The process-lifetime enrollment host over the private security boundary.
//!
//! One host owns the enrollment registry, the host attempt budgets, the quarantine
//! set, and the pending one-time enrollments for a whole process. Connections come
//! and go: each one derives its own channel from this host, so replacing a
//! connection never resets a registration and never refills a host budget.

use std::collections::HashMap;
use std::fmt;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use matinee_security::{
    ChromeCapability, EncryptedKeyOutput, EnrollmentBundle, EnrollmentChannel, EnrollmentClock,
    EnrollmentConsumptionService, enrollment_proof_message,
};

/// The security-boundary values a consumer of this host names directly.
pub use matinee_security::{
    ChromeReconnectOutcome, ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding,
    EnrollmentConsumeError, EnrollmentCreateError, EnrollmentCreation, EnrollmentCustodyError,
    EnrollmentExpiry, EnrollmentProof, ExpiryResult, Fingerprint, IdentityId, PublicKey,
    TransitionId, UNCOMPRESSED_KEY_BYTES,
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

    #[cfg(test)]
    pub(crate) fn reset_for_test(&self) {
        *self.pending.lock().expect("pending enrollment lock") = HashMap::new();
        self.service.reset_for_test();
    }

    /// Open one bounded, one-time enrollment at this host's own clock reading and keep
    /// its bundle in host custody.
    ///
    /// The invariant this entry point establishes: a caller outside this crate cannot
    /// choose the instant an enrollment's ten-minute window is anchored to. This host is
    /// the process that holds the clock, so it takes the reading itself. The security
    /// boundary deliberately defines no clock trait, and `EnrollmentCreation` names no
    /// instant, so a described enrollment carries nothing its window could be measured
    /// from; the reading has to arrive from the process that took it. What it must not do
    /// is arrive from the caller, because an anchor the caller supplies satisfies the
    /// width check and still places a ten-minute window arbitrarily far ahead, which
    /// bounds the width and nothing else. A requested `EnrollmentExpiry::Deadline` stays
    /// the caller's to name, but it is now measured against real time, so it can only
    /// fall within ten minutes of now.
    ///
    /// The returned ticket carries only ceremony-safe facts. The one-time private
    /// key leaves this host only as sealed channel output. A second creation under
    /// a live enrollment identifier is refused rather than replacing it, because
    /// replacement would refill that enrollment's failed-proof budget.
    pub fn create_pairing(
        &self,
        creation: EnrollmentCreation,
    ) -> Result<PairingTicket, EnrollmentFailure> {
        self.create_pairing_at_instant(creation, host_clock_ms()?)
    }

    /// Open one enrollment at a fixture's chosen instant.
    ///
    /// Expiry assertions have to name the instant they measure from, so the test
    /// surfaces pin it rather than racing the wall clock. Production compiles no such
    /// entry point, which is what keeps the anchor out of a caller's hands.
    #[cfg(test)]
    pub(crate) fn create_pairing_at(
        &self,
        creation: EnrollmentCreation,
        created_ms: u64,
    ) -> Result<PairingTicket, EnrollmentFailure> {
        self.create_pairing_at_instant(creation, created_ms)
    }



    /// The one creation path. `created_ms` reaches it from this host's own clock or from
    /// a `test-support` fixture, and from nowhere a consumer of this crate can reach.
    fn create_pairing_at_instant(
        &self,
        creation: EnrollmentCreation,
        created_ms: u64,
    ) -> Result<PairingTicket, EnrollmentFailure> {
        let enrollment = creation.enrollment;
        let bundle = EnrollmentBundle::create(creation, created_ms)?;
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
    ///
    /// An identifier this host holds nothing for yields the same normalized refusal
    /// a missed proof bound yields. Publishing a transcript at all is what tells the
    /// ticket holder its enrollment is live, so this helper states existence by
    /// succeeding; it never states it by the shape of a failure.
    pub fn proof_challenge(
        &self,
        enrollment: TransitionId,
        long_term_public_key: &PublicKey,
    ) -> Result<Vec<u8>, EnrollmentFailure> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        let bundle = pending.get(&enrollment).ok_or(EnrollmentFailure::Consume(
            EnrollmentConsumeError::InvalidProof,
        ))?;
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

    /// Whether a registered principal may resume on a presented key fingerprint
    /// and a currently reported browser custody capability.
    pub fn reconnect(
        &self,
        identity: IdentityId,
        fingerprint: &Fingerprint,
        binding: &EnrollmentBinding<'_>,
        storage_local: bool,
        non_exportable: bool,
    ) -> ChromeReconnectOutcome {
        let Ok(capability) = ChromeCapability::reported(binding, storage_local, non_exportable)
        else {
            return ChromeReconnectOutcome::Mismatch;
        };
        self.service.reconnect(identity, fingerprint, &capability)
    }

    /// Replace a registered principal's key, quarantining the stale fingerprint.
    pub fn update_custody(
        &self,
        identity: IdentityId,
        key: &PublicKey,
        binding: &EnrollmentBinding<'_>,
        storage_local: bool,
        non_exportable: bool,
    ) -> Result<Fingerprint, EnrollmentFailure> {
        let capability = ChromeCapability::reported(binding, storage_local, non_exportable)?;
        Ok(self.service.update_custody(identity, key, &capability)?)
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

/// This host's clock, in milliseconds since the Unix epoch.
///
/// The deadline an enrollment fixes travels to the extension inside a ticket and is
/// compared against the occurrence time of a later pairing attempt, so the anchor has to
/// be an absolute instant both sides can name; a monotonic `Instant` carries no such base
/// and could not be published. A clock set before the epoch, or so far past it that the
/// millisecond count leaves `u64`, offers no usable anchor, so each fails closed rather
/// than substituting an instant nothing vouched for.
fn host_clock_ms() -> Result<u64, EnrollmentFailure> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| EnrollmentFailure::HostUnavailable)?;
    host_clock_ms_from_duration(since_epoch)
}

fn host_clock_ms_from_duration(since_epoch: std::time::Duration) -> Result<u64, EnrollmentFailure> {
    u64::try_from(since_epoch.as_millis()).map_err(|_| EnrollmentFailure::HostUnavailable)
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

    /// The enrollment deadline, in the time base of the clock the creating host read.
    pub fn expiry_deadline_ms(&self) -> u64 {
        self.expiry_deadline_ms
    }
}

/// The sealed one-time key as it travels over the authenticated native channel.
pub struct SealedOneTimeKey(EncryptedKeyOutput);

impl SealedOneTimeKey {
    /// The enrollment whose transfer context is authenticated by this output.
    pub fn enrollment(&self) -> TransitionId {
        self.0.enrollment()
    }

    /// The unique nonce carried with this sealed output.
    pub fn nonce(&self) -> &[u8; 12] {
        self.0.nonce()
    }

    /// The AEAD ciphertext.
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
    ///
    /// Custody is one-use and a consumed enrollment leaves this map, so an
    /// identifier absent from it was either never created or already spent. Both are
    /// the refusal a second seal of a live bundle already returns, and reporting that
    /// one refusal keeps custody from answering which it was.
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
            .ok_or(EnrollmentFailure::Custody(
                EnrollmentCustodyError::AlreadyTransferred,
            ))?;
        Ok(SealedOneTimeKey(self.channel.seal_one_time_key(bundle)?))
    }

    /// Test-only peer simulation. The sealed key never crosses back as plaintext;
    /// the helper returns only the signature a remote peer would send.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn sign_proof_for_test(
        &self,
        expected_enrollment: TransitionId,
        sealed: &SealedOneTimeKey,
        challenge: &[u8],
    ) -> Result<Vec<u8>, EnrollmentFailure> {
        Ok(self
            .channel
            .sign_sealed_for_test(expected_enrollment, &sealed.0, challenge)?)
    }

    /// Consume one pairing proof and register its long-term key.
    ///
    /// The invariant this entry point establishes: a caller outside this crate cannot
    /// choose the instant used by the host's failed-pairing budget. This host owns the
    /// clock reading, so production pairing always measures the attempt against the
    /// instant this process observed rather than against a caller-supplied occurrence.
    /// A bad host clock fails closed as [`EnrollmentFailure::HostUnavailable`].
    ///
    /// Success removes the enrollment from host custody: it is one-use. A failure
    /// leaves it pending so that its own failed-proof budget, and the shared host
    /// budget, keep counting.
    ///
    /// Resolving the presented identifier is this layer's lookup but not this
    /// layer's decision. An identifier naming no pending enrollment is handed to the
    /// security boundary as `None` instead of being refused here, because
    /// `contracts/enrollment-bootstrap.md` requires such an envelope to count
    /// against the host budget and to owe its fact. Refusing it early would also
    /// answer whether that enrollment is pending.
    ///
    pub fn complete_pairing(
        &mut self,
        completion: &PairingCompletion<'_>,
    ) -> Result<PairedPrincipal, EnrollmentFailure> {
        self.complete_pairing_with_clock(completion, host_clock_ms())
    }

    /// Consume one pairing proof at a fixture's chosen instant.
    ///
    /// Production code cannot reach this deterministic clock injection point.
    #[cfg(test)]
    pub(crate) fn complete_pairing_at(
        &mut self,
        completion: &PairingCompletion<'_>,
        occurrence_ms: u64,
    ) -> Result<PairedPrincipal, EnrollmentFailure> {
        self.complete_pairing_with_clock(completion, Ok(occurrence_ms))
    }

    fn complete_pairing_with_clock(
        &mut self,
        completion: &PairingCompletion<'_>,
        occurrence_ms: Result<u64, EnrollmentFailure>,
    ) -> Result<PairedPrincipal, EnrollmentFailure> {
        let occurrence_ms = occurrence_ms?;
        let capability = ChromeCapability::reported(
            &completion.binding,
            completion.storage_local,
            completion.non_exportable,
        )?;
        let clock = EnrollmentClock::new(occurrence_ms, completion.expiry.clone());
        let mut pending = self
            .host
            .pending
            .lock()
            .map_err(|_| EnrollmentFailure::HostUnavailable)?;
        let fingerprint = self.host.service.consume_pairing_proof(
            pending.get_mut(&completion.enrollment),
            completion.proof,
            completion.expected_identity,
            &clock,
            &completion.binding,
            &capability,
            &mut self.channel,
        )?;
        // Only a bound enrollment can reach success, so this consumes the one that did.
        pending.remove(&completion.enrollment);
        Ok(PairedPrincipal {
            identity: completion.expected_identity,
            fingerprint,
        })
    }
}

/// The closed set of enrollment-boundary failures a consumer observes.
///
/// There is deliberately no "unknown enrollment" failure. Every stable code in
/// `contracts/failures-events.md` is reachable here, and that table has none:
/// whether an identifier names a pending enrollment is exactly what this boundary
/// must not answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentFailure {
    /// The enrollment could not be created from the supplied values.
    Create(EnrollmentCreateError),
    /// The pairing proof was refused.
    Consume(EnrollmentConsumeError),
    /// One-time key custody was refused.
    Custody(EnrollmentCustodyError),
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
            Self::DuplicateEnrollment => formatter.write_str("enrollment is already pending"),
            Self::HostUnavailable => formatter.write_str("enrollment host state is unavailable"),
        }
    }
}

impl std::error::Error for EnrollmentFailure {}

#[cfg(test)]
mod tests {
    use super::*;
    use matinee_security::SupportedExtensionVersions;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    use uuid::Uuid;

    const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
    const STORE: &str = "Chrome Web Store";
    const UPDATE: &str = "https://updates.example.test/ext.xml";
    const INSTALL: &str = "normal";
    const ENDPOINT: &str = "127.0.0.1:7777";
    /// FR-007's window, restated here so a change to the security crate's ceiling shows
    /// up as a failure at this boundary rather than passing silently.
    const TEN_MINUTES_MS: u64 = 10 * 60 * 1_000;
    const A_YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1_000;

    fn binding() -> EnrollmentBinding<'static> {
        EnrollmentBinding {
            origin: ORIGIN,
            endpoint: ENDPOINT,
            store_metadata: STORE,
            update_metadata: UPDATE,
            install_metadata: INSTALL,
            version: "1.4.2",
            development_allowance: DevelopmentIdentityAllowance::None,
        }
    }

    /// A structurally valid public key. Nothing verifies a signature against it on
    /// the path under test; it only has to be a point the boundary accepts.
    fn some_public_key() -> PublicKey {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
        bytes.copy_from_slice(signer.public_key().as_ref());
        PublicKey::from_uncompressed(bytes).unwrap()
    }

    fn attempt_unknown_at_clock(
        host: &EnrollmentHost,
        connection: u128,
        enrollment: u128,
        occurrence_ms: Result<u64, EnrollmentFailure>,
    ) -> EnrollmentFailure {
        let proof = EnrollmentProof {
            identity: IdentityId::new(Uuid::from_u128(0xd00d)),
            signature: vec![0; 8],
            long_term_public_key: some_public_key(),
        };
        host.session(ConnectionId::new(Uuid::from_u128(connection)), 1)
            .expect("open a session")
            .complete_pairing_with_clock(
                &PairingCompletion {
                    enrollment: TransitionId::new(Uuid::from_u128(enrollment)),
                    expected_identity: IdentityId::new(Uuid::from_u128(0xd00d)),
                    proof: &proof,
                    binding: binding(),
                    expiry: ExpiryResult::valid(600_000).expect("bounded deadline"),
                    storage_local: true,
                    non_exportable: true,
                },
                occurrence_ms,
            )
            .expect_err("an enrollment that was never created cannot pair")
    }

    fn attempt_unknown(
        host: &EnrollmentHost,
        connection: u128,
        enrollment: u128,
        occurrence_ms: u64,
    ) -> EnrollmentFailure {
        attempt_unknown_at_clock(host, connection, enrollment, Ok(occurrence_ms))
    }

    #[test]
    fn a_bad_host_clock_fails_closed_without_granting_an_attempt() {
        let host = EnrollmentHost::new();
        assert_eq!(
            attempt_unknown_at_clock(
                &host,
                0xc300,
                0xbeef,
                Err(EnrollmentFailure::HostUnavailable),
            ),
            EnrollmentFailure::HostUnavailable,
        );
        for attempt in 0..10u64 {
            assert_eq!(
                attempt_unknown(&host, 0xc400 + u128::from(attempt), 0xbeef, attempt + 1),
                EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
            );
        }
        assert_eq!(
            attempt_unknown(&host, 0xc410, 0xbeef, 11),
            EnrollmentFailure::Consume(EnrollmentConsumeError::RateLimited),
        );
    }

    #[test]
    fn an_unrepresentable_clock_reading_fails_closed() {
        assert_eq!(
            host_clock_ms_from_duration(
                std::time::Duration::from_millis(u64::MAX)
                    .checked_add(std::time::Duration::from_millis(1))
                    .expect("duration arithmetic")
            ),
            Err(EnrollmentFailure::HostUnavailable),
        );
    }

    /// An identifier this host holds nothing for reaches the budgeted boundary.
    ///
    /// `contracts/enrollment-bootstrap.md` requires a malformed or unknown envelope to
    /// count against the host budget, and FR-009 sets that budget at ten per loopback
    /// address per minute. Resolving the identifier here and refusing early would
    /// charge nothing, so the eleventh attempt is what proves the ten before it were
    /// charged through this wiring rather than only inside the security crate.
    #[test]
    fn an_unknown_identifier_is_charged_the_host_budget_through_the_runtime_boundary() {
        let host = EnrollmentHost::new();
        for attempt in 0..10u64 {
            assert_eq!(
                attempt_unknown(
                    &host,
                    0xc000 + u128::from(attempt),
                    0xbad0,
                    70_000 + attempt
                ),
                EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
                "attempt {attempt} is refused without naming a distinct unknown-enrollment code"
            );
        }
        assert_eq!(
            attempt_unknown(&host, 0xc010, 0xbad0, 70_010),
            EnrollmentFailure::Consume(EnrollmentConsumeError::RateLimited),
            "the eleventh unknown attempt is rate limited, so each of the ten was charged"
        );
    }

    /// Probing many identifiers spends the same one budget.
    ///
    /// A per-identifier charge would let an attacker sweep the pending space ten
    /// attempts at a time, so the charge has to follow the host and not the
    /// identifier presented.
    #[test]
    fn probing_distinct_unknown_identifiers_shares_one_host_budget() {
        let host = EnrollmentHost::new();
        for attempt in 0..10u64 {
            assert_eq!(
                attempt_unknown(
                    &host,
                    0xc100 + u128::from(attempt),
                    0xbb00 + u128::from(attempt),
                    80_000 + attempt
                ),
                EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof)
            );
        }
        assert_eq!(
            attempt_unknown(&host, 0xc110, 0xbbff, 80_010),
            EnrollmentFailure::Consume(EnrollmentConsumeError::RateLimited),
            "ten distinct unknown identifiers exhaust one host window, not ten"
        );
    }

    /// A pending enrollment is not disclosed by the shape of a refusal.
    ///
    /// One identifier here is pending and one was never created. Both attempts carry a
    /// proof that cannot verify, and `contracts/failures-events.md` names no code for
    /// an absent object, so both must refuse identically.
    #[test]
    fn a_pending_and_an_absent_identifier_refuse_identically() {
        let host = EnrollmentHost::new();
        let ticket = host
            .create_pairing_at_instant(
                EnrollmentCreation::new(
                    TransitionId::new(Uuid::from_u128(0xbc01)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    INSTALL,
                    SupportedExtensionVersions::parse("1.0", "2.5.1").expect("bounded versions"),
                    IdentityId::new(Uuid::from_u128(0xbc02)),
                    ENDPOINT,
                    EnrollmentExpiry::Deadline(
                        ExpiryResult::valid(600_000).expect("bounded deadline"),
                    ),
                ),
                0,
            )
            .expect("create one pending enrollment");
        let pending = attempt_unknown(&host, 0xc200, ticket.enrollment().get().as_u128(), 90_000);
        let absent = attempt_unknown(&host, 0xc201, 0xbcff, 90_001);
        assert_eq!(
            pending, absent,
            "a pending identifier and an absent one must not be told apart by their refusal"
        );
    }

    fn described(enrollment: u128, expiry: EnrollmentExpiry) -> EnrollmentCreation {
        EnrollmentCreation::new(
            TransitionId::new(Uuid::from_u128(enrollment)),
            ORIGIN,
            STORE,
            UPDATE,
            INSTALL,
            SupportedExtensionVersions::parse("1.0", "2.5.1").expect("bounded versions"),
            IdentityId::new(Uuid::from_u128(0xbc02)),
            ENDPOINT,
            expiry,
        )
    }

    /// A caller cannot anchor an enrollment's ten-minute window in the future.
    ///
    /// `create_pairing` accepts no instant, so the only instant a caller can still name
    /// is the requested deadline, and this host measures it from its own clock. A
    /// deadline a year out therefore describes a year-wide window and is refused. The
    /// same deadline beside a caller-supplied creation instant a year ahead described a
    /// ten-minute window placed a year ahead, and passed the width check: that is the
    /// hole, and restoring the instant parameter reopens it and fails this test.
    #[test]
    fn a_caller_cannot_anchor_the_expiry_window_in_the_future() {
        let host = EnrollmentHost::new();
        let far_future = host_clock_ms().expect("a readable host clock") + A_YEAR_MS;
        assert_eq!(
            host.create_pairing(described(
                0xbd01,
                EnrollmentExpiry::Deadline(
                    ExpiryResult::valid(far_future + TEN_MINUTES_MS).expect("bounded deadline")
                ),
            ))
            .unwrap_err(),
            EnrollmentFailure::Create(EnrollmentCreateError::InvalidExpiry),
            "a deadline a year ahead is a year-wide window once it is measured from this \
             host's own clock, and no caller may widen it"
        );
    }

    /// A legitimate creation still opens a window, and opens it ten minutes past real time.
    ///
    /// The deadline has to land ten minutes past an instant bracketed by two readings of
    /// this host's clock. An anchor frozen at some constant would put it ten minutes past
    /// that constant instead, which is exactly what this refuses to accept.
    #[test]
    fn a_default_expiry_opens_ten_minutes_past_this_hosts_clock() {
        let host = EnrollmentHost::new();
        let before = host_clock_ms().expect("a readable host clock");
        let ticket = host
            .create_pairing(described(0xbd02, EnrollmentExpiry::Default))
            .expect("a described enrollment with a default expiry is created");
        let after = host_clock_ms().expect("a readable host clock");
        let deadline = ticket.expiry_deadline_ms();
        assert!(
            (before + TEN_MINUTES_MS..=after + TEN_MINUTES_MS).contains(&deadline),
            "deadline {deadline} is not ten minutes past an instant this host read between \
             {before} and {after}"
        );
    }

    /// A caller may still name a deadline; it just has to be one real time allows.
    ///
    /// Taking the anchor away from callers must not take the requested deadline with it,
    /// so a deadline five minutes out is still honoured exactly as named.
    #[test]
    fn a_requested_deadline_within_ten_minutes_is_honoured() {
        let host = EnrollmentHost::new();
        let requested = host_clock_ms().expect("a readable host clock") + TEN_MINUTES_MS / 2;
        let ticket = host
            .create_pairing(described(
                0xbd03,
                EnrollmentExpiry::Deadline(
                    ExpiryResult::valid(requested).expect("bounded deadline"),
                ),
            ))
            .expect("a deadline inside ten minutes of now is created");
        assert_eq!(
            ticket.expiry_deadline_ms(),
            requested,
            "a deadline real time allows is carried through unchanged"
        );
    }
}
