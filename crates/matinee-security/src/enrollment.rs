//! Closed, bounded enrollment creation and binding validation.
//!
//! This module owns the creation contract and the private checks that bind a
//! pairing attempt to its expected browser origin, loopback endpoint, and
//! installation metadata. All checks fail closed before proof work or state
//! mutation.

use core::fmt;
use std::collections::HashMap;
use std::sync::Mutex;

use ring::rand::SecureRandom;
use ring::signature::KeyPair;
use ring::{digest, rand, signature};

use crate::events::{
    emit_required, EndpointClass, EventBoundary, EventOutcome, EventTime, SafeNextAction,
    SecurityCode, SecurityEvent, SecurityEventSink,
};
use crate::identity::{
    EnrollmentLifecycle, ExpiryResult, ExpiryStatus, ExtensionEnrollment, Fingerprint, IdentityId,
    PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES,
};

const SECRET_BYTES: usize = 32;
const MAX_EXPIRY_MS: u64 = 10 * 60 * 1_000;
const MAX_ORIGIN_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 256;

/// The bounded metadata and daemon binding supplied when an administrator creates
/// an enrollment. Strings are copied into the resulting bundle and never interpreted
/// as policy by this module.
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

/// Compatibility name for downstream crate-private consumers.
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
            Self::EmptyOrOversizedOrigin => "invalid enrollment origin",
            Self::EmptyOrOversizedMetadata => "invalid enrollment metadata",
            Self::EmptyOrOversizedEndpoint => "invalid enrollment endpoint",
            Self::InvalidOrigin => "invalid enrollment origin",
            Self::InvalidEndpoint => "invalid enrollment endpoint",
            Self::InvalidInstallMetadata => "invalid enrollment install metadata",
            Self::InvalidExpiry => "invalid enrollment expiry",
            Self::KeyGenerationFailed => "enrollment key generation failed",
            Self::InvalidPublicKey => "invalid enrollment public key",
            Self::InvalidFingerprint => "invalid enrollment fingerprint",
        })
    }
}

/// The one-use bundle returned by the authenticated native-channel operation.
///
/// The secret and PKCS#8 bytes are transient and intentionally absent from `Debug`.
/// `take_one_time_private_key` consumes the only retained private-key copy.
pub(crate) struct EnrollmentBundle {
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
            .field(
                "one_time_public_key_fingerprint",
                &self.one_time_public_key_fingerprint,
            )
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
        rng.fill(&mut secret)
            .map_err(|_| EnrollmentCreateError::KeyGenerationFailed)?;
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
            input.expiry.clone(),
        )
        .map_err(|_| EnrollmentCreateError::InvalidExpiry)?;
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

    pub(crate) fn enrollment(&self) -> &ExtensionEnrollment {
        &self.enrollment
    }
    pub(crate) fn lifecycle(&self) -> EnrollmentLifecycle {
        self.enrollment.lifecycle()
    }
    pub(crate) fn secret(&self) -> &[u8; SECRET_BYTES] {
        &self.secret
    }
    pub(crate) fn one_time_public_key(&self) -> &PublicKey {
        &self.one_time_public_key
    }
    pub(crate) fn one_time_public_key_fingerprint(&self) -> &Fingerprint {
        &self.one_time_public_key_fingerprint
    }
    pub(crate) fn origin(&self) -> &str {
        &self.origin
    }
    pub(crate) fn store_metadata(&self) -> &str {
        &self.store_metadata
    }
    pub(crate) fn update_metadata(&self) -> &str {
        &self.update_metadata
    }
    pub(crate) fn install_metadata(&self) -> &str {
        &self.install_metadata
    }
    pub(crate) fn record_failed_proof<S: SecurityEventSink>(
        &mut self,
        now: &ExpiryResult,
        sink: Option<&mut S>,
    ) -> Result<u8, EnrollmentConsumeError> {
        if !now.is_security_valid() {
            return Err(if now.status() == ExpiryStatus::Uncertain { EnrollmentConsumeError::UncertainExpiry } else { EnrollmentConsumeError::Expired });
        }
        let event = SecurityEvent::new(
            self.enrollment_id.get(), EventBoundary::Enrollment, SecurityCode::ProofRejected,
            EventOutcome::Rejected, SafeNextAction::Reconnect, Some(self.daemon.get()), None,
            EndpointClass::Extension, EventTime(now.deadline_ms()), self.daemon.get(), Vec::new(),
        ).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        self.enrollment.record_failed_proof().map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        Ok(self.enrollment.failed_proofs())
    }
    pub(crate) fn daemon(&self) -> IdentityId {
        self.daemon
    }
    pub(crate) fn daemon_endpoint(&self) -> &str {
        &self.daemon_endpoint
    }
    pub(crate) fn take_one_time_private_key(&mut self) -> Option<Vec<u8>> {
        self.one_time_private_key_pkcs8.take()
    }
}
/// A browser proof binds the one-time key to the newly generated long-term key.
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostAttemptResult {
    Allowed,
    RateLimited,
}

/// Independent host budget. The supplied timestamp is authoritative; this type
/// never reads a wall clock and never resets on successful pairing.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostAttemptBudget {
    failures: u8,
    window_start_ms: Option<u64>,
}

impl HostAttemptBudget {
    pub(crate) fn failures(&self) -> u8 { self.failures }

    pub(crate) fn before_attempt(&self, now: &ExpiryResult) -> HostAttemptResult {
        if !now.is_security_valid() { return HostAttemptResult::RateLimited; }
        let Some(start) = self.window_start_ms else { return HostAttemptResult::Allowed; };
        if now.deadline_ms().saturating_sub(start) >= 60_000 { HostAttemptResult::Allowed }
        else if self.failures >= 10 { HostAttemptResult::RateLimited } else { HostAttemptResult::Allowed }
    }

    pub(crate) fn record_failure(&mut self, now: &ExpiryResult) -> HostAttemptResult {
        if !now.is_security_valid() { return HostAttemptResult::RateLimited; }
        let at = now.deadline_ms();
        if self.window_start_ms.is_none() || at.saturating_sub(self.window_start_ms.unwrap_or(at)) >= 60_000 {
            self.window_start_ms = Some(at);
            self.failures = 0;
        }
        if self.failures >= 10 { return HostAttemptResult::RateLimited; }
        self.failures = self.failures.saturating_add(1);
        HostAttemptResult::Allowed
    }

    pub(crate) fn record_failure_gated<S: SecurityEventSink>(
        &mut self,
        now: &ExpiryResult,
        state_directory: IdentityId,
        sink: Option<&mut S>,
    ) -> Result<HostAttemptResult, EnrollmentConsumeError> {
        let outcome = self.before_attempt(now);
        if outcome == HostAttemptResult::RateLimited {
            let event = SecurityEvent::new(
                state_directory.get(), EventBoundary::Enrollment, SecurityCode::RateLimited,
                EventOutcome::Rejected, SafeNextAction::Wait, None, None, EndpointClass::Loopback,
                EventTime(now.deadline_ms()), state_directory.get(), Vec::new(),
            ).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
            return Ok(HostAttemptResult::RateLimited);
        }
        Ok(self.record_failure(now))
    }

    pub(crate) fn reset_if_elapsed(&mut self, now: &ExpiryResult) {
        if now.is_security_valid() && self.window_start_ms.is_some_and(|s| now.deadline_ms().saturating_sub(s) >= 60_000) {
            self.window_start_ms = None;
            self.failures = 0;
        }
    }
}

/// A registration table used by the production path. The mutex serializes the
/// check, required-event gate, and commit so concurrent proofs have one winner.
#[derive(Default)]
pub(crate) struct EnrollmentRegistry {
    registrations: Mutex<HashMap<TransitionId, ([u8; UNCOMPRESSED_KEY_BYTES], Fingerprint)>>,
}

impl EnrollmentRegistry {
    pub(crate) fn registered_public_key(&self, id: TransitionId) -> Option<PublicKey> {
        let bytes = self.registrations.lock().ok()?.get(&id)?.0;
        PublicKey::from_uncompressed(bytes).ok()
    }

    pub(crate) fn registered_fingerprint(&self, id: TransitionId) -> Option<Fingerprint> {
        self.registrations.lock().ok()?.get(&id).map(|entry| entry.1.clone())
    }

    pub(crate) fn consume_and_register<S: SecurityEventSink>(
        &self,
        bundle: &mut EnrollmentBundle,
        proof: &EnrollmentProof,
        expected_identity: IdentityId,
        now: &ExpiryResult,
        binding: &EnrollmentBinding<'_>,
        sink: Option<&mut S>,
    ) -> Result<Fingerprint, EnrollmentConsumeError> {
        if !now.is_security_valid() { return Err(if now.status() == ExpiryStatus::Uncertain { EnrollmentConsumeError::UncertainExpiry } else { EnrollmentConsumeError::Expired }); }
        if now.deadline_ms() > bundle.expiry_deadline_ms { return Err(EnrollmentConsumeError::Expired); }
        let expected = EnrollmentCreation::new(
            bundle.enrollment_id, bundle.origin.clone(), bundle.store_metadata.clone(),
            bundle.update_metadata.clone(), bundle.install_metadata.clone(), bundle.daemon,
            bundle.daemon_endpoint.clone(), ExpiryResult::valid(bundle.expiry_deadline_ms)
                .map_err(|_| EnrollmentConsumeError::Expired)?,
        );
        validate_enrollment_binding(&expected, binding).map_err(|_| EnrollmentConsumeError::InvalidProof)?;
        if proof.identity != expected_identity { return Err(EnrollmentConsumeError::WrongIdentity); }
        let fingerprint = Fingerprint::new(hex_digest(proof.long_term_public_key.as_bytes())).map_err(|_| EnrollmentConsumeError::InvalidPublicKey)?;
        let message = proof_message(bundle, &proof.long_term_public_key);
        let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, bundle.one_time_public_key.as_bytes());
        key.verify(&message, &proof.signature).map_err(|_| EnrollmentConsumeError::InvalidProof)?;
        let mut registrations = self.registrations.lock().map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        if registrations.contains_key(&bundle.enrollment_id) || bundle.lifecycle() != EnrollmentLifecycle::Pending {
            return Err(EnrollmentConsumeError::AlreadyConsumed);
        }
        let event = SecurityEvent::new(
            bundle.enrollment_id.get(), EventBoundary::Enrollment, SecurityCode::EnrollmentAccepted,
            EventOutcome::Committed, SafeNextAction::Continue, Some(expected_identity.get()), None,
            EndpointClass::Extension, EventTime(now.deadline_ms()), bundle.daemon.get(), Vec::new(),
        ).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        emit_required(sink, event).map_err(|_| EnrollmentConsumeError::EventUnavailable)?;
        bundle.enrollment.consume().map_err(|_| EnrollmentConsumeError::AlreadyConsumed)?;
        registrations.insert(bundle.enrollment_id, (*proof.long_term_public_key.as_bytes(), fingerprint.clone()));
        Ok(fingerprint)
    }
}

fn proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
    let mut message = Vec::with_capacity(32 + 16 + UNCOMPRESSED_KEY_BYTES);
    message.extend_from_slice(&bundle.secret);
    message.extend_from_slice(bundle.enrollment_id.get().as_bytes());
    message.extend_from_slice(long_term.as_bytes());
    message
}

pub(crate) fn enrollment_proof_message(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
    proof_message(bundle, long_term)
}


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
        assert!(bundle.take_one_time_private_key().is_some());
        assert!(bundle.take_one_time_private_key().is_none());
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
