//! Closed, bounded enrollment creation and binding validation.
//!
//! This module owns the creation contract and the private checks that bind a
//! pairing attempt to its expected browser origin, loopback endpoint, and
//! installation metadata. All checks fail closed before proof work or state
//! mutation.

use core::fmt;

use ring::rand::SecureRandom;
use ring::signature::KeyPair;
use ring::{digest, rand, signature};

use crate::identity::{
    EnrollmentLifecycle, ExpiryResult, ExtensionEnrollment, Fingerprint, IdentityId, PublicKey,
    TransitionId, UNCOMPRESSED_KEY_BYTES,
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
    let Some(id) = origin.strip_prefix("chrome-extension://") else { return false };
    (id.len() == 16 || id.len() == 32) && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

fn validate_endpoint(endpoint: &str) -> bool {
    let Some((host, port)) = endpoint.rsplit_once(':') else { return false };
    let valid_host = host == "127.0.0.1" || host == "[::1]" || host == "::1";
    valid_host && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_metadata(value: &str, update: bool) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
        && (!update || value.starts_with("https://"))
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
    let development_id = expected.origin.ends_with("-dev") || expected.install_metadata == "development";
    if development_id
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
            "chrome-extension://abcdefghijklmnop",
            "stable",
            "https://updates.example.test/ext.xml",
            "webstore",
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
            origin: "chrome-extension://abcdefghijklmnop",
            endpoint: "127.0.0.1:7777",
            store_metadata: "stable",
            update_metadata: "https://updates.example.test/ext.xml",
            install_metadata: "webstore",
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
}
