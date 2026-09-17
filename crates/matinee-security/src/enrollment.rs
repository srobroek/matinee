//! Closed, bounded enrollment creation.
//!
//! This module owns only the creation contract. Origin policy and consumption are
//! downstream concerns; this boundary stores their expected values without accepting
//! unbounded or uncertain input.

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
    bounded(
        &input.daemon_endpoint,
        MAX_ENDPOINT_BYTES,
        EnrollmentCreateError::EmptyOrOversizedEndpoint,
    )?;
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
}
