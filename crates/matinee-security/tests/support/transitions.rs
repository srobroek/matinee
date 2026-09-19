//! Fixtures for driving the serialized transition boundary.
//!
//! Every fixture here goes through the production surface: a registered principal
//! snapshot, a real handshake pair, the closed command set, and the enrollment host's
//! own proof consumption. Nothing models a transition locally.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

use crate::enrollment::{
    ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentChannel,
    EnrollmentClock, EnrollmentCreation, EnrollmentProof, SupportedExtensionVersions,
};
use crate::events::EventTime;
use crate::identity::{
    Capability, CapabilityAction, CredentialReference, ExpiryResult, ExtensionGrant, Fingerprint,
    IdempotencyKey, IdentityId, Principal, PrincipalKind, PublicKey, TransitionId, TransitionInput,
    TransitionOperation, TransitionOutcome, UNCOMPRESSED_KEY_BYTES,
};
use crate::test_support_channel::{
    ENDPOINT, OWNER, RecordingSink, RingSigner, SCOPE, STATE_DIRECTORY, capability,
    establish_pair_for, id, registered_principal,
};
use crate::transition::{
    PairingMaterial, ReplacementCredential, SecurityTransitions, TransitionMaterial,
    TransitionRejection,
};
use crate::{
    AuthorizedInput, AuthorizedOutput, ChannelSession, ChannelSigner, ConnectionId, ObjectOwner,
    PayloadKind, SecurityCommand, SecurityFailure, SessionInput,
};

/// The administrator principal fixture transitions are owned by. Its identity is the
/// owning daemon identity the channel fixtures register objects under.
pub(crate) const ADMINISTRATOR: u128 = OWNER;
pub(crate) const EXTENSION: u128 = 0x51;
pub(crate) const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
pub(crate) const STORE: &str = "Chrome Web Store";
pub(crate) const UPDATE: &str = "https://updates.example.test/ext.xml";
pub(crate) const INSTALL: &str = "normal";
pub(crate) const VERSION: &str = "1.4.2";
pub(crate) const MIN_VERSION: &str = "1.0";
pub(crate) const MAX_VERSION: &str = "2.5.1";

pub(crate) fn supported_versions() -> SupportedExtensionVersions {
    SupportedExtensionVersions::parse(MIN_VERSION, MAX_VERSION)
        .expect("a minimum-first supported extension version range")
}

pub(crate) fn key(value: u128) -> IdempotencyKey {
    IdempotencyKey::new(Uuid::from_u128(value))
}

pub(crate) fn connection(value: u128) -> ConnectionId {
    ConnectionId::new(Uuid::from_u128(0x1000 + value))
}

pub(crate) fn transition(value: u128) -> TransitionId {
    TransitionId::new(Uuid::from_u128(0x2000 + value))
}

/// A locator inside the fixture state directory, owned by the fixture daemon. Every
/// registered principal names one of these, so a rotation can only move between
/// locators the same daemon and state directory hold.
pub(crate) fn credential(locator: &str) -> CredentialReference {
    CredentialReference::new("fixture-store", locator, id(OWNER), id(STATE_DIRECTORY))
        .expect("bounded credential reference")
}

pub(crate) fn ceiling() -> Vec<Capability> {
    vec![capability(CapabilityAction::Write, "matinee")]
}

pub(crate) fn input(
    operation: TransitionOperation,
    idempotency: u128,
    prior_epoch: u64,
    outcome: TransitionOutcome,
) -> TransitionInput {
    TransitionInput::new(
        id(STATE_DIRECTORY),
        TransitionId::new(Uuid::from_u128(0x7000 + idempotency)),
        operation,
        key(idempotency),
        prior_epoch,
        outcome,
    )
}

/// Register one active principal and hand back its snapshot.
pub(crate) fn registered(
    transitions: &SecurityTransitions,
    identity: u128,
    kind: PrincipalKind,
    signer: &RingSigner,
) -> Principal {
    let principal = registered_principal(identity, kind, signer.public_key().clone(), ceiling(), 0);
    transitions
        .register_principal(principal.clone())
        .expect("registry accepts one active snapshot");
    principal
}

pub(crate) fn grant(extension: IdentityId, epoch: u64) -> ExtensionGrant {
    ExtensionGrant::new(
        extension,
        id(OWNER),
        vec![capability(CapabilityAction::Write, SCOPE)],
        epoch,
    )
    .expect("bounded grant")
}

/// Admit one channel through the production registry with a sink that accepts and is
/// then discarded. A test that asserts what admission recorded passes its own sink to
/// `register_channel` instead.
pub(crate) fn admit(
    transitions: &SecurityTransitions,
    session: ChannelSession,
) -> Result<ConnectionId, TransitionRejection> {
    transitions.register_channel(session, &mut RecordingSink::default())
}

/// One live daemon channel in the registry, with the client half kept by the caller.
pub(crate) fn live_channel(
    transitions: &SecurityTransitions,
    principal: &Principal,
    signer: &RingSigner,
    value: u128,
) -> ChannelSession {
    let (client, daemon) = establish_pair_for(principal, signer, connection(value))
        .expect("production handshake fixture");
    admit(transitions, daemon).expect("channel at the registered epoch");
    client
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rotate(
    transitions: &SecurityTransitions,
    principal: IdentityId,
    replacement: &RingSigner,
    locator: &str,
    idempotency: u128,
    prior_epoch: u64,
    custody: Option<&ChromeCapability>,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    let command = SecurityCommand::Rotate {
        principal,
        new_fingerprint: Fingerprint::from_public_key(replacement.public_key()),
        idempotency: key(idempotency),
    };
    let mut material =
        ReplacementCredential::new(replacement.public_key().clone(), credential(locator));
    if let Some(capability) = custody {
        material = material.with_extension_custody(capability.clone());
    }
    transitions.apply(
        &command,
        &input(
            TransitionOperation::Rotation,
            idempotency,
            prior_epoch,
            TransitionOutcome::Committed,
        ),
        TransitionMaterial::Replacement(material),
        sink,
        EventTime(7),
    )
}

pub(crate) fn revoke(
    transitions: &SecurityTransitions,
    principal: IdentityId,
    reason: &str,
    idempotency: u128,
    prior_epoch: u64,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    let command = SecurityCommand::Revoke {
        principal,
        idempotency: key(idempotency),
    };
    transitions.apply(
        &command,
        &input(
            TransitionOperation::Revocation,
            idempotency,
            prior_epoch,
            TransitionOutcome::Committed,
        ),
        TransitionMaterial::Revocation(reason),
        sink,
        EventTime(9),
    )
}

/// Seal one request payload on the client half of a live pair.
pub(crate) fn request(client: &mut ChannelSession, sink: &mut RecordingSink) -> Vec<u8> {
    let output = AuthorizedOutput::filtered(PayloadKind::Command, b"operation".to_vec())
        .expect("bounded request payload");
    client.send(&output, sink).expect("sealed request")
}

pub(crate) fn mutation_input() -> SessionInput<'static> {
    SessionInput::new(
        capability(CapabilityAction::Write, SCOPE),
        PayloadKind::Command,
        ObjectOwner::Owned(id(OWNER)),
        None,
    )
}

pub(crate) fn receive(
    transitions: &SecurityTransitions,
    connection: ConnectionId,
    frame: &[u8],
    sink: &mut RecordingSink,
) -> Result<AuthorizedInput, SecurityFailure> {
    let operation = mutation_input();
    transitions.receive(
        connection,
        frame,
        operation.requested().clone(),
        operation.kind(),
        operation.owner(),
        sink,
    )
}

pub(crate) fn commit_mutation(
    transitions: &SecurityTransitions,
    input: &AuthorizedInput,
) -> Result<u64, SecurityFailure> {
    transitions.commit_mutation(input, &mutation_input())
}

pub(crate) fn binding() -> EnrollmentBinding<'static> {
    EnrollmentBinding {
        origin: ORIGIN,
        endpoint: ENDPOINT,
        store_metadata: STORE,
        update_metadata: UPDATE,
        install_metadata: INSTALL,
        version: VERSION,
        development_allowance: DevelopmentIdentityAllowance::None,
    }
}

pub(crate) fn browser_capability() -> ChromeCapability {
    ChromeCapability::reported(&binding(), true, true).expect("reported browser capability")
}

/// One enrollment creation, opened at instant zero, which is the origin every deadline and
/// occurrence time in these fixtures is measured from.
pub(crate) fn creation(enrollment: TransitionId, daemon: IdentityId) -> EnrollmentCreation {
    EnrollmentCreation::new(
        enrollment,
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        supported_versions(),
        daemon,
        ENDPOINT,
        0,
        ExpiryResult::valid(600_000).expect("bounded ten-minute expiry"),
    )
}

/// Open one bounded enrollment through the command boundary, naming its deadline.
pub(crate) fn create_enrollment(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    daemon: IdentityId,
    idempotency: u128,
    prior_epoch: u64,
    expiry: ExpiryResult,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    let mut creation = creation(enrollment, daemon);
    creation.expiry = expiry;
    apply_creation(
        transitions,
        creation,
        enrollment,
        daemon,
        idempotency,
        prior_epoch,
        sink,
    )
}

/// Open one enrollment the way FR-007 lets an administrator open it: without naming a
/// deadline, so the creation path resolves the ten-minute default itself.
pub(crate) fn create_enrollment_with_default_expiry(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    daemon: IdentityId,
    idempotency: u128,
    prior_epoch: u64,
    created_ms: u64,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    apply_creation(
        transitions,
        EnrollmentCreation::with_default_expiry(
            enrollment,
            ORIGIN,
            STORE,
            UPDATE,
            INSTALL,
            supported_versions(),
            daemon,
            ENDPOINT,
            created_ms,
        ),
        enrollment,
        daemon,
        idempotency,
        prior_epoch,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_creation(
    transitions: &SecurityTransitions,
    creation: EnrollmentCreation,
    enrollment: TransitionId,
    daemon: IdentityId,
    idempotency: u128,
    prior_epoch: u64,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    let command = SecurityCommand::CreateEnrollment {
        enrollment,
        daemon,
        idempotency: key(idempotency),
    };
    transitions.apply(
        &command,
        &input(
            TransitionOperation::EnrollmentCreate,
            idempotency,
            prior_epoch,
            TransitionOutcome::Committed,
        ),
        TransitionMaterial::Enrollment(creation),
        sink,
        EventTime(1),
    )
}

/// Consume one pairing proof through the command boundary and register the principal
/// it pairs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn consume_enrollment(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    identity: IdentityId,
    proof: &EnrollmentProof,
    clock: &EnrollmentClock,
    channel: &mut EnrollmentChannel,
    idempotency: u128,
    prior_epoch: u64,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    apply_consumption(
        transitions,
        enrollment,
        identity,
        proof,
        clock,
        channel,
        idempotency,
        prior_epoch,
        credential("extension-key-0"),
        sink,
    )
}

/// The same consumption, naming the credential the paired principal would be bound to.
/// A locator outside the enrollment owner's daemon or state directory is the binding
/// mismatch the transition refuses before the enrollment host ever sees the proof.
#[allow(clippy::too_many_arguments)]
pub(crate) fn consume_enrollment_with_credential(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    identity: IdentityId,
    proof: &EnrollmentProof,
    clock: &EnrollmentClock,
    channel: &mut EnrollmentChannel,
    idempotency: u128,
    prior_epoch: u64,
    credential: CredentialReference,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    apply_consumption(
        transitions,
        enrollment,
        identity,
        proof,
        clock,
        channel,
        idempotency,
        prior_epoch,
        credential,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_consumption(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    identity: IdentityId,
    proof: &EnrollmentProof,
    clock: &EnrollmentClock,
    channel: &mut EnrollmentChannel,
    idempotency: u128,
    prior_epoch: u64,
    credential: CredentialReference,
    sink: Option<&mut RecordingSink>,
) -> Result<TransitionOutcome, TransitionRejection> {
    let command = SecurityCommand::ConsumeEnrollment {
        enrollment,
        idempotency: key(idempotency),
    };
    let browser = browser_capability();
    transitions.apply(
        &command,
        &input(
            TransitionOperation::EnrollmentConsume,
            idempotency,
            prior_epoch,
            TransitionOutcome::Committed,
        ),
        TransitionMaterial::Pairing(PairingMaterial {
            identity,
            proof,
            clock,
            binding: &binding(),
            capability: &browser,
            channel,
            ceiling: ceiling(),
            credential,
        }),
        sink,
        EventTime(2),
    )
}

/// A fresh long-term public key, as a pairing peer would generate for itself.
pub(crate) fn long_term_key() -> PublicKey {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("fixture key generation");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("fixture key import");
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(pair.public_key().as_ref());
    PublicKey::from_uncompressed(bytes).expect("valid fixture public key")
}

/// Sign one pairing proof with the one-time key the transition sealed to this channel,
/// offering a freshly generated long-term key.
pub(crate) fn paired_proof(
    transitions: &SecurityTransitions,
    enrollment: TransitionId,
    channel: &mut EnrollmentChannel,
    identity: IdentityId,
) -> EnrollmentProof {
    let sealed = transitions
        .seal_one_time_key(enrollment, channel)
        .expect("one-time key seals once");
    let private = channel
        .open_sealed_for_test(enrollment, &sealed)
        .expect("the channel peer recovers the sealed key");
    let rng = SystemRandom::new();
    let one_time = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng)
        .expect("one-time key import");
    let long_term_public_key = long_term_key();
    let message = transitions
        .proof_message(enrollment, &long_term_public_key)
        .expect("pending enrollment transcript");
    let signature = one_time
        .sign(&rng, &message)
        .expect("proof signature")
        .as_ref()
        .to_vec();
    EnrollmentProof {
        identity,
        signature,
        long_term_public_key,
    }
}
