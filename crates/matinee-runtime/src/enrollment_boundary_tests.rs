#![cfg(feature = "test-support")]

//! Consumer-level contract for the runtime's enrollment boundary.
//!
//! Every call here goes through `matinee_runtime`'s public surface, the same one a
//! daemon route uses: nothing reaches into the security crate's internals.

use matinee_runtime::{
    ChromeReconnectOutcome, ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding,
    EnrollmentConsumeError, EnrollmentCreation, EnrollmentCustodyError, EnrollmentExpiry,
    EnrollmentFailure, EnrollmentHost, EnrollmentProof, ExpiryResult, IdentityId,
    PairingCompletion, PairingSession, PairingTicket, PublicKey, TransitionId,
    UNCOMPRESSED_KEY_BYTES, enrollment_host,
};
use matinee_security::SupportedExtensionVersions;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const STORE: &str = "Chrome Web Store";
const UPDATE: &str = "https://updates.example.test/ext.xml";
const INSTALL: &str = "normal";
const ENDPOINT: &str = "127.0.0.1:7777";
const CREATED_MS: u64 = 1_000;
const DEADLINE_MS: u64 = CREATED_MS + 600_000;

fn creation(enrollment: u128, daemon: u128) -> EnrollmentCreation {
    EnrollmentCreation::new(
        TransitionId::new(Uuid::from_u128(enrollment)),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        SupportedExtensionVersions::parse("1.0", "2.5.1").expect("supported versions"),
        IdentityId::new(Uuid::from_u128(daemon)),
        ENDPOINT,
        EnrollmentExpiry::Deadline(ExpiryResult::valid(DEADLINE_MS).expect("bounded deadline")),
    )
}

fn binding() -> EnrollmentBinding<'static> {
    EnrollmentBinding {
        origin: ORIGIN,
        endpoint: ENDPOINT,
        store_metadata: STORE,
        update_metadata: UPDATE,
        install_metadata: INSTALL,
        version: "1.0",
        development_allowance: DevelopmentIdentityAllowance::None,
    }
}

fn completion<'a>(
    ticket: &PairingTicket,
    identity: IdentityId,
    proof: &'a EnrollmentProof,
    binding: EnrollmentBinding<'a>,
    occurrence_ms: u64,
) -> PairingCompletion<'a> {
    PairingCompletion {
        enrollment: ticket.enrollment(),
        expected_identity: identity,
        proof,
        binding,
        expiry: ExpiryResult::valid(DEADLINE_MS).expect("bounded deadline"),
        storage_local: true,
        non_exportable: true,
    }
}

/// A fresh long-term keypair plus the exact public point the daemon registers.
fn long_term_keypair(rng: &SystemRandom) -> (EcdsaKeyPair, PublicKey) {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rng)
        .expect("generate long-term key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), rng)
        .expect("parse long-term key");
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(key_pair.public_key().as_ref());
    let public = PublicKey::from_uncompressed(bytes).expect("uncompressed SEC1 point");
    (key_pair, public)
}

/// The client half of `/v1/pair`: take the sealed one-time key off the channel, mint
/// a fresh long-term key, and sign the challenge the host publishes.
fn client_proof(
    host: &EnrollmentHost,
    session: &mut PairingSession<'_>,
    ticket: &PairingTicket,
    identity: IdentityId,
) -> EnrollmentProof {
    let sealed = session
        .deliver_one_time_key(ticket.enrollment())
        .expect("seal the one-time key for this channel");
    assert!(
        !sealed.ciphertext().is_empty(),
        "transport carries ciphertext"
    );
    let rng = SystemRandom::new();
    let (_long_term, public) = long_term_keypair(&rng);
    let challenge = host
        .proof_challenge(ticket.enrollment(), &public)
        .expect("host publishes the challenge for a pending enrollment");
    let signature = session
        .sign_proof_for_test(ticket.enrollment(), &sealed, &challenge)
        .expect("peer returns only its signature");
    EnrollmentProof {
        identity,
        signature,
        long_term_public_key: public,
    }
}

#[test]
fn pairing_registers_the_principal_and_seals_the_one_time_key_once() {
    let host = EnrollmentHost::new_for_test();
    let identity = IdentityId::new(Uuid::from_u128(0x1000));
    let ticket = host
        .create_pairing_at(creation(0x1001, 0x1002), CREATED_MS)
        .expect("create pairing");
    assert_eq!(ticket.origin(), ORIGIN);
    assert_eq!(ticket.daemon_endpoint(), ENDPOINT);
    assert_eq!(ticket.expiry_deadline_ms(), DEADLINE_MS);
    assert_eq!(ticket.one_time_public_key().as_bytes()[0], 0x04);

    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(0x1003)), 1)
        .expect("open pairing session");
    let proof = client_proof(&host, &mut session, &ticket, identity);
    assert_eq!(
        session
            .deliver_one_time_key(ticket.enrollment())
            .unwrap_err(),
        EnrollmentFailure::Custody(EnrollmentCustodyError::AlreadyTransferred),
        "the one-time key leaves host custody exactly once"
    );

    let paired = session
        .complete_pairing_at(
            &completion(&ticket, identity, &proof, binding(), 1_000),
            1_000,
        )
        .expect("consume the pairing proof");
    assert_eq!(
        host.registered_fingerprint(identity).as_ref(),
        Some(paired.fingerprint())
    );
    assert_eq!(
        host.registered_key(identity),
        Some(proof.long_term_public_key.clone())
    );
    assert!(
        session.is_open(),
        "a committed pairing leaves the channel open"
    );

    assert_eq!(
        host.proof_challenge(ticket.enrollment(), &proof.long_term_public_key),
        Err(EnrollmentFailure::Consume(
            EnrollmentConsumeError::InvalidProof
        )),
        "a consumed enrollment leaves host custody, and its absence is not reported as its own code"
    );
    assert_eq!(
        session
            .complete_pairing_at(
                &completion(&ticket, identity, &proof, binding(), 1_001),
                1_001
            )
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
        "a replay against a spent enrollment binds to nothing and is refused as any other unbindable attempt"
    );
}

#[test]
fn registration_and_custody_survive_session_replacement() {
    let host = enrollment_host();
    let identity = IdentityId::new(Uuid::from_u128(0x2000));
    let ticket = host
        .create_pairing_at(creation(0x2001, 0x2002), CREATED_MS)
        .expect("create pairing");
    let mut first = host
        .session(ConnectionId::new(Uuid::from_u128(0x2003)), 1)
        .expect("open first session");
    let proof = client_proof(host, &mut first, &ticket, identity);
    let paired = first
        .complete_pairing_at(
            &completion(&ticket, identity, &proof, binding(), 2_000),
            2_000,
        )
        .expect("consume the pairing proof");
    let original = paired.fingerprint().clone();
    first.close();
    drop(first);

    // A replacement connection reads the same registry through a separately
    // obtained host handle.
    let later = enrollment_host();
    let second = later
        .session(ConnectionId::new(Uuid::from_u128(0x2004)), 2)
        .expect("open replacement session");
    assert_ne!(
        second.connection(),
        ConnectionId::new(Uuid::from_u128(0x2003))
    );
    assert_eq!(
        second.epoch(),
        2,
        "the replacement session carries its own epoch"
    );
    assert!(second.is_open());
    assert_eq!(
        later.reconnect(identity, &original, &binding(), false, true),
        ChromeReconnectOutcome::Mismatch,
        "reconnect fails closed after durable custody is lost",
    );
    assert_eq!(
        later.reconnect(identity, &original, &binding(), true, true),
        ChromeReconnectOutcome::Reconnected
    );

    let rng = SystemRandom::new();
    let (_rotated_key, rotated) = long_term_keypair(&rng);
    assert_eq!(
        later
            .update_custody(identity, &rotated, &binding(), true, false)
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::CapabilityRejected),
        "custody rotation fails closed after non-exportable binding is lost",
    );
    assert!(!later.is_quarantined(&original));
    let updated = later
        .update_custody(identity, &rotated, &binding(), true, true)
        .expect("update custody");
    assert_ne!(updated, original);
    assert!(
        later.is_quarantined(&original),
        "the stale key is quarantined"
    );
    assert_eq!(
        later.reconnect(identity, &original, &binding(), true, true),
        ChromeReconnectOutcome::Mismatch
    );
    assert_eq!(
        later.reconnect(identity, &updated, &binding(), true, true),
        ChromeReconnectOutcome::Reconnected
    );

    later.revoke(identity).expect("revoke the principal");
    assert_eq!(
        later.reconnect(identity, &updated, &binding(), true, true),
        ChromeReconnectOutcome::Revoked
    );
    assert_eq!(
        later
            .update_custody(identity, &rotated, &binding(), true, true)
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::CredentialMismatch),
        "a revoked principal accepts no replacement key"
    );
}

#[test]
fn browser_without_required_key_semantics_fails_closed() {
    let host = EnrollmentHost::new_for_test();
    let identity = IdentityId::new(Uuid::from_u128(0x3000));
    let ticket = host
        .create_pairing_at(creation(0x3001, 0x3002), CREATED_MS)
        .expect("create pairing");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(0x3003)), 1)
        .expect("open pairing session");
    let proof = client_proof(&host, &mut session, &ticket, identity);

    let mut unsupported = completion(&ticket, identity, &proof, binding(), 3_000);
    unsupported.storage_local = false;
    assert_eq!(
        session
            .complete_pairing_at(&unsupported, 3_000)
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::CapabilityRejected)
    );

    let mut exportable = completion(&ticket, identity, &proof, binding(), 3_001);
    exportable.non_exportable = false;
    assert_eq!(
        session.complete_pairing_at(&exportable, 3_001).unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::CapabilityRejected)
    );

    assert!(host.registered_fingerprint(identity).is_none());
    assert!(
        host.proof_challenge(ticket.enrollment(), &proof.long_term_public_key)
            .is_ok(),
        "a refused capability consumes nothing"
    );
    assert!(session.is_open());
}

#[test]
fn invalid_proof_closes_the_channel_and_registers_nothing() {
    let host = EnrollmentHost::new_for_test();
    let identity = IdentityId::new(Uuid::from_u128(0x4000));
    let ticket = host
        .create_pairing_at(creation(0x4001, 0x4002), CREATED_MS)
        .expect("create pairing");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(0x4003)), 1)
        .expect("open pairing session");
    let mut proof = client_proof(&host, &mut session, &ticket, identity);
    proof.signature[0] ^= 0xff;

    assert_eq!(
        session
            .complete_pairing_at(
                &completion(&ticket, identity, &proof, binding(), 4_000),
                4_000
            )
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof)
    );
    assert!(!session.is_open(), "a failed proof closes the channel");
    assert_eq!(
        session
            .complete_pairing_at(
                &completion(&ticket, identity, &proof, binding(), 4_001),
                4_001
            )
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::ChannelClosed),
        "the closed channel accepts no further attempt"
    );
    assert!(host.registered_fingerprint(identity).is_none());
}

#[test]
fn uncertain_expiry_refuses_pairing_without_consuming_the_enrollment() {
    let host = EnrollmentHost::new_for_test();
    let identity = IdentityId::new(Uuid::from_u128(0x5000));
    let ticket = host
        .create_pairing_at(creation(0x5001, 0x5002), CREATED_MS)
        .expect("create pairing");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(0x5003)), 1)
        .expect("open pairing session");
    let proof = client_proof(&host, &mut session, &ticket, identity);

    let mut uncertain = completion(&ticket, identity, &proof, binding(), 5_000);
    uncertain.expiry = ExpiryResult::uncertain(DEADLINE_MS);
    assert_eq!(
        session.complete_pairing_at(&uncertain, 5_000).unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::UncertainExpiry)
    );

    let mut expired = completion(&ticket, identity, &proof, binding(), 5_001);
    expired.expiry = ExpiryResult::expired(DEADLINE_MS);
    assert_eq!(
        session.complete_pairing_at(&expired, 5_001).unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::Expired)
    );

    let paired = session
        .complete_pairing_at(
            &completion(&ticket, identity, &proof, binding(), 5_002),
            5_002,
        )
        .expect("a certain, valid expiry still pairs");
    assert_eq!(
        host.registered_fingerprint(identity).as_ref(),
        Some(paired.fingerprint())
    );
}

#[test]
fn a_closed_channel_seals_and_opens_no_one_time_key() {
    let host = EnrollmentHost::new_for_test();
    let ticket = host
        .create_pairing_at(creation(0x6001, 0x6002), CREATED_MS)
        .expect("create pairing");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(0x6003)), 1)
        .expect("open pairing session");
    let sealed = session
        .deliver_one_time_key(ticket.enrollment())
        .expect("seal the one-time key");
    session.close();
    let challenge = host
        .proof_challenge(ticket.enrollment(), ticket.one_time_public_key())
        .unwrap();
    assert_eq!(
        session
            .sign_proof_for_test(ticket.enrollment(), &sealed, &challenge)
            .unwrap_err(),
        EnrollmentFailure::Custody(EnrollmentCustodyError::ChannelNotAuthenticated),
        "a closed channel signs nothing already on the wire"
    );

    let second = host
        .create_pairing_at(creation(0x6004, 0x6002), CREATED_MS)
        .expect("create second pairing");
    assert_eq!(
        session
            .deliver_one_time_key(second.enrollment())
            .unwrap_err(),
        EnrollmentFailure::Custody(EnrollmentCustodyError::ChannelNotAuthenticated),
        "a closed channel seals nothing further"
    );
}

#[test]
fn a_live_enrollment_identifier_is_never_silently_replaced() {
    let host = EnrollmentHost::new_for_test();
    host.create_pairing_at(creation(0x7001, 0x7002), CREATED_MS)
        .expect("create pairing");
    assert_eq!(
        host.create_pairing_at(creation(0x7001, 0x7002), CREATED_MS)
            .unwrap_err(),
        EnrollmentFailure::DuplicateEnrollment,
        "replacement would refill that enrollment's failed-proof budget"
    );
}
