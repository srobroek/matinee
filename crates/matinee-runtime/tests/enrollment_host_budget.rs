//! The host attempt budget belongs to the process, not to a connection.
//!
//! This file is its own test binary on purpose: exhausting a host key is process
//! state, so it must not leak into the other boundary contracts.

use matinee_runtime::{
    ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentConsumeError,
    EnrollmentCreation, EnrollmentFailure, EnrollmentProof, ExpiryResult, IdentityId,
    PairingCompletion, PairingSession, PairingTicket, PublicKey, TransitionId,
    UNCOMPRESSED_KEY_BYTES, enrollment_host,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const STORE: &str = "Chrome Web Store";
const UPDATE: &str = "https://updates.example.test/ext.xml";
const INSTALL: &str = "normal";
const LOOPBACK_V4: &str = "127.0.0.1:7777";
const LOOPBACK_V6: &str = "[::1]:7777";
const DEADLINE_MS: u64 = 600_000;

fn creation(enrollment: u128, endpoint: &str) -> EnrollmentCreation {
    EnrollmentCreation::new(
        TransitionId::new(Uuid::from_u128(enrollment)),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        IdentityId::new(Uuid::from_u128(0xda3e_0001)),
        endpoint,
        ExpiryResult::valid(DEADLINE_MS).expect("bounded deadline"),
    )
}

fn binding(endpoint: &'static str) -> EnrollmentBinding<'static> {
    EnrollmentBinding {
        origin: ORIGIN,
        endpoint,
        store_metadata: STORE,
        update_metadata: UPDATE,
        install_metadata: INSTALL,
        development_allowance: DevelopmentIdentityAllowance::None,
    }
}

fn completion<'a>(
    ticket: &PairingTicket,
    identity: IdentityId,
    proof: &'a EnrollmentProof,
    endpoint: &'static str,
    occurrence_ms: u64,
) -> PairingCompletion<'a> {
    PairingCompletion {
        enrollment: ticket.enrollment(),
        expected_identity: identity,
        proof,
        binding: binding(endpoint),
        occurrence_ms,
        expiry: ExpiryResult::valid(DEADLINE_MS).expect("bounded deadline"),
        storage_local: true,
        non_exportable: true,
    }
}

fn unsigned_proof(identity: IdentityId) -> EnrollmentProof {
    EnrollmentProof {
        identity,
        signature: vec![0; 8],
        long_term_public_key: PublicKey::from_uncompressed([0x04; UNCOMPRESSED_KEY_BYTES])
            .expect("uncompressed SEC1 prefix"),
    }
}

fn client_proof(
    session: &mut PairingSession<'_>,
    ticket: &PairingTicket,
    identity: IdentityId,
) -> EnrollmentProof {
    let sealed = session
        .deliver_one_time_key(ticket.enrollment())
        .expect("seal the one-time key");
    let one_time_pkcs8 = session
        .open_sealed(ticket.enrollment(), &sealed)
        .expect("peer opens the sealed key");
    let rng = SystemRandom::new();
    let one_time = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &one_time_pkcs8, &rng)
        .expect("sealed bytes are the one-time PKCS#8 key");
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate long-term key");
    let long_term = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("parse long-term key");
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(long_term.public_key().as_ref());
    let public = PublicKey::from_uncompressed(bytes).expect("uncompressed SEC1 point");
    let challenge = enrollment_host()
        .proof_challenge(ticket.enrollment(), &public)
        .expect("host publishes the challenge");
    let signature = one_time
        .sign(&rng, &challenge)
        .expect("sign with the one-time key")
        .as_ref()
        .to_vec();
    EnrollmentProof {
        identity,
        signature,
        long_term_public_key: public,
    }
}

/// Ten failures spread over ten connections rate-limit the eleventh attempt on the
/// same loopback host, and a fresh connection does not refill the budget.
#[test]
fn host_budget_accumulates_across_connections_and_enrollments() {
    let host = enrollment_host();
    let identity = IdentityId::new(Uuid::from_u128(0xfa11));
    let mut connection = 0x8100u128;
    let mut occurrence = 1_000u64;

    for enrollment in [0x8001u128, 0x8002] {
        let ticket = host
            .create_pairing(creation(enrollment, LOOPBACK_V4))
            .expect("create pairing");
        for attempt in 0..5 {
            let mut session = host
                .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
                .expect("open a replacement session for each failed proof");
            connection += 1;
            occurrence += 1;
            assert_eq!(
                session
                    .complete_pairing(&completion(
                        &ticket,
                        identity,
                        &unsigned_proof(identity),
                        LOOPBACK_V4,
                        occurrence,
                    ))
                    .unwrap_err(),
                EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
                "attempt {attempt} of enrollment {enrollment:#x} is a counted proof failure"
            );
            assert!(
                !session.is_open(),
                "each failed proof closes its own channel"
            );
        }

        // The enrollment's own budget is terminal after five failures. Assert that
        // for the first enrollment only: once the host key holds ten failures the
        // rate-limit refusal comes first, before any per-enrollment work.
        if enrollment == 0x8001 {
            let mut exhausted = host
                .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
                .expect("open a session after the enrollment budget is spent");
            connection += 1;
            occurrence += 1;
            assert_eq!(
                exhausted
                    .complete_pairing(&completion(
                        &ticket,
                        identity,
                        &unsigned_proof(identity),
                        LOOPBACK_V4,
                        occurrence,
                    ))
                    .unwrap_err(),
                EnrollmentFailure::Consume(EnrollmentConsumeError::AlreadyConsumed),
                "the sixth proof of one enrollment is refused by its own budget"
            );
        }
    }

    // Eleventh counted attempt on this host key: refused before any proof work,
    // even with a valid proof and a brand-new connection.
    let ticket = host
        .create_pairing(creation(0x8003, LOOPBACK_V4))
        .expect("create pairing");
    let mut limited = host
        .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
        .expect("open a fresh session");
    connection += 1;
    let proof = client_proof(&mut limited, &ticket, identity);
    occurrence += 1;
    assert_eq!(
        limited
            .complete_pairing(&completion(
                &ticket,
                identity,
                &proof,
                LOOPBACK_V4,
                occurrence,
            ))
            .unwrap_err(),
        EnrollmentFailure::Consume(EnrollmentConsumeError::RateLimited),
        "a replacement connection does not refill the host budget"
    );
    assert!(
        !limited.is_open(),
        "a rate-limited attempt closes the channel"
    );
    assert!(host.registered_fingerprint(identity).is_none());

    // The budget is scoped to its own loopback host key, not to the process.
    let other_identity = IdentityId::new(Uuid::from_u128(0xfa12));
    let other = host
        .create_pairing(creation(0x8004, LOOPBACK_V6))
        .expect("create pairing on the other loopback host");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
        .expect("open a session for the other host");
    let other_proof = client_proof(&mut session, &other, other_identity);
    let paired = session
        .complete_pairing(&completion(
            &other,
            other_identity,
            &other_proof,
            LOOPBACK_V6,
            occurrence + 1,
        ))
        .expect("the other host key still pairs");
    assert_eq!(
        host.registered_fingerprint(other_identity).as_ref(),
        Some(paired.fingerprint())
    );
}
