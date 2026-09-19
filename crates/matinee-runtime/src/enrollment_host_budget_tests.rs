#![cfg(feature = "test-support")]

//! The host attempt budget belongs to the process, not to a connection.
//!
//! This file is its own test binary on purpose: exhausting a host key is process
//! state, so it must not leak into the other boundary contracts.

use matinee_runtime::{
    ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentConsumeError,
    EnrollmentCreation, EnrollmentExpiry, EnrollmentFailure, EnrollmentHost, EnrollmentProof,
    ExpiryResult, IdentityId, PairingCompletion, PairingSession, PairingTicket, PublicKey,
    TransitionId, UNCOMPRESSED_KEY_BYTES,
};
use matinee_security::SupportedExtensionVersions;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const STORE: &str = "Chrome Web Store";
const UPDATE: &str = "https://updates.example.test/ext.xml";
const INSTALL: &str = "normal";
const LOOPBACK_V4: &str = "127.0.0.1:7777";
const LOOPBACK_V6: &str = "[::1]:7777";
const CREATED_MS: u64 = 1_000;
const DEADLINE_MS: u64 = CREATED_MS + 600_000;

fn creation(enrollment: u128, endpoint: &str) -> EnrollmentCreation {
    EnrollmentCreation::new(
        TransitionId::new(Uuid::from_u128(enrollment)),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        SupportedExtensionVersions::parse("1.0", "2.5.1").expect("supported versions"),
        IdentityId::new(Uuid::from_u128(0xda3e_0001)),
        endpoint,
        EnrollmentExpiry::Deadline(ExpiryResult::valid(DEADLINE_MS).expect("bounded deadline")),
    )
}

fn creation_default(enrollment: u128, endpoint: &str) -> EnrollmentCreation {
    EnrollmentCreation::new(
        TransitionId::new(Uuid::from_u128(enrollment)),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        SupportedExtensionVersions::parse("1.0", "2.5.1").expect("supported versions"),
        IdentityId::new(Uuid::from_u128(0xda3e_0001)),
        endpoint,
        EnrollmentExpiry::Default,
    )
}

fn binding(endpoint: &'static str) -> EnrollmentBinding<'static> {
    EnrollmentBinding {
        origin: ORIGIN,
        endpoint,
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
    endpoint: &'static str,
    _occurrence_ms: u64,
) -> PairingCompletion<'a> {
    PairingCompletion {
        enrollment: ticket.enrollment(),
        expected_identity: identity,
        proof,
        binding: binding(endpoint),
        expiry: ExpiryResult::valid(ticket.expiry_deadline_ms()).expect("bounded deadline"),
        storage_local: true,
        non_exportable: true,
    }
}

fn unsigned_proof(identity: IdentityId) -> EnrollmentProof {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate long-term key");
    let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("parse long-term key");
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(signer.public_key().as_ref());
    EnrollmentProof {
        identity,
        signature: vec![0; 8],
        long_term_public_key: PublicKey::from_uncompressed(bytes).expect("uncompressed SEC1 point"),
    }
}

fn client_proof(
    host: &EnrollmentHost,
    session: &mut PairingSession<'_>,
    ticket: &PairingTicket,
    identity: IdentityId,
) -> EnrollmentProof {
    let sealed = session
        .deliver_one_time_key(ticket.enrollment())
        .expect("seal the one-time key");
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate long-term key");
    let long_term = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("parse long-term key");
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(long_term.public_key().as_ref());
    let public = PublicKey::from_uncompressed(bytes).expect("uncompressed SEC1 point");
    let challenge = host
        .proof_challenge(ticket.enrollment(), &public)
        .expect("host publishes the challenge");
    let signature = session
        .sign_proof_for_test(ticket.enrollment(), &sealed, &challenge)
        .expect("peer returns only its signature");
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
    let host = EnrollmentHost::new_for_test();
    let identity = IdentityId::new(Uuid::from_u128(0xfa11));
    let mut connection = 0x8100u128;
    let mut occurrence = 1_000u64;

    for enrollment in [0x8001u128, 0x8002] {
        let ticket = host
            .create_pairing_at(creation(enrollment, LOOPBACK_V4), CREATED_MS)
            .expect("create pairing");
        for attempt in 0..5 {
            let mut session = host
                .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
                .expect("open a replacement session for each failed proof");
            connection += 1;
            occurrence += 1;
            assert_eq!(
                session
                    .complete_pairing_at(
                        &completion(
                            &ticket,
                            identity,
                            &unsigned_proof(identity),
                            LOOPBACK_V4,
                            occurrence,
                        ),
                        occurrence,
                    )
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
                    .complete_pairing_at(
                        &completion(
                            &ticket,
                            identity,
                            &unsigned_proof(identity),
                            LOOPBACK_V4,
                            occurrence,
                        ),
                        occurrence,
                    )
                    .unwrap_err(),
                EnrollmentFailure::Consume(EnrollmentConsumeError::AlreadyConsumed),
                "the sixth proof of one enrollment is refused by its own budget"
            );
        }
    }

    // Eleventh counted attempt on this host key: refused before any proof work,
    // even with a valid proof and a brand-new connection.
    let ticket = host
        .create_pairing_at(creation(0x8003, LOOPBACK_V4), CREATED_MS)
        .expect("create pairing");
    let mut limited = host
        .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
        .expect("open a fresh session");
    connection += 1;
    let proof = client_proof(&host, &mut limited, &ticket, identity);
    occurrence += 1;
    assert_eq!(
        limited
            .complete_pairing_at(
                &completion(&ticket, identity, &proof, LOOPBACK_V4, occurrence,),
                occurrence,
            )
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
        .create_pairing_at(creation(0x8004, LOOPBACK_V6), CREATED_MS)
        .expect("create pairing on the other loopback host");
    let mut session = host
        .session(ConnectionId::new(Uuid::from_u128(connection)), 1)
        .expect("open a session for the other host");
    let other_proof = client_proof(&host, &mut session, &other, other_identity);
    let paired = session
        .complete_pairing_at(
            &completion(
                &other,
                other_identity,
                &other_proof,
                LOOPBACK_V6,
                occurrence + 1,
            ),
            occurrence + 1,
        )
        .expect("the other host key still pairs");
    assert_eq!(
        host.registered_fingerprint(other_identity).as_ref(),
        Some(paired.fingerprint())
    );
    let reset_ticket = host
        .create_pairing(creation_default(0x8005, LOOPBACK_V4))
        .expect("create pairing against the host clock");
    let reset_anchor = reset_ticket.expiry_deadline_ms() - 600_000;
    for attempt in 0..10u64 {
        let ticket = host
            .create_pairing(creation_default(0x8100 + u128::from(attempt), LOOPBACK_V4))
            .expect("create counted failure enrollment");
        let mut failed = host
            .session(
                ConnectionId::new(Uuid::from_u128(0x8200 + u128::from(attempt))),
                1,
            )
            .expect("open counted failure session");
        let occurrence = reset_anchor + attempt + 1;
        assert_eq!(
            failed
                .complete_pairing_at(
                    &completion(
                        &ticket,
                        identity,
                        &unsigned_proof(identity),
                        LOOPBACK_V4,
                        occurrence
                    ),
                    occurrence,
                )
                .unwrap_err(),
            EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
        );
    }
    let reset_identity = IdentityId::new(Uuid::from_u128(0xfa15));
    let mut reset_session = host
        .session(ConnectionId::new(Uuid::from_u128(0x8300)), 1)
        .expect("open reset session");
    let reset_proof = client_proof(&host, &mut reset_session, &reset_ticket, reset_identity);
    assert!(
        reset_session
            .complete_pairing_at(
                &completion(
                    &reset_ticket,
                    reset_identity,
                    &reset_proof,
                    LOOPBACK_V4,
                    reset_anchor + 60_001,
                ),
                reset_anchor + 60_001,
            )
            .is_ok(),
        "the host budget resets after an injected real minute"
    );

    // These are independent public-clock controls. Keep them on a fresh host because
    // HostAttemptBudget measures elapsed time with saturating_sub: presenting an earlier
    // instant to a host makes a stale window look current.
    let host = EnrollmentHost::new_for_test();
    let public_ticket = host
        .create_pairing(creation_default(0x8006, LOOPBACK_V4))
        .expect("create public-clock enrollment");
    let public_anchor = public_ticket.expiry_deadline_ms() - 600_000;
    for attempt in 0..10u64 {
        let ticket = host
            .create_pairing(creation_default(0x8400 + u128::from(attempt), LOOPBACK_V4))
            .expect("create public-clock failure enrollment");
        let mut failed = host
            .session(
                ConnectionId::new(Uuid::from_u128(0x8500 + u128::from(attempt))),
                1,
            )
            .expect("open public-clock failure session");
        let occurrence = public_anchor + attempt + 1;
        assert_eq!(
            failed
                .complete_pairing_at(
                    &completion(
                        &ticket,
                        identity,
                        &unsigned_proof(identity),
                        LOOPBACK_V4,
                        occurrence
                    ),
                    occurrence,
                )
                .unwrap_err(),
            EnrollmentFailure::Consume(EnrollmentConsumeError::InvalidProof),
        );
    }
    let public_identity = IdentityId::new(Uuid::from_u128(0xfa16));
    let mut public_session = host
        .session(ConnectionId::new(Uuid::from_u128(0x8600)), 1)
        .expect("open public-clock session");
    let public_proof = client_proof(&host, &mut public_session, &public_ticket, public_identity);
    let public_completion = PairingCompletion {
        enrollment: public_ticket.enrollment(),
        expected_identity: public_identity,
        proof: &public_proof,
        binding: binding(LOOPBACK_V4),
        expiry: ExpiryResult::valid(public_ticket.expiry_deadline_ms()).expect("deadline"),
        storage_local: true,
        non_exportable: true,
    };
    assert_eq!(
        public_session.complete_pairing(&public_completion),
        Err(EnrollmentFailure::Consume(
            EnrollmentConsumeError::RateLimited
        )),
        "the public completion input cannot claim a later instant to obtain an eleventh attempt"
    );
}
