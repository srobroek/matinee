//! A runnable consumer of the runtime enrollment boundary.
//!
//! Run with `cargo run -p matinee-runtime --features test-support --example enrollment_lifecycle`. It drives
//! the whole pairing lifecycle - create, seal the one-time key, consume the proof,
//! reconnect on a replacement connection, update custody, revoke - against the one
//! process-lifetime host, and it plays the client half over the same channel.
use std::error::Error;

use matinee_runtime::{
    ChromeReconnectOutcome, ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding,
    EnrollmentCreation, EnrollmentExpiry, EnrollmentProof, ExpiryResult, IdentityId,
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

fn long_term_public_key(rng: &SystemRandom) -> Result<PublicKey, Box<dyn Error>> {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, rng)
        .map_err(|error| format!("generate long-term key: {error}"))?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), rng)
        .map_err(|error| format!("parse long-term key: {error}"))?;
    let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
    bytes.copy_from_slice(key_pair.public_key().as_ref());
    Ok(PublicKey::from_uncompressed(bytes)?)
}

/// The client half of `/v1/pair`, driven over the same authenticated channel.
fn client_proof(
    session: &mut PairingSession<'_>,
    ticket: &PairingTicket,
    identity: IdentityId,
) -> Result<EnrollmentProof, Box<dyn Error>> {
    let sealed = session.deliver_one_time_key(ticket.enrollment())?;
    println!(
        "  sealed one-time key: {} ciphertext bytes, debug projection {sealed:?}",
        sealed.ciphertext().len()
    );
    let rng = SystemRandom::new();
    let public = long_term_public_key(&rng)?;
    let challenge = enrollment_host().proof_challenge(ticket.enrollment(), &public)?;
    println!("  signing a {}-byte published challenge", challenge.len());
    let signature = session.sign_proof_for_test(ticket.enrollment(), &sealed, &challenge)?;
    Ok(EnrollmentProof {
        identity,
        signature,
        long_term_public_key: public,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let host = enrollment_host();
    let daemon = IdentityId::new(Uuid::now_v7());
    let extension = IdentityId::new(Uuid::now_v7());

    println!("1. create pairing");
    let ticket = host.create_pairing(EnrollmentCreation::new(
        TransitionId::new(Uuid::now_v7()),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        SupportedExtensionVersions::parse("1.0", "2.5.1").expect("supported versions"),
        daemon,
        ENDPOINT,
        EnrollmentExpiry::Default,
    ))?;
    println!(
        "  enrollment {} on {}, one-time key fingerprint {}",
        ticket.enrollment().get(),
        ticket.daemon_endpoint(),
        ticket.one_time_public_key_fingerprint().as_str()
    );

    println!("2. open the authenticated native channel and deliver the one-time key");
    let mut session = host.session(ConnectionId::new(Uuid::now_v7()), 1)?;
    let proof = client_proof(&mut session, &ticket, extension)?;

    println!("3. consume the pairing proof");
    let paired = session.complete_pairing(&PairingCompletion {
        enrollment: ticket.enrollment(),
        expected_identity: extension,
        proof: &proof,
        binding: binding(),
        expiry: ExpiryResult::valid(ticket.expiry_deadline_ms())?,
        storage_local: true,
        non_exportable: true,
    })?;
    let original = paired.fingerprint().clone();
    println!(
        "  registered {} as {}",
        paired.identity().get(),
        original.as_str()
    );
    if host.registered_fingerprint(extension).as_ref() != Some(&original) {
        return Err("the host did not register the paired principal".into());
    }

    println!("4. replace the connection and reconnect");
    session.close();
    let replacement = host.session(ConnectionId::new(Uuid::now_v7()), 2)?;
    println!(
        "  replacement connection {}",
        replacement.connection().get()
    );
    match host.reconnect(extension, &original, &binding(), true, true) {
        ChromeReconnectOutcome::Reconnected => println!("  reconnected on shared registry state"),
        other => return Err(format!("expected a reconnect, observed {other:?}").into()),
    }

    println!("5. update custody");
    let rotated = long_term_public_key(&SystemRandom::new())?;
    let updated = host.update_custody(extension, &rotated, &binding(), true, true)?;
    println!("  rotated to {}", updated.as_str());
    if !host.is_quarantined(&original) {
        return Err("the stale key was not quarantined".into());
    }
    match host.reconnect(extension, &original, &binding(), true, true) {
        ChromeReconnectOutcome::Mismatch => println!("  the stale fingerprint is refused"),
        other => return Err(format!("expected a mismatch, observed {other:?}").into()),
    }

    println!("6. revoke");
    host.revoke(extension)?;
    match host.reconnect(extension, &updated, &binding(), true, true) {
        ChromeReconnectOutcome::Revoked => println!("  the principal is terminally revoked"),
        other => return Err(format!("expected a revocation, observed {other:?}").into()),
    }

    println!("7. a browser without the required key semantics fails closed");
    let unsupported_identity = IdentityId::new(Uuid::now_v7());
    let unsupported = host.create_pairing(EnrollmentCreation::new(
        TransitionId::new(Uuid::now_v7()),
        ORIGIN,
        STORE,
        UPDATE,
        INSTALL,
        SupportedExtensionVersions::parse("1.0", "2.5.1").expect("supported versions"),
        daemon,
        ENDPOINT,
        EnrollmentExpiry::Default,
    ))?;
    let mut unsupported_session = host.session(ConnectionId::new(Uuid::now_v7()), 1)?;
    let unsupported_proof =
        client_proof(&mut unsupported_session, &unsupported, unsupported_identity)?;
    let refusal = unsupported_session
        .complete_pairing(&PairingCompletion {
            enrollment: unsupported.enrollment(),
            expected_identity: unsupported_identity,
            proof: &unsupported_proof,
            binding: binding(),
            expiry: ExpiryResult::valid(unsupported.expiry_deadline_ms())?,
            storage_local: false,
            non_exportable: true,
        })
        .expect_err("a browser without durable custody must not pair");
    println!("  refused: {refusal}");

    println!("enrollment lifecycle complete");
    Ok(())
}
