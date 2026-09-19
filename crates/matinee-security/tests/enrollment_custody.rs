macro_rules! enrollment_custody_tests {
    () => {
        use crate::enrollment::{
            enrollment_proof_message, ChromeCapability, DevelopmentIdentityAllowance,
            EnrollmentBinding, EnrollmentBundle, EnrollmentChannel, EnrollmentClock,
            EnrollmentConsumeError, EnrollmentConsumptionService, EnrollmentCreation,
            EnrollmentProof, SupportedExtensionVersions,
        };
        use crate::identity::{ConnectionId, ExpiryResult, Fingerprint, IdentityId, PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES};
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        use uuid::Uuid;

        fn input(id: u128) -> EnrollmentCreation {
            EnrollmentCreation::new(
                TransitionId::new(Uuid::from_u128(id)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop", "Chrome Web Store",
                "https://updates.example.test/ext.xml", "normal",
                SupportedExtensionVersions::parse("1.0", "2.5.1").unwrap(),
                IdentityId::new(Uuid::from_u128(0x41)), "127.0.0.1:7777",
                0, ExpiryResult::valid(600_000).unwrap(),
            )
        }

        fn binding() -> EnrollmentBinding<'static> {
            EnrollmentBinding {
                origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                endpoint: "127.0.0.1:7777", store_metadata: "Chrome Web Store",
                update_metadata: "https://updates.example.test/ext.xml", install_metadata: "normal",
                version: "1.4.2",
                development_allowance: DevelopmentIdentityAllowance::None,
            }
        }

        fn capability() -> ChromeCapability {
            ChromeCapability::reported(&binding(), true, true).unwrap()
        }

        fn signed_proof(bundle: &mut EnrollmentBundle, identity: IdentityId) -> (EnrollmentProof, Vec<u8>) {
            let channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9000)), 1).unwrap();
            let transfer = channel.seal_one_time_key(bundle).unwrap();
            let private = channel.open_sealed_for_test(bundle.enrollment_id(), &transfer).unwrap();
            let rng = SystemRandom::new();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng).unwrap();
            let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
            bytes.copy_from_slice(signer.public_key().as_ref());
            let public = PublicKey::from_uncompressed(bytes).unwrap();
            let signature = signer.sign(&rng, &enrollment_proof_message(bundle, &public)).unwrap().as_ref().to_vec();
            (EnrollmentProof { identity, signature, long_term_public_key: public }, private)
        }

        fn fresh_public_key() -> PublicKey {
            let rng = SystemRandom::new();
            let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &rng).unwrap();
            let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
            bytes.copy_from_slice(signer.public_key().as_ref());
            PublicKey::from_uncompressed(bytes).unwrap()
        }

        #[test]
        fn enrollment_custody_chrome_capability_records_supported_or_fail_closed_unsupported_outcome() {
            let output = std::process::Command::new("node")
                .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/chrome-capability/capability.mjs"))
                .output().expect("Chrome capability fixture");
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("\"result\":\"unsupported\"") || stdout.contains("\"result\":\"pass\""), "{stdout}");
            if stdout.contains("\"result\":\"unsupported\"") {
                assert!(stdout.contains("capability.unsupported"));
                assert!(stdout.contains("\"channel_state\":\"closed\""));
            } else {
                assert!(stdout.contains("storage.local.persistence"));
                assert!(stdout.contains("webcrypto.non_exportable"));
            }
            assert!(!stdout.to_ascii_lowercase().contains("private_key"));
            assert!(!stdout.to_ascii_lowercase().contains("pkcs#8"));
        }

        #[test]
        fn enrollment_custody_surfaces_never_contain_raw_pkcs8_backup_bytes() {
            let mut bundle = EnrollmentBundle::create(input(0x100)).unwrap();
            let channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x101)), 1).unwrap();
            let sealed = channel.seal_one_time_key(&mut bundle).unwrap();
            let private = channel.open_sealed_for_test(bundle.enrollment_id(), &sealed).unwrap();
            let observed = [format!("{bundle:?}"), format!("nonce={:?};ciphertext={:?}", sealed.nonce(), sealed.ciphertext()), format!("{private:?}"), "credential_store.mismatch".to_owned(), "revoked".to_owned()];
            for (index, record) in observed.iter().enumerate() {
                if index == 2 { continue; }
                assert!(!record.as_bytes().windows(private.len()).any(|bytes| bytes == private), "raw PKCS#8 in custody record {index}");
                assert!(!record.contains("PKCS#8"));
            }
        }

        #[test]
        fn enrollment_custody_reconnect_quarantines_stale_key_and_deletes_old_registration() {
            let identity = IdentityId::new(Uuid::from_u128(0x200));
            let mut bundle = EnrollmentBundle::create(input(0x201)).unwrap();
            let (proof, _) = signed_proof(&mut bundle, identity);
            let old = proof.long_term_public_key.clone();
            let old_fingerprint = Fingerprint::from_public_key(&old);
            let service = EnrollmentConsumptionService::default();
            let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x202)), 1).unwrap();
            let clock = EnrollmentClock::new(1, ExpiryResult::valid(600_000).unwrap());
            let current = capability();
            service.consume_pairing_proof(Some(&mut bundle), &proof, identity, &clock, &binding(), &current, &mut channel).unwrap();
            let replacement = fresh_public_key();
            let new_fingerprint = service.update_custody(identity, &replacement, &current).unwrap();
            assert!(service.is_quarantined(&old_fingerprint));
            assert_eq!(service.reconnect(identity, &old_fingerprint, &current), crate::enrollment::ChromeReconnectOutcome::Mismatch);
            assert_eq!(service.reconnect(identity, &new_fingerprint, &current), crate::enrollment::ChromeReconnectOutcome::Reconnected);
            service.revoke(identity).unwrap();
            assert_eq!(service.reconnect(identity, &new_fingerprint, &current), crate::enrollment::ChromeReconnectOutcome::Revoked);
        }

        #[test]
        fn enrollment_custody_credential_store_mismatch_and_revoked_are_fail_closed() {
            let identity = IdentityId::new(Uuid::from_u128(0x300));
            let mut bundle = EnrollmentBundle::create(input(0x301)).unwrap();
            let (proof, _) = signed_proof(&mut bundle, identity);
            let service = EnrollmentConsumptionService::default();
            let current = capability();
            let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x302)), 1).unwrap();
            let clock = EnrollmentClock::new(1, ExpiryResult::valid(600_000).unwrap());
            service.consume_pairing_proof(Some(&mut bundle), &proof, identity, &clock, &binding(), &current, &mut channel).unwrap();
            let mismatch = service.update_custody(identity, &proof.long_term_public_key, &current);
            assert_eq!(mismatch, Err(EnrollmentConsumeError::CredentialMismatch));
            let fingerprint = service.registered_fingerprint(identity).unwrap();
            service.revoke(identity).unwrap();
            assert_eq!(service.reconnect(identity, &fingerprint, &current), crate::enrollment::ChromeReconnectOutcome::Revoked);
            assert!(service.registered_public_key(identity).is_some());
        }
    };
}
