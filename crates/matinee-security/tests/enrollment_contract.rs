macro_rules! enrollment_contract_tests {
    () => {
        use crate::enrollment::{
            validate_enrollment_binding, DevelopmentIdentityAllowance, EnrollmentBinding,
            EnrollmentBindingError, EnrollmentBundle, EnrollmentCreation, EnrollmentCreateError,
        };
        use crate::identity::{
            ConnectionId, EnrollmentLifecycle, ExpiryResult, ExpiryStatus, ExtensionEnrollment,
            Fingerprint, IdentityId, PublicKey, TransitionId, UNCOMPRESSED_KEY_BYTES,
        };
        use uuid::Uuid;

        fn creation() -> EnrollmentCreation {
            EnrollmentCreation::new(
                TransitionId::new(Uuid::from_u128(0x10)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                "Chrome Web Store",
                "https://updates.example.test/ext.xml",
                "normal",
                IdentityId::new(Uuid::from_u128(0x20)),
                "127.0.0.1:7777",
                ExpiryResult::valid(10 * 60 * 1_000).expect("bounded ten-minute expiry"),
            )
        }

        fn enrollment_fixture(expiry: ExpiryResult) -> ExtensionEnrollment {
            ExtensionEnrollment::new(
                TransitionId::new(Uuid::from_u128(0x10)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                "store=stable;update=https://updates.example.test/ext.xml;install=normal",
                IdentityId::new(Uuid::from_u128(0x20)),
                "127.0.0.1:7777",
                Fingerprint::new("a".repeat(64)).expect("valid daemon fingerprint"),
                expiry,
            )
            .expect("valid enrollment fixture")
        }

        #[test]
        fn creation_bounds_lifecycle_metadata() {
            let bundle = EnrollmentBundle::create(creation()).expect("valid enrollment creation");
            assert_eq!(bundle.lifecycle(), EnrollmentLifecycle::Pending);
            assert_eq!(bundle.origin(), "chrome-extension://abcdefghijklmnopabcdefghijklmnop");
            assert_eq!(bundle.store_metadata(), "Chrome Web Store");
            assert_eq!(bundle.update_metadata(), "https://updates.example.test/ext.xml");
            assert_eq!(bundle.install_metadata(), "normal");
            assert_eq!(bundle.daemon_endpoint(), "127.0.0.1:7777");
            assert_eq!(bundle.one_time_public_key_fingerprint().as_str().len(), 64);
        }

        #[test]
        fn expiry_accepts_ten_minutes_and_rejects_uncertain_or_overlong_inputs() {
            let expiry = ExpiryResult::valid(10 * 60 * 1_000).expect("bounded deadline");
            assert_eq!(expiry.status(), ExpiryStatus::Valid);
            assert_eq!(expiry.deadline_ms(), 10 * 60 * 1_000);
            assert!(enrollment_fixture(expiry).lifecycle() == EnrollmentLifecycle::Pending);

            let mut uncertain = creation();
            uncertain.expiry = ExpiryResult::uncertain(10 * 60 * 1_000);
            assert_eq!(
                EnrollmentBundle::create(uncertain).expect_err("clock uncertainty fails closed"),
                EnrollmentCreateError::InvalidExpiry
            );
            let mut overlong = creation();
            overlong.expiry = ExpiryResult::valid(10 * 60 * 1_000 + 1).unwrap();
            assert_eq!(
                EnrollmentBundle::create(overlong).expect_err("expiry over ten minutes fails closed"),
                EnrollmentCreateError::InvalidExpiry
            );
        }

        #[test]
        fn binding_requires_exact_origin_endpoint_and_install_metadata() {
            let expected = creation();
            let mut attempt = EnrollmentBinding {
                origin: expected.origin.as_str(),
                endpoint: expected.daemon_endpoint.as_str(),
                store_metadata: expected.store_metadata.as_str(),
                update_metadata: expected.update_metadata.as_str(),
                install_metadata: expected.install_metadata.as_str(),
                development_allowance: DevelopmentIdentityAllowance::None,
            };
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Ok(()));
            attempt.origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnox";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Origin));
            attempt.origin = expected.origin.as_str();
            attempt.endpoint = "localhost:7777";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Endpoint));
            attempt.endpoint = expected.daemon_endpoint.as_str();
            attempt.install_metadata = "development";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Metadata));
        }

        #[test]
        fn one_time_private_key_is_owned_by_authenticated_encrypted_output() {
            let mut bundle = EnrollmentBundle::create(creation()).expect("valid enrollment creation");
            let mut channel = crate::enrollment::EnrollmentChannel::open(
                ConnectionId::new(Uuid::from_u128(0x30)), 1,
            )
            .expect("open native channel");
            let output = channel.seal_one_time_key(&mut bundle).unwrap();
            assert!(!output.ciphertext().is_empty());
            assert!(channel.seal_one_time_key(&mut bundle).is_err(), "PKCS#8 transfer is one-use");
            let plain = channel.open_sealed_for_test(bundle.enrollment_id(), &output).unwrap();
            assert!(!plain.is_empty());
            assert!(!format!("{bundle:?}").contains("PKCS#8"));
            channel.close();
            assert_eq!(
                channel.open_sealed_for_test(bundle.enrollment_id(), &output),
                Err(crate::enrollment::EnrollmentCustodyError::ChannelNotAuthenticated),
                "a closed channel recovers no one-time key",
            );
        }

        #[test]
        fn public_key_boundary_is_exact_uncompressed_sec1_and_has_no_private_bytes() {
            let bundle = EnrollmentBundle::create(creation()).expect("valid enrollment creation");
            let key = bundle.one_time_public_key();
            assert_eq!(key.as_bytes().len(), UNCOMPRESSED_KEY_BYTES);
            assert_eq!(key.as_bytes()[0], 0x04);
            let encoded = key.uncompressed_hex();
            assert_eq!(encoded.len(), UNCOMPRESSED_KEY_BYTES * 2);
            assert!(encoded.iter().all(u8::is_ascii_hexdigit));
            let mut malformed = *key.as_bytes();
            malformed[0] = 0x02;
            assert!(PublicKey::from_uncompressed(malformed).is_err());
        }

        #[test]
        fn enrollment_consumption_and_failure_budget_are_terminal_and_idempotent() {
            let mut enrollment = enrollment_fixture(ExpiryResult::valid(600_000).unwrap());
            enrollment.consume().expect("first proof consumes enrollment");
            assert_eq!(enrollment.lifecycle(), EnrollmentLifecycle::Consumed);
            assert_eq!(enrollment.consume(), Err("enrollment is not pending"));
            assert_eq!(enrollment.record_failed_proof(), Err("enrollment is not pending"));

            let mut budget = enrollment_fixture(ExpiryResult::valid(600_000).unwrap());
            for _ in 0..5 {
                budget.record_failed_proof().expect("pending failure budget");
            }
            assert_eq!(budget.failed_proofs(), 5);
            assert_eq!(budget.lifecycle(), EnrollmentLifecycle::Closed);
            assert_eq!(budget.record_failed_proof(), Err("enrollment is not pending"));
        }

    };
}
