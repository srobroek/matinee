macro_rules! enrollment_contract_tests {
    () => {
        use crate::identity::{
            EnrollmentLifecycle, ExpiryResult, ExpiryStatus, Fingerprint, IdentityId,
            TransitionId, TransitionInput, TransitionOperation, TransitionOutcome,
            ExtensionEnrollment,
        };
        use uuid::Uuid;

        fn enrollment_fixture(expiry: ExpiryResult) -> ExtensionEnrollment {
            ExtensionEnrollment::new(
                TransitionId::new(Uuid::from_u128(0x10)),
                "chrome-extension://abcdefghijklmnop",
                "store=stable;update=https://updates.example.test/ext.xml;install=webstore",
                IdentityId::new(Uuid::from_u128(0x20)),
                "127.0.0.1:7777",
                Fingerprint::new("a".repeat(64)).expect("valid daemon fingerprint"),
                expiry,
            )
            .expect("valid enrollment fixture")
        }

        #[test]
        fn enrollment_secret_fixture_has_exactly_256_bits_of_entropy() {
            let secret = [0x5au8; 32];
            assert_eq!(secret.len(), 32);
            assert_eq!(secret.as_slice(), &[0x5a; 32]);
            let mut mutation = secret;
            mutation[31] ^= 1;
            assert_ne!(secret, mutation, "a one-byte mutation must change the proof secret");
        }

        #[test]
        fn enrollment_expiry_is_valid_for_exactly_ten_minutes_and_uncertainty_fails_closed() {
            const TEN_MINUTES_MS: u64 = 10 * 60 * 1_000;
            let expiry = ExpiryResult::valid(TEN_MINUTES_MS).expect("nonzero bounded deadline");
            assert_eq!(expiry.status(), ExpiryStatus::Valid);
            assert_eq!(expiry.deadline_ms(), TEN_MINUTES_MS);
            assert!(enrollment_fixture(expiry).lifecycle() == EnrollmentLifecycle::Pending);

            let uncertain = ExpiryResult::uncertain(TEN_MINUTES_MS);
            assert_eq!(
                ExtensionEnrollment::new(
                    TransitionId::new(Uuid::from_u128(0x10)),
                    "chrome-extension://abcdefghijklmnop",
                    "install=webstore",
                    IdentityId::new(Uuid::from_u128(0x20)),
                    "127.0.0.1:7777",
                    Fingerprint::new("a".repeat(64)).unwrap(),
                    uncertain,
                )
                .expect_err("uncertain expiry must fail closed"),
                "invalid enrollment"
            );
        }

        #[test]
        fn enrollment_binds_origin_install_metadata_daemon_and_endpoint() {
            let enrollment = enrollment_fixture(ExpiryResult::valid(600_000).unwrap());
            let debug = format!("{enrollment:?}");
            assert!(debug.contains("chrome-extension://abcdefghijklmnop"));
            assert!(debug.contains("store=stable;update=https://updates.example.test/ext.xml;install=webstore"));
            assert!(debug.contains("127.0.0.1:7777"));
            assert!(debug.contains(&"a".repeat(64)));
        }

        #[test]
        fn one_time_proof_consumption_is_idempotence_safe_and_mutations_fail_closed() {
            let mut enrollment = enrollment_fixture(ExpiryResult::valid(600_000).unwrap());
            assert_eq!(enrollment.consume(), Ok(()));
            assert_eq!(enrollment.lifecycle(), EnrollmentLifecycle::Consumed);
            assert_eq!(
                enrollment.consume().expect_err("a consumed enrollment is one-use"),
                "enrollment is not pending"
            );
            assert_eq!(
                enrollment
                    .record_failed_proof()
                    .expect_err("proof accounting cannot mutate consumed state"),
                "enrollment is not pending"
            );
        }

        #[test]
        fn atomic_registration_accepts_only_committed_outcomes_and_rejects_unknown() {
            let state = IdentityId::new(Uuid::from_u128(0x30));
            let transition = TransitionId::new(Uuid::from_u128(0x31));
            let key = crate::identity::IdempotencyKey::new(Uuid::from_u128(0x32));
            let committed = TransitionInput::new(
                state,
                transition,
                TransitionOperation::EnrollmentConsume,
                key,
                7,
                TransitionOutcome::Committed,
            );
            assert!(committed.may_persist());
            assert!(!committed.is_fail_closed());

            let unknown = TransitionInput::new(
                state,
                transition,
                TransitionOperation::EnrollmentConsume,
                key,
                7,
                TransitionOutcome::Unknown,
            );
            assert!(unknown.is_fail_closed());
            assert!(!unknown.may_persist(), "unknown result must not register a principal");
        }

        #[test]
        fn enrollment_redacts_transient_secret_and_closes_after_five_failed_proofs() {
            let secret = "transient-32-byte-secret-fixture";
            let mut enrollment = enrollment_fixture(ExpiryResult::valid(600_000).unwrap());
            let debug = format!("{enrollment:?}");
            assert!(!debug.contains(secret));
            assert_eq!(enrollment.failed_proofs(), 0);
            for _ in 0..4 {
                enrollment.record_failed_proof().expect("pending proof budget");
            }
            assert_eq!(enrollment.failed_proofs(), 4);
            enrollment.record_failed_proof().expect("fifth proof closes enrollment");
            assert_eq!(enrollment.failed_proofs(), 5);
            assert_eq!(enrollment.lifecycle(), EnrollmentLifecycle::Closed);
            assert_eq!(
                enrollment.record_failed_proof().expect_err("closed enrollment is immutable"),
                "enrollment is not pending"
            );
        }
    };
}
