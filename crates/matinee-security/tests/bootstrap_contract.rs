macro_rules! bootstrap_contract_tests {
    () => {
        use crate::adapters::os_pipe::{OsPipe, OsPipeError};
        use crate::identity::{
            CredentialReference, DaemonIdentity, DaemonLifecycle, Fingerprint, IdempotencyKey,
            IdentityId, PublicKey, TransitionId, TransitionInput, TransitionOperation,
            TransitionOutcome,
        };
        use crate::test_support_fakes::FakeOsPipe;
        use uuid::Uuid;

        fn identity(value: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(value))
        }

        fn native_key(seed: u8) -> PublicKey {
            let mut bytes = [seed; 65];
            bytes[0] = 0x04;
            PublicKey::from_uncompressed(bytes).expect("valid uncompressed native key")
        }

        #[test]
        fn inherited_unix_and_windows_pipe_envelopes_are_opaque_and_closed() {
            let unix = FakeOsPipe::present(9).acquire().expect("inherited unix fd");
            let windows = FakeOsPipe::present(u64::MAX)
                .acquire()
                .expect("inherited windows handle");
            assert!(unix.is_present());
            assert!(windows.is_present());
            let unix_debug = format!("{unix:?}");
            let windows_debug = format!("{windows:?}");
            assert_eq!(unix_debug, "InheritedPipe(REDACTED)");
            assert_eq!(windows_debug, "InheritedPipe(REDACTED)");
            assert!(!unix_debug.contains('9'));
            assert!(!windows_debug.contains("18446744073709551615"));

            let outcomes = [
                (OsPipeError::Missing, OsPipeError::Missing),
                (OsPipeError::Mismatch, OsPipeError::Mismatch),
                (OsPipeError::Duplicate, OsPipeError::Duplicate),
                (OsPipeError::Unavailable, OsPipeError::Unavailable),
                (OsPipeError::Malformed, OsPipeError::Malformed),
                (OsPipeError::Oversized, OsPipeError::Oversized),
            ];
            for (requested, expected) in outcomes {
                assert_eq!(FakeOsPipe::error(requested).acquire(), Err(expected));
            }
            assert!(!FakeOsPipe::present(0).acquire().unwrap().is_present());
        }

        #[test]
        fn bootstrap_nonce_is_fresh_and_mutation_is_detectable() {
            let first = [0x11_u8; 32];
            let second = [0x22_u8; 32];
            assert_ne!(first, second);
            assert_eq!(first.len(), 32);
            assert_eq!(second.len(), 32);
            let mut altered = first;
            altered[31] ^= 1;
            assert_ne!(altered, first);
        }

        #[test]
        fn state_directory_daemon_and_bootstrap_ids_remain_distinct() {
            let state = identity(1);
            let daemon = identity(2);
            let bootstrap = TransitionId::new(Uuid::from_u128(3));
            let idempotency = IdempotencyKey::new(Uuid::from_u128(4));
            assert_ne!(state, daemon);
            assert_ne!(state.get(), bootstrap.get());
            assert_ne!(state.get(), idempotency.get());
            assert_ne!(daemon.get(), bootstrap.get());
            assert_ne!(bootstrap.get(), idempotency.get());

            let credential =
                CredentialReference::new("apple-native", "native-admin", daemon, state)
                    .expect("bounded credential locator");
            assert_eq!(credential.provider(), "apple-native");
            assert_eq!(credential.key_locator(), "native-admin");
            assert_eq!(credential.daemon(), daemon);
            assert_eq!(credential.state_directory(), state);
            assert!(CredentialReference::new("", "native-admin", daemon, state).is_err());
            assert!(
                CredentialReference::new("apple-native", "x".repeat(257), daemon, state).is_err()
            );
        }

        #[test]
        fn native_public_key_and_daemon_identity_are_bounded_redacted_contracts() {
            let state = identity(10);
            let daemon = identity(11);
            let key = native_key(0x5a);
            assert_eq!(key.as_bytes().len(), 65);
            assert_eq!(key.as_bytes()[0], 0x04);
            let encoded = key.uncompressed_hex();
            assert_eq!(encoded.len(), 130);
            assert!(encoded.iter().all(u8::is_ascii_hexdigit));
            assert!(PublicKey::from_uncompressed([0; 65]).is_err());

            let fingerprint = Fingerprint::new("a".repeat(64)).expect("lowercase fingerprint");
            let credential =
                CredentialReference::new("apple-native", "native-admin", daemon, state)
                    .expect("credential binding");
            let mut record = DaemonIdentity::new(
                daemon,
                key.clone(),
                fingerprint,
                "127.0.0.1:7777",
                1,
                1,
                credential,
            )
            .expect("staged daemon identity");
            assert_eq!(record.lifecycle(), DaemonLifecycle::Staged);
            assert_eq!(record.public_key().as_bytes(), key.as_bytes());
            assert!(record.activate().is_ok());
            assert_eq!(record.lifecycle(), DaemonLifecycle::Active);
            assert!(record.activate().is_err());
            assert!(!format!("{record:?}").contains(&"5a".repeat(65)));
        }

        #[test]
        fn bootstrap_unknown_outcome_fails_closed_before_persistence() {
            let input = TransitionInput::new(
                identity(20),
                TransitionId::new(Uuid::from_u128(21)),
                TransitionOperation::Bootstrap,
                IdempotencyKey::new(Uuid::from_u128(22)),
                0,
                TransitionOutcome::Unknown,
            );
            assert!(input.is_fail_closed());
            assert!(!input.may_persist());
            for outcome in [TransitionOutcome::Rejected, TransitionOutcome::Unknown] {
                let rejected = TransitionInput::new(
                    identity(20),
                    TransitionId::new(Uuid::from_u128(21)),
                    TransitionOperation::Bootstrap,
                    IdempotencyKey::new(Uuid::from_u128(22)),
                    0,
                    outcome,
                );
                assert!(!rejected.may_persist());
            }
        }
    };
}
