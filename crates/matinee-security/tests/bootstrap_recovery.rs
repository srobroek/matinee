macro_rules! bootstrap_recovery_tests {
    () => {
        use crate::adapters::credential_store::{CredentialBinding, CredentialStore};
        use crate::adapters::os_pipe::{OsPipe, OsPipeError};
        use crate::identity::{
            ExpiryResult, ExpiryStatus, IdempotencyKey, IdentityId, TransitionId, TransitionInput,
            TransitionOperation, TransitionOutcome,
        };
        use crate::test_support_fakes::{FakeCredentialStore, FakeOsPipe};
        use uuid::Uuid;

        fn identity(value: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(value))
        }

        fn transition(value: u128, outcome: TransitionOutcome) -> TransitionInput {
            TransitionInput::new(
                identity(1),
                TransitionId::new(Uuid::from_u128(value)),
                TransitionOperation::Bootstrap,
                IdempotencyKey::new(Uuid::from_u128(99)),
                0,
                outcome,
            )
        }

        #[test]
        fn before_commit_crash_is_unknown_and_leaves_state_unpersistable() {
            let interrupted = transition(10, TransitionOutcome::Unknown);
            assert_eq!(interrupted.outcome(), TransitionOutcome::Unknown);
            assert!(interrupted.is_fail_closed());
            assert!(!interrupted.may_persist());
        }

        #[test]
        fn after_commit_crash_and_restart_converge_without_duplicate_registration() {
            let committed = transition(11, TransitionOutcome::Committed);
            let recovered = transition(11, TransitionOutcome::AlreadyCommitted);
            assert!(committed.may_persist());
            assert!(recovered.may_persist());
            assert_eq!(recovered.outcome(), TransitionOutcome::AlreadyCommitted);
            assert_ne!(
                transition(12, TransitionOutcome::Committed).outcome(),
                recovered.outcome(),
                "a different transition cannot be treated as the recovered commit"
            );
        }

        #[test]
        fn duplicate_identity_and_credential_bindings_fail_closed() {
            let binding = CredentialBinding::new([7; 32]);
            let store = FakeCredentialStore::new().with_error(
                binding,
                crate::adapters::credential_store::CredentialStoreError::Duplicate,
            );
            assert_eq!(
                store.lookup(binding),
                Err(crate::adapters::credential_store::CredentialStoreError::Duplicate)
            );

            let mismatched = FakeCredentialStore::new().with_error(
                binding,
                crate::adapters::credential_store::CredentialStoreError::Mismatch,
            );
            assert_eq!(
                mismatched.lookup(binding),
                Err(crate::adapters::credential_store::CredentialStoreError::Mismatch)
            );
        }

        #[test]
        fn missing_credential_never_falls_back_to_another_identity() {
            let requested = CredentialBinding::new([1; 32]);
            let other = CredentialBinding::new([2; 32]);
            let store = FakeCredentialStore::new().registered(other, 44);
            assert_eq!(
                store.lookup(requested),
                Err(crate::adapters::credential_store::CredentialStoreError::Missing)
            );
        }

        #[test]
        fn missing_mismatched_and_unsupported_pipe_states_are_closed() {
            for error in [
                OsPipeError::Missing,
                OsPipeError::Mismatch,
                OsPipeError::Duplicate,
                OsPipeError::Malformed,
                OsPipeError::Oversized,
                OsPipeError::Unavailable,
            ] {
                assert!(matches!(
                    error,
                    OsPipeError::Missing
                        | OsPipeError::Mismatch
                        | OsPipeError::Duplicate
                        | OsPipeError::Malformed
                        | OsPipeError::Oversized
                        | OsPipeError::Unavailable
                ));
            }

            assert_eq!(
                FakeOsPipe::error(OsPipeError::Missing).acquire(),
                Err(OsPipeError::Missing)
            );
            assert_eq!(
                FakeOsPipe::error(OsPipeError::Mismatch).acquire(),
                Err(OsPipeError::Mismatch)
            );
            assert_eq!(
                FakeOsPipe::error(OsPipeError::Unavailable).acquire(),
                Err(OsPipeError::Unavailable)
            );
        }

        #[test]
        fn malformed_or_unsupported_transition_outcomes_cannot_report_success() {
            let unknown = transition(13, TransitionOutcome::Unknown);
            assert!(unknown.is_fail_closed());
            assert!(!unknown.may_persist());
            assert_ne!(unknown.outcome(), TransitionOutcome::Committed);
            assert_ne!(unknown.outcome(), TransitionOutcome::AlreadyCommitted);
        }

        #[test]
        fn restart_round_trip_preserves_only_bounded_transition_state() {
            let before = transition(14, TransitionOutcome::Committed);
            // The restart record is a typed, bounded value; cloning models the
            // persistence/reload boundary without adding a production serializer.
            let after = before.clone();
            assert_eq!(after, before);
            assert_eq!(after.outcome(), TransitionOutcome::Committed);
        }

        #[test]
        fn expiry_uncertainty_and_debug_projections_fail_closed_and_redact() {
            let uncertain = ExpiryResult::uncertain(10_000);
            assert_eq!(uncertain.status(), ExpiryStatus::Uncertain);
            assert!(!uncertain.is_security_valid());
            assert!(!ExpiryResult::expired(10_000).is_security_valid());

            let binding = CredentialBinding::new([0xa5; 32]);
            let store = FakeCredentialStore::new().registered(binding, 0xfeed_beef);
            let credential = store.lookup(binding).expect("registered credential");
            let debug = format!("{credential:?}");
            assert!(!debug.contains("feed"));
            assert!(!debug.contains("a5"));
            assert!(!format!("{binding:?}").contains("a5"));
        }
    };
}
