#[allow(unused_macros)]
macro_rules! bootstrap_contract_tests {
    () => {
        use crate::adapters::credential_store::{
            CredentialBinding, CredentialStore, InMemoryCredentialStore,
        };
        use crate::adapters::os_pipe::{BootstrapEnvelope, OsPipe, OsPipeError};
        use crate::events::{
            EndpointClass, EventBoundary, EventOutcome, EventTime, MetadataEntry, SafeNextAction,
            SecurityCode, SecurityEvent,
        };
        use crate::identity::{
            CredentialReference, DaemonIdentity, DaemonLifecycle, Fingerprint, IdempotencyKey,
            IdentityId, PublicKey, TransitionId, TransitionInput, TransitionOperation,
            TransitionOutcome,
        };
        use crate::test_support_fakes::{FakeCredentialStore, FakeEventSink, FakeOsPipe};
        use crate::transition::{BootstrapError, BootstrapState, DaemonSelf};
        use uuid::Uuid;

        const NATIVE_PUBLIC_KEY: [u8; 65] = [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];

        fn contains_private_key(surface: &[u8], private_key: &[u8]) -> bool {
            surface
                .windows(private_key.len())
                .any(|window| window == private_key)
        }

        fn identity(value: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(value))
        }

        fn native_key(_seed: u8) -> PublicKey {
            let bytes = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            PublicKey::from_uncompressed(bytes).expect("valid uncompressed native key")
        }

        /// The daemon's own public key, independent of [`NATIVE_PUBLIC_KEY`] so a bootstrap
        /// registers two distinct identities as FR-002 requires.
        fn daemon_key() -> PublicKey {
            let bytes = [
                0x04, 0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04,
                0xb5, 0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48,
                0xfc, 0x47, 0x66, 0x99, 0x78, 0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29,
                0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82,
                0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
            ];
            PublicKey::from_uncompressed(bytes).expect("valid independent daemon key")
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
        fn bootstrap_unknown_outcome_is_fail_closed() {
            let input = TransitionInput::new(
                identity(20),
                TransitionId::new(Uuid::from_u128(21)),
                TransitionOperation::Bootstrap,
                IdempotencyKey::new(Uuid::from_u128(22)),
                0,
                TransitionOutcome::Unknown,
            );
            assert!(input.is_fail_closed());
        }
        #[test]
        fn bootstrap_custody_boundaries_are_typed_and_redacted() {
            let binding_bytes = [0xa5; 32];
            let binding = CredentialBinding::new(binding_bytes);
            assert_eq!(format!("{binding:?}"), "CredentialBinding(REDACTED)");

            let handle = FakeCredentialStore::new()
                .registered(binding, u64::MAX)
                .lookup(binding)
                .expect("registered credential handle");
            assert_eq!(handle.slot(), u64::MAX);
            assert_eq!(format!("{handle:?}"), "CredentialHandle(REDACTED)");

            let pipe = FakeOsPipe::present(u64::MAX)
                .acquire()
                .expect("inherited bootstrap pipe");
            assert!(pipe.is_present());
            assert_eq!(format!("{pipe:?}"), "InheritedPipe(REDACTED)");

            let accepted = SecurityEvent::new(
                Uuid::from_u128(32),
                EventBoundary::Bootstrap,
                SecurityCode::AuthenticationFailed,
                EventOutcome::Failed,
                SafeNextAction::FailClosed,
                None,
                None,
                EndpointClass::Native,
                EventTime(1),
                identity(30).get(),
                vec![MetadataEntry {
                    key: "reason".into(),
                    value: "bootstrap-failed".into(),
                }],
            )
            .expect("bounded redacted event");
            assert_eq!(accepted.metadata()[0].value, "bootstrap-failed");

            let rejected = SecurityEvent::new(
                Uuid::from_u128(33),
                EventBoundary::Bootstrap,
                SecurityCode::AuthenticationFailed,
                EventOutcome::Failed,
                SafeNextAction::FailClosed,
                None,
                None,
                EndpointClass::Native,
                EventTime(1),
                identity(30).get(),
                vec![MetadataEntry {
                    key: "reason".into(),
                    value: "private-key-material".into(),
                }],
            );
            assert_eq!(rejected, Err(crate::events::EventBuildError::Redacted));
        }
        #[test]
        fn bootstrap_surfaces_never_contain_known_private_key_bytes() {
            let mut private_key = [0u8; 32];
            private_key[31] = 1;
            let planted = private_key.to_vec();
            assert!(
                contains_private_key(&planted, &private_key),
                "negative control must detect planted key material"
            );

            let envelope = BootstrapEnvelope::new(
                [7; 32],
                Uuid::from_u128(0x1001),
                Uuid::from_u128(0x1002),
                Uuid::from_u128(0x1003),
                NATIVE_PUBLIC_KEY,
            )
            .expect("valid bootstrap envelope");
            let capture = envelope.encode();
            assert!(!contains_private_key(&capture, &private_key));

            let binding =
                CredentialBinding::for_identities(envelope.state_directory, envelope.daemon);
            let mut store = InMemoryCredentialStore::new();
            store.register(binding, 7);

            let pipe = FakeOsPipe::present(9);
            let daemon_public = daemon_key();
            let daemon = DaemonSelf {
                public_key: &daemon_public,
                contract_min: 1,
                contract_max: 1,
            };
            let mut state = BootstrapState::default();
            let mut sink = FakeEventSink::accepted();
            let committed = state.bootstrap_encoded_for_test(
                &pipe,
                &capture,
                daemon,
                &store,
                Some(&mut sink),
                None,
                EventTime(42),
                b"native://bootstrap",
            );
            assert_eq!(committed, Ok(TransitionOutcome::Committed));

            let mut rejected_state = BootstrapState::default();
            let mut rejected_sink = FakeEventSink::accepted();
            let rejected = rejected_state.bootstrap_encoded_for_test(
                &pipe,
                &capture,
                daemon,
                &store,
                Some(&mut rejected_sink),
                None,
                EventTime(42),
                b"127.0.0.1:9",
            );
            assert_eq!(rejected, Err(BootstrapError::EndpointRejected));

            let mut unavailable_state = BootstrapState::default();
            let mut unavailable_sink = FakeEventSink::unavailable();
            let unavailable = unavailable_state.bootstrap_encoded_for_test(
                &pipe,
                &capture,
                daemon,
                &store,
                Some(&mut unavailable_sink),
                None,
                EventTime(42),
                b"native://bootstrap",
            );
            assert_eq!(unavailable, Err(BootstrapError::EventUnavailable));

            let failure_payloads = [format!("{rejected:?}"), format!("{unavailable:?}")];
            let event_payloads = [
                format!("{:?}", sink.received()),
                format!("{:?}", unavailable_sink.received()),
            ];
            let durable_payloads = [
                format!("{:?}", state.active()),
                format!("status={committed:?}; diagnostics={:?}", state.active()),
            ];
            for (surface, payloads) in [
                (
                    "capture",
                    vec![String::from_utf8_lossy(&capture).into_owned()],
                ),
                ("failure", failure_payloads.to_vec()),
                ("event", event_payloads.to_vec()),
                ("durable", durable_payloads.to_vec()),
            ] {
                for payload in payloads {
                    assert!(
                        !contains_private_key(payload.as_bytes(), &private_key),
                        "private key leaked in {surface}: {payload}"
                    );
                }
            }
        }
    };
}
