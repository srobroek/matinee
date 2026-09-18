macro_rules! bootstrap_recovery_tests {
    () => {
        use crate::adapters::credential_store::{CredentialBinding, CredentialStore, CredentialStoreError, InMemoryCredentialStore};
        use crate::adapters::os_pipe::{BootstrapEnvelope, BootstrapEnvelope as Envelope, EnvelopeError};
        use crate::events::{EndpointClass, EventBoundary, EventOutcome, EventTime, SecurityCode};
        use crate::test_support_fakes::{FakeEventSink, FakeOsPipe};
        use crate::transition::{BootstrapError, BootstrapState, CrashPoint};
        use uuid::Uuid;

        fn envelope(value: u128, nonce_byte: u8) -> BootstrapEnvelope {
            let key = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
                0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
                0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
                0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
                0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            BootstrapEnvelope::new(
                [nonce_byte; 32],
                Uuid::from_u128(value + 1),
                Uuid::from_u128(value + 2),
                Uuid::from_u128(value + 3),
                key,
            ).expect("valid native bootstrap envelope")
        }

        fn registered(envelope: &BootstrapEnvelope) -> InMemoryCredentialStore {
            let mut store = InMemoryCredentialStore::new();
            store.register(
                CredentialBinding::for_identities(envelope.state_directory, envelope.daemon),
                0xfeed_beef,
            );
            store
        }

        fn apply(
            state: &mut BootstrapState,
            envelope: &BootstrapEnvelope,
            store: &InMemoryCredentialStore,
            sink: &mut FakeEventSink,
            crash: Option<CrashPoint>,
        ) -> Result<crate::identity::TransitionOutcome, BootstrapError> {
            let pipe = FakeOsPipe::present(9);
            match crash {
                Some(crash) => state.bootstrap_encoded_for_test(
                    &pipe,
                    &envelope.encode(),
                    store,
                    Some(sink),
                    Some(crash),
                    EventTime(42),
                    b"native://bootstrap",
                ),
                None => state.bootstrap_encoded_with_store_for_test(
                    &pipe,
                    &envelope.encode(),
                    store,
                    Some(sink),
                    EventTime(42),
                    b"native://bootstrap",
                ),
            }
        }

        #[test]
        fn clean_bootstrap_calls_production_operation_and_emits_bounded_events() {
            let envelope = envelope(10, 7);
            let store = registered(&envelope);
            let handle = store.lookup(CredentialBinding::for_identities(envelope.state_directory, envelope.daemon)).expect("credential selected");
            assert_eq!(format!("{handle:?}"), "CredentialHandle(REDACTED)");
            assert!(!String::from_utf8_lossy(&envelope.encode()).contains("feed"));
            let mut sink = FakeEventSink::accepted();
            let mut state = BootstrapState::default();
            assert_eq!(apply(&mut state, &envelope, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::Committed));
            let active = state.active().expect("committed native identity");
            assert_eq!(active.bootstrap, envelope.bootstrap);
            assert_eq!(active.endpoint, "native://bootstrap");
            assert_eq!(active.event_time, EventTime(42));
            assert!(state.staged().is_none());
            assert_eq!(sink.received().len(), 2);
            assert!(sink.received().iter().all(|event| {
                event.boundary == EventBoundary::Bootstrap
                    && event.endpoint == EndpointClass::Native
                    && event.time == EventTime(42)
                    && event.outcome == EventOutcome::Accepted
            }));
            assert_eq!(sink.received()[0].code, SecurityCode::EnrollmentAccepted);
            assert_eq!(sink.received()[1].code, SecurityCode::AuthorizationAccepted);
        }

        #[test]
        fn crash_before_or_after_event_reopens_nonce_without_state_mutation() {
            for crash in [CrashPoint::BeforeEvent, CrashPoint::AfterEvent] {
                let envelope = envelope(20 + crash as u128, 8 + crash as u8);
                let store = registered(&envelope);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(apply(&mut state, &envelope, &store, &mut sink, Some(crash)), Err(BootstrapError::Crash(crash)));
                assert!(state.active().is_none());
                assert!(state.staged().is_none());
                assert_eq!(apply(&mut state, &envelope, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::Committed));
            }
        }

        #[test]
        fn staged_and_post_commit_crashes_recover_without_duplicate_registration() {
            for (value, crash) in [(30, CrashPoint::AfterStage), (31, CrashPoint::AfterCommit)] {
                let envelope = envelope(value, value as u8);
                let store = registered(&envelope);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(apply(&mut state, &envelope, &store, &mut sink, Some(crash)), Err(BootstrapError::Crash(crash)));
                state.recover();
                assert!(state.active().is_some());
                assert!(state.staged().is_none());
                assert_eq!(apply(&mut state, &envelope, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::AlreadyCommitted));
                assert_eq!(state.active().unwrap().bootstrap, envelope.bootstrap);
            }
        }

        #[test]
        fn different_identity_and_all_credential_failures_leave_no_registration() {
            let first = envelope(40, 1);
            let mut state = BootstrapState::default();
            let first_store = registered(&first);
            let mut sink = FakeEventSink::accepted();
            apply(&mut state, &first, &first_store, &mut sink, None).expect("first bootstrap");
            let before = state.active().cloned();
            let different = envelope(41, 2);
            let different_store = registered(&different);
            assert_eq!(apply(&mut state, &different, &different_store, &mut sink, None), Err(BootstrapError::IdentityMismatch));
            assert_eq!(state.active(), before.as_ref());

            for (value, expected) in [
                (50, CredentialStoreError::Missing),
                (51, CredentialStoreError::Mismatch),
                (52, CredentialStoreError::Duplicate),
                (53, CredentialStoreError::Unavailable),
            ] {
                let candidate = envelope(value, value as u8);
                let mut store = InMemoryCredentialStore::new();
                let binding = CredentialBinding::for_identities(candidate.state_directory, candidate.daemon);
                match expected {
                    CredentialStoreError::Missing => {}
                    CredentialStoreError::Mismatch => store.register_mismatched(binding, value as u64),
                    CredentialStoreError::Duplicate => { store.register(binding, 1); store.register(binding, 2); }
                    CredentialStoreError::Unavailable => store.set_unavailable(true),
                }
                let mut candidate_state = BootstrapState::default();
                let mut candidate_sink = FakeEventSink::accepted();
                assert_eq!(apply(&mut candidate_state, &candidate, &store, &mut candidate_sink, None), Err(BootstrapError::Credential(expected)));
                assert!(candidate_state.active().is_none());
                assert!(candidate_state.staged().is_none());
            }
        }

        #[test]
        fn unavailable_required_sink_rolls_back_and_retry_is_idempotent() {
            let envelope = envelope(60, 6);
            let store = registered(&envelope);
            let mut unavailable = FakeEventSink::unavailable();
            let mut state = BootstrapState::default();
            assert_eq!(apply(&mut state, &envelope, &store, &mut unavailable, None), Err(BootstrapError::EventUnavailable));
            assert!(state.active().is_none());
            assert!(state.staged().is_none());
            let mut accepted = FakeEventSink::accepted();
            assert_eq!(apply(&mut state, &envelope, &store, &mut accepted, None), Ok(crate::identity::TransitionOutcome::Committed));
        }

        #[test]
        fn endpoint_and_envelope_validation_are_meaningful() {
            assert_eq!(Envelope::parse_endpoint(&[0xff]), Err(EnvelopeError::InvalidUtf8));
            assert_eq!(Envelope::parse_endpoint(b""), Err(EnvelopeError::InvalidType));
            assert_eq!(Envelope::parse_endpoint(&[b'a'; 257]), Err(EnvelopeError::Oversized));
            let mut malformed = envelope(70, 7).encode();
            malformed[2] = 0;
            assert_eq!(Envelope::parse(&malformed), Err(EnvelopeError::Malformed));
        }

        #[test]
        fn sc001_clean_runs_and_sc002_crash_runs_converge() {
            for value in 0..100u128 {
                let candidate = envelope(1000 + value, value as u8);
                let store = registered(&candidate);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(apply(&mut state, &candidate, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::Committed));
                assert!(state.active().is_some());
                assert!(state.staged().is_none());
                assert_eq!(state.active().unwrap().bootstrap, candidate.bootstrap);
                assert_eq!(sink.received().len(), 2);
            }
            for value in 0..100u128 {
                let candidate = envelope(2000 + value, (value as u8).wrapping_add(1));
                let store = registered(&candidate);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                let crash = match value % 4 {
                    0 => CrashPoint::BeforeEvent,
                    1 => CrashPoint::AfterEvent,
                    2 => CrashPoint::AfterStage,
                    _ => CrashPoint::AfterCommit,
                };
                assert!(apply(&mut state, &candidate, &store, &mut sink, Some(crash)).is_err());
                state.recover();
                if state.active().is_none() {
                    assert_eq!(apply(&mut state, &candidate, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::Committed));
                } else {
                    assert_eq!(apply(&mut state, &candidate, &store, &mut sink, None), Ok(crate::identity::TransitionOutcome::AlreadyCommitted));
                }
                assert!(state.active().is_some());
                assert!(state.staged().is_none());
            }
        }
        #[test]
        fn malformed_public_keys_fail_closed_before_registration() {
            let valid = envelope(70, 7);
            let encoded = valid.encode();

            let mut invalid_prefix = encoded.clone();
            let prefix_offset = invalid_prefix.len() - 65;
            invalid_prefix[prefix_offset] = 0x02;
            assert_eq!(Envelope::parse(&invalid_prefix), Err(EnvelopeError::Malformed));

            let mut invalid_length = encoded.clone();
            let key_length_offset = invalid_length.len() - 67;
            invalid_length[key_length_offset + 1] = 64;
            assert_eq!(Envelope::parse(&invalid_length), Err(EnvelopeError::Malformed));

            let mut off_curve = encoded;
            let last_offset = off_curve.len() - 1;
            off_curve[last_offset] ^= 1;
            assert_eq!(Envelope::parse(&off_curve), Err(EnvelopeError::Malformed));
        }
    };
}
