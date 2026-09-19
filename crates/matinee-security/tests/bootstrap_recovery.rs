#[allow(unused_macros)]
macro_rules! bootstrap_recovery_tests {
    () => {
        use crate::adapters::credential_store::{
            CredentialBinding, CredentialStore, CredentialStoreError, InMemoryCredentialStore,
        };
        use crate::adapters::os_pipe::{
            BootstrapEnvelope, BootstrapEnvelope as Envelope, EnvelopeError,
        };
        use crate::events::{EndpointClass, EventBoundary, EventOutcome, EventTime, SecurityCode};
        use crate::identity::{
            DaemonLifecycle, Fingerprint, PrincipalKind, PrincipalLifecycle, PublicKey,
        };
        use crate::test_support_fakes::{FakeEventSink, FakeOsPipe};
        use crate::transition::{BootstrapError, BootstrapState, CrashPoint, DaemonSelf};
        use uuid::Uuid;

        /// The daemon's own public key: a valid P-256 point independent of every
        /// administrator key an envelope carries, as FR-002 requires.
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

        fn daemon_self(key: &PublicKey) -> DaemonSelf<'_> {
            DaemonSelf {
                public_key: key,
                contract_min: 1,
                contract_max: 1,
            }
        }

        fn envelope(value: u128, nonce_byte: u8) -> BootstrapEnvelope {
            let key = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            BootstrapEnvelope::new(
                [nonce_byte; 32],
                Uuid::from_u128(value + 1),
                Uuid::from_u128(value + 2),
                Uuid::from_u128(value + 3),
                key,
            )
            .expect("valid native bootstrap envelope")
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
            let key = daemon_key();
            match crash {
                Some(crash) => state.bootstrap_encoded_for_test(
                    &pipe,
                    &envelope.encode(),
                    daemon_self(&key),
                    store,
                    Some(sink),
                    Some(crash),
                    EventTime(42),
                    b"native://bootstrap",
                ),
                None => state.bootstrap_encoded_with_store_for_test(
                    &pipe,
                    &envelope.encode(),
                    daemon_self(&key),
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
            let handle = store
                .lookup(CredentialBinding::for_identities(
                    envelope.state_directory,
                    envelope.daemon,
                ))
                .expect("credential selected");
            assert_eq!(format!("{handle:?}"), "CredentialHandle(REDACTED)");
            assert!(!String::from_utf8_lossy(&envelope.encode()).contains("feed"));
            let mut sink = FakeEventSink::accepted();
            let mut state = BootstrapState::default();
            assert_eq!(
                apply(&mut state, &envelope, &store, &mut sink, None),
                Ok(crate::identity::TransitionOutcome::Committed)
            );
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
                assert_eq!(
                    apply(&mut state, &envelope, &store, &mut sink, Some(crash)),
                    Err(BootstrapError::Crash(crash))
                );
                assert!(state.active().is_none());
                assert!(state.staged().is_none());
                assert_eq!(
                    apply(&mut state, &envelope, &store, &mut sink, None),
                    Ok(crate::identity::TransitionOutcome::Committed)
                );
            }
        }

        #[test]
        fn staged_and_post_commit_crashes_recover_without_duplicate_registration() {
            for (value, crash) in [(30, CrashPoint::AfterStage), (31, CrashPoint::AfterCommit)] {
                let envelope = envelope(value, value as u8);
                let store = registered(&envelope);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(
                    apply(&mut state, &envelope, &store, &mut sink, Some(crash)),
                    Err(BootstrapError::Crash(crash))
                );
                state.recover();
                assert!(state.active().is_some());
                assert!(state.staged().is_none());
                assert_eq!(
                    apply(&mut state, &envelope, &store, &mut sink, None),
                    Ok(crate::identity::TransitionOutcome::AlreadyCommitted)
                );
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
            assert_eq!(
                apply(&mut state, &different, &different_store, &mut sink, None),
                Err(BootstrapError::IdentityMismatch)
            );
            assert_eq!(state.active(), before.as_ref());

            for (value, expected) in [
                (50, CredentialStoreError::Missing),
                (51, CredentialStoreError::Mismatch),
                (52, CredentialStoreError::Duplicate),
                (53, CredentialStoreError::Unavailable),
            ] {
                let candidate = envelope(value, value as u8);
                let mut store = InMemoryCredentialStore::new();
                let binding =
                    CredentialBinding::for_identities(candidate.state_directory, candidate.daemon);
                match expected {
                    CredentialStoreError::Missing => {}
                    CredentialStoreError::Mismatch => {
                        store.register_mismatched(binding, value as u64)
                    }
                    CredentialStoreError::Duplicate => {
                        store.register(binding, 1);
                        store.register(binding, 2);
                    }
                    CredentialStoreError::Unavailable => store.set_unavailable(true),
                }
                let mut candidate_state = BootstrapState::default();
                let mut candidate_sink = FakeEventSink::accepted();
                assert_eq!(
                    apply(
                        &mut candidate_state,
                        &candidate,
                        &store,
                        &mut candidate_sink,
                        None
                    ),
                    Err(BootstrapError::Credential(expected))
                );
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
            assert_eq!(
                apply(&mut state, &envelope, &store, &mut unavailable, None),
                Err(BootstrapError::EventUnavailable)
            );
            assert!(state.active().is_none());
            assert!(state.staged().is_none());
            let mut accepted = FakeEventSink::accepted();
            assert_eq!(
                apply(&mut state, &envelope, &store, &mut accepted, None),
                Ok(crate::identity::TransitionOutcome::Committed)
            );
        }

        #[test]
        fn endpoint_and_envelope_validation_are_meaningful() {
            assert_eq!(
                Envelope::parse_endpoint(&[0xff]),
                Err(EnvelopeError::InvalidUtf8)
            );
            assert_eq!(
                Envelope::parse_endpoint(b""),
                Err(EnvelopeError::InvalidType)
            );
            assert_eq!(
                Envelope::parse_endpoint(&[b'a'; 257]),
                Err(EnvelopeError::Oversized)
            );
            let mut malformed = envelope(70, 7).encode();
            malformed[2] = 0;
            assert_eq!(Envelope::parse(&malformed), Err(EnvelopeError::Malformed));
        }

        /// SC-001 and SC-002 are identity claims, not record claims: "all successful runs
        /// create exactly one daemon identity and one native administrator" and "every retry
        /// converges to one principal with no duplicate or orphaned registration". This
        /// counts the committed identities on every run and keeps the private-byte scan
        /// SC-001 also requires.
        #[test]
        fn sc001_clean_runs_and_sc002_crash_runs_converge() {
            let key = daemon_key();
            let expected_daemon_fingerprint = Fingerprint::from_public_key(&key);
            // The provisioned secret every fixture store registers. SC-001 requires zero
            // private-key bytes on any durable or transport surface, so this is the needle.
            let private_bytes = 0xfeed_beefu64.to_be_bytes();

            for value in 0..100u128 {
                let candidate = envelope(1000 + value, value as u8);
                let store = registered(&candidate);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(
                    apply(&mut state, &candidate, &store, &mut sink, None),
                    Ok(crate::identity::TransitionOutcome::Committed)
                );

                // Exactly one daemon identity, carrying the daemon's own key.
                let daemon = state
                    .active_daemon()
                    .expect("one committed daemon identity");
                assert_eq!(
                    daemon.id(),
                    crate::identity::IdentityId::new(candidate.daemon)
                );
                assert_eq!(daemon.public_key(), &key);
                assert_eq!(daemon.fingerprint(), &expected_daemon_fingerprint);
                assert_eq!(daemon.lifecycle(), DaemonLifecycle::Active);

                // Exactly one native administrator, independent of the daemon identity.
                let admin = state.active_admin().expect("one native administrator");
                assert_eq!(admin.kind(), PrincipalKind::NativeAdmin);
                assert_eq!(admin.lifecycle(), PrincipalLifecycle::Active);
                assert_eq!(admin.owner(), daemon.id());
                assert_ne!(admin.id(), daemon.id());
                assert_ne!(admin.public_key(), daemon.public_key());
                assert_ne!(admin.fingerprint(), daemon.fingerprint());
                assert_eq!(
                    admin.fingerprint(),
                    &Fingerprint::from_public_key(admin.public_key())
                );
                assert!(state.staged().is_none());
                assert!(state.staged_admin().is_none());
                assert_eq!(sink.received().len(), 2);

                // Zero private-key bytes on any durable or transport surface.
                for payload in [
                    String::from_utf8_lossy(&candidate.encode()).into_owned(),
                    format!("{:?}", state.active()),
                    format!("{daemon:?}"),
                    format!("{admin:?}"),
                    format!("{:?}", sink.received()),
                ] {
                    assert!(
                        !payload
                            .as_bytes()
                            .windows(private_bytes.len())
                            .any(|window| window == private_bytes),
                        "private key leaked on a bootstrap surface: {payload}"
                    );
                }
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

                // A crash before the promotion leaves no principal at all: registration is
                // part of the commit, so there is nothing to orphan.
                match crash {
                    CrashPoint::BeforeEvent | CrashPoint::AfterEvent => {
                        // Nothing even staged yet.
                        assert!(state.active_admin().is_none());
                        assert!(state.active_daemon().is_none());
                        assert!(state.staged_admin().is_none());
                    }
                    CrashPoint::AfterStage => {
                        // Staged is durable intent, not a registration: the administrator
                        // exists on the staged side and is still invisible as a principal.
                        assert!(state.staged_admin().is_some());
                        assert!(
                            state.active_admin().is_none(),
                            "a staged bootstrap must not register a principal"
                        );
                        assert!(
                            state.active_daemon().is_none(),
                            "a staged bootstrap must not register a daemon identity"
                        );
                    }
                    CrashPoint::AfterCommit => {
                        // The promotion already happened, so exactly one of each exists.
                        assert!(state.active_admin().is_some());
                        assert!(state.active_daemon().is_some());
                        assert!(state.staged_admin().is_none());
                    }
                }

                state.recover();
                let expected = if state.active().is_none() {
                    crate::identity::TransitionOutcome::Committed
                } else {
                    crate::identity::TransitionOutcome::AlreadyCommitted
                };
                assert_eq!(
                    apply(&mut state, &candidate, &store, &mut sink, None),
                    Ok(expected)
                );

                // Converged on exactly one daemon identity and one administrator, with the
                // derived administrator identifier proving the retry did not create a second.
                let (daemon_id, daemon_lifecycle) = {
                    let daemon = state
                        .active_daemon()
                        .expect("one converged daemon identity");
                    (daemon.id(), daemon.lifecycle())
                };
                let admin_id = {
                    let admin = state.active_admin().expect("one converged administrator");
                    assert_eq!(admin.kind(), PrincipalKind::NativeAdmin);
                    assert_eq!(admin.lifecycle(), PrincipalLifecycle::Active);
                    assert_eq!(admin.owner(), daemon_id);
                    assert_ne!(admin.id(), daemon_id);
                    admin.id()
                };
                assert_eq!(daemon_lifecycle, DaemonLifecycle::Active);
                assert!(state.staged().is_none());
                assert!(state.staged_admin().is_none());

                // A second retry is still the same one administrator, never a duplicate.
                assert_eq!(
                    apply(&mut state, &candidate, &store, &mut sink, None),
                    Ok(crate::identity::TransitionOutcome::AlreadyCommitted)
                );
                assert_eq!(state.active_admin().map(|found| found.id()), Some(admin_id));
            }
        }

        /// FR-002 fixes the fingerprint as "lowercase hexadecimal SHA-256 over the exact
        /// 65-byte uncompressed public key".
        ///
        /// The two expected digests are known-answer vectors computed outside this program
        /// (`xxd -r -p | shasum -a 256` over the 65 fixture key bytes), so nothing in the
        /// crate produces the value being compared against. A change to the digest, the
        /// encoding, the case, or the byte range `Fingerprint::from_public_key` covers moves
        /// the committed fingerprint away from these constants and fails here.
        #[test]
        fn committed_fingerprints_are_the_independent_lowercase_sha256_digest() {
            const ADMIN_KEY_DIGEST: &str =
                "698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be";
            const DAEMON_KEY_DIGEST: &str =
                "a9f300eb5960e89133af7362011a1e26f0e2ea2e36dc402a04af6c192b891a8c";

            let candidate = envelope(4200, 0x5c);
            let store = registered(&candidate);
            let mut sink = FakeEventSink::accepted();
            let mut state = BootstrapState::default();
            assert_eq!(
                apply(&mut state, &candidate, &store, &mut sink, None),
                Ok(crate::identity::TransitionOutcome::Committed)
            );

            let daemon = state.active_daemon().expect("committed daemon identity");
            let admin = state.active_admin().expect("committed administrator");

            // The vectors describe exactly the bytes FR-002 names: 65, uncompressed.
            assert_eq!(daemon.public_key().as_bytes().len(), 65);
            assert_eq!(daemon.public_key().as_bytes()[0], 0x04);
            assert_eq!(admin.public_key().as_bytes().len(), 65);
            assert_eq!(admin.public_key().as_bytes()[0], 0x04);

            assert_eq!(daemon.fingerprint().as_str(), DAEMON_KEY_DIGEST);
            assert_eq!(admin.fingerprint().as_str(), ADMIN_KEY_DIGEST);
            assert_eq!(
                state.active().unwrap().fingerprint.as_str(),
                ADMIN_KEY_DIGEST
            );

            // The digest is over the key, so two independent keys cannot share one.
            assert_ne!(DAEMON_KEY_DIGEST, ADMIN_KEY_DIGEST);
            for text in [DAEMON_KEY_DIGEST, ADMIN_KEY_DIGEST] {
                assert_eq!(text.len(), 64);
                assert!(
                    text.bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                    "FR-002 requires lowercase hexadecimal"
                );
            }
        }

        /// FR-002 wants the daemon identity and the principal identity to be independent.
        /// One keypair offered as both is refused, and nothing is registered.
        #[test]
        fn a_daemon_key_reused_as_the_administrator_key_is_refused() {
            let candidate = envelope(4300, 0x6d);
            let store = registered(&candidate);
            let mut sink = FakeEventSink::accepted();
            let mut state = BootstrapState::default();
            let collapsed = PublicKey::from_uncompressed(candidate.public_key)
                .expect("the envelope carries a valid administrator key");
            let pipe = FakeOsPipe::present(9);
            assert_eq!(
                state.bootstrap_encoded_with_store_for_test(
                    &pipe,
                    &candidate.encode(),
                    daemon_self(&collapsed),
                    &store,
                    Some(&mut sink),
                    EventTime(42),
                    b"native://bootstrap",
                ),
                Err(BootstrapError::KeyNotIndependent)
            );
            assert!(state.active().is_none());
            assert!(state.active_daemon().is_none());
            assert!(state.active_admin().is_none());
            assert!(state.staged_admin().is_none());
            assert!(sink.received().is_empty());
        }
        #[test]
        fn malformed_public_keys_fail_closed_before_registration() {
            let valid = envelope(70, 7);
            let encoded = valid.encode();

            let mut invalid_prefix = encoded.clone();
            let prefix_offset = invalid_prefix.len() - 65;
            invalid_prefix[prefix_offset] = 0x02;
            assert_eq!(
                Envelope::parse(&invalid_prefix),
                Err(EnvelopeError::Malformed)
            );

            let mut invalid_length = encoded.clone();
            let key_length_offset = invalid_length.len() - 67;
            invalid_length[key_length_offset + 1] = 64;
            assert_eq!(
                Envelope::parse(&invalid_length),
                Err(EnvelopeError::Malformed)
            );

            let mut off_curve = encoded;
            let last_offset = off_curve.len() - 1;
            off_curve[last_offset] ^= 1;
            assert_eq!(Envelope::parse(&off_curve), Err(EnvelopeError::Malformed));
        }
    };
}
