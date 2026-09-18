macro_rules! rotation_revocation_tests {
    () => {
        use crate::enrollment::{EnrollmentChannel, EnrollmentClock};
        use crate::events::{EventBoundary, EventTime, SecurityCode};
        use crate::failures::FailureCode;
        use crate::identity::{
            CredentialReference, EnrollmentLifecycle, ExpiryResult, Fingerprint, GrantLifecycle,
            PrincipalKind, PrincipalLifecycle, TransitionOperation, TransitionOutcome,
        };
        use crate::test_support_channel::{
            id, establish_pair_for, RecordingSink, RingSigner, DAEMON, STATE_DIRECTORY,
        };
        use crate::test_support_fakes::{FakeCredentialStore, FakeOsPipe};
        use crate::test_support_transitions::{
            browser_capability, connection, consume_enrollment, create_enrollment, credential,
            grant, input, key, live_channel, paired_proof, receive, registered, request, revoke,
            rotate, transition, ADMINISTRATOR, EXTENSION,
        };
        use crate::transition::{
            BootstrapMaterial, DecisionState, ReplacementCredential, SecurityTransitions,
            TransitionMaterial, TransitionRecord,
        };
        use crate::{ChannelSigner, SecurityCommand};
        use uuid::Uuid;

        /// FR-024: the replacement credential is registered as part of the transition that
        /// advances the epoch, and the epoch is reachable through nothing else.
        #[test]
        fn replacement_registration_precedes_epoch_transition() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let _client = live_channel(&transitions, &principal, &signer, 1);
            let replacement = RingSigner::generate();
            let mut sink = RecordingSink::default();

            // A fingerprint that does not name the replacement key is refused, and the
            // epoch, the key, the locator, and the live channel are all left alone.
            let mismatched = SecurityCommand::Rotate {
                principal: principal.id(),
                new_fingerprint: Fingerprint::new("b".repeat(64)).expect("64 hex digits"),
                idempotency: key(10),
            };
            let rejection = transitions
                .apply(
                    &mismatched,
                    &input(
                        TransitionOperation::Rotation,
                        10,
                        0,
                        TransitionOutcome::Committed,
                    ),
                    TransitionMaterial::Replacement(ReplacementCredential::new(
                        replacement.public_key().clone(),
                        credential("key-1"),
                    )),
                    Some(&mut sink),
                    EventTime(7),
                )
                .expect_err("the fingerprint has to name the replacement key");
            assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
            assert_eq!(rejection.code(), FailureCode::CredentialStoreMismatch);
            assert!(
                sink.events.is_empty(),
                "a rotation refused by validation emits no transition event"
            );
            let unchanged = transitions
                .registered_principal(principal.id())
                .expect("registered snapshot");
            assert_eq!(unchanged.epoch(), 0);
            assert_eq!(unchanged.public_key(), signer.public_key());
            assert_eq!(unchanged.credential().key_locator(), "principal-key-0");
            assert!(transitions.channel_is_open(connection(1)));

            // A locator outside the owning daemon cannot be installed either.
            let foreign = CredentialReference::new(
                "fixture-store",
                "key-foreign",
                id(0x99),
                id(STATE_DIRECTORY),
            )
            .expect("bounded credential reference");
            let command = SecurityCommand::Rotate {
                principal: principal.id(),
                new_fingerprint: Fingerprint::from_public_key(replacement.public_key()),
                idempotency: key(11),
            };
            assert_eq!(
                transitions
                    .apply(
                        &command,
                        &input(
                            TransitionOperation::Rotation,
                            11,
                            0,
                            TransitionOutcome::Committed
                        ),
                        TransitionMaterial::Replacement(ReplacementCredential::new(
                            replacement.public_key().clone(),
                            foreign,
                        )),
                        Some(&mut sink),
                        EventTime(7),
                    )
                    .expect_err("a foreign locator is not a replacement")
                    .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert_eq!(
                transitions
                    .registered_principal(principal.id())
                    .expect("registered snapshot")
                    .epoch(),
                0
            );

            // The committed rotation installs one whole credential and advances the epoch
            // exactly once.
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    12,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let rotated = transitions
                .registered_principal(principal.id())
                .expect("registered snapshot");
            assert_eq!(rotated.epoch(), 1);
            assert_eq!(rotated.lifecycle(), PrincipalLifecycle::Active);
            assert_eq!(rotated.public_key(), replacement.public_key());
            assert_ne!(rotated.public_key(), signer.public_key());
            assert_eq!(
                rotated.fingerprint(),
                &Fingerprint::from_public_key(replacement.public_key())
            );
            assert_eq!(rotated.credential().key_locator(), "key-1");

            // The auditable carrier names the boundary the transition crossed.
            match transitions.recorded(key(12)).expect("recorded rotation") {
                TransitionRecord::Rotated(carrier) => {
                    assert_eq!(carrier.principal(), principal.id());
                    assert_eq!(carrier.old_epoch(), 0);
                    assert_eq!(carrier.new_epoch(), 1);
                    assert_eq!(carrier.effective_boundary(), 1);
                    assert_eq!(carrier.outcome(), TransitionOutcome::Committed);
                }
                other => panic!("a rotation records a rotation carrier, not {other:?}"),
            }

            // Exactly one required rotation event, and the old channel is closed.
            assert_eq!(sink.events.len(), 1);
            assert_eq!(sink.events[0].boundary(), EventBoundary::Rotation);
            assert_eq!(sink.events[0].code(), SecurityCode::Rotation);
            assert!(!transitions.channel_is_open(connection(1)));

            // The replacement signer reconnects at the new epoch: the boundary refuses the
            // retired credential, not the principal.
            let reconnected = live_channel(&transitions, &rotated, &replacement, 2);
            assert!(transitions.channel_is_open(connection(2)));
            drop(reconnected);

            // A handshake that completed against the retired snapshot never becomes a live
            // channel: the registry, not the snapshot the peers held, decides.
            let (_, stale_daemon) = establish_pair_for(&principal, &signer, connection(3))
                .expect("two peers can still agree on a retired snapshot between themselves");
            assert_eq!(
                transitions
                    .register_channel(stale_daemon)
                    .expect_err("a channel from the retired epoch is refused")
                    .code(),
                FailureCode::StaleEpoch
            );
            assert!(!transitions.channel_is_open(connection(3)));
        }

        /// FR-026, FR-032: a frame sealed before the commit dispatches no payload after it,
        /// and an input authorized before the commit mutates nothing.
        #[test]
        fn stale_frames_and_inputs_complete_no_work_after_the_commit() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut client = live_channel(&transitions, &principal, &signer, 1);
            let mut sink = RecordingSink::default();

            let first = request(&mut client, &mut sink);
            let authorized = receive(&transitions, connection(1), &first, &mut sink)
                .expect("an authorized input at the current epoch");
            assert_eq!(
                transitions.commit_mutation(&authorized),
                Ok(1),
                "the live epoch commits one mutation"
            );
            let stale_frame = request(&mut client, &mut sink);

            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    20,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );

            let failure = receive(&transitions, connection(1), &stale_frame, &mut sink)
                .expect_err("a frame from the retired epoch is refused");
            assert_eq!(failure.code(), FailureCode::StaleEpoch);
            assert_eq!(
                transitions
                    .commit_mutation(&authorized)
                    .expect_err("an input from the retired epoch mutates nothing")
                    .code(),
                FailureCode::StaleEpoch
            );
            assert_eq!(
                transitions.object_version(),
                1,
                "only the pre-commit mutation is committed"
            );

            // A plain disconnect is not a transition, and confirmed work survives it.
            let reconnected = transitions
                .registered_principal(principal.id())
                .expect("registered snapshot");
            let mut client = live_channel(&transitions, &reconnected, &replacement, 2);
            let frame = request(&mut client, &mut sink);
            let authorized = receive(&transitions, connection(2), &frame, &mut sink)
                .expect("the new epoch authorizes again");
            assert!(transitions.close_channel(connection(2)));
            assert!(!transitions.close_channel(connection(2)), "closing repeats safely");
            assert_eq!(
                transitions
                    .commit_mutation(&authorized)
                    .expect_err("a closed channel completes no new mutation")
                    .code(),
                FailureCode::AuthenticationFailed
            );
            assert_eq!(transitions.object_version(), 1);
        }

        /// FR-024, FR-025: a rotation invalidates the grants and the pending decisions the
        /// retired epoch approved, and a later grant from that epoch cannot re-enter.
        #[test]
        fn stale_grants_and_decisions_are_invalidated_by_a_rotation() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let extension =
                registered(&transitions, EXTENSION, PrincipalKind::BrowserExtension, &signer);
            let stale = grant(extension.id(), 0);
            transitions
                .register_grant(stale.clone())
                .expect("a grant at the registered epoch");
            let decision = transition(1);
            transitions
                .open_decision(decision, extension.id())
                .expect("a pending extension decision");
            let mut client = live_channel(&transitions, &extension, &signer, 1);
            let mut sink = RecordingSink::default();

            // The grant authorizes an extension operation while the epoch stands.
            let frame = request(&mut client, &mut sink);
            receive(&transitions, connection(1), &frame, &mut sink)
                .expect("the registered grant authorizes the operation");

            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    extension.id(),
                    &replacement,
                    "key-1",
                    30,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.grant_lifecycles(extension.id()),
                vec![GrantLifecycle::Revoked]
            );
            assert_eq!(
                transitions.decision_state(decision),
                Some(DecisionState::Invalidated)
            );
            assert_eq!(
                transitions
                    .complete_decision(decision, Some(&mut sink), EventTime(8))
                    .expect_err("an invalidated decision completes nothing")
                    .code(),
                FailureCode::StaleEpoch
            );
            // The retired epoch cannot be re-approved.
            assert_eq!(
                transitions
                    .register_grant(stale)
                    .expect_err("a grant from the retired epoch is refused")
                    .code(),
                FailureCode::StaleEpoch
            );

            // A grant and a decision at the current epoch work again.
            let rotated = transitions
                .registered_principal(extension.id())
                .expect("registered snapshot");
            transitions
                .register_grant(grant(extension.id(), 1))
                .expect("a grant at the current epoch");
            let current = transition(2);
            transitions
                .open_decision(current, extension.id())
                .expect("a pending decision at the current epoch");
            assert_eq!(
                transitions.complete_decision(current, Some(&mut sink), EventTime(8)),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.decision_state(current),
                Some(DecisionState::Completed)
            );
            let mut client = live_channel(&transitions, &rotated, &replacement, 2);
            let frame = request(&mut client, &mut sink);
            receive(&transitions, connection(2), &frame, &mut sink)
                .expect("the current grant authorizes again");
        }

        /// FR-025: revocation is terminal and idempotent, and nothing the revoked principal
        /// held authenticates, authorizes, mutates, or completes afterwards.
        #[test]
        fn revocation_is_terminal_and_idempotent() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let extension =
                registered(&transitions, EXTENSION, PrincipalKind::BrowserExtension, &signer);
            transitions
                .register_grant(grant(extension.id(), 0))
                .expect("a grant at the registered epoch");
            let decision = transition(3);
            transitions
                .open_decision(decision, extension.id())
                .expect("a pending extension decision");
            let mut client = live_channel(&transitions, &extension, &signer, 1);
            let mut sink = RecordingSink::default();
            let stale_frame = request(&mut client, &mut sink);

            assert_eq!(
                revoke(
                    &transitions,
                    extension.id(),
                    "administrator",
                    40,
                    0,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            match transitions.recorded(key(40)).expect("recorded revocation") {
                TransitionRecord::Revoked(carrier) => {
                    assert_eq!(carrier.principal(), extension.id());
                    assert_eq!(carrier.epoch(), 0);
                    assert_eq!(carrier.reason_class(), "administrator");
                    assert_eq!(carrier.invalidated_channels(), 1);
                    assert_eq!(carrier.invalidated_grants(), 1);
                }
                other => panic!("a revocation records a revocation carrier, not {other:?}"),
            }
            assert_eq!(sink.events.len(), 1);
            assert_eq!(sink.events[0].boundary(), EventBoundary::Revocation);
            assert_eq!(sink.events[0].code(), SecurityCode::Revocation);

            // The repeat of the same command answers from the record and commits nothing.
            assert_eq!(
                revoke(
                    &transitions,
                    extension.id(),
                    "administrator",
                    40,
                    0,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::AlreadyCommitted)
            );
            assert_eq!(sink.events.len(), 1, "a replay emits no second event");

            // Revocation is terminal: no later transition reopens the principal.
            assert_eq!(
                revoke(
                    &transitions,
                    extension.id(),
                    "administrator",
                    41,
                    0,
                    Some(&mut sink)
                )
                .expect_err("a revoked principal is terminal")
                .code(),
                FailureCode::Revoked
            );
            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    extension.id(),
                    &replacement,
                    "key-1",
                    42,
                    0,
                    None,
                    Some(&mut sink)
                )
                .expect_err("a revoked principal does not rotate")
                .code(),
                FailureCode::Revoked
            );

            let revoked = transitions
                .registered_principal(extension.id())
                .expect("registered snapshot");
            assert_eq!(revoked.lifecycle(), PrincipalLifecycle::Revoked);
            assert_eq!(
                transitions.grant_lifecycles(extension.id()),
                vec![GrantLifecycle::Revoked]
            );
            assert_eq!(
                transitions.decision_state(decision),
                Some(DecisionState::Invalidated)
            );
            assert!(!transitions.channel_is_open(connection(1)));
            assert_eq!(
                receive(&transitions, connection(1), &stale_frame, &mut sink)
                    .expect_err("a revoked principal dispatches no payload")
                    .code(),
                FailureCode::Revoked
            );
            assert_eq!(transitions.object_version(), 0);
            assert_eq!(
                transitions
                    .complete_decision(decision, Some(&mut sink), EventTime(8))
                    .expect_err("a revoked principal completes no decision")
                    .code(),
                FailureCode::StaleEpoch
            );
            // Authentication itself is refused: no replacement channel is registered.
            assert!(
                establish_pair_for(&revoked, &signer, connection(2)).is_err(),
                "a revoked snapshot never reaches a traffic key"
            );
        }

        /// FR-024, FR-025: every transition commit is gated on its required event, so an
        /// unavailable or absent sink leaves the whole state untouched.
        #[test]
        fn transitions_fail_closed_when_the_required_event_is_unavailable() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let _client = live_channel(&transitions, &principal, &signer, 1);
            let replacement = RingSigner::generate();

            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };
            let rejection = rotate(
                &transitions,
                principal.id(),
                &replacement,
                "key-1",
                50,
                0,
                None,
                Some(&mut unavailable),
            )
            .expect_err("an unavailable sink blocks the epoch commit");
            assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
            assert_eq!(rejection.code(), FailureCode::EventSinkUnavailable);

            // No sink at all is the same fail-closed answer.
            let command = SecurityCommand::Rotate {
                principal: principal.id(),
                new_fingerprint: Fingerprint::from_public_key(replacement.public_key()),
                idempotency: key(51),
            };
            assert_eq!(
                transitions
                    .apply(
                        &command,
                        &input(
                            TransitionOperation::Rotation,
                            51,
                            0,
                            TransitionOutcome::Committed
                        ),
                        TransitionMaterial::Replacement(ReplacementCredential::new(
                            replacement.public_key().clone(),
                            credential("key-1"),
                        )),
                        None::<&mut RecordingSink>,
                        EventTime(7),
                    )
                    .expect_err("an absent sink is unavailable")
                    .code(),
                FailureCode::EventSinkUnavailable
            );
            assert_eq!(
                revoke(&transitions, principal.id(), "administrator", 52, 0, None)
                    .expect_err("a revocation is gated the same way")
                    .code(),
                FailureCode::EventSinkUnavailable
            );

            let unchanged = transitions
                .registered_principal(principal.id())
                .expect("registered snapshot");
            assert_eq!(unchanged.epoch(), 0);
            assert_eq!(unchanged.lifecycle(), PrincipalLifecycle::Active);
            assert_eq!(unchanged.public_key(), signer.public_key());
            assert!(transitions.channel_is_open(connection(1)));
            assert!(transitions.recorded(key(50)).is_none());
            assert!(transitions.recorded(key(51)).is_none());
            assert!(transitions.recorded(key(52)).is_none());

            // Once the sink is available the same key commits exactly once.
            let mut sink = RecordingSink::default();
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    50,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(sink.events.len(), 1);
        }

        /// FR-027, FR-028: a transition event carries a bounded redacted reason class only,
        /// and metadata that reads as protected material blocks the commit.
        #[test]
        fn transition_events_are_bounded_and_redacted() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();

            assert_eq!(
                revoke(
                    &transitions,
                    principal.id(),
                    "credential-loss",
                    60,
                    0,
                    Some(&mut sink)
                )
                .expect_err("a reason class that reads as protected material is refused")
                .code(),
                FailureCode::EventSinkUnavailable
            );
            assert!(sink.events.is_empty());
            assert_eq!(
                transitions
                    .registered_principal(principal.id())
                    .expect("registered snapshot")
                    .lifecycle(),
                PrincipalLifecycle::Active
            );

            assert_eq!(
                revoke(
                    &transitions,
                    principal.id(),
                    "administrator",
                    61,
                    0,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let event = &sink.events[0];
            assert!(event.encoded_len() <= 2_048);
            assert_eq!(event.principal_id(), Some(principal.id().get()));
            assert_eq!(event.state_directory_id(), id(STATE_DIRECTORY).get());
            let rendered = format!("{event:?}");
            assert!(rendered.contains("administrator"));
            assert!(!rendered.contains("principal-key-0"));
            for entry in event.metadata() {
                assert!(entry.key().len() <= 32);
                assert!(entry.value().len() <= 128);
            }
            let state = format!("{transitions:?}");
            assert!(!state.contains("principal-key-0"), "{state}");
            assert!(!state.contains("fixture-store"), "{state}");
        }

        /// FR-024, FR-025: an extension principal registered through enrollment consumption
        /// rotates together with its browser custody, and the retired key is quarantined.
        #[test]
        fn enrollment_consumption_registers_a_principal_whose_rotation_quarantines_custody() {
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let mut sink = RecordingSink::default();
            let enrollment = transition(4);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    70,
                    0,
                    ExpiryResult::valid(600_000).expect("deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );
            assert_eq!(sink.events[0].code(), SecurityCode::EnrollmentAccepted);

            let mut channel = EnrollmentChannel::open(connection(9), 1).expect("native channel");
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            let browser = browser_capability();
            let clock = EnrollmentClock::new(0, ExpiryResult::valid(600_000).expect("deadline"));
            let long_term = proof.long_term_public_key.clone();
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    71,
                    0,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Consumed)
            );
            let extension = transitions
                .registered_principal(id(EXTENSION))
                .expect("consumption registers the extension principal");
            assert_eq!(extension.kind(), PrincipalKind::BrowserExtension);
            assert_eq!(extension.epoch(), 0);
            assert_eq!(extension.public_key(), &long_term);
            let retired = Fingerprint::from_public_key(&long_term);
            assert_eq!(transitions.custody_fingerprint(id(EXTENSION)), Some(retired.clone()));
            assert!(!transitions.is_quarantined(&retired));

            // A principal whose long-term key the enrollment host stores cannot rotate
            // without the custody that key lives in.
            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    extension.id(),
                    &replacement,
                    "extension-key-1",
                    72,
                    0,
                    None,
                    Some(&mut sink)
                )
                .expect_err("an extension rotation needs its browser custody")
                .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert!(!transitions.is_quarantined(&retired));

            assert_eq!(
                rotate(
                    &transitions,
                    extension.id(),
                    &replacement,
                    "extension-key-1",
                    73,
                    0,
                    Some(&browser),
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert!(
                transitions.is_quarantined(&retired),
                "the retired extension key is quarantined by the rotation that replaced it"
            );
            assert_eq!(
                transitions.custody_fingerprint(id(EXTENSION)),
                Some(Fingerprint::from_public_key(replacement.public_key()))
            );

            // Revoking the administrator revokes the enrollments it still owns.
            let second = transition(5);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    second,
                    administrator.id(),
                    74,
                    0,
                    ExpiryResult::valid(600_000).expect("deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                revoke(
                    &transitions,
                    administrator.id(),
                    "administrator",
                    75,
                    0,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(second),
                Some(EnrollmentLifecycle::Revoked)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Consumed),
                "a consumed enrollment is already terminal"
            );
        }

        /// The bootstrap command keeps the certified crash-safe behaviour and records its
        /// idempotency key through the same transition boundary.
        #[test]
        fn the_bootstrap_command_applies_through_the_serialized_boundary() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let envelope = crate::adapters::os_pipe::BootstrapEnvelope {
                nonce: [7; 32],
                state_directory: id(STATE_DIRECTORY).get(),
                daemon: id(DAEMON).get(),
                bootstrap: Uuid::from_u128(0x4001),
                public_key: *signer.public_key().as_bytes(),
            };
            let encoded = envelope.encode();
            let store = FakeCredentialStore::new().registered(
                crate::adapters::credential_store::CredentialBinding::for_identities(
                    envelope.state_directory,
                    envelope.daemon,
                ),
                4,
            );
            let pipe = FakeOsPipe::present(9);
            let command = SecurityCommand::Bootstrap {
                state_directory: id(STATE_DIRECTORY),
                idempotency: key(80),
            };
            let mut sink = RecordingSink::default();
            assert_eq!(
                transitions.apply(
                    &command,
                    &input(
                        TransitionOperation::Bootstrap,
                        80,
                        0,
                        TransitionOutcome::Committed
                    ),
                    TransitionMaterial::Bootstrap(BootstrapMaterial::with_store_for_test(
                        &pipe,
                        &encoded,
                        b"native://matinee",
                        &store,
                    )),
                    Some(&mut sink),
                    EventTime(5),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(transitions.recorded(key(80)), Some(TransitionRecord::Bootstrap));
            assert_eq!(sink.events.len(), 2, "the certified bootstrap events are emitted");

            // The same key answers from the record rather than bootstrapping twice.
            let pipe = FakeOsPipe::present(9);
            assert_eq!(
                transitions.apply(
                    &command,
                    &input(
                        TransitionOperation::Bootstrap,
                        80,
                        0,
                        TransitionOutcome::Committed
                    ),
                    TransitionMaterial::Bootstrap(BootstrapMaterial::with_store_for_test(
                        &pipe,
                        &encoded,
                        b"native://matinee",
                        &store,
                    )),
                    Some(&mut sink),
                    EventTime(5),
                ),
                Ok(TransitionOutcome::AlreadyCommitted)
            );
            assert_eq!(sink.events.len(), 2);
        }
    };
}
