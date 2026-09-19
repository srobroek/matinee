macro_rules! rotation_revocation_tests {
    () => {
        use crate::enrollment::{EnrollmentChannel, EnrollmentClock};
        use crate::events::{
            EventBoundary, EventOutcome, EventTime, SafeNextAction as EventNextAction, SecurityCode,
        };
        use crate::failures::{FailureBoundary, FailureCode, SafeNextAction};
        use crate::identity::{
            Capability, CredentialReference, EnrollmentLifecycle, ExpiryResult, Fingerprint,
            GrantLifecycle, Principal, PrincipalKind, PrincipalLifecycle, PublicKey,
            TransitionOperation, TransitionOutcome,
        };
        use crate::test_support_channel::{
            capability, id, establish_pair_for, registered_principal, RecordingSink, RingSigner,
            DAEMON, STATE_DIRECTORY,
        };
        use crate::test_support_fakes::{FakeCredentialStore, FakeOsPipe};
        use crate::test_support_transitions::{
            admit, browser_capability, ceiling, commit_mutation, connection, consume_enrollment,
            create_enrollment, create_enrollment_with_default_expiry, credential, grant, input,
            key, live_channel, paired_proof, receive,
            registered, request, revoke, rotate, transition, ADMINISTRATOR, EXTENSION,
        };
        use crate::transition::{
            BootstrapMaterial, DecisionState, ReplacementCredential, SecurityTransitions,
            TransitionMaterial, TransitionRecord,
        };
        use crate::{CapabilityAction, ChannelSigner, ObjectOwner, PayloadKind, ProjectionClass, SecurityCommand, SessionInput, SessionProjection};
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
                admit(&transitions, stale_daemon)
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
                commit_mutation(&transitions, &authorized),
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
                commit_mutation(&transitions, &authorized)
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
                commit_mutation(&transitions, &authorized)
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
            // The daemon's own key, independent of the administrator key the envelope
            // carries, as FR-002 requires of a bootstrap.
            let daemon_signer = RingSigner::generate();
            let daemon_self = crate::transition::DaemonSelf {
                public_key: daemon_signer.public_key(),
                contract_min: 1,
                contract_max: 1,
            };
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
                        daemon_self,
                        &store,
                    )),
                    Some(&mut sink),
                    EventTime(5),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(transitions.recorded(key(80)), Some(TransitionRecord::Bootstrap));
            assert_eq!(sink.events.len(), 2, "the certified bootstrap events are emitted");
            // FR-002/FR-004: the commit published one daemon identity and one native
            // administrator into the registry the rest of the boundary reads, not just a
            // bootstrap record.
            let daemon = transitions
                .bootstrapped_daemon()
                .expect("one committed daemon identity");
            let admin = transitions
                .bootstrapped_admin()
                .expect("one committed native administrator");
            assert_eq!(daemon.id(), id(DAEMON));
            assert_eq!(daemon.public_key(), daemon_signer.public_key());
            assert_eq!(admin.kind(), crate::identity::PrincipalKind::NativeAdmin);
            assert_eq!(admin.owner(), id(DAEMON));
            assert_ne!(admin.id(), daemon.id());
            assert_eq!(transitions.registered_principal_count(), 1);
            assert_eq!(
                transitions.registered_principal(admin.id()).map(|found| found.id()),
                Some(admin.id()),
                "the administrator is readable through the registry every decision reads"
            );

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
                        daemon_self,
                        &store,
                    )),
                    Some(&mut sink),
                    EventTime(5),
                ),
                Ok(TransitionOutcome::AlreadyCommitted)
            );
            assert_eq!(sink.events.len(), 2);
            // The retry registered no second administrator.
            assert_eq!(transitions.registered_principal_count(), 1);
            assert_eq!(
                transitions.bootstrapped_admin().map(|found| found.id()),
                Some(admin.id())
            );
        }
        #[test]
        fn retired_key_material_and_locator_never_reactivate() {
            let transitions = SecurityTransitions::default();
            let key_one = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &key_one);
            let key_two = RingSigner::generate();
            let mut sink = RecordingSink::default();
            assert_eq!(
                rotate(&transitions, principal.id(), &key_two, "key-2", 90, 0, None, Some(&mut sink)),
                Ok(TransitionOutcome::Committed)
            );

            let reactivation = rotate(
                &transitions,
                principal.id(),
                &key_one,
                "key-3",
                91,
                1,
                None,
                Some(&mut sink),
            ).expect_err("K1 remains retired after K1 to K2");
            assert_eq!(reactivation.code(), FailureCode::CredentialStoreMismatch);

            let key_three = RingSigner::generate();
            let locator_reuse = rotate(
                &transitions,
                principal.id(),
                &key_three,
                "principal-key-0",
                92,
                1,
                None,
                Some(&mut sink),
            ).expect_err("a retired locator remains retired too");
            assert_eq!(locator_reuse.code(), FailureCode::CredentialStoreMismatch);
            assert_eq!(transitions.registered_principal(principal.id()).unwrap().epoch(), 1);
        }

        #[test]
        fn idempotency_replay_covers_full_input_and_public_material() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let replacement = RingSigner::generate();
            let command = SecurityCommand::Rotate {
                principal: principal.id(),
                new_fingerprint: Fingerprint::from_public_key(replacement.public_key()),
                idempotency: key(93),
            };
            let original_input = input(TransitionOperation::Rotation, 93, 0, TransitionOutcome::Committed);
            let mut sink = RecordingSink::default();
            assert_eq!(
                transitions.apply(
                    &command,
                    &original_input,
                    TransitionMaterial::Replacement(
                        ReplacementCredential::new(replacement.public_key().clone(), credential("key-93"))
                    ),
                    Some(&mut sink),
                    EventTime(1),
                ),
                Ok(TransitionOutcome::Committed)
            );

            let changed_material = transitions.apply(
                &command,
                &original_input,
                TransitionMaterial::Replacement(
                    ReplacementCredential::new(replacement.public_key().clone(), credential("changed"))
                ),
                Some(&mut sink),
                EventTime(2),
            ).expect_err("same key cannot replay changed public material");
            assert_eq!(changed_material.outcome(), TransitionOutcome::Unknown);

            let changed_input = crate::identity::TransitionInput::new(
                id(STATE_DIRECTORY),
                transition(999),
                TransitionOperation::Rotation,
                key(93),
                0,
                TransitionOutcome::Committed,
            );
            let input_collision = transitions.apply(
                &command,
                &changed_input,
                TransitionMaterial::Replacement(
                    ReplacementCredential::new(replacement.public_key().clone(), credential("key-93"))
                ),
                Some(&mut sink),
                EventTime(3),
            ).expect_err("same key cannot replay changed transition input");
            assert_eq!(input_collision.outcome(), TransitionOutcome::Unknown);
        }

        #[test]
        fn mutation_commit_requires_exact_write_command_and_object_binding() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut client = live_channel(&transitions, &principal, &signer, 94);
            let mut sink = RecordingSink::default();
            let frame = request(&mut client, &mut sink);
            let authorized = receive(&transitions, connection(94), &frame, &mut sink).unwrap();

            let wrong_capability = SessionInput::new(
                crate::identity::Capability::new(CapabilityAction::Read, "matinee/object").unwrap(),
                PayloadKind::Command,
                ObjectOwner::Owned(id(ADMINISTRATOR)),
                None,
            );
            assert_eq!(
                transitions.commit_mutation(&authorized, &wrong_capability).unwrap_err().code(),
                FailureCode::AuthorizationDenied
            );
            let wrong_kind = SessionInput::new(
                authorized.granted().clone(),
                PayloadKind::Event,
                ObjectOwner::Owned(id(ADMINISTRATOR)),
                None,
            );
            assert_eq!(
                transitions.commit_mutation(&authorized, &wrong_kind).unwrap_err().code(),
                FailureCode::AuthorizationDenied
            );
            let wrong_owner = SessionInput::new(
                authorized.granted().clone(),
                PayloadKind::Command,
                ObjectOwner::Owned(id(99)),
                None,
            );
            assert_eq!(
                transitions.commit_mutation(&authorized, &wrong_owner).unwrap_err().code(),
                FailureCode::AuthorizationDenied
            );
            assert_eq!(commit_mutation(&transitions, &authorized), Ok(1));
        }

        #[test]
        fn coordinator_refuses_server_send_from_a_retired_epoch() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let _client = live_channel(&transitions, &principal, &signer, 98);
            let replacement = RingSigner::generate();
            let mut sink = RecordingSink::default();
            rotate(
                &transitions,
                principal.id(),
                &replacement,
                "key-98",
                98,
                0,
                None,
                Some(&mut sink),
            ).unwrap();
            let projection = SessionProjection::new(
                ProjectionClass::Event,
                crate::identity::Capability::new(CapabilityAction::Write, "matinee/object").unwrap(),
                ObjectOwner::Owned(id(ADMINISTRATOR)),
                None,
                b"secret",
            );
            let failure = transitions
                .send_projection(connection(98), &projection, &mut sink)
                .expect_err("a retired daemon session emits no protected projection");
            assert_eq!(failure.code(), FailureCode::StaleEpoch);
        }

        /// Each refusal admission emits must also fail closed when nobody can record it:
        /// the sink failure is what the caller sees, and the registry is left exactly as
        /// it was. Both wired paths are covered, because a path that only proves the
        /// happy half proves nothing about what happens when the sink is gone.
        #[test]
        fn an_unrecordable_admission_refusal_fails_closed_and_admits_nothing() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let forged = registered_principal(
                EXTENSION,
                PrincipalKind::NativeAdmin,
                signer.public_key().clone(),
                ceiling(),
                0,
            );
            let (_, forged_daemon) = establish_pair_for(&forged, &signer, connection(120))
                .expect("two peers can agree on a snapshot the registry never held");
            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };
            let rejection = transitions
                .register_channel(forged_daemon, &mut unavailable)
                .expect_err("a refusal nobody can record is still a refusal");
            assert_eq!(rejection.code(), FailureCode::EventSinkUnavailable);
            assert!(!transitions.channel_is_open(connection(120)));
            assert_eq!(transitions.open_channels(), 0);

            // The positive control: a sink that accepts admits the registered snapshot.
            let (_, honest) = establish_pair_for(&principal, &signer, connection(121))
                .expect("production handshake fixture");
            let mut accepting = RecordingSink::default();
            assert_eq!(
                transitions.register_channel(honest, &mut accepting),
                Ok(connection(121))
            );
            assert!(transitions.channel_is_open(connection(121)));
            assert!(
                accepting.events.is_empty(),
                "an admitted channel is not one of the facts the contract enumerates"
            );

            // The replay path, second half: the duplicate of a live connection cannot be
            // recorded, so it is the sink failure, and the channel already admitted is
            // neither closed nor replaced.
            let (_, duplicate) = establish_pair_for(&principal, &signer, connection(121))
                .expect("production handshake fixture");
            let rejection = transitions
                .register_channel(duplicate, &mut unavailable)
                .expect_err("a replay nobody can record is still refused");
            assert_eq!(rejection.code(), FailureCode::EventSinkUnavailable);
            assert!(transitions.channel_is_open(connection(121)));
            assert_eq!(
                transitions.open_channels(),
                1,
                "the duplicate registered nothing"
            );
            assert!(
                unavailable.events.is_empty(),
                "an unavailable sink records neither refusal"
            );
        }


        /// FR-007: "enrollment expiry MUST be ten minutes by default". The default is not
        /// observable as a number a caller passed in, so it is proved by what a pairing peer
        /// must present: the extension pairs only when it carries exactly the deadline the
        /// administrator never named, and `EnrollmentClock` refuses any other.
        ///
        /// The enrollment is opened at a realistic wall-clock instant rather than at zero,
        /// because ten minutes is an interval and a deadline is an instant: from a zero
        /// origin the two are the same number, so a default fixed at the bare figure
        /// 600_000 would satisfy a test written that way while giving an enrollment created
        /// at any real instant a deadline in the past. Both boundaries are checked here,
        /// the last millisecond inside the window and the deadline itself.
        #[test]
        fn an_unnamed_enrollment_deadline_defaults_to_ten_minutes() {
            const CREATED_MS: u64 = 1_763_000_000_000;
            const TEN_MINUTES_MS: u64 = 10 * 60 * 1_000;
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let mut sink = RecordingSink::default();
            let enrollment = transition(110);
            assert_eq!(
                create_enrollment_with_default_expiry(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    110,
                    0,
                    CREATED_MS,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );

            // The deadline the peer must present is ten minutes after creation. A peer that
            // presents the interval itself, as a deadline measured from nothing, is refused.
            let mut channel = EnrollmentChannel::open(connection(110), 1).expect("native channel");
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &EnrollmentClock::new(
                        CREATED_MS,
                        ExpiryResult::valid(TEN_MINUTES_MS).expect("bounded deadline")
                    ),
                    &mut channel,
                    111,
                    0,
                    Some(&mut sink),
                )
                .expect_err("ten minutes from nothing is not this enrollment's deadline")
                .code(),
                FailureCode::ReplayDetected
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );

            // The deadline itself has arrived, so it is outside the window: an enrollment
            // ten minutes long is unexpired up to its deadline, never at it.
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &EnrollmentClock::new(
                        CREATED_MS + TEN_MINUTES_MS,
                        ExpiryResult::valid(CREATED_MS + TEN_MINUTES_MS).expect("bounded deadline")
                    ),
                    &mut channel,
                    112,
                    0,
                    Some(&mut sink),
                )
                .expect_err("an arrived deadline consumes nothing")
                .code(),
                FailureCode::ReplayDetected
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );

            // The last millisecond inside the ten minutes pairs, which fixes the window's
            // width exactly: one millisecond wider or narrower and this is refused.
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &EnrollmentClock::new(
                        CREATED_MS + TEN_MINUTES_MS - 1,
                        ExpiryResult::valid(CREATED_MS + TEN_MINUTES_MS).expect("bounded deadline")
                    ),
                    &mut channel,
                    113,
                    0,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Consumed)
            );
        }

        /// FR-007: "an administrator MUST be able to create" one. Only an
        /// administrator: a principal of any other kind opens nothing, and the
        /// administrator's own creation still succeeds beside it.
        #[test]
        fn only_a_native_administrator_opens_an_enrollment() {
            let transitions = SecurityTransitions::default();
            let client_signer = RingSigner::generate();
            let client = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &client_signer);
            let mut sink = RecordingSink::default();
            let refused = transition(112);
            let rejection = create_enrollment_with_default_expiry(
                &transitions,
                refused,
                client.id(),
                112,
                0,
                1_763_000_000_000,
                Some(&mut sink),
            )
            .expect_err("a client principal is not an administrator");
            assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
            assert_eq!(rejection.code(), FailureCode::AuthorizationDenied);
            assert_eq!(
                rejection.code().safe_next_action(),
                SafeNextAction::RequestAdministratorGrant
            );
            assert_eq!(transitions.enrollment_lifecycle(refused), None);
            // SEC-006. This assertion used to read `sink.events.is_empty()`, justified as
            // "a transition that did not happen emits nothing". That describes the code and
            // contradicts the contract: `contracts/failures-events.md` lists "An
            // authorization denial" in the closed set of outcomes this module states, and a
            // denial is a decided outcome, not an absent one. Nothing happening to the
            // registry is exactly why the denial has to be recorded — otherwise refusing a
            // non-administrator leaves no trace at all. What it asserts now is that fact:
            // one enrollment-boundary denial, rejected, fail-closed, naming the refused
            // principal and no protected state.
            let denial = sink.events.last().expect("a denied enrollment states its fact");
            assert_eq!(denial.boundary(), EventBoundary::Enrollment);
            assert_eq!(denial.code(), SecurityCode::AuthorizationDenied);
            assert_eq!(denial.outcome(), EventOutcome::Rejected);
            assert_eq!(denial.next_action(), EventNextAction::FailClosed);
            assert_eq!(denial.principal_id(), Some(client.id().get()));
            assert_eq!(sink.events.len(), 1, "one denial is one fact");

            // The positive control: the administrator still opens one.
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let allowed = transition(113);
            assert_eq!(
                create_enrollment_with_default_expiry(
                    &transitions,
                    allowed,
                    administrator.id(),
                    113,
                    0,
                    1_763_000_000_000,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(allowed),
                Some(EnrollmentLifecycle::Pending)
            );
            assert_eq!(sink.events.last().expect("a committed enrollment emits").code(), SecurityCode::EnrollmentAccepted);
        }

        #[test]
        fn custody_validation_failure_cannot_follow_an_accepted_event() {
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let mut sink = RecordingSink::default();
            let enrollment = transition(95);
            let clock = EnrollmentClock::new(1, ExpiryResult::valid(600_000).unwrap());
            create_enrollment(
                &transitions,
                enrollment,
                administrator.id(),
                95,
                0,
                ExpiryResult::valid(600_000).unwrap(),
                Some(&mut sink),
            ).unwrap();
            let mut channel = EnrollmentChannel::open(connection(95), 1).unwrap();
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                96,
                0,
                Some(&mut sink),
            ).unwrap();
            let before_events = sink.events.len();
            let before_fingerprint = transitions.custody_fingerprint(id(EXTENSION));
            transitions.fail_next_custody_validation();
            let replacement = RingSigner::generate();
            let rejected = rotate(
                &transitions,
                id(EXTENSION),
                &replacement,
                "extension-key-2",
                97,
                0,
                Some(&browser_capability()),
                Some(&mut sink),
            ).expect_err("injected validation failure occurs before acceptance");
            assert_eq!(rejected.code(), FailureCode::TransitionUnknown);
            assert_eq!(sink.events.len(), before_events);
            assert_eq!(transitions.custody_fingerprint(id(EXTENSION)), before_fingerprint);
            assert_eq!(transitions.registered_principal(id(EXTENSION)).unwrap().epoch(), 0);
        }

        #[test]
        fn custody_revocation_is_staged_before_event_and_retries_atomically() {
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let mut sink = RecordingSink::default();
            let enrollment = transition(96);
            let clock = EnrollmentClock::new(1, ExpiryResult::valid(600_000).unwrap());
            create_enrollment(
                &transitions,
                enrollment,
                administrator.id(),
                96,
                0,
                ExpiryResult::valid(600_000).unwrap(),
                Some(&mut sink),
            ).unwrap();
            let mut channel = EnrollmentChannel::open(connection(96), 1).unwrap();
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                97,
                0,
                Some(&mut sink),
            ).unwrap();
            transitions.register_grant(grant(id(EXTENSION), 0)).unwrap();
            let decision = transition(97);
            transitions.open_decision(decision, id(EXTENSION)).unwrap();

            let snapshot = || format!(
                "principal={:?};custody={:?};custody_revoked={:?};enrollment={:?};channels={};grants={:?};decision={:?};objects={};state={:?}",
                transitions.registered_principal(id(EXTENSION)),
                transitions.custody_fingerprint(id(EXTENSION)),
                transitions.custody_is_revoked(id(EXTENSION)),
                transitions.enrollment_lifecycle(enrollment),
                transitions.open_channels(),
                transitions.grant_lifecycles(id(EXTENSION)),
                transitions.decision_state(decision),
                transitions.object_version(),
                transitions,
            );
            let before = snapshot();
            let before_events = sink.events.len();
            transitions.fail_next_custody_revocation();
            let rejected = revoke(
                &transitions,
                id(EXTENSION),
                "administrator",
                98,
                0,
                Some(&mut sink),
            ).expect_err("custody rejection occurs before acceptance");
            assert_eq!(rejected.code(), FailureCode::TransitionUnknown);
            assert_eq!(sink.events.len(), before_events, "no accepted event escapes");
            assert_eq!(snapshot().as_bytes(), before.as_bytes(), "all state is byte-for-byte unchanged");
            assert!(transitions.recorded(key(98)).is_none());

            let mut unavailable = RecordingSink { events: Vec::new(), unavailable: true };
            assert_eq!(
                revoke(&transitions, id(EXTENSION), "administrator", 99, 0, Some(&mut unavailable))
                    .expect_err("event failure blocks custody and coordinator commit")
                    .code(),
                FailureCode::EventSinkUnavailable
            );
            assert!(unavailable.events.is_empty());
            assert_eq!(snapshot().as_bytes(), before.as_bytes(), "event failure changes no state");

            assert_eq!(
                revoke(&transitions, id(EXTENSION), "administrator", 99, 0, Some(&mut sink)),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(sink.events.len(), before_events + 1);
            assert_eq!(transitions.custody_is_revoked(id(EXTENSION)), Some(true));
            assert_eq!(
                revoke(&transitions, id(EXTENSION), "administrator", 99, 0, Some(&mut sink)),
                Ok(TransitionOutcome::AlreadyCommitted)
            );
            assert_eq!(sink.events.len(), before_events + 1, "retry emits no second event");
        }

        /// The fingerprint the fixture registry holds at epoch 0.
        fn fixture_fingerprint() -> Fingerprint {
            Fingerprint::new("a".repeat(64)).expect("64 lowercase hex digits")
        }

        /// One principal snapshot a caller assembled for itself: active, at epoch 0, under
        /// the fixture identity and owning daemon.
        ///
        /// `ServerHandshakeConfig::new` is public, so this is exactly what a caller can
        /// hand a handshake in place of the registry's own snapshot. Every argument is a
        /// field the registry decides, so every argument is a forgery surface.
        fn self_built(
            kind: PrincipalKind,
            key: &PublicKey,
            fingerprint: Fingerprint,
            ceiling: Vec<Capability>,
            reference: CredentialReference,
        ) -> Principal {
            let mut snapshot = Principal::new(
                id(EXTENSION),
                kind,
                key.clone(),
                fingerprint,
                id(DAEMON),
                ceiling,
                reference,
            )
            .expect("valid principal binding");
            snapshot.activate().expect("pending principal");
            snapshot
        }

        /// The registered snapshot of the fixture principal, rebuilt field for field.
        fn faithful(key: &PublicKey) -> Principal {
            self_built(
                PrincipalKind::McpClient,
                key,
                fixture_fingerprint(),
                ceiling(),
                credential("principal-key-0"),
            )
        }

        /// FR-025: a channel is admitted bound to the registered snapshot, so a self-built
        /// one is refused before it is ever inserted.
        #[test]
        fn a_forged_principal_snapshot_is_rejected_before_channel_insertion() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);

            // The control: a snapshot rebuilt faithfully is the registered one, so it is
            // admitted. Every forgery below diverges from exactly this in one field.
            let honest_snapshot = faithful(signer.public_key());
            assert_eq!(
                honest_snapshot, principal,
                "the fixture rebuilds the registered snapshot field for field"
            );
            let (_, honest) = establish_pair_for(&honest_snapshot, &signer, connection(1))
                .expect("production handshake fixture");
            assert_eq!(admit(&transitions, honest), Ok(connection(1)));
            assert!(transitions.channel_is_open(connection(1)));

            // A forged kind is indistinguishable to the handshake: the same identity, the
            // same live epoch, the same bound key, a valid transcript signature.
            let forged = self_built(
                PrincipalKind::BrowserExtension,
                signer.public_key(),
                fixture_fingerprint(),
                ceiling(),
                credential("principal-key-0"),
            );
            let (_, daemon) = establish_pair_for(&forged, &signer, connection(2))
                .expect("two peers can agree on a snapshot the registry never held");
            let rejection = admit(&transitions, daemon)
                .expect_err("a self-built snapshot is not the registered snapshot");
            assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
            assert_eq!(rejection.code(), FailureCode::CredentialStoreMismatch);
            assert_eq!(
                rejection.failure().boundary(),
                FailureBoundary::CredentialStore
            );
            assert_eq!(
                rejection.failure().safe_next_action(),
                SafeNextAction::StopAndAdministratorRepair
            );
            assert!(!transitions.channel_is_open(connection(2)));

            // The refusal precedes insertion: the connection slot is still free, so an
            // honest session takes it instead of colliding with a recorded replay.
            let (_, retry) = establish_pair_for(&principal, &signer, connection(2))
                .expect("production handshake fixture");
            assert_eq!(admit(&transitions, retry), Ok(connection(2)));
            assert_eq!(transitions.open_channels(), 2);
        }

        /// FR-021: the ceiling and the fingerprint every later decision reads are the
        /// registry's, so a session cannot arrive carrying its own.
        #[test]
        fn forged_metadata_is_rejected_at_daemon_admission() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            assert_eq!(principal.ceiling(), ceiling().as_slice());
            assert_eq!(principal.fingerprint(), &fixture_fingerprint());

            // A ceiling the registry never granted, widened to principal management.
            let widened = self_built(
                PrincipalKind::McpClient,
                signer.public_key(),
                fixture_fingerprint(),
                vec![
                    capability(CapabilityAction::Write, "matinee"),
                    capability(CapabilityAction::ManagePrincipals, "matinee"),
                ],
                credential("principal-key-0"),
            );
            let (_, wide) = establish_pair_for(&widened, &signer, connection(1))
                .expect("two peers can agree on a widened ceiling between themselves");
            assert_eq!(
                admit(&transitions, wide)
                    .expect_err("a widened ceiling is not the registered ceiling")
                    .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert!(!transitions.channel_is_open(connection(1)));

            // A fingerprint that names the bound key is still not the one the registry
            // recorded, so it does not become a live channel either.
            let renamed = self_built(
                PrincipalKind::McpClient,
                signer.public_key(),
                Fingerprint::from_public_key(signer.public_key()),
                ceiling(),
                credential("principal-key-0"),
            );
            assert_ne!(renamed.fingerprint(), principal.fingerprint());
            let (_, named) = establish_pair_for(&renamed, &signer, connection(2))
                .expect("two peers can agree on a recomputed fingerprint between themselves");
            assert_eq!(
                admit(&transitions, named)
                    .expect_err("a recomputed fingerprint is not the registered fingerprint")
                    .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert_eq!(transitions.open_channels(), 0);
        }

        /// FR-025: the boundary reads the store, the locator, and the owning state
        /// directory off the registered credential reference, so each of its fields has to
        /// match and none may be compared loosely.
        #[test]
        fn a_forged_credential_reference_is_rejected_at_daemon_admission() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);

            let forgeries = [
                (
                    "a foreign provider",
                    CredentialReference::new(
                        "forged-store",
                        "principal-key-0",
                        id(DAEMON),
                        id(STATE_DIRECTORY),
                    ),
                ),
                (
                    "a foreign locator",
                    CredentialReference::new(
                        "fixture-store",
                        "forged-key",
                        id(DAEMON),
                        id(STATE_DIRECTORY),
                    ),
                ),
                (
                    "a foreign state directory",
                    CredentialReference::new(
                        "fixture-store",
                        "principal-key-0",
                        id(DAEMON),
                        id(STATE_DIRECTORY + 1),
                    ),
                ),
            ];
            for (index, (what, reference)) in forgeries.into_iter().enumerate() {
                let forged = self_built(
                    PrincipalKind::McpClient,
                    signer.public_key(),
                    fixture_fingerprint(),
                    ceiling(),
                    reference.expect("bounded credential reference"),
                );
                let slot = connection(10 + index as u128);
                let (_, daemon) = establish_pair_for(&forged, &signer, slot)
                    .expect("two peers can agree on a forged locator between themselves");
                assert_eq!(
                    admit(&transitions, daemon).expect_err(what).code(),
                    FailureCode::CredentialStoreMismatch,
                    "{what} is not the registered credential reference"
                );
                assert!(!transitions.channel_is_open(slot));
            }
            assert_eq!(transitions.open_channels(), 0);
        }

        /// FR-024, FR-025: an epoch the registry never reached is the stale epoch it is,
        /// and a retired credential presented at the live epoch -- the epoch check's blind
        /// spot -- is refused by the snapshot binding.
        #[test]
        fn a_forged_epoch_is_rejected_at_daemon_admission() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();

            // The retired key held at epoch 1. Before the rotation the registry is at
            // epoch 0, so this is simply ahead of it.
            let at_epoch_one = registered_principal(
                EXTENSION,
                PrincipalKind::McpClient,
                signer.public_key().clone(),
                ceiling(),
                1,
            );
            let (_, early) = establish_pair_for(&at_epoch_one, &signer, connection(1))
                .expect("two peers can agree on an epoch the registry never reached");
            assert_eq!(
                admit(&transitions, early)
                    .expect_err("an epoch the registry does not hold is refused")
                    .code(),
                FailureCode::StaleEpoch
            );

            // The committed rotation moves the registry to epoch 1 under the replacement
            // key. The same snapshot now names the live epoch while still carrying the
            // retired key, so lifecycle and epoch both pass and only the binding refuses.
            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    40,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let rotated = transitions
                .registered_principal(principal.id())
                .expect("registered snapshot");
            assert_eq!(rotated.epoch(), at_epoch_one.epoch());
            assert_eq!(rotated.lifecycle(), PrincipalLifecycle::Active);
            assert_ne!(rotated.public_key(), at_epoch_one.public_key());
            let (_, retired) = establish_pair_for(&at_epoch_one, &signer, connection(2))
                .expect("two peers can still agree on the retired key between themselves");
            assert_eq!(
                admit(&transitions, retired)
                    .expect_err("the retired key is not the registered credential at epoch 1")
                    .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert!(!transitions.channel_is_open(connection(2)));

            // The replacement signer still reconnects: the binding refuses the retired
            // credential, not the principal.
            let _live = live_channel(&transitions, &rotated, &replacement, 3);
            assert!(transitions.channel_is_open(connection(3)));
        }
    };
}
