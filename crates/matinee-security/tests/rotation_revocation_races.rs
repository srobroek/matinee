macro_rules! rotation_revocation_races_tests {
    () => {
        use crate::enrollment::{EnrollmentChannel, EnrollmentClock};
        use crate::events::EventTime;
        use crate::failures::{FailureCode, SafeNextAction};
        use crate::identity::{
            EnrollmentLifecycle, ExpiryResult, Fingerprint, GrantLifecycle, IdentityId,
            PrincipalKind, PrincipalLifecycle, TransitionOperation, TransitionOutcome,
        };
        use crate::test_support_channel::{establish_pair_for, id, RecordingSink, RingSigner};
        use crate::test_support_transitions::{
            connection, consume_enrollment, create_enrollment, credential, grant, input, key,
            live_channel, paired_proof, receive, registered, request, revoke, rotate, transition,
            ADMINISTRATOR, EXTENSION,
        };
        use crate::transition::{
            DecisionState, ReplacementCredential, SecurityTransitions, TransitionMaterial,
            TransitionRecord,
        };
        use crate::{ChannelSigner, ConnectionId, SecurityCommand};

        /// Every observable fact one transition may touch, as one comparable value. A
        /// fail-closed refusal has to leave this identical.
        fn snapshot(
            transitions: &SecurityTransitions,
            principal: IdentityId,
            decision: Option<crate::identity::TransitionId>,
        ) -> String {
            let registered = transitions.registered_principal(principal);
            format!(
                "epoch={:?} lifecycle={:?} key={:?} locator={:?} channels={} grants={:?} \
                 decision={:?} objects={} debug={:?}",
                registered.as_ref().map(crate::identity::Principal::epoch),
                registered
                    .as_ref()
                    .map(crate::identity::Principal::lifecycle),
                registered
                    .as_ref()
                    .map(|snapshot| snapshot.fingerprint().clone()),
                registered
                    .as_ref()
                    .map(|snapshot| snapshot.credential().key_locator().to_owned()),
                transitions.open_channels(),
                transitions.grant_lifecycles(principal),
                decision.and_then(|decision| transitions.decision_state(decision)),
                transitions.object_version(),
                transitions,
            )
        }

        /// FR-026, FR-032: one rotation racing one late registration of a channel that was
        /// established against the retired snapshot. Whatever the interleaving, the epoch
        /// moves exactly once and no retired-epoch channel is live afterwards.
        #[test]
        fn a_concurrent_handshake_never_outlives_the_rotation_it_raced() {
            for trial in 0..8u128 {
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal =
                    registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
                let replacement = RingSigner::generate();
                // Both peers agreed on the retired snapshot before the transition ran.
                let (_client, stale) = establish_pair_for(&principal, &signer, connection(500))
                    .expect("production handshake fixture");

                let shared = &transitions;
                let (rotation, registration) = std::thread::scope(|scope| {
                    let rotating = scope.spawn(|| {
                        let mut sink = RecordingSink::default();
                        rotate(
                            shared,
                            principal.id(),
                            &replacement,
                            "key-1",
                            200 + trial,
                            0,
                            None,
                            Some(&mut sink),
                        )
                    });
                    let registering = scope.spawn(move || shared.register_channel(stale));
                    (
                        rotating.join().expect("rotation thread"),
                        registering.join().expect("registration thread"),
                    )
                });

                assert_eq!(rotation, Ok(TransitionOutcome::Committed));
                if let Err(rejection) = registration {
                    assert_eq!(
                        rejection.code(),
                        FailureCode::StaleEpoch,
                        "a late registration is refused only as a stale epoch"
                    );
                }
                assert!(
                    !transitions.channel_is_open(connection(500)),
                    "a retired-epoch channel is never live after the commit"
                );
                assert_eq!(transitions.open_channels(), 0);
                assert_eq!(
                    transitions
                        .registered_principal(principal.id())
                        .expect("registered snapshot")
                        .epoch(),
                    1
                );
            }
        }

        /// FR-026, SC-008: repeated delivery of one command from several threads commits
        /// once and records one carrier, with one required event.
        #[test]
        fn repeated_delivery_of_one_command_commits_exactly_once() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let replacement = RingSigner::generate();

            let outcomes = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..4)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut sink = RecordingSink::default();
                            let outcome = rotate(
                                &transitions,
                                principal.id(),
                                &replacement,
                                "key-1",
                                300,
                                0,
                                None,
                                Some(&mut sink),
                            );
                            (outcome, sink.events.len())
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|worker| worker.join().expect("delivery thread"))
                    .collect::<Vec<_>>()
            });

            let committed = outcomes
                .iter()
                .filter(|(outcome, _)| outcome == &Ok(TransitionOutcome::Committed))
                .count();
            let replayed = outcomes
                .iter()
                .filter(|(outcome, _)| outcome == &Ok(TransitionOutcome::AlreadyCommitted))
                .count();
            assert_eq!(committed, 1, "exactly one delivery commits: {outcomes:?}");
            assert_eq!(replayed, 3, "every other delivery replays: {outcomes:?}");
            let events: usize = outcomes.iter().map(|(_, events)| events).sum();
            assert_eq!(events, 1, "one commit emits one required event");
            assert_eq!(
                transitions
                    .registered_principal(principal.id())
                    .expect("registered snapshot")
                    .epoch(),
                1,
                "four deliveries advance one epoch"
            );
            match transitions.recorded(key(300)).expect("one recorded carrier") {
                TransitionRecord::Rotated(carrier) => {
                    assert_eq!(carrier.old_epoch(), 0);
                    assert_eq!(carrier.new_epoch(), 1);
                }
                other => panic!("unexpected record: {other:?}"),
            }
        }

        /// FR-025, FR-026: object mutations racing one revocation. Every commit happened
        /// while the principal was live, and nothing commits after the revocation does.
        #[test]
        fn concurrent_mutations_stop_at_a_committed_revocation() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();
            // Every frame is sealed while the channel is live; the race is on the receive
            // and the mutation that follow.
            let mut frames: Vec<(ConnectionId, Vec<u8>)> = Vec::new();
            for index in 0..8u128 {
                let mut client = live_channel(&transitions, &principal, &signer, 600 + index);
                frames.push((connection(600 + index), request(&mut client, &mut sink)));
            }

            let shared = &transitions;
            let (revocation, committed) = std::thread::scope(|scope| {
                let revoking = scope.spawn(|| {
                    let mut sink = RecordingSink::default();
                    revoke(
                        shared,
                        principal.id(),
                        "administrator",
                        310,
                        0,
                        Some(&mut sink),
                    )
                });
                let workers: Vec<_> = frames
                    .into_iter()
                    .map(|(connection, frame)| {
                        scope.spawn(move || {
                            let mut sink = RecordingSink::default();
                            match receive(shared, connection, &frame, &mut sink) {
                                Ok(authorized) => shared.commit_mutation(&authorized).is_ok(),
                                Err(failure) => {
                                    assert!(
                                        matches!(
                                            failure.code(),
                                            FailureCode::Revoked
                                                | FailureCode::AuthenticationFailed
                                        ),
                                        "a refused frame names a closed class: {failure:?}"
                                    );
                                    false
                                }
                            }
                        })
                    })
                    .collect();
                (
                    revoking.join().expect("revocation thread"),
                    workers
                        .into_iter()
                        .map(|worker| worker.join().expect("mutation thread"))
                        .filter(|committed| *committed)
                        .count(),
                )
            });

            assert_eq!(revocation, Ok(TransitionOutcome::Committed));
            assert_eq!(
                transitions.object_version(),
                committed as u64,
                "the committed object version counts exactly the mutations that succeeded"
            );
            assert!(committed <= 8);
            assert_eq!(
                transitions
                    .registered_principal(principal.id())
                    .expect("registered snapshot")
                    .lifecycle(),
                PrincipalLifecycle::Revoked
            );
            assert_eq!(transitions.open_channels(), 0, "every channel is closed");

            // After the commit no further work of that principal completes.
            let settled = transitions.object_version();
            let mut sink = RecordingSink::default();
            let (mut client, _) = establish_pair_for(&principal, &signer, connection(699))
                .expect("two peers still agree between themselves");
            let frame = request(&mut client, &mut sink);
            assert_eq!(
                receive(&transitions, connection(699), &frame, &mut sink)
                    .expect_err("an unregistered connection dispatches nothing")
                    .code(),
                FailureCode::AuthenticationFailed
            );
            assert_eq!(transitions.object_version(), settled);
        }

        /// FR-026: an owner rotation reordered between enrollment creation and consumption
        /// makes the consumption stale, and the enrollment stays pending.
        #[test]
        fn a_reordered_enrollment_consumption_is_stale_after_an_owner_rotation() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let administrator =
                registered(&transitions, ADMINISTRATOR, PrincipalKind::NativeAdmin, &signer);
            let mut sink = RecordingSink::default();
            let enrollment = transition(40);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    320,
                    0,
                    ExpiryResult::valid(600_000).expect("deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let mut channel = EnrollmentChannel::open(connection(700), 1).expect("native channel");
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            let clock = EnrollmentClock::new(0, ExpiryResult::valid(600_000).expect("deadline"));

            // The owner rotates before the pairing peer answers.
            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    administrator.id(),
                    &replacement,
                    "key-1",
                    321,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                322,
                0,
                Some(&mut sink),
            )
            .expect_err("consumption against the retired epoch is stale");
            assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
            assert_eq!(rejection.code(), FailureCode::StaleEpoch);
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending),
                "a stale consumption consumes nothing"
            );
            assert!(transitions.registered_principal(id(EXTENSION)).is_none());

            // The enrollment stays bound to the epoch that opened it, so naming the
            // current epoch does not revive it either: the credential that authorized it
            // is retired.
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    323,
                    1,
                    Some(&mut sink),
                )
                .expect_err("a retired enrollment is not revived by a newer epoch")
                .code(),
                FailureCode::StaleEpoch
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );
            assert!(transitions.registered_principal(id(EXTENSION)).is_none());

            // An enrollment opened at the current epoch consumes once, and its replay
            // registers no second principal.
            let current = transition(44);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    current,
                    administrator.id(),
                    324,
                    1,
                    ExpiryResult::valid(600_000).expect("deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let mut channel = EnrollmentChannel::open(connection(705), 1).expect("native channel");
            let proof = paired_proof(&transitions, current, &mut channel, id(EXTENSION));
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    current,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    325,
                    1,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let extension = transitions
                .registered_principal(id(EXTENSION))
                .expect("the pairing registers one principal");
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    current,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    325,
                    1,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::AlreadyCommitted)
            );
            assert_eq!(
                transitions
                    .registered_principal(id(EXTENSION))
                    .expect("registered snapshot"),
                extension
            );
        }

        /// FR-026: an uncertain deadline decides nothing, at creation and at consumption.
        #[test]
        fn an_uncertain_expiry_fails_closed_without_a_partial_commit() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let administrator =
                registered(&transitions, ADMINISTRATOR, PrincipalKind::NativeAdmin, &signer);
            let mut sink = RecordingSink::default();
            let uncertain = transition(41);
            let rejection = create_enrollment(
                &transitions,
                uncertain,
                administrator.id(),
                330,
                0,
                ExpiryResult::uncertain(600_000),
                Some(&mut sink),
            )
            .expect_err("an uncertain deadline opens no enrollment");
            assert_eq!(rejection.outcome(), TransitionOutcome::Unknown);
            assert_eq!(rejection.code(), FailureCode::TransitionUnknown);
            assert_eq!(transitions.enrollment_lifecycle(uncertain), None);
            assert!(sink.events.is_empty(), "nothing is asserted about a transition that did not happen");

            let enrollment = transition(42);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    331,
                    0,
                    ExpiryResult::valid(600_000).expect("deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let mut channel = EnrollmentChannel::open(connection(701), 1).expect("native channel");
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            let clock = EnrollmentClock::new(0, ExpiryResult::uncertain(600_000));
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                332,
                0,
                Some(&mut sink),
            )
            .expect_err("an uncertain deadline consumes nothing");
            assert_eq!(rejection.outcome(), TransitionOutcome::Unknown);
            assert_eq!(rejection.code(), FailureCode::TransitionUnknown);
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending)
            );
            assert!(transitions.registered_principal(id(EXTENSION)).is_none());
        }

        /// FR-026: an uncertain durable record and a conflicting idempotency reuse both
        /// fail closed and leave every observable fact identical.
        #[test]
        fn an_unknown_record_or_a_conflicting_key_changes_nothing() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let extension =
                registered(&transitions, EXTENSION, PrincipalKind::BrowserExtension, &signer);
            transitions
                .register_grant(grant(extension.id(), 0))
                .expect("a grant at the registered epoch");
            let decision = transition(43);
            transitions
                .open_decision(decision, extension.id())
                .expect("a pending decision");
            let _client = live_channel(&transitions, &extension, &signer, 702);
            let replacement = RingSigner::generate();
            let mut sink = RecordingSink::default();
            let before = snapshot(&transitions, extension.id(), Some(decision));

            // An uncertain durable record is never a protected success.
            let command = SecurityCommand::Rotate {
                principal: extension.id(),
                new_fingerprint: Fingerprint::from_public_key(replacement.public_key()),
                idempotency: key(340),
            };
            let rejection = transitions
                .apply(
                    &command,
                    &input(
                        TransitionOperation::Rotation,
                        340,
                        0,
                        TransitionOutcome::Unknown,
                    ),
                    TransitionMaterial::Replacement(ReplacementCredential::new(
                        replacement.public_key().clone(),
                        credential("key-1"),
                    )),
                    Some(&mut sink),
                    EventTime(7),
                )
                .expect_err("an uncertain record commits nothing");
            assert_eq!(rejection.outcome(), TransitionOutcome::Unknown);
            assert_eq!(rejection.code(), FailureCode::TransitionUnknown);

            // A rejected record is a decided refusal, and a committed record this process
            // holds no decision for is undecidable.
            assert_eq!(
                transitions
                    .apply(
                        &command,
                        &input(
                            TransitionOperation::Rotation,
                            340,
                            0,
                            TransitionOutcome::Rejected
                        ),
                        TransitionMaterial::Replacement(ReplacementCredential::new(
                            replacement.public_key().clone(),
                            credential("key-1"),
                        )),
                        Some(&mut sink),
                        EventTime(7),
                    )
                    .expect_err("a rejected record commits nothing")
                    .outcome(),
                TransitionOutcome::Rejected
            );
            assert_eq!(
                transitions
                    .apply(
                        &command,
                        &input(
                            TransitionOperation::Rotation,
                            340,
                            0,
                            TransitionOutcome::AlreadyCommitted
                        ),
                        TransitionMaterial::Replacement(ReplacementCredential::new(
                            replacement.public_key().clone(),
                            credential("key-1"),
                        )),
                        Some(&mut sink),
                        EventTime(7),
                    )
                    .expect_err("a record with no local decision is undecidable")
                    .outcome(),
                TransitionOutcome::Unknown
            );

            // A command whose operation disagrees with its record names no one transition.
            assert_eq!(
                transitions
                    .apply(
                        &command,
                        &input(
                            TransitionOperation::Revocation,
                            340,
                            0,
                            TransitionOutcome::Committed
                        ),
                        TransitionMaterial::Replacement(ReplacementCredential::new(
                            replacement.public_key().clone(),
                            credential("key-1"),
                        )),
                        Some(&mut sink),
                        EventTime(7),
                    )
                    .expect_err("a mismatched operation is undecidable")
                    .outcome(),
                TransitionOutcome::Unknown
            );
            assert_eq!(
                before,
                snapshot(&transitions, extension.id(), Some(decision)),
                "every fail-closed refusal left the whole state untouched"
            );
            assert!(sink.events.is_empty());

            // One committed rotation, then the same key under a different command.
            assert_eq!(
                rotate(
                    &transitions,
                    extension.id(),
                    &replacement,
                    "key-1",
                    341,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let after = snapshot(&transitions, extension.id(), Some(decision));
            let conflicting = SecurityCommand::Revoke {
                principal: extension.id(),
                idempotency: key(341),
            };
            let rejection = transitions
                .apply(
                    &conflicting,
                    &input(
                        TransitionOperation::Revocation,
                        341,
                        1,
                        TransitionOutcome::Committed,
                    ),
                    TransitionMaterial::Revocation("administrator"),
                    Some(&mut sink),
                    EventTime(9),
                )
                .expect_err("a conflicting reuse of a recorded key fails closed");
            assert_eq!(rejection.outcome(), TransitionOutcome::Unknown);
            assert_eq!(rejection.code(), FailureCode::TransitionUnknown);
            assert_eq!(
                after,
                snapshot(&transitions, extension.id(), Some(decision)),
                "a conflicting reuse mutates nothing"
            );
        }

        /// FR-027: an event outage during a race blocks the epoch, and the same key
        /// commits exactly once when the sink returns.
        #[test]
        fn an_event_outage_blocks_the_epoch_and_the_retry_commits_once() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            transitions
                .register_grant(grant(principal.id(), 0))
                .expect("a grant at the registered epoch");
            let _client = live_channel(&transitions, &principal, &signer, 703);
            let replacement = RingSigner::generate();

            let outcomes = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..4)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut unavailable = RecordingSink {
                                events: Vec::new(),
                                unavailable: true,
                            };
                            rotate(
                                &transitions,
                                principal.id(),
                                &replacement,
                                "key-1",
                                350,
                                0,
                                None,
                                Some(&mut unavailable),
                            )
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|worker| worker.join().expect("outage thread"))
                    .collect::<Vec<_>>()
            });
            for outcome in &outcomes {
                let rejection = outcome.expect_err("no delivery commits during the outage");
                assert_eq!(rejection.outcome(), TransitionOutcome::Rejected);
                assert_eq!(rejection.code(), FailureCode::EventSinkUnavailable);
            }
            assert_eq!(
                transitions
                    .registered_principal(principal.id())
                    .expect("registered snapshot")
                    .epoch(),
                0
            );
            assert!(transitions.channel_is_open(connection(703)));
            assert_eq!(
                transitions.grant_lifecycles(principal.id()),
                vec![GrantLifecycle::Active]
            );
            assert!(transitions.recorded(key(350)).is_none());

            let mut sink = RecordingSink::default();
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    350,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(sink.events.len(), 1);
            assert!(transitions.recorded(key(350)).is_some());
        }

        /// SC-006: in 100 rotation and revocation trials with a live channel and a pending
        /// extension decision, zero stale-epoch frames complete a mutation or a decision
        /// after the transition commits.
        #[test]
        fn sc006_no_stale_frame_completes_a_mutation_or_a_decision() {
            let mut stale_dispatches = 0usize;
            let mut stale_mutations = 0usize;
            let mut stale_decisions = 0usize;
            for trial in 0..100u128 {
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let extension =
                    registered(&transitions, EXTENSION, PrincipalKind::BrowserExtension, &signer);
                transitions
                    .register_grant(grant(extension.id(), 0))
                    .expect("a grant at the registered epoch");
                let decision = transition(50);
                transitions
                    .open_decision(decision, extension.id())
                    .expect("a pending extension decision");
                let mut client = live_channel(&transitions, &extension, &signer, 800);
                let mut sink = RecordingSink::default();
                let authorized = receive(
                    &transitions,
                    connection(800),
                    &request(&mut client, &mut sink),
                    &mut sink,
                )
                .expect("the live epoch authorizes");
                let stale_frame = request(&mut client, &mut sink);

                let replacement = RingSigner::generate();
                let outcome = if trial % 2 == 0 {
                    rotate(
                        &transitions,
                        extension.id(),
                        &replacement,
                        "key-1",
                        400 + trial,
                        0,
                        None,
                        Some(&mut sink),
                    )
                } else {
                    revoke(
                        &transitions,
                        extension.id(),
                        "administrator",
                        400 + trial,
                        0,
                        Some(&mut sink),
                    )
                };
                assert_eq!(outcome, Ok(TransitionOutcome::Committed));

                if receive(&transitions, connection(800), &stale_frame, &mut sink).is_ok() {
                    stale_dispatches += 1;
                }
                if transitions.commit_mutation(&authorized).is_ok() {
                    stale_mutations += 1;
                }
                if transitions
                    .complete_decision(decision, Some(&mut sink), EventTime(8))
                    .is_ok()
                {
                    stale_decisions += 1;
                }
                assert_eq!(
                    transitions.decision_state(decision),
                    Some(DecisionState::Invalidated)
                );
            }
            assert_eq!(stale_dispatches, 0, "no stale frame dispatched a payload");
            assert_eq!(stale_mutations, 0, "no stale input completed a mutation");
            assert_eq!(stale_decisions, 0, "no invalidated decision completed");
        }

        /// FR-031, SC-008: in 100 disconnects, confirmed work stays independent of
        /// connection lifetime and no disconnect creates a duplicate transition.
        #[test]
        fn sc008_disconnects_preserve_confirmed_work_and_duplicate_no_transition() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();
            for index in 0..100u128 {
                let mut client = live_channel(&transitions, &principal, &signer, 900 + index);
                let frame = request(&mut client, &mut sink);
                let authorized = receive(&transitions, connection(900 + index), &frame, &mut sink)
                    .expect("the live epoch authorizes");
                assert_eq!(
                    transitions.commit_mutation(&authorized),
                    Ok(index as u64 + 1)
                );
                assert!(transitions.close_channel(connection(900 + index)));
                assert!(
                    !transitions.close_channel(connection(900 + index)),
                    "a repeated disconnect is not a second event"
                );
            }
            assert_eq!(
                transitions.object_version(),
                100,
                "every confirmed mutation survives its connection"
            );
            assert_eq!(transitions.open_channels(), 0);
            assert!(
                sink.events.iter().all(|event| event.code()
                    == crate::events::SecurityCode::AuthorizationAccepted),
                "a disconnect emits no transition event"
            );

            // One revocation, then a hundred further disconnect attempts.
            assert_eq!(
                revoke(
                    &transitions,
                    principal.id(),
                    "administrator",
                    500,
                    0,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            let recorded = transitions.recorded(key(500)).expect("one revocation record");
            for index in 0..100u128 {
                assert!(!transitions.close_channel(connection(900 + index)));
            }
            assert_eq!(
                transitions.recorded(key(500)),
                Some(recorded),
                "no disconnect duplicates the revocation transition"
            );
            assert_eq!(transitions.object_version(), 100);
            assert_eq!(
                revoke(
                    &transitions,
                    principal.id(),
                    "administrator",
                    501,
                    0,
                    Some(&mut sink)
                )
                .expect_err("revocation stays terminal across disconnects")
                .code(),
                FailureCode::Revoked
            );
        }

        /// FR-028, FR-032: the failure a real stale race produced reports one stable class
        /// and one safe action, and discloses no key, locator, or payload.
        #[test]
        fn stale_race_failures_are_redacted_in_both_contexts() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut client = live_channel(&transitions, &principal, &signer, 704);
            let mut sink = RecordingSink::default();
            let frame = request(&mut client, &mut sink);
            let replacement = RingSigner::generate();
            assert_eq!(
                rotate(
                    &transitions,
                    principal.id(),
                    &replacement,
                    "key-1",
                    510,
                    0,
                    None,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );

            let failure = receive(&transitions, connection(704), &frame, &mut sink)
                .expect_err("a retired-epoch frame is refused");
            assert_eq!(failure.code(), FailureCode::StaleEpoch);
            assert_eq!(
                failure.safe_next_action(),
                SafeNextAction::ReconnectCurrentEpoch
            );
            assert_eq!(failure.redacted().1, FailureCode::StaleEpoch);
            // The stable class travels in the rendered failure; the debug projection names
            // the same closed values. Neither carries key, locator, or payload material.
            assert!(
                failure.to_string().contains("stale_epoch"),
                "{failure}"
            );
            for rendered in [failure.to_string(), format!("{failure:?}")] {
                assert!(rendered.contains("StaleEpoch") || rendered.contains("stale_epoch"));
                assert!(!rendered.contains("private"), "{rendered}");
                assert!(!rendered.contains("secret"), "{rendered}");
                assert!(!rendered.contains("key-1"), "{rendered}");
                assert!(!rendered.contains("principal-key-0"), "{rendered}");
                assert!(!rendered.contains("fixture-store"), "{rendered}");
            }
        }
    };
}
