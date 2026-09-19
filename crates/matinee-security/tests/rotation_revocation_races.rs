#[allow(unused_macros)]
macro_rules! rotation_revocation_races_tests {
    () => {
        use crate::enrollment::{EnrollmentChannel, EnrollmentClock};
        use crate::events::EventTime;
        use crate::failures::{FailureCode, SafeNextAction};
        use crate::identity::{
            EnrollmentLifecycle, ExpiryResult, Fingerprint, GrantLifecycle, IdentityId,
            PrincipalKind, PrincipalLifecycle, TransitionOperation, TransitionOutcome,
        };
        use crate::test_support_channel::{RecordingSink, RingSigner, establish_pair_for, id};
        use crate::test_support_transitions::{
            ADMINISTRATOR, EXTENSION, admit, commit_mutation, connection, consume_enrollment,
            create_enrollment, credential, grant, input, key, live_channel, paired_proof, receive,
            registered, request, revoke, rotate, transition,
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
        struct StartGate {
            barrier: std::sync::Barrier,
            entrants: std::sync::atomic::AtomicUsize,
            expected: usize,
        }

        impl StartGate {
            fn new(expected: usize) -> Self {
                Self {
                    barrier: std::sync::Barrier::new(expected + 1),
                    entrants: std::sync::atomic::AtomicUsize::new(0),
                    expected,
                }
            }

            fn enter(&self) {
                self.entrants
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.barrier.wait();
            }

            fn release(&self) {
                while self.entrants.load(std::sync::atomic::Ordering::SeqCst) < self.expected {
                    std::thread::yield_now();
                }
                assert_eq!(
                    self.entrants.load(std::sync::atomic::Ordering::SeqCst),
                    self.expected,
                    "every contender reached the latch together"
                );
                self.barrier.wait();
            }
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
                let apply_gate = transitions.gate_next_apply();
                let attempted = std::sync::atomic::AtomicBool::new(false);
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
                    apply_gate.wait_until_acquired();
                    let attempted_ref = &attempted;
                    let registering = scope.spawn(move || {
                        attempted_ref.store(true, std::sync::atomic::Ordering::SeqCst);
                        admit(&shared, stale)
                    });
                    while !attempted.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                    apply_gate.release();
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

            let gate = StartGate::new(4);
            let apply_gate = transitions.gate_next_apply();
            let outcomes = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..4)
                    .map(|_| {
                        scope.spawn(|| {
                            gate.enter();
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
                gate.release();
                apply_gate.wait_until_acquired();
                apply_gate.release();
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
            match transitions
                .recorded(key(300))
                .expect("one recorded carrier")
            {
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
            let apply_gate = transitions.gate_next_apply();
            let gate = StartGate::new(frames.len());
            let attempting = std::sync::atomic::AtomicUsize::new(0);
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
                apply_gate.wait_until_acquired();
                let worker_gate = &gate;
                let worker_attempting = &attempting;
                let workers: Vec<_> = frames
                    .into_iter()
                    .map(|(connection, frame)| {
                        scope.spawn(move || {
                            worker_gate.enter();
                            worker_attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut sink = RecordingSink::default();
                            match receive(shared, connection, &frame, &mut sink) {
                                Ok(authorized) => commit_mutation(shared, &authorized).is_ok(),
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
                gate.release();
                while attempting.load(std::sync::atomic::Ordering::SeqCst) < 8 {
                    std::thread::yield_now();
                }
                apply_gate.release();
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
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &signer,
            );
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
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &signer,
            );
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
            assert!(
                sink.events.is_empty(),
                "nothing is asserted about a transition that did not happen"
            );

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
            let extension = registered(
                &transitions,
                EXTENSION,
                PrincipalKind::BrowserExtension,
                &signer,
            );
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
                let extension = registered(
                    &transitions,
                    EXTENSION,
                    PrincipalKind::BrowserExtension,
                    &signer,
                );
                transitions
                    .register_grant(grant(extension.id(), 0))
                    .unwrap();
                let decision = transition(50);
                transitions.open_decision(decision, extension.id()).unwrap();
                let mut client = live_channel(&transitions, &extension, &signer, 800);
                let mut setup_sink = RecordingSink::default();
                let authorized = receive(
                    &transitions,
                    connection(800),
                    &request(&mut client, &mut setup_sink),
                    &mut setup_sink,
                )
                .unwrap();
                let stale_frame = request(&mut client, &mut setup_sink);
                let replacement = RingSigner::generate();
                let apply_gate = transitions.gate_next_apply();
                let start = StartGate::new(3);
                let attempting = std::sync::atomic::AtomicUsize::new(0);
                let shared = &transitions;

                let (transition_outcome, dispatch, mutation, completion) =
                    std::thread::scope(|scope| {
                        let transitioning = scope.spawn(|| {
                            let mut sink = RecordingSink::default();
                            if trial % 2 == 0 {
                                rotate(
                                    shared,
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
                                    shared,
                                    extension.id(),
                                    "administrator",
                                    400 + trial,
                                    0,
                                    Some(&mut sink),
                                )
                            }
                        });
                        apply_gate.wait_until_acquired();
                        let start_ref = &start;
                        let attempting_ref = &attempting;
                        let dispatching = scope.spawn(move || {
                            start_ref.enter();
                            attempting_ref.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut sink = RecordingSink::default();
                            receive(shared, connection(800), &stale_frame, &mut sink)
                        });
                        let mutating = scope.spawn(|| {
                            start.enter();
                            attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            commit_mutation(shared, &authorized)
                        });
                        let completing = scope.spawn(|| {
                            start.enter();
                            attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut sink = RecordingSink::default();
                            shared.complete_decision(decision, Some(&mut sink), EventTime(8))
                        });
                        start.release();
                        while attempting.load(std::sync::atomic::Ordering::SeqCst) < 3 {
                            std::thread::yield_now();
                        }
                        apply_gate.release();
                        (
                            transitioning.join().unwrap(),
                            dispatching.join().unwrap(),
                            mutating.join().unwrap(),
                            completing.join().unwrap(),
                        )
                    });

                assert_eq!(transition_outcome, Ok(TransitionOutcome::Committed));
                stale_dispatches += usize::from(dispatch.is_ok());
                stale_mutations += usize::from(mutation.is_ok());
                stale_decisions += usize::from(completion.is_ok());
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
            let mut transition_events = 0usize;
            let mut replayed = 0usize;
            for trial in 0..100u128 {
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal =
                    registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
                let connection_id = connection(900 + trial);
                let mut client = live_channel(&transitions, &principal, &signer, 900 + trial);
                let mut setup_sink = RecordingSink::default();
                let frame = request(&mut client, &mut setup_sink);
                let authorized = receive(&transitions, connection_id, &frame, &mut setup_sink)
                    .expect("the live epoch authorizes");
                let apply_gate = transitions.gate_next_apply();
                let start = StartGate::new(3);
                let attempting = std::sync::atomic::AtomicUsize::new(0);

                let (revocation, events, mutation, disconnected, retry) =
                    std::thread::scope(|scope| {
                        let revoking = scope.spawn(|| {
                            let mut sink = RecordingSink::default();
                            let outcome = revoke(
                                &transitions,
                                principal.id(),
                                "administrator",
                                500 + trial,
                                0,
                                Some(&mut sink),
                            );
                            (outcome, sink.events.len())
                        });
                        apply_gate.wait_until_acquired();
                        let mutating = scope.spawn(|| {
                            start.enter();
                            attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            commit_mutation(&transitions, &authorized)
                        });
                        let disconnecting = scope.spawn(|| {
                            start.enter();
                            attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            transitions.close_channel(connection_id)
                        });
                        let retrying = scope.spawn(|| {
                            start.enter();
                            attempting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let mut sink = RecordingSink::default();
                            revoke(
                                &transitions,
                                principal.id(),
                                "administrator",
                                500 + trial,
                                0,
                                Some(&mut sink),
                            )
                        });
                        start.release();
                        while attempting.load(std::sync::atomic::Ordering::SeqCst) < 3 {
                            std::thread::yield_now();
                        }
                        apply_gate.release();
                        let (revocation, events) = revoking.join().unwrap();
                        (
                            revocation,
                            events,
                            mutating.join().unwrap(),
                            disconnecting.join().unwrap(),
                            retrying.join().unwrap(),
                        )
                    });

                assert_eq!(revocation, Ok(TransitionOutcome::Committed));
                transition_events += events;
                assert!(
                    mutation.is_err(),
                    "revocation linearized before the mutation"
                );
                assert!(!disconnected, "revocation already closed the channel");
                replayed += usize::from(retry == Ok(TransitionOutcome::AlreadyCommitted));
                assert_eq!(transitions.object_version(), 0);
                assert_eq!(transitions.open_channels(), 0);
                assert!(transitions.recorded(key(500 + trial)).is_some());
            }
            assert_eq!(transition_events, 100, "one event per revocation");
            assert_eq!(replayed, 100, "every overlapping retry replays one commit");
        }

        /// Recorded so the campaign repeats exactly: the seed drives the per-trial
        /// fixture id space and the order the two confirmed transitions commit in.
        const SC008_SEED: u64 = 0x5c00_0800_d15c_0111;
        const SC008_DISCONNECTS: u128 = 100;

        /// One SplitMix64 step. The campaign needs a reproducible draw and nothing
        /// cryptographic, so it carries its own generator rather than a dependency.
        fn sc008_draw(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        /// FR-031, SC-008: 100 disconnects, each one taken after real confirmed
        /// daemon-owned work exists, and none of which disturbs it.
        ///
        /// The campaign above races a revocation against the disconnect, so its
        /// mutation is always refused and its object version never leaves zero: it
        /// proves the revocation half of SC-008 and never reaches the confirmed-work
        /// half. This one commits the work first -- one object mutation and one
        /// accepted authorization decision per trial, in a seeded order -- then
        /// disconnects and proves the work is still exactly there, that the
        /// disconnect created no second authorization or revocation transition, and
        /// that a reconnect observes one consistent state it can build on.
        #[test]
        fn sc008_confirmed_work_survives_a_hundred_disconnects_and_duplicates_no_transition() {
            let started = std::time::Instant::now();
            let mut seed = SC008_SEED;
            let mut confirmed_mutations = 0usize;
            let mut confirmed_decisions = 0usize;
            let mut disconnects = 0usize;
            let mut duplicate_closes_refused = 0usize;
            let mut duplicate_decisions_refused = 0usize;
            let mut dead_channel_mutations_refused = 0usize;
            let mut reconnects_on_confirmed_work = 0usize;
            let mut first_revocations = 0usize;
            let mut events_emitted_by_a_disconnect = 0usize;
            let mut mutation_first_trials = 0usize;

            for trial in 0..SC008_DISCONNECTS {
                let mutate_first = sc008_draw(&mut seed) & 1 == 0;
                mutation_first_trials += usize::from(mutate_first);
                let first = 0x8_0000 + trial;
                let second = 0x9_0000 + trial;
                let decision = transition(0xd_0000 + trial);

                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let extension = registered(
                    &transitions,
                    EXTENSION,
                    PrincipalKind::BrowserExtension,
                    &signer,
                );
                transitions
                    .register_grant(grant(extension.id(), 0))
                    .expect("a grant at the registered epoch");
                transitions
                    .open_decision(decision, extension.id())
                    .expect("a pending decision");
                let grants_before = transitions.grant_lifecycles(extension.id());

                let mut client = live_channel(&transitions, &extension, &signer, first);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                let authorized = receive(&transitions, connection(first), &frame, &mut sink)
                    .expect("the live epoch authorizes the frame");

                // Confirmed daemon-owned work: one committed object mutation and one
                // accepted authorization decision, in the order the seed drew.
                if mutate_first {
                    assert_eq!(commit_mutation(&transitions, &authorized), Ok(1));
                    confirmed_mutations += 1;
                    assert_eq!(
                        transitions.complete_decision(decision, Some(&mut sink), EventTime(9)),
                        Ok(TransitionOutcome::Committed)
                    );
                    confirmed_decisions += 1;
                } else {
                    assert_eq!(
                        transitions.complete_decision(decision, Some(&mut sink), EventTime(9)),
                        Ok(TransitionOutcome::Committed)
                    );
                    confirmed_decisions += 1;
                    assert_eq!(commit_mutation(&transitions, &authorized), Ok(1));
                    confirmed_mutations += 1;
                }
                assert_eq!(transitions.object_version(), 1, "the work is confirmed");
                assert_eq!(
                    transitions.decision_state(decision),
                    Some(DecisionState::Completed)
                );
                assert_eq!(transitions.open_channels(), 1);
                let events_before = sink.events.len();

                // The disconnect.
                assert!(
                    transitions.close_channel(connection(first)),
                    "the live channel closed"
                );
                disconnects += 1;
                events_emitted_by_a_disconnect += sink.events.len() - events_before;

                // The confirmed work is still exactly there, and the disconnect moved no
                // principal, epoch, grant, or decision.
                assert_eq!(
                    transitions.object_version(),
                    1,
                    "the confirmed mutation outlived the connection"
                );
                assert_eq!(
                    transitions.decision_state(decision),
                    Some(DecisionState::Completed),
                    "the accepted decision outlived the connection"
                );
                let after = transitions
                    .registered_principal(extension.id())
                    .expect("the principal outlived the connection");
                assert_eq!(
                    after.lifecycle(),
                    PrincipalLifecycle::Active,
                    "a disconnect revokes nothing"
                );
                assert_eq!(after.epoch(), 0, "a disconnect rotates nothing");
                assert_eq!(
                    transitions.grant_lifecycles(extension.id()),
                    grants_before,
                    "a disconnect invalidates no grant"
                );
                assert_eq!(transitions.open_channels(), 0);

                // A second disconnect is not a second anything.
                assert!(
                    !transitions.close_channel(connection(first)),
                    "a closed channel closes once"
                );
                duplicate_closes_refused += 1;

                // The disconnect did not reopen the authorization transition: completing
                // the decision again is a replay and emits no second accepted fact.
                let before_retry = sink.events.len();
                let replayed = transitions
                    .complete_decision(decision, Some(&mut sink), EventTime(9))
                    .expect_err("a completed decision never completes twice");
                assert_eq!(replayed.code(), FailureCode::ReplayDetected);
                assert_eq!(
                    sink.events.len(),
                    before_retry,
                    "the refused replay emitted no duplicate authorization fact"
                );
                duplicate_decisions_refused += 1;

                // The dead channel authorizes no new mutation, and that refusal commits
                // nothing: confirmed work is preserved separately from connection life,
                // in both directions.
                let refused = commit_mutation(&transitions, &authorized)
                    .expect_err("a disconnected channel authorizes no new mutation");
                assert_eq!(refused.code(), FailureCode::AuthenticationFailed);
                assert_eq!(
                    transitions.object_version(),
                    1,
                    "the refusal committed nothing"
                );
                dead_channel_mutations_refused += 1;

                // The reconnect observes exactly one consistent state and builds on it.
                let mut reconnected = live_channel(&transitions, &extension, &signer, second);
                assert_eq!(
                    transitions.open_channels(),
                    1,
                    "exactly one live channel after the reconnect"
                );
                assert_eq!(
                    transitions.object_version(),
                    1,
                    "the reconnect observes the confirmed work once: not zero, not twice"
                );
                assert_eq!(
                    transitions.decision_state(decision),
                    Some(DecisionState::Completed)
                );
                assert_eq!(
                    transitions
                        .registered_principal(extension.id())
                        .map(|found| (found.lifecycle(), found.epoch())),
                    Some((PrincipalLifecycle::Active, 0))
                );
                let reconnect_frame = request(&mut reconnected, &mut sink);
                let reauthorized = receive(
                    &transitions,
                    connection(second),
                    &reconnect_frame,
                    &mut sink,
                )
                .expect("the reconnected channel authorizes");
                assert_eq!(
                    commit_mutation(&transitions, &reauthorized),
                    Ok(2),
                    "the reconnect extends the confirmed version rather than restarting \
                     or doubling it"
                );
                reconnects_on_confirmed_work += 1;

                // Had the disconnect created a revocation transition of its own, this
                // explicit one would replay an existing commit instead of being the first.
                let mut revocation_sink = RecordingSink::default();
                assert_eq!(
                    revoke(
                        &transitions,
                        extension.id(),
                        "administrator",
                        0xe_0000 + trial,
                        0,
                        Some(&mut revocation_sink),
                    ),
                    Ok(TransitionOutcome::Committed),
                    "the disconnect created no revocation transition"
                );
                assert_eq!(
                    revocation_sink.events.len(),
                    1,
                    "exactly one revocation fact, and the disconnect contributed none"
                );
                first_revocations += 1;
            }

            let cases = SC008_DISCONNECTS as usize;
            assert_eq!(disconnects, cases, "every trial disconnected");
            assert_eq!(
                confirmed_mutations, cases,
                "one confirmed mutation per trial"
            );
            assert_eq!(
                confirmed_decisions, cases,
                "one confirmed decision per trial"
            );
            assert_eq!(
                events_emitted_by_a_disconnect, 0,
                "no disconnect emitted a transition fact"
            );
            assert_eq!(duplicate_closes_refused, cases);
            assert_eq!(duplicate_decisions_refused, cases);
            assert_eq!(dead_channel_mutations_refused, cases);
            assert_eq!(reconnects_on_confirmed_work, cases);
            assert_eq!(first_revocations, cases);
            // The seeded split, recorded so a rerun that drifts is visible rather than
            // silently covering one commit order only.
            assert_eq!(
                mutation_first_trials, 56,
                "seeded commit-order split for {SC008_SEED:#x}"
            );
            assert!(
                cases - mutation_first_trials > 0,
                "both commit orders occurred"
            );
            assert!(
                started.elapsed() < std::time::Duration::from_secs(120),
                "the campaign must stay a test, not a benchmark: {:?}",
                started.elapsed()
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
            assert!(failure.to_string().contains("stale_epoch"), "{failure}");
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
