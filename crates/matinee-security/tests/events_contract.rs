macro_rules! events_contract_tests {
    () => {
        use crate::ChannelSigner;
        use crate::events;
        use crate::test_support_fakes::FakeEventSink;
        use uuid::Uuid;

        fn event(code: events::SecurityCode) -> events::SecurityEvent {
            events::SecurityEvent::new(
                Uuid::from_u128(1),
                events::EventBoundary::Authentication,
                code,
                events::EventOutcome::Rejected,
                events::SafeNextAction::FailClosed,
                None,
                None,
                events::EndpointClass::Loopback,
                events::EventTime(7),
                Uuid::from_u128(2),
                vec![],
            )
            .expect("valid event fixture")
        }

        /// Every required fact, and the production operation that owes it.
        ///
        /// `contracts/failures-events.md` says "the security module emits one typed
        /// redacted fact for each of these outcomes" and then lists them, so the
        /// obligation is per outcome, not per enum value: constructing a `SecurityCode`
        /// proves nothing about whether any code path ever reaches it. Each entry below
        /// is therefore driven through a real operation, and the fact is read back off
        /// the sink that operation was given.
        const REQUIRED_FACTS: [events::SecurityCode; 13] = [
            events::SecurityCode::EnrollmentAccepted,
            events::SecurityCode::AuthorizationAccepted,
            events::SecurityCode::ProofRejected,
            events::SecurityCode::OriginRejected,
            events::SecurityCode::AuthenticationFailed,
            events::SecurityCode::AuthorizationDenied,
            events::SecurityCode::Rotation,
            events::SecurityCode::Revocation,
            events::SecurityCode::ReplayDetected,
            events::SecurityCode::Downgrade,
            events::SecurityCode::MalformedInput,
            events::SecurityCode::ResourceLimit,
            events::SecurityCode::RateLimited,
        ];

        #[test]
        fn every_required_security_fact_is_emitted_by_the_production_path_that_owes_it() {
            let observed = [
                transition_facts(),
                channel_admission_facts(),
                channel_frame_facts(),
                pairing_facts(),
            ]
            .concat();
            for required in REQUIRED_FACTS {
                assert!(
                    observed.contains(&required),
                    "no production operation emitted {required:?}; \
                     contracts/failures-events.md requires one for it"
                );
            }
        }

        /// A committed enrollment, rotation, and revocation, and the authorization
        /// decision a live channel reaches on the way.
        fn transition_facts() -> Vec<events::SecurityCode> {
            use crate::identity::{ExpiryResult, PrincipalKind, TransitionOutcome};
            use crate::test_support_channel::{RecordingSink, RingSigner, capability, id};
            use crate::test_support_transitions::{
                ADMINISTRATOR, EXTENSION, connection, create_enrollment, live_channel, receive,
                registered, request, revoke, rotate, transition,
            };
            use crate::transition::SecurityTransitions;

            let transitions = SecurityTransitions::default();
            let admin_signer = RingSigner::generate();
            let admin = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &admin_signer,
            );
            let mut sink = RecordingSink::default();
            assert_eq!(
                create_enrollment(
                    &transitions,
                    transition(90),
                    admin.id(),
                    900,
                    0,
                    ExpiryResult::valid(600_000).expect("bounded ten-minute deadline"),
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                sink.events
                    .last()
                    .expect("a committed enrollment emits")
                    .code(),
                events::SecurityCode::EnrollmentAccepted
            );

            // An authorized operation on a live channel is the accepted-decision fact.
            let client_signer = RingSigner::generate();
            let client = registered(
                &transitions,
                EXTENSION,
                PrincipalKind::McpClient,
                &client_signer,
            );
            let mut session = live_channel(&transitions, &client, &client_signer, 90);
            let frame = request(&mut session, &mut sink);
            receive(&transitions, connection(90), &frame, &mut sink)
                .expect("an operation inside the ceiling is authorized");
            assert_eq!(
                sink.events
                    .last()
                    .expect("an authorized operation emits")
                    .code(),
                events::SecurityCode::AuthorizationAccepted
            );

            // The same live channel, asked for an action above its ceiling.
            let denied_frame = request(&mut session, &mut sink);
            assert_eq!(
                transitions
                    .receive(
                        connection(90),
                        &denied_frame,
                        capability(crate::CapabilityAction::ManagePrincipals, "matinee"),
                        crate::PayloadKind::Command,
                        crate::ObjectOwner::Owned(id(ADMINISTRATOR)),
                        &mut sink,
                    )
                    .expect_err("an action above the ceiling is denied")
                    .code(),
                crate::FailureCode::AuthorizationDenied
            );
            assert_eq!(
                sink.events.last().expect("a denied operation emits").code(),
                events::SecurityCode::AuthorizationDenied
            );

            assert_eq!(
                rotate(
                    &transitions,
                    client.id(),
                    &RingSigner::generate(),
                    "principal-key-1",
                    901,
                    0,
                    None,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                sink.events
                    .last()
                    .expect("a committed rotation emits")
                    .code(),
                events::SecurityCode::Rotation
            );
            assert_eq!(
                revoke(
                    &transitions,
                    client.id(),
                    "operator",
                    902,
                    1,
                    Some(&mut sink)
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                sink.events
                    .last()
                    .expect("a committed revocation emits")
                    .code(),
                events::SecurityCode::Revocation
            );
            sink.events
                .iter()
                .map(events::SecurityEvent::code)
                .collect()
        }

        /// Channel admission: a forged snapshot is an authentication failure and a
        /// duplicate connection is a replay. Both rejections registered nothing before
        /// this contract required them to be recorded.
        fn channel_admission_facts() -> Vec<events::SecurityCode> {
            use crate::identity::PrincipalKind;
            use crate::test_support_channel::{
                RecordingSink, RingSigner, establish_pair_for, id, registered_principal,
            };
            use crate::test_support_transitions::{EXTENSION, ceiling, connection, registered};
            use crate::transition::SecurityTransitions;

            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();

            // A snapshot two peers agreed on between themselves, which the registry does
            // not hold: the handshake cannot tell, so admission is the only check left.
            let forged = registered_principal(
                EXTENSION,
                PrincipalKind::NativeAdmin,
                signer.public_key().clone(),
                ceiling(),
                0,
            );
            let (_, forged_daemon) = establish_pair_for(&forged, &signer, connection(91))
                .expect("two peers can agree on a snapshot the registry never held");
            assert_eq!(
                transitions
                    .register_channel(forged_daemon, &mut sink)
                    .expect_err("a forged snapshot is never admitted")
                    .code(),
                crate::FailureCode::CredentialStoreMismatch
            );
            assert_eq!(
                sink.events
                    .last()
                    .expect("a refused admission emits")
                    .code(),
                events::SecurityCode::AuthenticationFailed
            );
            // The fact names the connection it refused, so a reader can correlate it
            // without the refused snapshot itself being disclosed.
            assert_eq!(
                sink.events
                    .last()
                    .expect("a refused admission emits")
                    .connection_id(),
                Some(connection(91).get())
            );

            // The positive control: the registered snapshot is still admitted.
            let (_, honest) = establish_pair_for(&principal, &signer, connection(92))
                .expect("production handshake fixture");
            assert_eq!(
                transitions.register_channel(honest, &mut sink),
                Ok(connection(92))
            );
            assert!(transitions.channel_is_open(connection(92)));

            // The same connection a second time is a replay.
            let (_, duplicate) = establish_pair_for(&principal, &signer, connection(92))
                .expect("production handshake fixture");
            assert_eq!(
                transitions
                    .register_channel(duplicate, &mut sink)
                    .expect_err("one connection is admitted once")
                    .code(),
                crate::FailureCode::ReplayDetected
            );
            assert_eq!(
                sink.events
                    .last()
                    .expect("a refused admission emits")
                    .code(),
                events::SecurityCode::ReplayDetected
            );
            assert_eq!(transitions.open_channels(), 1);
            sink.events
                .iter()
                .map(events::SecurityEvent::code)
                .collect()
        }

        /// Frame-boundary facts: a downgraded contract, a malformed frame, and a frame
        /// whose declared length exceeds the production bound.
        fn channel_frame_facts() -> Vec<events::SecurityCode> {
            use crate::test_support_channel::{
                CONNECTION, DAEMON, ENDPOINT, PRINCIPAL, RecordingSink, RingSigner, establish_pair,
                fixture_principal, id, owned_operation,
            };

            let mut sink = RecordingSink::default();
            let client_signer = RingSigner::generate();
            let daemon_signer = RingSigner::generate();
            let client = crate::ClientHandshakeConfig::new(
                ENDPOINT,
                id(PRINCIPAL),
                client_signer.public_key().clone(),
                id(DAEMON),
                daemon_signer.public_key().clone(),
                7,
                1,
                3,
            )
            .expect("bounded client configuration");
            let server = crate::ServerHandshakeConfig::new(
                ENDPOINT,
                fixture_principal(client_signer.public_key().clone(), 7),
                id(DAEMON),
                daemon_signer.public_key().clone(),
                2,
                4,
                crate::ConnectionId::new(Uuid::from_u128(CONNECTION)),
            )
            .expect("bounded server configuration");
            let (client_pending, hello) =
                crate::ClientHandshake::start(client).expect("production client hello");
            let (_, mut proof) =
                crate::ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink)
                    .expect("production server proof");
            // The selected-contract byte inside the server proof, moved below the range
            // the client offered.
            proof[4 + b"server-proof".len() + hello.len() + 4] = b'2';
            assert_eq!(
                client_pending
                    .finish(&proof, &client_signer, &mut sink)
                    .expect_err("a downgraded contract is refused")
                    .code(),
                crate::FailureCode::DowngradeRejected
            );
            assert_eq!(
                sink.events.last().expect("a downgrade emits").code(),
                events::SecurityCode::Downgrade
            );

            let (_, mut daemon) = establish_pair(0);
            assert_eq!(
                daemon
                    .receive(
                        &[0, 0, 0, 1, 1],
                        &owned_operation(crate::PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("a frame shorter than its header is refused")
                    .code(),
                crate::FailureCode::MalformedInput
            );
            assert_eq!(
                sink.events.last().expect("a malformed frame emits").code(),
                events::SecurityCode::MalformedInput
            );

            let (_, mut oversized_peer) = establish_pair(0);
            assert_eq!(
                oversized_peer
                    .receive(
                        &1_048_577u32.to_be_bytes(),
                        &owned_operation(crate::PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("a declared length above the bound is refused")
                    .code(),
                crate::FailureCode::ResourceLimit
            );
            assert_eq!(
                sink.events.last().expect("a resource limit emits").code(),
                events::SecurityCode::ResourceLimit
            );
            sink.events
                .iter()
                .map(events::SecurityEvent::code)
                .collect()
        }

        /// Pairing facts: a rejected proof, a rejected Origin, and a rate limit, all
        /// through the enrollment host's own proof consumption.
        fn pairing_facts() -> Vec<events::SecurityCode> {
            use crate::enrollment::{
                ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding,
                EnrollmentBundle, EnrollmentChannel, EnrollmentChannelState, EnrollmentClock,
                EnrollmentConsumeError, EnrollmentConsumptionService, EnrollmentCreation,
                EnrollmentProof,
            };
            use crate::identity::{ExpiryResult, IdentityId, TransitionId};
            use crate::test_support_channel::{ENDPOINT, RecordingSink};
            use crate::test_support_transitions::{
                INSTALL, ORIGIN, STORE, UPDATE, binding, long_term_key,
            };

            fn bundle(value: u128) -> EnrollmentBundle {
                EnrollmentBundle::create(EnrollmentCreation::with_default_expiry(
                    TransitionId::new(Uuid::from_u128(value)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    INSTALL,
                    IdentityId::new(Uuid::from_u128(0x2f)),
                    ENDPOINT,
                ))
                .expect("the ten-minute default is inside the creation bounds")
            }

            /// A proof no one-time key ever signed. Every consumption below is meant to
            /// be refused, so the signature never has to be the valid one.
            fn unsigned_proof(identity: IdentityId) -> EnrollmentProof {
                EnrollmentProof {
                    identity,
                    signature: vec![0; 8],
                    long_term_public_key: long_term_key(),
                }
            }

            fn channel() -> EnrollmentChannel {
                EnrollmentChannel::open(crate::ConnectionId::new(Uuid::from_u128(0x9100)), 1)
                    .expect("native pairing channel")
            }

            fn clock(occurrence_ms: u64) -> EnrollmentClock {
                EnrollmentClock::new(
                    occurrence_ms,
                    ExpiryResult::valid(600_000).expect("bounded ten-minute deadline"),
                )
            }

            let identity = IdentityId::new(Uuid::from_u128(0x790));
            // One host budget per drive: a refusal recorded by an earlier drive would
            // otherwise count towards the rate limit the last drive measures.
            let service = EnrollmentConsumptionService::default();
            let capability = ChromeCapability::reported(&binding(), true, true)
                .expect("reported browser capability");
            let mut observed = Vec::new();

            // A proof that misses no bound but carries no valid signature.
            let mut sink = RecordingSink::default();
            let mut rejected = bundle(0x790);
            let mut open = channel();
            assert_eq!(
                service.consume_proof(
                    &mut rejected,
                    &unsigned_proof(identity),
                    identity,
                    &clock(1_000),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut sink),
                ),
                Err(EnrollmentConsumeError::InvalidProof)
            );
            assert_eq!(
                sink.events.last().expect("a rejected proof emits").code(),
                events::SecurityCode::ProofRejected
            );
            assert_eq!(open.state(), EnrollmentChannelState::Closed);
            observed.extend(sink.events.iter().map(events::SecurityEvent::code));

            // The same proof against a binding whose Origin is not the enrolled one. The
            // returned error is unchanged, so only the fact tells the two apart.
            let mut sink = RecordingSink::default();
            let service = EnrollmentConsumptionService::default();
            let mut wrong_origin_bundle = bundle(0x791);
            let wrong_origin = EnrollmentBinding {
                origin: "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba",
                endpoint: ENDPOINT,
                store_metadata: STORE,
                update_metadata: UPDATE,
                install_metadata: INSTALL,
                development_allowance: DevelopmentIdentityAllowance::None,
            };
            let capability_for_origin = ChromeCapability::reported(&wrong_origin, true, true)
                .expect("a browser reports whatever origin it loaded");
            let mut open = channel();
            assert_eq!(
                service.consume_proof(
                    &mut wrong_origin_bundle,
                    &unsigned_proof(identity),
                    identity,
                    &clock(2_000),
                    &wrong_origin,
                    &capability_for_origin,
                    &mut open,
                    Some(&mut sink),
                ),
                Err(EnrollmentConsumeError::InvalidProof)
            );
            assert_eq!(
                sink.events.last().expect("a rejected Origin emits").code(),
                events::SecurityCode::OriginRejected
            );
            observed.extend(sink.events.iter().map(events::SecurityEvent::code));

            // The host budget: ten refusals in one window, and the eleventh is the
            // rate limit rather than another proof rejection.
            let mut sink = RecordingSink::default();
            let service = EnrollmentConsumptionService::default();
            for attempt in 0..10 {
                let mut current = bundle(0x7a0 + attempt);
                let mut open = channel();
                assert_eq!(
                    service.consume_proof(
                        &mut current,
                        &unsigned_proof(identity),
                        identity,
                        &clock(5_000),
                        &binding(),
                        &capability,
                        &mut open,
                        Some(&mut sink),
                    ),
                    Err(EnrollmentConsumeError::InvalidProof)
                );
            }
            let mut limited = bundle(0x7b0);
            let mut open = channel();
            assert_eq!(
                service.consume_proof(
                    &mut limited,
                    &unsigned_proof(identity),
                    identity,
                    &clock(5_001),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut sink),
                ),
                Err(EnrollmentConsumeError::RateLimited)
            );
            assert_eq!(
                sink.events.last().expect("a rate limit emits").code(),
                events::SecurityCode::RateLimited
            );
            observed.extend(sink.events.iter().map(events::SecurityEvent::code));

            observed
        }

        #[test]
        fn authorization_success_tuple_is_explicit() {
            let event = events::SecurityEvent::new(
                Uuid::from_u128(1),
                events::EventBoundary::Authorization,
                events::SecurityCode::AuthorizationAccepted,
                events::EventOutcome::Accepted,
                events::SafeNextAction::Continue,
                Some(Uuid::from_u128(3)),
                Some(Uuid::from_u128(4)),
                events::EndpointClass::Loopback,
                events::EventTime(7),
                Uuid::from_u128(2),
                vec![events::MetadataEntry {
                    key: "reason".into(),
                    value: "accepted".into(),
                }],
            )
            .expect("valid authorization success event");
            let mut sink = FakeEventSink::accepted();
            assert_eq!(
                events::emit_required(Some(&mut sink), event),
                Ok(events::SecurityEventSinkResult::Accepted)
            );
            assert_eq!(
                sink.received()[0].boundary,
                events::EventBoundary::Authorization
            );
            assert_eq!(
                sink.received()[0].code,
                events::SecurityCode::AuthorizationAccepted
            );
            assert_eq!(sink.received()[0].outcome, events::EventOutcome::Accepted);
            assert_eq!(
                sink.received()[0].next_action,
                events::SafeNextAction::Continue
            );
        }
        #[test]
        fn event_and_metadata_bounds_accept_edges_and_reject_overflows() {
            let metadata = (0..8)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i:0>31}"),
                    value: "v".repeat(32),
                })
                .collect();
            let bounded = events::SecurityEvent::new(
                Uuid::nil(),
                events::EventBoundary::Bootstrap,
                events::SecurityCode::EnrollmentAccepted,
                events::EventOutcome::Accepted,
                events::SafeNextAction::Retry,
                Some(Uuid::from_u128(3)),
                Some(Uuid::from_u128(4)),
                events::EndpointClass::Native,
                events::EventTime(0),
                Uuid::nil(),
                metadata,
            )
            .expect("512 metadata bytes are accepted");
            assert_eq!(bounded.metadata().len(), 8);
            assert_eq!(
                bounded
                    .metadata()
                    .iter()
                    .map(|m| m.key.len() + m.value.len())
                    .sum::<usize>(),
                512
            );
            assert!(bounded.encoded_len() <= 2_048);

            let too_many = (0..9)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i}"),
                    value: "v".into(),
                })
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted,
                    events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry,
                    None,
                    None,
                    events::EndpointClass::Native,
                    events::EventTime(0),
                    Uuid::nil(),
                    too_many,
                ),
                Err(events::EventBuildError::TooManyMetadata)
            );

            let metadata_over = (0..7)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i:0>31}"),
                    value: "v".repeat(32),
                })
                .chain(std::iter::once(events::MetadataEntry {
                    key: "k".repeat(32),
                    value: "v".repeat(33),
                }))
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted,
                    events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry,
                    None,
                    None,
                    events::EndpointClass::Native,
                    events::EventTime(0),
                    Uuid::nil(),
                    metadata_over,
                ),
                Err(events::EventBuildError::MetadataTooLarge)
            );

            let base = |entry| {
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted,
                    events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry,
                    None,
                    None,
                    events::EndpointClass::Native,
                    events::EventTime(0),
                    Uuid::nil(),
                    vec![entry],
                )
            };
            assert_eq!(
                base(events::MetadataEntry {
                    key: "k".repeat(33),
                    value: "v".into()
                }),
                Err(events::EventBuildError::MetadataKeyTooLong)
            );
            assert_eq!(
                base(events::MetadataEntry {
                    key: "k".into(),
                    value: "v".repeat(129)
                }),
                Err(events::EventBuildError::MetadataValueTooLong)
            );

            // Metadata is capped at 512 bytes, so the fixed event fields plus metadata
            // can never reach 2,048; EventTooLarge is mathematically unreachable.
            assert!(
                bounded.encoded_len()
                    <= 16 + 1 + 1 + 1 + 1 + 1 + 8 + 16 + 1 + 16 + 16 + 512 + (8 * 4)
            );
            assert!(bounded.encoded_len() < 2_048);
        }

        #[test]
        fn event_and_sink_failure_redaction_rejects_secret_vocabulary() {
            let words = [
                "private_key",
                "pkcs8",
                "enrollment_secret",
                "credential",
                "password",
                "cookie",
                "authorization_header",
                "payload_text",
                "https://host/path",
                "object_id",
                "artifact_id",
                "stream_id",
            ];
            for word in words {
                for (field, entry) in [
                    (
                        "key",
                        events::MetadataEntry {
                            key: word.into(),
                            value: "safe".into(),
                        },
                    ),
                    (
                        "value",
                        events::MetadataEntry {
                            key: "reason".into(),
                            value: word.into(),
                        },
                    ),
                ] {
                    let result = events::SecurityEvent::new(
                        Uuid::nil(),
                        events::EventBoundary::Input,
                        events::SecurityCode::MalformedInput,
                        events::EventOutcome::Rejected,
                        events::SafeNextAction::FailClosed,
                        None,
                        None,
                        events::EndpointClass::Unknown,
                        events::EventTime(0),
                        Uuid::nil(),
                        vec![entry],
                    );
                    assert_eq!(
                        result,
                        Err(events::EventBuildError::Redacted),
                        "{field}: {word}"
                    );
                }
            }

            let mut sink = FakeEventSink::unavailable();
            assert_eq!(
                events::emit_required(
                    Some(&mut sink),
                    event(events::SecurityCode::EventSinkUnavailable)
                ),
                Err(events::RequiredEventError::Unavailable)
            );
            let failure = &sink.received()[0];
            assert!(failure.metadata().is_empty());
            assert_eq!(failure.code, events::SecurityCode::EventSinkUnavailable);
        }

        #[test]
        fn aggregation_is_bounded_by_64_buckets_and_saturates_at_255() {
            use crate::events::SecurityEventSink;
            let make = |i: u128| {
                events::SecurityEvent::new(
                    Uuid::from_u128(i),
                    events::EventBoundary::Authentication,
                    events::SecurityCode::AuthenticationFailed,
                    events::EventOutcome::Failed,
                    events::SafeNextAction::FailClosed,
                    Some(Uuid::from_u128(i)),
                    None,
                    events::EndpointClass::Loopback,
                    events::EventTime(0),
                    Uuid::nil(),
                    vec![],
                )
                .unwrap()
            };
            let repeated = make(1);
            let mut state = events::AggregationState::default();
            for _ in 0..255 {
                assert_eq!(
                    state.emit(repeated.clone()),
                    events::SecurityEventSinkResult::Aggregated
                );
            }
            assert_eq!(state.count_for(&repeated), Some(255));
            assert_eq!(
                state.emit(repeated.clone()),
                events::SecurityEventSinkResult::Aggregated
            );
            assert_eq!(state.count_for(&repeated), Some(255));

            for i in 2..=64 {
                assert_eq!(
                    state.emit(make(i)),
                    events::SecurityEventSinkResult::Aggregated
                );
            }
            assert_eq!(state.bucket_count(), 64);
            let before = state.bucket_count();
            let overflow = make(65);
            assert_eq!(
                state.emit(overflow.clone()),
                events::SecurityEventSinkResult::Unavailable
            );
            assert_eq!(
                state.bucket_count(),
                before,
                "overflow leaves aggregation unchanged"
            );
            assert_eq!(state.count_for(&overflow), None);
        }

        fn guarded_increment(
            sink: Option<&mut FakeEventSink>,
            protected_state: &mut u8,
        ) -> Result<(), events::SecurityCode> {
            match events::emit_required(sink, event(events::SecurityCode::AuthenticationFailed)) {
                Ok(_) => {
                    *protected_state += 1;
                    Ok(())
                }
                Err(events::RequiredEventError::Unavailable) => {
                    Err(events::SecurityCode::EventSinkUnavailable)
                }
            }
        }

        #[test]
        fn required_sink_gates_mutation_and_projects_unavailable_failure() {
            let mut protected_state = 0u8;
            let mut accepted = FakeEventSink::accepted();
            assert_eq!(
                guarded_increment(Some(&mut accepted), &mut protected_state),
                Ok(())
            );
            assert_eq!(protected_state, 1);
            assert_eq!(accepted.received().len(), 1);

            let mut unavailable = FakeEventSink::unavailable();
            assert_eq!(
                guarded_increment(Some(&mut unavailable), &mut protected_state),
                Err(events::SecurityCode::EventSinkUnavailable)
            );
            assert_eq!(protected_state, 1);
            assert_eq!(unavailable.received().len(), 1);
        }
        #[test]
        fn production_channel_and_authorization_failures_feed_bounded_aggregation() {
            use crate::test_support_channel::{
                DAEMON, ENDPOINT, PRINCIPAL, RingSigner, capability, establish_pair,
                fixture_principal, id,
            };
            struct CapturingAggregation {
                state: events::AggregationState,
                events: Vec<events::SecurityEvent>,
            }
            impl events::SecurityEventSink for CapturingAggregation {
                fn emit(
                    &mut self,
                    event: events::SecurityEvent,
                ) -> events::SecurityEventSinkResult {
                    self.events.push(event.clone());
                    self.state.emit(event)
                }
            }
            let client_signer = RingSigner::generate();
            let server_signer = RingSigner::generate();
            let client = crate::ClientHandshakeConfig::new(
                ENDPOINT,
                id(PRINCIPAL),
                client_signer.public_key().clone(),
                id(DAEMON),
                server_signer.public_key().clone(),
                0,
                1,
                3,
            )
            .unwrap();
            let server = crate::ServerHandshakeConfig::new(
                ENDPOINT,
                fixture_principal(client_signer.public_key().clone(), 0),
                id(DAEMON),
                server_signer.public_key().clone(),
                1,
                3,
                crate::ConnectionId::new(Uuid::from_u128(0xabcdefabcdefabcdefabcdefabcd)),
            )
            .unwrap();
            let (_client_pending, hello) = crate::ClientHandshake::start(client).unwrap();
            let wrong_signer = RingSigner::generate();
            let mut aggregate = CapturingAggregation {
                state: events::AggregationState::default(),
                events: Vec::new(),
            };
            let failure =
                crate::ServerHandshake::accept(server, &hello, &wrong_signer, &mut aggregate)
                    .expect_err("the wrong server signer must fail authentication");
            assert_eq!(failure.code(), crate::FailureCode::AuthenticationFailed);
            assert_eq!(aggregate.state.bucket_count(), 1);
            let (mut client_session, mut daemon_session) = establish_pair(0);
            let output = crate::AuthorizedOutput::filtered(
                crate::PayloadKind::Command,
                b"bounded-request".to_vec(),
            )
            .unwrap();
            let frame = client_session
                .send(&output, &mut aggregate)
                .expect("production client seals the request");
            let denied_operation = crate::SessionInput::new(
                capability(crate::CapabilityAction::ManagePrincipals, "matinee"),
                crate::PayloadKind::Command,
                crate::ObjectOwner::Owned(id(DAEMON)),
                None,
            );
            let denied = daemon_session
                .receive(&frame, &denied_operation, &mut aggregate)
                .expect_err("authorization must reject the out-of-ceiling action");
            assert_eq!(denied.code(), crate::FailureCode::AuthorizationDenied);
            assert_eq!(aggregate.events.len(), 2);
            assert_eq!(
                aggregate.events[1].boundary(),
                events::EventBoundary::Authorization
            );
            assert_eq!(
                aggregate.events[1].code(),
                events::SecurityCode::AuthorizationDenied
            );
            assert_eq!(aggregate.state.bucket_count(), 2);
        }
    };
}
