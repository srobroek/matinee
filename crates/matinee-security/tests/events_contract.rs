#[allow(unused_macros)]
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

        /// One pending enrollment at the ten-minute default, as an administrator opens it,
        /// created at instant zero so every `pairing_clock` occurrence below is inside it.
        fn pairing_bundle(value: u128) -> crate::enrollment::EnrollmentBundle {
            use crate::test_support_channel::ENDPOINT;
            use crate::test_support_transitions::{
                INSTALL, ORIGIN, STORE, UPDATE, supported_versions,
            };
            crate::enrollment::EnrollmentBundle::create(
                crate::enrollment::EnrollmentCreation::with_default_expiry(
                    crate::identity::TransitionId::new(Uuid::from_u128(value)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    INSTALL,
                    supported_versions(),
                    crate::identity::IdentityId::new(Uuid::from_u128(0x2f)),
                    ENDPOINT,
                ),
                0,
            )
            .expect("the ten-minute default is inside the creation bounds")
        }

        /// A proof no one-time key ever signed. Every consumption below is meant to be
        /// refused, so the signature never has to be the valid one.
        fn unsigned_proof(
            identity: crate::identity::IdentityId,
        ) -> crate::enrollment::EnrollmentProof {
            crate::enrollment::EnrollmentProof {
                identity,
                signature: vec![0; 8],
                long_term_public_key: crate::test_support_transitions::long_term_key(),
            }
        }

        fn pairing_channel() -> crate::enrollment::EnrollmentChannel {
            crate::enrollment::EnrollmentChannel::open(
                crate::ConnectionId::new(Uuid::from_u128(0x9100)),
                1,
            )
            .expect("native pairing channel")
        }

        fn pairing_clock(occurrence_ms: u64) -> crate::enrollment::EnrollmentClock {
            crate::enrollment::EnrollmentClock::new(
                occurrence_ms,
                crate::identity::ExpiryResult::valid(600_000).expect("bounded ten-minute deadline"),
            )
        }

        /// The enrolled bounds with one exception: an Origin the enrollment was not
        /// created for. A browser reports whatever origin it actually loaded, so the
        /// reported capability is built from this binding too.
        fn wrong_origin_binding() -> crate::enrollment::EnrollmentBinding<'static> {
            use crate::test_support_channel::ENDPOINT;
            use crate::test_support_transitions::{INSTALL, STORE, UPDATE, VERSION};
            crate::enrollment::EnrollmentBinding {
                origin: "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba",
                endpoint: ENDPOINT,
                store_metadata: STORE,
                update_metadata: UPDATE,
                install_metadata: INSTALL,
                version: VERSION,
                development_allowance: crate::enrollment::DevelopmentIdentityAllowance::None,
            }
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

        /// Every enrollment-pairing refusal that owes a fact, named by the bound it
        /// refuses on, with the fact it owes.
        ///
        /// Membership in `REQUIRED_FACTS` is satisfied by whichever path happens to reach a
        /// code first, so a second path returning the same listed outcome in silence
        /// satisfies it too: that is exactly how a rejected pairing with no fact at all
        /// survived this file. The obligation is per outcome, and an outcome is something a
        /// path returns, so the paths are enumerated here and each is required to state its
        /// own fact. `contracts/failures-events.md` decides which fact through the mapping
        /// every boundary shares, so a replay and an authentication failure are named
        /// identically wherever the pairing died.
        const REQUIRED_REJECTION_PATHS: [(&str, events::SecurityCode); 7] = [
            (
                "consumption of an enrollment nobody opened",
                events::SecurityCode::ReplayDetected,
            ),
            (
                "consumption at an epoch the enrollment does not hold",
                events::SecurityCode::AuthenticationFailed,
            ),
            (
                "consumption for a principal already registered",
                events::SecurityCode::ReplayDetected,
            ),
            (
                "a proof naming an identity other than the pairing one",
                events::SecurityCode::AuthenticationFailed,
            ),
            (
                "a credential outside the enrollment owner's binding",
                events::SecurityCode::AuthenticationFailed,
            ),
            (
                "a proof against an enrollment past its deadline",
                events::SecurityCode::ReplayDetected,
            ),
            (
                "a proof against an enrollment already consumed",
                events::SecurityCode::ReplayDetected,
            ),
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

            // The same obligation, read per refusing path instead of per code.
            let by_path = pairing_rejection_facts();
            for (path, required) in REQUIRED_REJECTION_PATHS {
                let stated = by_path
                    .iter()
                    .find(|(name, _)| *name == path)
                    .map(|(_, code)| *code);
                assert_eq!(
                    stated,
                    Some(required),
                    "{path} refused without stating {required:?}; \
                     contracts/failures-events.md requires the fact before the refusal"
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
                RecordingSink, RingSigner, establish_pair_for, registered_principal,
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
                ChromeCapability, EnrollmentChannelState, EnrollmentConsumeError,
                EnrollmentConsumptionService,
            };
            use crate::identity::IdentityId;
            use crate::test_support_channel::RecordingSink;
            use crate::test_support_transitions::binding;

            let identity = IdentityId::new(Uuid::from_u128(0x790));
            // One host budget per drive: a refusal recorded by an earlier drive would
            // otherwise count towards the rate limit the last drive measures.
            let service = EnrollmentConsumptionService::default();
            let capability = ChromeCapability::reported(&binding(), true, true)
                .expect("reported browser capability");
            let mut observed = Vec::new();

            // A proof that misses no bound but carries no valid signature.
            let mut sink = RecordingSink::default();
            let mut rejected = pairing_bundle(0x790);
            let mut open = pairing_channel();
            assert_eq!(
                service.consume_proof(
                    &mut rejected,
                    &unsigned_proof(identity),
                    identity,
                    &pairing_clock(1_000),
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
            let mut wrong_origin_bundle = pairing_bundle(0x791);
            let wrong_origin = wrong_origin_binding();
            let capability_for_origin = ChromeCapability::reported(&wrong_origin, true, true)
                .expect("a browser reports whatever origin it loaded");
            let mut open = pairing_channel();
            assert_eq!(
                service.consume_proof(
                    &mut wrong_origin_bundle,
                    &unsigned_proof(identity),
                    identity,
                    &pairing_clock(2_000),
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
                let mut current = pairing_bundle(0x7a0 + attempt);
                let mut open = pairing_channel();
                assert_eq!(
                    service.consume_proof(
                        &mut current,
                        &unsigned_proof(identity),
                        identity,
                        &pairing_clock(5_000),
                        &binding(),
                        &capability,
                        &mut open,
                        Some(&mut sink),
                    ),
                    Err(EnrollmentConsumeError::InvalidProof)
                );
            }
            let mut limited = pairing_bundle(0x7b0);
            let mut open = pairing_channel();
            assert_eq!(
                service.consume_proof(
                    &mut limited,
                    &unsigned_proof(identity),
                    identity,
                    &pairing_clock(5_001),
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

        /// The rejected-Origin fact, both halves.
        ///
        /// The fact is required before the refusal is recorded against the enrollment, so
        /// an unavailable sink must leave the proof budget and the pairing channel exactly
        /// as they were: an Origin nobody could record is not an Origin quietly accepted,
        /// and it is not a failure silently charged to the extension either.
        #[test]
        fn a_rejected_origin_is_recorded_or_the_refusal_fails_closed() {
            use crate::enrollment::{
                ChromeCapability, EnrollmentChannelState, EnrollmentConsumeError,
                EnrollmentConsumptionService,
            };
            use crate::identity::IdentityId;
            use crate::test_support_channel::RecordingSink;

            let identity = IdentityId::new(Uuid::from_u128(0x7c0));
            let wrong_origin = wrong_origin_binding();
            let capability = ChromeCapability::reported(&wrong_origin, true, true)
                .expect("a browser reports whatever origin it loaded");

            // An available sink observes the fact, and only then is the refusal charged.
            let mut accepting = RecordingSink::default();
            let mut recorded = pairing_bundle(0x7c0);
            let mut open = pairing_channel();
            assert_eq!(
                EnrollmentConsumptionService::default().consume_proof(
                    &mut recorded,
                    &unsigned_proof(identity),
                    identity,
                    &pairing_clock(1_000),
                    &wrong_origin,
                    &capability,
                    &mut open,
                    Some(&mut accepting),
                ),
                Err(EnrollmentConsumeError::InvalidProof)
            );
            assert_eq!(
                accepting
                    .events
                    .last()
                    .expect("a rejected Origin emits")
                    .code(),
                events::SecurityCode::OriginRejected
            );
            assert_eq!(recorded.enrollment().failed_proofs(), 1);
            assert_eq!(open.state(), EnrollmentChannelState::Closed);

            // An unavailable sink fails closed, and nothing was charged or closed.
            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };
            let mut untouched = pairing_bundle(0x7c1);
            let mut still_open = pairing_channel();
            assert_eq!(
                EnrollmentConsumptionService::default().consume_proof(
                    &mut untouched,
                    &unsigned_proof(identity),
                    identity,
                    &pairing_clock(1_000),
                    &wrong_origin,
                    &capability,
                    &mut still_open,
                    Some(&mut unavailable),
                ),
                Err(EnrollmentConsumeError::EventUnavailable)
            );
            assert_eq!(
                untouched.enrollment().failed_proofs(),
                0,
                "an unrecordable refusal charges the extension nothing"
            );
            assert_eq!(still_open.state(), EnrollmentChannelState::Open);
            assert!(unavailable.events.is_empty());
        }

        /// One valid pairing proof, signed by the one-time key this channel took custody of.
        /// A refused pairing needs no valid signature, but a consumption that must first
        /// succeed does, and a proof that succeeded once is what a replay re-presents.
        fn signed_pairing_proof(
            bundle: &mut crate::enrollment::EnrollmentBundle,
            channel: &crate::enrollment::EnrollmentChannel,
            who: crate::identity::IdentityId,
        ) -> crate::enrollment::EnrollmentProof {
            use ring::rand::SystemRandom;
            use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};

            let enrollment = bundle.enrollment_id();
            let transfer = channel
                .seal_one_time_key(bundle)
                .expect("one-time key custody");
            let private = channel
                .open_sealed_for_test(enrollment, &transfer)
                .expect("the pairing peer opens its own sealed key");
            let rng = SystemRandom::new();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng)
                .expect("the one-time key");
            let long_term = crate::test_support_transitions::long_term_key();
            let signature = signer
                .sign(
                    &rng,
                    &crate::enrollment::enrollment_proof_message(bundle, &long_term),
                )
                .expect("a one-time proof signature")
                .as_ref()
                .to_vec();
            crate::enrollment::EnrollmentProof {
                identity: who,
                signature,
                long_term_public_key: long_term,
            }
        }

        /// Drive every refusal named in `REQUIRED_REJECTION_PATHS` and report the fact each
        /// one stated, alongside the typed failure it returned.
        ///
        /// Each path gets its own sink, so the fact read back is the one that path emitted
        /// and not a leftover from an earlier drive, and each asserts its own stable code:
        /// stating a fact may never change what a caller is told.
        fn pairing_rejection_facts() -> Vec<(&'static str, events::SecurityCode)> {
            use crate::enrollment::{
                ChromeCapability, EnrollmentChannel, EnrollmentClock, EnrollmentConsumeError,
                EnrollmentConsumptionService,
            };
            use crate::identity::{
                CredentialReference, ExpiryResult, IdentityId, PrincipalKind, TransitionOutcome,
            };
            use crate::test_support_channel::{RecordingSink, RingSigner, STATE_DIRECTORY, id};
            use crate::test_support_transitions::{
                ADMINISTRATOR, EXTENSION, binding, connection, consume_enrollment,
                consume_enrollment_with_credential, create_enrollment, paired_proof, registered,
                transition,
            };
            use crate::transition::SecurityTransitions;

            let deadline = || ExpiryResult::valid(600_000).expect("bounded ten-minute deadline");
            let clock = EnrollmentClock::new(1_000, deadline());
            let mut observed = Vec::new();

            // One administrator opens one enrollment, and one pairing peer holds one proof
            // for it. Every refusal below is that peer missing one bound.
            let open_pairing = |transitions: &SecurityTransitions,
                                enrollment,
                                idempotency,
                                connection_value|
             -> (EnrollmentChannel, crate::enrollment::EnrollmentProof) {
                let administrator_signer = RingSigner::generate();
                let administrator = registered(
                    transitions,
                    ADMINISTRATOR,
                    PrincipalKind::NativeAdmin,
                    &administrator_signer,
                );
                assert_eq!(
                    create_enrollment(
                        transitions,
                        enrollment,
                        administrator.id(),
                        idempotency,
                        0,
                        deadline(),
                        Some(&mut RecordingSink::default()),
                    ),
                    Ok(TransitionOutcome::Committed)
                );
                let mut channel = EnrollmentChannel::open(connection(connection_value), 1)
                    .expect("native pairing channel");
                let proof = paired_proof(transitions, enrollment, &mut channel, id(EXTENSION));
                (channel, proof)
            };

            // An enrollment nobody opened: a consumption naming one is a replay.
            let transitions = SecurityTransitions::default();
            let (mut channel, proof) = open_pairing(&transitions, transition(0xd0), 0xd00, 0xd0);
            let mut sink = RecordingSink::default();
            let rejection = consume_enrollment(
                &transitions,
                transition(0xdf),
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                0xd01,
                0,
                Some(&mut sink),
            )
            .expect_err("an enrollment nobody opened consumes nothing");
            assert_eq!(rejection.code(), crate::FailureCode::ReplayDetected);
            observed.push((
                "consumption of an enrollment nobody opened",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // An epoch the enrollment does not hold.
            let transitions = SecurityTransitions::default();
            let enrollment = transition(0xd1);
            let (mut channel, proof) = open_pairing(&transitions, enrollment, 0xd10, 0xd1);
            let mut sink = RecordingSink::default();
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                0xd11,
                1,
                Some(&mut sink),
            )
            .expect_err("an enrollment is bound to the epoch that opened it");
            assert_eq!(rejection.code(), crate::FailureCode::StaleEpoch);
            observed.push((
                "consumption at an epoch the enrollment does not hold",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // A principal already registered: pairing it again is a replay.
            let transitions = SecurityTransitions::default();
            let enrollment = transition(0xd2);
            let (mut channel, proof) = open_pairing(&transitions, enrollment, 0xd20, 0xd2);
            let extension_signer = RingSigner::generate();
            registered(
                &transitions,
                EXTENSION,
                PrincipalKind::McpClient,
                &extension_signer,
            );
            let mut sink = RecordingSink::default();
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                0xd21,
                0,
                Some(&mut sink),
            )
            .expect_err("a registered principal is not paired a second time");
            assert_eq!(rejection.code(), crate::FailureCode::ReplayDetected);
            observed.push((
                "consumption for a principal already registered",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // A proof naming an identity other than the one being paired.
            let transitions = SecurityTransitions::default();
            let enrollment = transition(0xd3);
            let (mut channel, proof) = open_pairing(&transitions, enrollment, 0xd30, 0xd3);
            let mut sink = RecordingSink::default();
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                IdentityId::new(Uuid::from_u128(0xd3f)),
                &proof,
                &clock,
                &mut channel,
                0xd31,
                0,
                Some(&mut sink),
            )
            .expect_err("a proof for another identity pairs nobody");
            assert_eq!(rejection.code(), crate::FailureCode::AuthenticationFailed);
            observed.push((
                "a proof naming an identity other than the pairing one",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // A credential outside the enrollment owner's own binding.
            let transitions = SecurityTransitions::default();
            let enrollment = transition(0xd4);
            let (mut channel, proof) = open_pairing(&transitions, enrollment, 0xd40, 0xd4);
            let mut sink = RecordingSink::default();
            let foreign = CredentialReference::new(
                "fixture-store",
                "foreign-key-0",
                IdentityId::new(Uuid::from_u128(0xd4e)),
                id(STATE_DIRECTORY),
            )
            .expect("bounded credential reference");
            let rejection = consume_enrollment_with_credential(
                &transitions,
                enrollment,
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                0xd41,
                0,
                foreign,
                Some(&mut sink),
            )
            .expect_err("a credential another daemon holds binds nothing here");
            assert_eq!(
                rejection.code(),
                crate::FailureCode::CredentialStoreMismatch
            );
            observed.push((
                "a credential outside the enrollment owner's binding",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // An enrollment past its deadline, at the enrollment host itself.
            let capability = ChromeCapability::reported(&binding(), true, true)
                .expect("reported browser capability");
            let mut sink = RecordingSink::default();
            let mut expired = pairing_bundle(0xd50);
            let mut open = pairing_channel();
            assert_eq!(
                EnrollmentConsumptionService::default().consume_proof(
                    &mut expired,
                    &unsigned_proof(id(EXTENSION)),
                    id(EXTENSION),
                    &EnrollmentClock::new(600_000, deadline()),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut sink),
                ),
                Err(EnrollmentConsumeError::Expired)
            );
            observed.push((
                "a proof against an enrollment past its deadline",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            // The same proof presented twice: the second is the replay.
            let service = EnrollmentConsumptionService::default();
            let mut sink = RecordingSink::default();
            let mut spent = pairing_bundle(0xd60);
            let mut open = pairing_channel();
            let valid = signed_pairing_proof(&mut spent, &open, id(EXTENSION));
            assert!(
                service
                    .consume_proof(
                        &mut spent,
                        &valid,
                        id(EXTENSION),
                        &pairing_clock(1_000),
                        &binding(),
                        &capability,
                        &mut open,
                        Some(&mut sink),
                    )
                    .is_ok(),
                "one valid proof pairs once"
            );
            let mut sink = RecordingSink::default();
            assert_eq!(
                service.consume_proof(
                    &mut spent,
                    &valid,
                    id(EXTENSION),
                    &pairing_clock(1_001),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut sink),
                ),
                Err(EnrollmentConsumeError::AlreadyConsumed)
            );
            observed.push((
                "a proof against an enrollment already consumed",
                sink.events
                    .last()
                    .expect("a refused consumption states one fact")
                    .code(),
            ));

            observed
        }

        /// The replay facts an elapsed or spent enrollment owes, both halves.
        ///
        /// The fact is required before the refusal is returned, so an unavailable sink must
        /// leave the enrollment, the proof budget, the registry, and the pairing channel
        /// exactly as they were: a replay nobody could record is not a replay quietly
        /// accepted, and it is not a pairing either.
        #[test]
        fn an_elapsed_or_spent_enrollment_states_its_replay_or_the_refusal_fails_closed() {
            use crate::enrollment::{
                ChromeCapability, EnrollmentChannelState, EnrollmentClock, EnrollmentConsumeError,
                EnrollmentConsumptionService,
            };
            use crate::identity::{EnrollmentLifecycle, ExpiryResult};
            use crate::test_support_channel::{RecordingSink, id};
            use crate::test_support_transitions::{EXTENSION, binding};

            let identity = id(EXTENSION);
            let capability = ChromeCapability::reported(&binding(), true, true)
                .expect("reported browser capability");
            let elapsed = || {
                EnrollmentClock::new(
                    600_000,
                    ExpiryResult::valid(600_000).expect("bounded ten-minute deadline"),
                )
            };

            // An available sink observes the replay, and the refusal states nothing else.
            let service = EnrollmentConsumptionService::default();
            let mut accepting = RecordingSink::default();
            let mut recorded = pairing_bundle(0x7d0);
            let mut open = pairing_channel();
            assert_eq!(
                service.consume_proof(
                    &mut recorded,
                    &unsigned_proof(identity),
                    identity,
                    &elapsed(),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut accepting),
                ),
                Err(EnrollmentConsumeError::Expired)
            );
            let fact = accepting
                .events
                .last()
                .expect("an elapsed deadline states its replay");
            assert_eq!(fact.code(), events::SecurityCode::ReplayDetected);
            assert_eq!(fact.outcome(), events::EventOutcome::Rejected);
            assert_eq!(fact.next_action(), events::SafeNextAction::Discard);
            assert_eq!(fact.principal_id(), Some(identity.get()));
            assert!(
                fact.metadata().is_empty(),
                "a replay fact carries no metadata to redact"
            );
            assert_eq!(recorded.enrollment().failed_proofs(), 0);
            assert_eq!(recorded.lifecycle(), EnrollmentLifecycle::Pending);
            assert_eq!(service.registered_fingerprint(identity), None);

            // An unavailable sink fails closed, and the enrollment is untouched.
            let service = EnrollmentConsumptionService::default();
            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };
            let mut untouched = pairing_bundle(0x7d1);
            let mut still_open = pairing_channel();
            assert_eq!(
                service.consume_proof(
                    &mut untouched,
                    &unsigned_proof(identity),
                    identity,
                    &elapsed(),
                    &binding(),
                    &capability,
                    &mut still_open,
                    Some(&mut unavailable),
                ),
                Err(EnrollmentConsumeError::EventUnavailable)
            );
            assert_eq!(untouched.enrollment().failed_proofs(), 0);
            assert_eq!(untouched.lifecycle(), EnrollmentLifecycle::Pending);
            assert_eq!(still_open.state(), EnrollmentChannelState::Open);
            assert_eq!(service.registered_fingerprint(identity), None);
            assert!(unavailable.events.is_empty());

            // The spent enrollment, both halves. One valid proof pairs once; the second
            // presentation is the replay, and it is refused whether or not it can be stated.
            let service = EnrollmentConsumptionService::default();
            let mut accepting = RecordingSink::default();
            let mut spent = pairing_bundle(0x7d2);
            let mut open = pairing_channel();
            let valid = signed_pairing_proof(&mut spent, &open, identity);
            let paired = service
                .consume_proof(
                    &mut spent,
                    &valid,
                    identity,
                    &pairing_clock(1_000),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut accepting),
                )
                .expect("one valid proof pairs once");
            assert_eq!(
                service.registered_fingerprint(identity),
                Some(paired.clone())
            );
            let mut accepting = RecordingSink::default();
            assert_eq!(
                service.consume_proof(
                    &mut spent,
                    &valid,
                    identity,
                    &pairing_clock(1_001),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut accepting),
                ),
                Err(EnrollmentConsumeError::AlreadyConsumed)
            );
            assert_eq!(
                accepting
                    .events
                    .last()
                    .expect("a spent enrollment states its replay")
                    .code(),
                events::SecurityCode::ReplayDetected
            );
            assert_eq!(spent.enrollment().failed_proofs(), 0);
            assert_eq!(
                service.registered_fingerprint(identity),
                Some(paired.clone())
            );

            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };
            assert_eq!(
                service.consume_proof(
                    &mut spent,
                    &valid,
                    identity,
                    &pairing_clock(1_002),
                    &binding(),
                    &capability,
                    &mut open,
                    Some(&mut unavailable),
                ),
                Err(EnrollmentConsumeError::EventUnavailable)
            );
            assert_eq!(spent.enrollment().failed_proofs(), 0);
            assert_eq!(service.registered_fingerprint(identity), Some(paired));
            assert!(unavailable.events.is_empty());
        }

        /// The facts a refused pairing transition owes, both halves.
        ///
        /// Each of these refusals precedes the proof consumption, so an unavailable sink
        /// costs nothing to honour: the refusal becomes `event_sink.unavailable`, the
        /// enrollment stays pending, and no principal is registered. The positive control is
        /// the same boundary pairing successfully with a sink that accepts.
        #[test]
        fn an_unrecordable_consumption_refusal_fails_closed_and_pairs_nothing() {
            use crate::enrollment::{EnrollmentChannel, EnrollmentClock};
            use crate::identity::{
                EnrollmentLifecycle, ExpiryResult, IdentityId, PrincipalKind, TransitionOutcome,
            };
            use crate::test_support_channel::{RecordingSink, RingSigner, id};
            use crate::test_support_transitions::{
                ADMINISTRATOR, EXTENSION, connection, consume_enrollment, create_enrollment,
                paired_proof, registered, transition,
            };
            use crate::transition::SecurityTransitions;

            let deadline = || ExpiryResult::valid(600_000).expect("bounded ten-minute deadline");
            let clock = EnrollmentClock::new(1_000, deadline());
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &administrator_signer,
            );
            let enrollment = transition(0xe0);
            assert_eq!(
                create_enrollment(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    0xe00,
                    0,
                    deadline(),
                    Some(&mut RecordingSink::default()),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let mut channel =
                EnrollmentChannel::open(connection(0xe0), 1).expect("native pairing channel");
            let proof = paired_proof(&transitions, enrollment, &mut channel, id(EXTENSION));
            let mut unavailable = RecordingSink {
                events: Vec::new(),
                unavailable: true,
            };

            // A replay: an enrollment nobody opened, refused by a sink that cannot record.
            let rejection = consume_enrollment(
                &transitions,
                transition(0xef),
                id(EXTENSION),
                &proof,
                &clock,
                &mut channel,
                0xe01,
                0,
                Some(&mut unavailable),
            )
            .expect_err("a replay nobody can record is still refused");
            assert_eq!(rejection.code(), crate::FailureCode::EventSinkUnavailable);

            // An authentication failure: a proof for another identity, same sink.
            let rejection = consume_enrollment(
                &transitions,
                enrollment,
                IdentityId::new(Uuid::from_u128(0xe0f)),
                &proof,
                &clock,
                &mut channel,
                0xe02,
                0,
                Some(&mut unavailable),
            )
            .expect_err("an authentication failure nobody can record is still refused");
            assert_eq!(rejection.code(), crate::FailureCode::EventSinkUnavailable);
            assert!(
                unavailable.events.is_empty(),
                "an unavailable sink records neither refusal"
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Pending),
                "an unrecordable refusal consumes nothing"
            );
            assert!(transitions.registered_principal(id(EXTENSION)).is_none());
            assert!(
                transitions
                    .registered_principal(IdentityId::new(Uuid::from_u128(0xe0f)))
                    .is_none()
            );

            // The positive control: the same boundary, the same proof, a sink that accepts.
            let mut accepting = RecordingSink::default();
            assert_eq!(
                consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    0xe03,
                    0,
                    Some(&mut accepting),
                ),
                Ok(TransitionOutcome::Committed)
            );
            assert_eq!(
                transitions.enrollment_lifecycle(enrollment),
                Some(EnrollmentLifecycle::Consumed)
            );
            assert!(transitions.registered_principal(id(EXTENSION)).is_some());
            assert_eq!(
                accepting
                    .events
                    .last()
                    .expect("a committed pairing emits")
                    .code(),
                events::SecurityCode::EnrollmentAccepted
            );
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

        /// Every acceptance failure class, driven to its failure through the production
        /// path that classifies it.
        ///
        /// `contracts/failures-events.md` bounds a failure with one stable boundary, one
        /// code, and one safe next action. Constructing a `FailureCode` proves nothing
        /// about that mapping, so each row below is a real refused operation and the
        /// triple is read off the value that operation returned.
        fn sc009_acceptance_matrix() -> Vec<(&'static str, crate::SecurityFailure)> {
            let mut matrix = sc009_handshake_failures();
            matrix.extend(sc009_frame_failures());
            matrix.extend(sc009_route_failures());
            matrix.extend(sc009_transition_failures());
            matrix
        }

        fn sc009_handshake_failures() -> Vec<(&'static str, crate::SecurityFailure)> {
            use crate::test_support_channel::{
                CONNECTION, DAEMON, ENDPOINT, PRINCIPAL, RecordingSink, RingSigner,
                establish_pair_at_epochs, establish_pair_with_ranges, fixture_principal, id,
            };
            let mut sink = RecordingSink::default();
            let client_signer = RingSigner::generate();
            let daemon_signer = RingSigner::generate();
            let configs = |epoch: u64, client_range: (u16, u16), server_range: (u16, u16)| {
                (
                    crate::ClientHandshakeConfig::new(
                        ENDPOINT,
                        id(PRINCIPAL),
                        client_signer.public_key().clone(),
                        id(DAEMON),
                        daemon_signer.public_key().clone(),
                        epoch,
                        client_range.0,
                        client_range.1,
                    )
                    .expect("bounded client configuration"),
                    crate::ServerHandshakeConfig::new(
                        ENDPOINT,
                        fixture_principal(client_signer.public_key().clone(), epoch),
                        id(DAEMON),
                        daemon_signer.public_key().clone(),
                        server_range.0,
                        server_range.1,
                        crate::ConnectionId::new(Uuid::from_u128(CONNECTION)),
                    )
                    .expect("bounded server configuration"),
                )
            };

            // A client hello whose transcript-bound endpoint was altered in flight.
            let (client, server) = configs(7, (1, 3), (2, 4));
            let (_, mut hello) = crate::ClientHandshake::start(client).unwrap();
            let needle = ENDPOINT.as_bytes();
            let at = hello
                .windows(needle.len())
                .position(|part| part == needle)
                .expect("the endpoint travels in the hello");
            // A different but perfectly well-formed authority, so the refusal is the
            // transcript binding and not an encoding fault.
            assert_eq!(hello[at], b'1');
            hello[at] = b'8';
            let authentication =
                crate::ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink)
                    .expect_err("an altered endpoint never authenticates");

            // A daemon that committed to a contract outside the range it offered.
            let (client, server) = configs(7, (1, 3), (2, 4));
            let (client_pending, hello) = crate::ClientHandshake::start(client).unwrap();
            let (_, mut proof) =
                crate::ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink).unwrap();
            let selected = 4 + b"server-proof".len() + hello.len() + 4;
            proof[selected] = b'2';
            let downgrade = client_pending
                .finish(&proof, &client_signer, &mut sink)
                .expect_err("a substituted selection never derives a key");

            vec![
                ("handshake: altered transcript endpoint", authentication),
                ("handshake: substituted contract selection", downgrade),
                (
                    "handshake: disjoint contract ranges",
                    establish_pair_with_ranges(7, (1, 1), (2, 2))
                        .expect_err("disjoint ranges create no channel"),
                ),
                (
                    "handshake: client epoch the registry moved past",
                    establish_pair_at_epochs(6, 7, (1, 3), (2, 4))
                        .expect_err("a retired epoch creates no channel"),
                ),
            ]
        }

        fn sc009_frame_failures() -> Vec<(&'static str, crate::SecurityFailure)> {
            use crate::test_support_channel::{
                OWNER, RecordingSink, SCOPE, capability, establish_pair, id, owned_operation,
            };
            let mut sink = RecordingSink::default();
            let output =
                crate::AuthorizedOutput::filtered(crate::PayloadKind::Command, b"probe".to_vec())
                    .unwrap();

            let (_, mut daemon) = establish_pair(7);
            let malformed = daemon
                .receive(
                    &[0, 0, 0, 1, 1],
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect_err("a frame shorter than its header is refused");

            let (_, mut daemon) = establish_pair(7);
            let mut oversized = vec![0u8; 4];
            oversized.copy_from_slice(&1_048_577u32.to_be_bytes());
            let resource = daemon
                .receive(
                    &oversized,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect_err("a declared length above the bound is refused");

            let (mut client, mut daemon) = establish_pair(7);
            let frame = client.send(&output, &mut sink).unwrap();
            daemon
                .receive(
                    &frame,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect("the first delivery is accepted");
            let replay = daemon
                .receive(
                    &frame,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect_err("the same counter never opens twice");

            let (mut client, mut daemon) = establish_pair(7);
            let mut skipped = client.send(&output, &mut sink).unwrap();
            skipped[21..29].copy_from_slice(&1u64.to_be_bytes());
            let counter = daemon
                .receive(
                    &skipped,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect_err("a skipped counter is refused");

            let (mut client, mut daemon) = establish_pair(7);
            let mut tampered = client.send(&output, &mut sink).unwrap();
            *tampered.last_mut().unwrap() ^= 1;
            let cryptographic = daemon
                .receive(
                    &tampered,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut sink,
                )
                .expect_err("an altered tag is refused");

            // An action above the ceiling this channel established with.
            let (mut client, mut daemon) = establish_pair(7);
            let frame = client.send(&output, &mut sink).unwrap();
            let denied = daemon
                .receive(
                    &frame,
                    &crate::SessionInput::new(
                        capability(crate::CapabilityAction::ManagePrincipals, "matinee"),
                        crate::PayloadKind::Command,
                        crate::ObjectOwner::Owned(id(OWNER)),
                        None,
                    ),
                    &mut sink,
                )
                .expect_err("an action above the ceiling is denied");

            // An object owned by someone else: the same result an unknown object gets.
            let (mut client, mut daemon) = establish_pair(7);
            let frame = client.send(&output, &mut sink).unwrap();
            let not_found = daemon
                .receive(
                    &frame,
                    &crate::SessionInput::new(
                        capability(crate::CapabilityAction::Read, SCOPE),
                        crate::PayloadKind::Command,
                        crate::ObjectOwner::Owned(id(0x777)),
                        None,
                    ),
                    &mut sink,
                )
                .expect_err("a cross-owner object is never disclosed");

            // The decision event is required, so a sink that cannot record it mints no
            // authorized input.
            let (mut client, mut daemon) = establish_pair(7);
            let frame = client.send(&output, &mut sink).unwrap();
            let mut unavailable = FakeEventSink::unavailable();
            let sink_unavailable = daemon
                .receive(
                    &frame,
                    &owned_operation(crate::PayloadKind::Command),
                    &mut unavailable,
                )
                .expect_err("an unrecordable decision authorizes nothing");

            vec![
                ("frame: shorter than its own header", malformed),
                ("frame: declared length above the bound", resource),
                ("frame: duplicate counter", replay),
                ("frame: skipped counter", counter),
                ("frame: altered authentication tag", cryptographic),
                ("authorization: action above the ceiling", denied),
                ("authorization: cross-owner object", not_found),
                (
                    "authorization: decision event unavailable",
                    sink_unavailable,
                ),
            ]
        }

        fn sc009_route_failures() -> Vec<(&'static str, crate::SecurityFailure)> {
            use crate::test_support_channel::RecordingSink;
            use crate::{LoopbackHost, StateBearingRequest, StateBearingRoute};
            const ALLOWED: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
            let route = StateBearingRoute::new(
                LoopbackHost::Ipv4,
                7777,
                "/matinee",
                "matinee.secure-channel.v1",
                [ALLOWED],
            )
            .expect("the configured loopback route");
            let mut sink = RecordingSink::default();
            let endpoint = route
                .admit(
                    &StateBearingRequest {
                        authority: "10.0.0.5:7777",
                        route: "/matinee",
                        subprotocol: "matinee.secure-channel.v1",
                        origin: ALLOWED,
                    },
                    1_000,
                    &mut sink,
                )
                .expect_err("a non-loopback authority is never admitted");
            let origin = route
                .admit(
                    &StateBearingRequest {
                        authority: "127.0.0.1:7777",
                        route: "/matinee",
                        subprotocol: "matinee.secure-channel.v1",
                        origin: "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba",
                    },
                    1_000,
                    &mut sink,
                )
                .expect_err("an unpaired Origin is never admitted");
            assert_eq!(
                sink.events.len(),
                1,
                "the rejected Origin is a required fact; the endpoint refusal is not"
            );
            vec![
                ("route: non-loopback authority", endpoint),
                ("route: unpaired browser Origin", origin),
            ]
        }

        fn sc009_transition_failures() -> Vec<(&'static str, crate::SecurityFailure)> {
            use crate::adapters::credential_store::{CredentialBinding, CredentialStoreError};
            use crate::identity::{
                ExpiryResult, PrincipalKind, TransitionOperation, TransitionOutcome,
            };
            use crate::test_support_channel::{
                DAEMON, RecordingSink, RingSigner, STATE_DIRECTORY, establish_pair_for, id,
                registered_principal,
            };
            use crate::test_support_fakes::{FakeCredentialStore, FakeOsPipe};
            use crate::test_support_transitions::{
                ADMINISTRATOR, EXTENSION, ceiling, connection, create_enrollment, input, key,
                live_channel, long_term_key, receive, registered, request, revoke, transition,
            };
            use crate::transition::{BootstrapMaterial, SecurityTransitions, TransitionMaterial};

            // A snapshot two peers agreed on that the registry never held.
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let _live = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut sink = RecordingSink::default();
            let forged = registered_principal(
                EXTENSION,
                PrincipalKind::NativeAdmin,
                signer.public_key().clone(),
                ceiling(),
                0,
            );
            let (_, forged_daemon) = establish_pair_for(&forged, &signer, connection(0x910))
                .expect("two peers can agree on a snapshot the registry never held");
            let mismatch = transitions
                .register_channel(forged_daemon, &mut sink)
                .expect_err("a forged snapshot is never admitted")
                .failure();

            // A revoked principal still holding a live channel.
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let principal = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);
            let mut client = live_channel(&transitions, &principal, &signer, 0x920);
            let frame = request(&mut client, &mut sink);
            assert_eq!(
                revoke(
                    &transitions,
                    principal.id(),
                    "administrator",
                    0x921,
                    0,
                    Some(&mut sink),
                ),
                Ok(TransitionOutcome::Committed)
            );
            let revoked = receive(&transitions, connection(0x920), &frame, &mut sink)
                .expect_err("a revoked principal never authenticates a frame");

            // A deadline the host could not decide: nothing is asserted either way.
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &signer,
            );
            let unknown = create_enrollment(
                &transitions,
                transition(0x930),
                administrator.id(),
                0x931,
                0,
                ExpiryResult::uncertain(600_000),
                Some(&mut sink),
            )
            .expect_err("an uncertain deadline decides nothing")
            .failure();

            // The host proof budget: refusals inside one window, then the rate limit.
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let administrator = registered(
                &transitions,
                ADMINISTRATOR,
                PrincipalKind::NativeAdmin,
                &signer,
            );
            let mut rate_limited = None;
            let mut refusals = 0usize;
            for attempt in 0..32u128 {
                let enrollment = transition(0x940 + attempt);
                create_enrollment(
                    &transitions,
                    enrollment,
                    administrator.id(),
                    0x960 + attempt,
                    0,
                    ExpiryResult::valid(600_000).expect("bounded deadline"),
                    Some(&mut sink),
                )
                .expect("the administrator opens one enrollment");
                let mut channel =
                    crate::enrollment::EnrollmentChannel::open(connection(0x980 + attempt), 1)
                        .expect("native pairing channel");
                let clock = crate::enrollment::EnrollmentClock::new(
                    1_000,
                    ExpiryResult::valid(600_000).expect("bounded deadline"),
                );
                let proof = crate::enrollment::EnrollmentProof {
                    identity: id(EXTENSION),
                    signature: vec![0; 8],
                    long_term_public_key: long_term_key(),
                };
                let rejection = crate::test_support_transitions::consume_enrollment(
                    &transitions,
                    enrollment,
                    id(EXTENSION),
                    &proof,
                    &clock,
                    &mut channel,
                    0x9a0 + attempt,
                    0,
                    Some(&mut sink),
                )
                .expect_err("a proof no one-time key signed never pairs");
                if rejection.code() == crate::FailureCode::RateLimited {
                    rate_limited = Some(rejection.failure());
                    break;
                }
                refusals += 1;
            }
            let rate_limited =
                rate_limited.expect("the host budget rate-limits a bounded run of refusals");
            assert!(
                refusals > 0,
                "the budget was spent by real refusals, not by the first attempt"
            );

            // The platform credential service is down while a bootstrap needs it.
            let transitions = SecurityTransitions::default();
            let administrator_signer = RingSigner::generate();
            let daemon_signer = RingSigner::generate();
            let envelope = crate::adapters::os_pipe::BootstrapEnvelope {
                nonce: [11; 32],
                state_directory: id(STATE_DIRECTORY).get(),
                daemon: id(DAEMON).get(),
                bootstrap: Uuid::from_u128(0x9b0),
                public_key: *administrator_signer.public_key().as_bytes(),
            };
            let encoded = envelope.encode();
            let store = FakeCredentialStore::new().with_error(
                CredentialBinding::for_identities(envelope.state_directory, envelope.daemon),
                CredentialStoreError::Unavailable,
            );
            let pipe = FakeOsPipe::present(9);
            let store_unavailable = transitions
                .apply(
                    &crate::SecurityCommand::Bootstrap {
                        state_directory: id(STATE_DIRECTORY),
                        idempotency: key(0x9c0),
                    },
                    &input(
                        TransitionOperation::Bootstrap,
                        0x9c0,
                        0,
                        TransitionOutcome::Committed,
                    ),
                    TransitionMaterial::Bootstrap(BootstrapMaterial::with_store_for_test(
                        &pipe,
                        &encoded,
                        b"native://matinee",
                        crate::transition::DaemonSelf {
                            public_key: daemon_signer.public_key(),
                            contract_min: 1,
                            contract_max: 1,
                        },
                        &store,
                    )),
                    Some(&mut sink),
                    crate::events::EventTime(5),
                )
                .expect_err("an unavailable credential service commits no bootstrap")
                .failure();

            vec![
                ("transition: forged principal snapshot", mismatch),
                ("transition: revoked principal frame", revoked),
                ("transition: undecidable enrollment deadline", unknown),
                ("transition: host proof budget exhausted", rate_limited),
                (
                    "transition: credential service unavailable",
                    store_unavailable,
                ),
            ]
        }

        /// SC-009: every security failure in the acceptance matrix maps to exactly one
        /// stable redacted failure class, boundary, and safe next action.
        ///
        /// The proof is two-sided. Coverage: every class in the closed taxonomy is
        /// reached by a real refused operation, so no class is decorative. Injectivity:
        /// the class determines the triple, so no failure yields two triples and no two
        /// distinct classes collapse into one. The one conflation the contract requires
        /// is checked separately, because it is deliberate: an unknown, a cross-owner,
        /// and an unauthorized object must all answer `object.not_found`.
        #[test]
        fn sc009_every_acceptance_failure_maps_to_one_stable_redacted_triple() {
            use std::collections::BTreeMap;

            let matrix = sc009_acceptance_matrix();

            // Stability, measured rather than re-read: a second independent run of the
            // same matrix generates fresh keys, nonces and connection state, so a class
            // that depended on incidental data would move here.
            let again = sc009_acceptance_matrix();
            assert_eq!(matrix.len(), again.len());
            for ((case, first), (repeated, second)) in matrix.iter().zip(&again) {
                assert_eq!(case, repeated, "the matrix order is fixed");
                assert_eq!(
                    (first.boundary(), first.code(), first.safe_next_action()),
                    (second.boundary(), second.code(), second.safe_next_action()),
                    "{case}: the triple is stable across independent runs"
                );
            }

            let mut by_triple: BTreeMap<(&str, &str, &str), Vec<&str>> = BTreeMap::new();
            let mut by_code: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
            let mut facts: BTreeMap<&str, Vec<crate::SecurityCode>> = BTreeMap::new();

            for (case, failure) in &matrix {
                let triple = (
                    failure.boundary().as_str(),
                    failure.code().as_str(),
                    failure.safe_next_action().as_str(),
                );
                by_triple.entry(triple).or_default().push(case);
                by_code
                    .entry(triple.1)
                    .or_default()
                    .push((triple.0, triple.2));
                // The redacted projection that travels in an event names the same three
                // closed values the failure reported to its caller.
                let redacted = failure.redacted();
                assert_eq!(
                    (
                        redacted.0.as_str(),
                        redacted.1.as_str(),
                        redacted.2.as_str()
                    ),
                    triple,
                    "{case}: the redacted projection diverged from the failure"
                );
                facts
                    .entry(triple.1)
                    .or_default()
                    .push(crate::channel::event_code(failure.code()));
            }

            // Injectivity: one class never presents two different boundaries or actions,
            // whichever production path produced it.
            for (code, observed) in &by_code {
                let first = observed[0];
                assert!(
                    observed.iter().all(|entry| *entry == first),
                    "{code} reported more than one boundary or safe action: {observed:?}"
                );
            }

            // And one class never becomes two different recorded facts, so a reader
            // cannot tell where the channel died from the fact it was given.
            for (code, observed) in &facts {
                let first = observed[0];
                assert!(
                    observed.iter().all(|fact| *fact == first),
                    "{code} was recorded as more than one fact: {observed:?}"
                );
            }

            // Coverage: every class the closed taxonomy declares was reached by a real
            // refused operation. A class missing here is unreachable in production and a
            // class here that is not declared cannot exist.
            let reached: std::collections::BTreeSet<&str> = by_code.keys().copied().collect();
            let declared: std::collections::BTreeSet<&str> = SC009_DECLARED_CLASSES
                .iter()
                .map(|code| code.as_str())
                .collect();
            assert_eq!(
                reached, declared,
                "every declared failure class must be driven by a production path"
            );
            assert_eq!(
                SC009_DECLARED_CLASSES.len(),
                19,
                "the closed acceptance-failure taxonomy"
            );

            // One-to-one, the direction that can actually break: the matrix holds 19
            // distinct refused operations and they produce 19 distinct classes, so no two
            // acceptance failures the contract separates collapse into one triple. The
            // boundary and the action may legitimately be shared -- `malformed.input` and
            // `authentication.cryptographic` both say discard and reconnect -- which is
            // why the class is what has to stay distinct.
            assert_eq!(
                matrix.len(),
                SC009_DECLARED_CLASSES.len(),
                "one acceptance condition per declared class"
            );
            assert_eq!(
                by_code.len(),
                matrix.len(),
                "two distinct acceptance conditions collapsed into one class"
            );
            assert_eq!(
                by_triple.len(),
                matrix.len(),
                "two distinct acceptance conditions collapsed into one triple"
            );

            // The deliberate conflation: existence is never disclosed, so an
            // unauthorized object and an unknown object share one boundary while keeping
            // distinct safe actions inside it.
            let denied = matrix
                .iter()
                .find(|(_, failure)| failure.code() == crate::FailureCode::AuthorizationDenied)
                .expect("the denial row");
            let not_found = matrix
                .iter()
                .find(|(_, failure)| failure.code() == crate::FailureCode::ObjectNotFound)
                .expect("the not-found row");
            assert_eq!(denied.1.boundary(), not_found.1.boundary());
            assert_eq!(
                not_found.1.safe_next_action(),
                crate::SafeNextAction::DoNotInferObjectExistence
            );

            // No triple carries a protected field. `Authorization` is deliberately not
            // in this list: it is the closed boundary name. The header a failure must
            // never carry is checked by its value form instead.
            for (case, failure) in &matrix {
                let rendered = format!("{failure} {failure:?}");
                for forbidden in [
                    "private",
                    "secret",
                    "cookie",
                    "Cookie",
                    "Bearer",
                    "-----BEGIN",
                    "matinee/status",
                    "fixture-store",
                    "principal-key",
                    "extension-key",
                    "native://",
                    "chrome-extension://",
                    "127.0.0.1",
                ] {
                    assert!(
                        !rendered.contains(forbidden),
                        "{case} disclosed {forbidden}: {rendered}"
                    );
                }
            }
        }

        /// The closed acceptance-failure taxonomy, as `failures.rs` declares it.
        const SC009_DECLARED_CLASSES: [crate::FailureCode; 19] = [
            crate::FailureCode::AuthenticationFailed,
            crate::FailureCode::AuthorizationDenied,
            crate::FailureCode::ObjectNotFound,
            crate::FailureCode::CompatibilityUnsupported,
            crate::FailureCode::DowngradeRejected,
            crate::FailureCode::MalformedInput,
            crate::FailureCode::OriginRejected,
            crate::FailureCode::EndpointRejected,
            crate::FailureCode::ReplayDetected,
            crate::FailureCode::CounterMismatch,
            crate::FailureCode::RateLimited,
            crate::FailureCode::CredentialStoreUnavailable,
            crate::FailureCode::CredentialStoreMismatch,
            crate::FailureCode::ResourceLimit,
            crate::FailureCode::StaleEpoch,
            crate::FailureCode::Revoked,
            crate::FailureCode::TransitionUnknown,
            crate::FailureCode::EventSinkUnavailable,
            crate::FailureCode::CryptographicFailure,
        ];
    };
}
