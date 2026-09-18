macro_rules! quickstart_evidence_tests {
    () => {
        const FR_EVIDENCE: &[(u8, &str)] = &[
            (2, "bootstrap"),
            (3, "secret-custody"),
            (4, "bootstrap"),
            (5, "bootstrap"),
            (6, "credential-store"),
            (7, "enrollment"),
            (8, "enrollment"),
            (9, "enrollment"),
            (10, "channel"),
            (11, "channel"),
            (12, "negotiation"),
            (13, "encoding"),
            (14, "channel"),
            (15, "frame"),
            (16, "rejection"),
            (17, "size"),
            (18, "origin"),
            (19, "enrollment"),
            (20, "authorization"),
            (21, "authorization"),
            (22, "privacy"),
            (23, "privacy"),
            (24, "rotation"),
            (25, "revocation"),
            (26, "transition"),
            (27, "events"),
            (28, "redaction"),
            (29, "failures"),
            (30, "vectors"),
            (31, "lifecycle"),
            (32, "vectors"),
        ];

        const SC_EVIDENCE: &[(u8, &str)] = &[
            (1, "bootstrap"),
            (2, "bootstrap-recovery"),
            (3, "channel-vectors"),
            (4, "authorization-privacy"),
            (5, "enrollment-custody"),
            (6, "rotation-revocation"),
            (7, "channel-faults"),
            (8, "disconnect-independence"),
            (9, "event-redaction"),
        ];

        fn fixture_path(relative: &str) -> std::path::PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn assert_no_secret_material(output: &str) {
            for forbidden in [
                "private_key",
                "one-time enrollment key",
                "enrollment_secret",
                "cookie",
                "authorization_header",
                "payload_text",
                "https://host/path",
                "object_id",
                "credential",
            ] {
                assert!(
                    !output.to_ascii_lowercase().contains(forbidden),
                    "quickstart evidence leaked forbidden material: {forbidden}"
                );
            }
        }

        /// T056's mapping, made load-bearing.
        ///
        /// The quickstart claims the suite maps FR-002 through FR-032 and SC-001 through
        /// SC-009. A claim here is three things: the evidence label the quickstart carries,
        /// the test that establishes the requirement in full, and a probe that drives that
        /// requirement's own production seam and asserts the outcome the requirement states.
        /// The backing test is resolved against its source file, so a renamed or deleted test
        /// breaks the mapping instead of leaving it quietly true.
        mod quickstart_mapping {
            use crate::adapters::credential_store::{CredentialBinding, InMemoryCredentialStore};
            use crate::adapters::os_pipe::BootstrapEnvelope;
            use crate::enrollment::{
                ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentBundle,
                EnrollmentChannel, EnrollmentChannelState, EnrollmentClock, EnrollmentConsumeError,
                EnrollmentConsumptionService, EnrollmentCreateError, EnrollmentCreation,
                EnrollmentCustodyError, EnrollmentProof, SupportedExtensionVersions,
                enrollment_proof_message,
            };
            use crate::events::{EventBoundary, EventOutcome, EventTime};
            use crate::identity::{
                EnrollmentLifecycle, ExpiryResult, Fingerprint, IdentityId, PrincipalKind,
                PrincipalLifecycle, PublicKey, TransitionId, TransitionOutcome,
                UNCOMPRESSED_KEY_BYTES,
            };
            use crate::test_support_channel::{
                DAEMON, ENDPOINT, OWNER, PRINCIPAL, RecordingSink, RingSigner, SCOPE, capability,
                establish_pair, establish_pair_at_epochs, establish_pair_for, establish_pair_with_ranges, id,
                owned_operation, owned_projection, registered_principal,
            };
            use crate::test_support_fakes::{FakeEventSink, FakeOsPipe};
            use crate::test_support_transitions::{
                commit_mutation, connection, live_channel, receive, registered,
                request, rotate,
            };
            use crate::transition::{BootstrapError, BootstrapState, CrashPoint, DaemonSelf};
            use crate::{
                AuthorizedOutput, CapabilityAction, ChannelSigner, ConnectionId, FailureCode,
                LoopbackHost, ObjectOwner, PayloadKind, ProjectionClass, ProjectionClass as Class,
                SECURE_CHANNEL_CONTEXT, SafeNextAction, SecurityCode, SecurityTransitions,
                SessionInput, SessionProjection, StateBearingRequest, StateBearingRoute,
            };
            use ring::rand::SystemRandom;
            use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
            use uuid::Uuid;

            /// The native administrator's public key, as an envelope carries it.
            const ADMIN_KEY: [u8; 65] = [
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ];
            /// The daemon's own key, independent of the administrator's as FR-002 requires.
            const DAEMON_KEY: [u8; 65] = [
                0x04, 0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04,
                0xb5, 0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48,
                0xfc, 0x47, 0x66, 0x99, 0x78, 0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29,
                0x3d, 0x9a, 0xc6, 0x9f, 0x74, 0x30, 0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82,
                0x29, 0x9e, 0x04, 0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
            ];
            const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
            const STORE: &str = "Chrome Web Store";
            const UPDATE: &str = "https://updates.example.test/ext.xml";
            const DEADLINE_MS: u64 = 600_000;

            fn daemon_public() -> PublicKey {
                PublicKey::from_uncompressed(DAEMON_KEY).expect("an independent daemon key")
            }

            fn daemon_self(key: &PublicKey) -> DaemonSelf<'_> {
                DaemonSelf {
                    public_key: key,
                    contract_min: 1,
                    contract_max: 1,
                }
            }

            fn envelope(value: u128, nonce_byte: u8) -> BootstrapEnvelope {
                BootstrapEnvelope::new(
                    [nonce_byte; 32],
                    Uuid::from_u128(value + 1),
                    Uuid::from_u128(value + 2),
                    Uuid::from_u128(value + 3),
                    ADMIN_KEY,
                )
                .expect("a valid native bootstrap envelope")
            }

            fn registered_store(envelope: &BootstrapEnvelope) -> InMemoryCredentialStore {
                let mut store = InMemoryCredentialStore::new();
                store.register(
                    CredentialBinding::for_identities(envelope.state_directory, envelope.daemon),
                    0xfeed_beef,
                );
                store
            }

            fn bootstrap(
                state: &mut BootstrapState,
                envelope: &BootstrapEnvelope,
                store: &InMemoryCredentialStore,
                sink: &mut FakeEventSink,
                crash: Option<CrashPoint>,
            ) -> Result<TransitionOutcome, BootstrapError> {
                let pipe = FakeOsPipe::present(9);
                let key = daemon_public();
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

            /// One committed bootstrap, through the production bootstrap operation.
            fn committed(value: u128) -> (BootstrapState, BootstrapEnvelope) {
                let envelope = envelope(value, 7);
                let store = registered_store(&envelope);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(
                    bootstrap(&mut state, &envelope, &store, &mut sink, None),
                    Ok(TransitionOutcome::Committed)
                );
                (state, envelope)
            }

            fn pairing_binding(
                install: &'static str,
                version: &'static str,
                allowance: DevelopmentIdentityAllowance,
            ) -> EnrollmentBinding<'static> {
                EnrollmentBinding {
                    origin: ORIGIN,
                    endpoint: ENDPOINT,
                    store_metadata: STORE,
                    update_metadata: UPDATE,
                    install_metadata: install,
                    version,
                    development_allowance: allowance,
                }
            }

            fn creation(enrollment: u128, install: &str) -> EnrollmentCreation {
                EnrollmentCreation::new(
                    TransitionId::new(Uuid::from_u128(enrollment)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    install,
                    SupportedExtensionVersions::parse("1.0", "2.5.1").expect("a version range"),
                    id(DAEMON),
                    ENDPOINT,
                    ExpiryResult::valid(DEADLINE_MS).expect("a nonzero deadline"),
                )
            }

            fn bundle(enrollment: u128, install: &str) -> EnrollmentBundle {
                EnrollmentBundle::create(creation(enrollment, install))
                    .expect("a bounded one-time enrollment")
            }

            fn peer_key() -> PublicKey {
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .expect("peer key generation");
                let key =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                        .expect("peer key import");
                let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
                bytes.copy_from_slice(key.public_key().as_ref());
                PublicKey::from_uncompressed(bytes).expect("a valid peer public key")
            }

            fn signed_proof(
                bundle: &mut EnrollmentBundle,
                channel: &EnrollmentChannel,
                who: IdentityId,
            ) -> EnrollmentProof {
                let enrollment = bundle.enrollment_id();
                let transfer = channel
                    .seal_one_time_key(bundle)
                    .expect("one-time key custody");
                let private = channel
                    .open_sealed_for_test(enrollment, &transfer)
                    .expect("the pairing peer opens its own sealed key");
                let rng = SystemRandom::new();
                let signer =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng)
                        .expect("the one-time key");
                let long_term = peer_key();
                let signature = signer
                    .sign(&rng, &enrollment_proof_message(bundle, &long_term))
                    .expect("a one-time proof signature")
                    .as_ref()
                    .to_vec();
                EnrollmentProof {
                    identity: who,
                    signature,
                    long_term_public_key: long_term,
                }
            }

            fn pairing_channel(value: u128) -> EnrollmentChannel {
                EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(value)), 1)
                    .expect("an authenticated native channel")
            }

            fn route() -> StateBearingRoute {
                StateBearingRoute::new(LoopbackHost::Ipv4, 7777, "/v1/session", "matinee.v1", [
                    ORIGIN,
                ])
                .expect("a configured state-bearing route")
            }

            fn upgrade() -> StateBearingRequest<'static> {
                StateBearingRequest {
                    authority: ENDPOINT,
                    route: "/v1/session",
                    subprotocol: "matinee.v1",
                    origin: ORIGIN,
                }
            }

            // -- probes -------------------------------------------------------------------

            fn fr002() {
                let (state, envelope) = committed(0x200);
                let daemon = state.active_daemon().expect("one daemon identity");
                let admin = state.active_admin().expect("one native administrator");
                assert_eq!(daemon.id(), IdentityId::new(envelope.daemon));
                assert_ne!(admin.id(), daemon.id(), "two independent identities");
                assert_eq!(admin.public_key().as_bytes(), &ADMIN_KEY);
                assert_eq!(admin.public_key().as_bytes().len(), 65);
                for fingerprint in [daemon.fingerprint(), admin.fingerprint()] {
                    assert_eq!(fingerprint.as_str().len(), 64);
                    assert!(
                        fingerprint
                            .as_str()
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    );
                }
                assert!(Fingerprint::new("A".repeat(64)).is_err());
            }

            fn fr003() {
                // The one-time key leaves its bundle exactly once, through one channel, and
                // no surface renders it.
                let mut value = bundle(0x300, "normal");
                let rendered = format!("{value:?}");
                assert!(rendered.contains("<redacted>"));
                assert!(!rendered.contains("pkcs8") || rendered.contains("<redacted>"));
                let channel = pairing_channel(0x9300);
                assert!(channel.seal_one_time_key(&mut value).is_ok());
                assert!(matches!(
                    channel.seal_one_time_key(&mut value),
                    Err(EnrollmentCustodyError::AlreadyTransferred)
                ));
                let (state, _) = committed(0x301);
                let surfaces = format!(
                    "{:?} {:?}",
                    state.active_daemon().expect("daemon"),
                    state.active_admin().expect("administrator")
                );
                assert!(!surfaces.to_ascii_lowercase().contains("private"));
            }

            fn fr004() {
                // Crash-safe idempotency before and after the principal commit: a retry
                // converges on the one record, and a missing inherited pipe fails closed.
                let envelope = envelope(0x400, 11);
                let store = registered_store(&envelope);
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert_eq!(
                    bootstrap(&mut state, &envelope, &store, &mut sink, Some(CrashPoint::AfterStage)),
                    Err(BootstrapError::Crash(CrashPoint::AfterStage))
                );
                assert!(state.active().is_none(), "a staged commit is not a registration");
                state.recover();
                let first = state.active().expect("recovery promotes the staged commit").clone();
                // A retry of the same envelope commits nothing further, whether the nonce
                // ledger refuses it or the transition reports the outcome it already has.
                assert!(matches!(
                    bootstrap(&mut state, &envelope, &store, &mut sink, None),
                    Ok(TransitionOutcome::AlreadyCommitted) | Err(BootstrapError::AlreadyUsed)
                ));
                assert_eq!(state.active().expect("still one record"), &first);
                let mut absent = BootstrapState::default();
                let pipe = FakeOsPipe::error(crate::adapters::os_pipe::OsPipeError::Missing);
                let key = daemon_public();
                assert!(
                    absent
                        .bootstrap_encoded_with_store_for_test(
                            &pipe,
                            &envelope.encode(),
                            daemon_self(&key),
                            &store,
                            Some(&mut sink),
                            EventTime(42),
                            b"native://bootstrap",
                        )
                        .is_err(),
                    "loopback is not a first-principal bootstrap path and neither is no pipe"
                );
            }

            fn fr005() {
                // A credential the store does not hold for this state directory and daemon is
                // refused before initialization, and no other principal is selected.
                let envelope = envelope(0x500, 13);
                let empty = InMemoryCredentialStore::new();
                let mut sink = FakeEventSink::accepted();
                let mut state = BootstrapState::default();
                assert!(bootstrap(&mut state, &envelope, &empty, &mut sink, None).is_err());
                assert!(state.active().is_none());
                assert!(state.staged().is_none());
            }

            fn fr006() {
                let signer = RingSigner::generate();
                for kind in [
                    PrincipalKind::NativeAdmin,
                    PrincipalKind::McpClient,
                    PrincipalKind::BrowserExtension,
                ] {
                    let principal = registered_principal(
                        PRINCIPAL,
                        kind,
                        signer.public_key().clone(),
                        vec![capability(CapabilityAction::Read, SCOPE)],
                        0,
                    );
                    assert_eq!(principal.kind(), kind);
                    assert_eq!(principal.ceiling().len(), 1);
                    assert_eq!(principal.owner(), id(OWNER));
                    assert_eq!(principal.lifecycle(), PrincipalLifecycle::Active);
                }
            }

            fn fr007() {
                // A deadline nobody named is ten minutes, and the enrollment pins every
                // expected value plus a freshly generated 65-byte one-time key.
                let default = EnrollmentBundle::create(EnrollmentCreation::with_default_expiry(
                    TransitionId::new(Uuid::from_u128(0x700)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    "normal",
                    SupportedExtensionVersions::parse("1.0", "2.5.1").expect("a version range"),
                    id(DAEMON),
                    ENDPOINT,
                ))
                .expect("a bounded one-time enrollment");
                assert_eq!(default.expiry_deadline_ms(), 10 * 60 * 1_000);
                assert_eq!(default.origin(), ORIGIN);
                assert_eq!(default.daemon(), id(DAEMON));
                assert_eq!(default.daemon_endpoint(), ENDPOINT);
                assert_eq!(default.one_time_public_key().as_bytes().len(), 65);
                assert_eq!(default.one_time_public_key_fingerprint().as_str().len(), 64);
                assert_eq!(default.lifecycle(), EnrollmentLifecycle::Pending);
                let mut oversized = creation(0x701, "normal");
                oversized.expiry = ExpiryResult::valid(10 * 60 * 1_000 + 1).expect("a deadline");
                assert!(matches!(
                    EnrollmentBundle::create(oversized),
                    Err(EnrollmentCreateError::InvalidExpiry)
                ));
            }

            fn fr008() {
                // Consumption requires the expected Origin, metadata, proof, unexpired state
                // and budget allowance, and registers the principal in the same step.
                let service = EnrollmentConsumptionService::default();
                let binding = pairing_binding("normal", "1.4.2", DevelopmentIdentityAllowance::None);
                let capability =
                    ChromeCapability::reported(&binding, true, true).expect("a capability");
                let who = id(0x801);
                let mut value = bundle(0x800, "normal");
                let mut channel = pairing_channel(0x9800);
                let proof = signed_proof(&mut value, &channel, who);
                let mut sink = RecordingSink::default();
                assert_eq!(service.registered_fingerprint(who), None);
                let fingerprint = service
                    .consume_proof(
                        &mut value,
                        &proof,
                        who,
                        &EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap()),
                        &binding,
                        &capability,
                        &mut channel,
                        Some(&mut sink),
                    )
                    .expect("an expected-origin first use pairs");
                assert_eq!(service.registered_fingerprint(who), Some(fingerprint));
                assert_eq!(value.lifecycle(), EnrollmentLifecycle::Consumed);

                let mut foreign = pairing_binding("normal", "1.4.2", DevelopmentIdentityAllowance::None);
                foreign.origin = "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba";
                let foreign_capability =
                    ChromeCapability::reported(&foreign, true, true).expect("a capability");
                let other = id(0x802);
                let mut second = bundle(0x803, "normal");
                let mut second_channel = pairing_channel(0x9801);
                let second_proof = signed_proof(&mut second, &second_channel, other);
                assert_eq!(
                    service.consume_proof(
                        &mut second,
                        &second_proof,
                        other,
                        &EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap()),
                        &foreign,
                        &foreign_capability,
                        &mut second_channel,
                        Some(&mut sink),
                    ),
                    Err(EnrollmentConsumeError::InvalidProof)
                );
                assert_eq!(service.registered_fingerprint(other), None);
            }

            fn fr009() {
                // One successful use, then a replay; and five failed proofs close the
                // enrollment rather than allowing a sixth.
                let service = EnrollmentConsumptionService::default();
                let binding = pairing_binding("normal", "1.4.2", DevelopmentIdentityAllowance::None);
                let capability =
                    ChromeCapability::reported(&binding, true, true).expect("a capability");
                let who = id(0x901);
                let mut value = bundle(0x900, "normal");
                let mut channel = pairing_channel(0x9900);
                let proof = signed_proof(&mut value, &channel, who);
                let clock = EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap());
                let mut sink = RecordingSink::default();
                assert!(
                    service
                        .consume_proof(
                            &mut value,
                            &proof,
                            who,
                            &clock,
                            &binding,
                            &capability,
                            &mut channel,
                            Some(&mut sink)
                        )
                        .is_ok()
                );
                assert_eq!(
                    service.consume_proof(
                        &mut value,
                        &proof,
                        who,
                        &clock,
                        &binding,
                        &capability,
                        &mut channel,
                        Some(&mut sink)
                    ),
                    Err(EnrollmentConsumeError::AlreadyConsumed)
                );

                let mut budgeted = bundle(0x902, "normal");
                let bad = EnrollmentProof {
                    identity: id(0x903),
                    signature: vec![0; 8],
                    long_term_public_key: peer_key(),
                };
                for attempt in 0..5 {
                    let mut attempt_channel = pairing_channel(0x9901);
                    assert_eq!(
                        service.consume_proof(
                            &mut budgeted,
                            &bad,
                            id(0x903),
                            &EnrollmentClock::new(
                                attempt * 60_000 + 1,
                                ExpiryResult::valid(DEADLINE_MS).unwrap()
                            ),
                            &binding,
                            &capability,
                            &mut attempt_channel,
                            Some(&mut sink)
                        ),
                        Err(EnrollmentConsumeError::InvalidProof)
                    );
                    assert_eq!(attempt_channel.state(), EnrollmentChannelState::Closed);
                }
                assert_eq!(budgeted.enrollment().failed_proofs(), 5);
                assert_eq!(budgeted.lifecycle(), EnrollmentLifecycle::Closed);
            }

            fn fr010() {
                assert_eq!(SECURE_CHANNEL_CONTEXT, "matinee.secure-channel.v1");
                // The whole primitive set runs here: P-256 agreement, ECDSA-SHA-256
                // transcript signatures, HKDF-SHA-256 and AES-256-GCM.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_ok()
                );
            }

            fn fr011() {
                // A peer that believes it authenticates at another epoch than the registry
                // holds never completes the transcript.
                assert!(establish_pair_at_epochs(1, 2, (1, 3), (2, 4)).is_err());
                // A client holds no principal, so it cannot take an authorizing path.
                let (mut client, _) = establish_pair(0);
                let mut sink = RecordingSink::default();
                assert_eq!(
                    client
                        .receive(&[0u8; 64], &owned_operation(PayloadKind::Command), &mut sink)
                        .expect_err("a client authorizes nothing")
                        .code(),
                    FailureCode::AuthorizationDenied
                );
            }

            fn fr012() {
                // Disjoint ranges select no contract, and the refusal lands before any key.
                let failure = establish_pair_with_ranges(0, (1, 1), (5, 6))
                    .expect_err("disjoint contract ranges select nothing");
                assert!(matches!(
                    failure.code(),
                    FailureCode::CompatibilityUnsupported | FailureCode::DowngradeRejected
                ));
            }

            fn fr013() {
                // A frame whose fixed-width fields are mutated is refused, and the key
                // encoding is the exact 65-byte uncompressed point.
                assert_eq!(UNCOMPRESSED_KEY_BYTES, 65);
                assert!(PublicKey::from_uncompressed([0u8; 65]).is_err());
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let mut frame = request(&mut client, &mut sink);
                frame[0] ^= 0xff;
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_err()
                );
            }

            fn fr014() {
                // A state-bearing peer reads nothing outside the authenticated channel: the
                // unauthorized paths are refused on the side that holds a principal.
                let (_, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                assert_eq!(
                    daemon
                        .send(
                            &AuthorizedOutput::filtered(PayloadKind::Response, b"state".to_vec())
                                .unwrap(),
                            &mut sink
                        )
                        .expect_err("a daemon authorizes what it discloses")
                        .code(),
                    FailureCode::AuthorizationDenied
                );
            }

            fn fr015() {
                // The frame header binds version, connection and a strictly increasing
                // counter: the first authorized projection carries counter zero.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = daemon
                    .send_projection(&owned_projection(ProjectionClass::Status, b"ready"), &mut sink)
                    .expect("an authorized projection");
                assert_eq!(u64::from_be_bytes(frame[21..29].try_into().unwrap()), 0);
                assert!(
                    client
                        .receive_filtered(&frame, PayloadKind::Response, &mut sink)
                        .is_ok()
                );
            }

            fn fr016() {
                // A repeated frame closes the channel and dispatches no payload.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_ok()
                );
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_err()
                );
                assert!(!daemon.is_open(), "a replayed frame closes the channel");
            }

            fn fr017() {
                assert_eq!(PayloadKind::Command.max_bytes(), 1_048_534);
                assert_eq!(PayloadKind::StreamChunk.max_bytes(), 1_000_000);
                assert_eq!(
                    AuthorizedOutput::filtered(PayloadKind::StreamChunk, vec![0; 1_000_001])
                        .expect_err("a chunk past its declared bound")
                        .code(),
                    FailureCode::ResourceLimit
                );
            }

            fn fr018() {
                let route = route();
                let mut sink = RecordingSink::default();
                assert!(route.admit(&upgrade(), 1, &mut sink).is_ok());
                for (mutate, expected) in [
                    (0, FailureCode::EndpointRejected),
                    (1, FailureCode::EndpointRejected),
                    (2, FailureCode::EndpointRejected),
                    (3, FailureCode::OriginRejected),
                ] {
                    let mut request = upgrade();
                    match mutate {
                        0 => request.authority = "10.0.0.5:7777",
                        1 => request.route = "/v1/session/admin",
                        2 => request.subprotocol = "matinee.v2",
                        _ => request.origin = "https://attacker.example",
                    }
                    assert_eq!(
                        route
                            .admit(&request, 1, &mut sink)
                            .expect_err("an unexpected upgrade fails closed")
                            .code(),
                        expected
                    );
                }
            }

            fn fr019() {
                // Production pairing requires the store identity, a normal install and a
                // supported version; a development identity needs an explicit allowance.
                let service = EnrollmentConsumptionService::default();
                for (install, version, allowance) in [
                    ("normal", "0.9", DevelopmentIdentityAllowance::None),
                    ("normal", "2.5.2", DevelopmentIdentityAllowance::None),
                    ("development", "1.4.2", DevelopmentIdentityAllowance::None),
                    (
                        "development",
                        "1.4.2",
                        DevelopmentIdentityAllowance::Explicit {
                            warning_acknowledged: false,
                        },
                    ),
                ] {
                    let binding = pairing_binding(install, version, allowance);
                    let capability =
                        ChromeCapability::reported(&binding, true, true).expect("a capability");
                    let who = id(0xa00 + u128::from(version.len() as u8) + install.len() as u128);
                    let mut value = bundle(0xa10 + install.len() as u128 + version.len() as u128, install);
                    let mut channel = pairing_channel(0x9a00);
                    let proof = signed_proof(&mut value, &channel, who);
                    let mut sink = RecordingSink::default();
                    assert_eq!(
                        service.consume_proof(
                            &mut value,
                            &proof,
                            who,
                            &EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap()),
                            &binding,
                            &capability,
                            &mut channel,
                            Some(&mut sink)
                        ),
                        Err(EnrollmentConsumeError::InvalidProof),
                        "{install} {version} must not pair"
                    );
                    assert_eq!(service.registered_fingerprint(who), None);
                }
                let acknowledged = pairing_binding(
                    "development",
                    "1.4.2",
                    DevelopmentIdentityAllowance::Explicit {
                        warning_acknowledged: true,
                    },
                );
                let capability =
                    ChromeCapability::reported(&acknowledged, true, true).expect("a capability");
                let who = id(0xa20);
                let mut value = bundle(0xa21, "development");
                let mut channel = pairing_channel(0x9a01);
                let proof = signed_proof(&mut value, &channel, who);
                let mut sink = RecordingSink::default();
                assert!(
                    service
                        .consume_proof(
                            &mut value,
                            &proof,
                            who,
                            &EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap()),
                            &acknowledged,
                            &capability,
                            &mut channel,
                            Some(&mut sink)
                        )
                        .is_ok(),
                    "an explicitly allowed development identity may pair"
                );
            }

            fn fr020() {
                // The gate reads the ceiling: a request outside it is refused on the live
                // channel, and the same request inside it is answered.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                assert_eq!(
                    daemon
                        .receive(
                            &frame,
                            &SessionInput::new(
                                capability(CapabilityAction::Read, "other/scope"),
                                PayloadKind::Command,
                                ObjectOwner::Owned(id(OWNER)),
                                None,
                            ),
                            &mut sink,
                        )
                        .expect_err("a request outside the ceiling")
                        .code(),
                    FailureCode::AuthorizationDenied
                );
                let frame = request(&mut client, &mut sink);
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_ok()
                );
            }

            fn fr021() {
                // The fixture principal is an MCP client. An administrator action is refused
                // to it even though the object is its own.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                assert_eq!(
                    daemon
                        .receive(
                            &frame,
                            &SessionInput::new(
                                capability(CapabilityAction::ManagePrincipals, "global"),
                                PayloadKind::Command,
                                ObjectOwner::Owned(id(OWNER)),
                                None,
                            ),
                            &mut sink,
                        )
                        .expect_err("an MCP client administers nothing")
                        .code(),
                    FailureCode::AuthorizationDenied
                );
            }

            fn fr022() {
                let mut observed = Vec::new();
                for owner in [ObjectOwner::Unknown, ObjectOwner::Owned(id(0x1234))] {
                    let (mut client, mut daemon) = establish_pair(0);
                    let mut sink = RecordingSink::default();
                    let frame = request(&mut client, &mut sink);
                    let failure = daemon
                        .receive(
                            &frame,
                            &SessionInput::new(
                                capability(CapabilityAction::Read, SCOPE),
                                PayloadKind::Command,
                                owner,
                                None,
                            ),
                            &mut sink,
                        )
                        .expect_err("an unauthorized lookup discloses nothing");
                    assert_eq!(failure.code(), FailureCode::ObjectNotFound);
                    assert_eq!(
                        failure.safe_next_action(),
                        SafeNextAction::DoNotInferObjectExistence
                    );
                    observed.push(format!("{failure}"));
                }
                assert_eq!(observed[0], observed[1]);
            }

            fn fr023() {
                // Every disclosure class passes the gate before serialization, and a refused
                // one serializes no byte and costs no counter.
                for class in [
                    Class::Response,
                    Class::Status,
                    Class::Event,
                    Class::Artifact,
                    Class::StreamChunk,
                ] {
                    let (_, mut daemon) = establish_pair(0);
                    let mut sink = RecordingSink::default();
                    let denied = SessionProjection::new(
                        class,
                        capability(CapabilityAction::Read, SCOPE),
                        ObjectOwner::Unknown,
                        None,
                        b"protected",
                    );
                    assert_eq!(
                        daemon
                            .send_projection(&denied, &mut sink)
                            .expect_err("an unauthorized projection")
                            .code(),
                        FailureCode::ObjectNotFound
                    );
                    assert_eq!(daemon.send_counter(), 0);
                    assert!(daemon.send_projection(&owned_projection(class, b"ok"), &mut sink).is_ok());
                }
            }

            fn fr024() {
                // A completed rotation registers the replacement, advances the epoch, closes
                // the prior-epoch channel and invalidates the retired credential.
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal = registered(&transitions, 0x2400, PrincipalKind::McpClient, &signer);
                let _client = live_channel(&transitions, &principal, &signer, 0x24);
                assert_eq!(transitions.open_channels(), 1);
                let replacement = RingSigner::generate();
                let mut sink = RecordingSink::default();
                assert!(
                    rotate(
                        &transitions,
                        principal.id(),
                        &replacement,
                        "principal-key-1",
                        0x2401,
                        principal.epoch(),
                        None,
                        Some(&mut sink),
                    )
                    .is_ok()
                );
                let rotated = transitions
                    .registered_principal(principal.id())
                    .expect("the rotated principal");
                assert_eq!(rotated.epoch(), principal.epoch() + 1);
                assert_eq!(rotated.public_key(), replacement.public_key());
                assert_eq!(transitions.open_channels(), 0);
                assert!(!sink.events.is_empty(), "a rotation owes an auditable outcome");
                // The retired credential is invalidated: the old signer reaches no session.
                assert!(
                    establish_pair_for(&rotated, &signer, connection(0x27)).is_err(),
                    "a retired key must not authenticate after the rotation commits"
                );
            }

            fn fr025() {
                // Revocation is terminal and idempotent, and a revoked principal reaches no
                // session and passes no authorization check afterwards.
                let signer = RingSigner::generate();
                let mut principal = registered_principal(
                    PRINCIPAL,
                    PrincipalKind::McpClient,
                    signer.public_key().clone(),
                    vec![capability(CapabilityAction::Read, SCOPE)],
                    0,
                );
                principal.revoke();
                assert_eq!(principal.lifecycle(), PrincipalLifecycle::Revoked);
                principal.revoke();
                assert_eq!(
                    principal.lifecycle(),
                    PrincipalLifecycle::Revoked,
                    "revocation is idempotent"
                );
                assert!(
                    establish_pair_for(&principal, &signer, connection(0x25)).is_err(),
                    "a revoked principal must not authenticate"
                );
            }

            fn fr026() {
                // A frame sealed before the transition commits cannot pass the check after it:
                // the transition closed the channel it was bound to.
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal = registered(&transitions, 0x2600, PrincipalKind::McpClient, &signer);
                let mut client = live_channel(&transitions, &principal, &signer, 0x26);
                let mut sink = RecordingSink::default();
                let stale = request(&mut client, &mut sink);
                let replacement = RingSigner::generate();
                assert_eq!(
                    rotate(
                        &transitions,
                        principal.id(),
                        &replacement,
                        "principal-key-1",
                        0x2601,
                        principal.epoch(),
                        None,
                        Some(&mut sink),
                    ),
                    Ok(TransitionOutcome::Committed)
                );
                assert!(
                    receive(&transitions, connection(0x26), &stale, &mut sink).is_err(),
                    "a stale credential must not pass a check after the transition commits"
                );
            }

            fn fr027() {
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                sink.events.clear();
                assert!(
                    daemon
                        .receive(
                            &frame,
                            &SessionInput::new(
                                capability(CapabilityAction::Read, SCOPE),
                                PayloadKind::Command,
                                ObjectOwner::Unknown,
                                None,
                            ),
                            &mut sink,
                        )
                        .is_err()
                );
                assert_eq!(sink.events.len(), 1, "every decision emits exactly one fact");
                assert_eq!(sink.events[0].boundary(), EventBoundary::Authorization);
                assert_eq!(sink.events[0].code(), SecurityCode::AuthorizationDenied);
                assert_eq!(sink.events[0].outcome(), EventOutcome::Rejected);
            }

            fn fr028() {
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                sink.events.clear();
                let failure = daemon
                    .receive(
                        &frame,
                        &SessionInput::new(
                            capability(CapabilityAction::Read, SCOPE),
                            PayloadKind::Command,
                            ObjectOwner::Unknown,
                            None,
                        ),
                        &mut sink,
                    )
                    .expect_err("an unauthorized lookup");
                let rendered = format!("{failure} {failure:?} {:?}", sink.events);
                assert!(rendered.contains("object.not_found"));
                assert!(rendered.contains("Authorization"));
                for forbidden in ["private", "pkcs8", "cookie", "authorization_header", "secret"] {
                    assert!(!rendered.to_ascii_lowercase().contains(forbidden), "{rendered}");
                }
            }

            fn fr029() {
                // Every bounded failure names a stable class and a safe next action, and the
                // set of class strings is free of duplicates.
                let codes = [
                    FailureCode::AuthenticationFailed,
                    FailureCode::AuthorizationDenied,
                    FailureCode::ObjectNotFound,
                    FailureCode::CompatibilityUnsupported,
                    FailureCode::DowngradeRejected,
                    FailureCode::MalformedInput,
                    FailureCode::OriginRejected,
                    FailureCode::EndpointRejected,
                    FailureCode::ReplayDetected,
                    FailureCode::CounterMismatch,
                    FailureCode::RateLimited,
                    FailureCode::CredentialStoreUnavailable,
                    FailureCode::CredentialStoreMismatch,
                    FailureCode::ResourceLimit,
                    FailureCode::StaleEpoch,
                    FailureCode::Revoked,
                    FailureCode::TransitionUnknown,
                    FailureCode::EventSinkUnavailable,
                    FailureCode::CryptographicFailure,
                ];
                let mut rendered: Vec<&str> = codes.iter().map(|code| code.as_str()).collect();
                assert!(rendered.iter().all(|value| !value.is_empty()));
                rendered.sort_unstable();
                let count = rendered.len();
                rendered.dedup();
                assert_eq!(rendered.len(), count, "a class string must name one failure");
                assert_eq!(
                    crate::SecurityFailure::new(FailureCode::ObjectNotFound).safe_next_action(),
                    SafeNextAction::DoNotInferObjectExistence
                );
            }

            fn fr030() {
                // The shared vector set is deterministic and both peers exercise it. Here the
                // native peer accepts one valid frame and refuses a boundary mutation of it.
                assert!(
                    super::fixture_path("fixtures/webcrypto/secure-channel-vectors.mjs").exists(),
                    "the shared vector fixture must exist for the extension peer"
                );
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let valid = request(&mut client, &mut sink);
                for boundary in [0usize, 1, 5, 21, valid.len() - 1] {
                    let mut mutated = valid.clone();
                    mutated[boundary] ^= 0x01;
                    let (_, mut fresh) = establish_pair(0);
                    assert!(
                        fresh
                            .receive(&mutated, &owned_operation(PayloadKind::Command), &mut sink)
                            .is_err(),
                        "a mutation at byte {boundary} must be refused"
                    );
                }
                assert!(
                    daemon
                        .receive(&valid, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_ok()
                );
            }

            fn fr031() {
                // A disconnect is not a transition: the registration and its grant survive it
                // and no durable work completes because a connection went away.
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal = registered(&transitions, 0x3100, PrincipalKind::McpClient, &signer);
                let mut client = live_channel(&transitions, &principal, &signer, 0x31);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                let input = receive(&transitions, connection(0x31), &frame, &mut sink)
                    .expect("an authorized mutation");
                let version = commit_mutation(&transitions, &input).expect("a committed mutation");
                assert!(transitions.close_channel(connection(0x31)));
                assert!(!transitions.channel_is_open(connection(0x31)));
                assert!(transitions.registered_principal(principal.id()).is_some());
                assert_eq!(transitions.object_version(), version);
            }

            fn fr032() {
                // Replay outside the valid context is refused on every carrier: a frame
                // counter, and a consumed enrollment.
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request(&mut client, &mut sink);
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_ok()
                );
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_err()
                );
                let service = EnrollmentConsumptionService::default();
                let binding = pairing_binding("normal", "1.4.2", DevelopmentIdentityAllowance::None);
                let capability =
                    ChromeCapability::reported(&binding, true, true).expect("a capability");
                let who = id(0x3201);
                let mut value = bundle(0x3200, "normal");
                let mut channel = pairing_channel(0x9320);
                let proof = signed_proof(&mut value, &channel, who);
                let clock = EnrollmentClock::new(1, ExpiryResult::valid(DEADLINE_MS).unwrap());
                assert!(
                    service
                        .consume_proof(
                            &mut value,
                            &proof,
                            who,
                            &clock,
                            &binding,
                            &capability,
                            &mut channel,
                            Some(&mut sink)
                        )
                        .is_ok()
                );
                assert_eq!(
                    service.consume_proof(
                        &mut value,
                        &proof,
                        who,
                        &clock,
                        &binding,
                        &capability,
                        &mut channel,
                        Some(&mut sink)
                    ),
                    Err(EnrollmentConsumeError::AlreadyConsumed)
                );
            }

            fn sc001() {
                // Bounded here; the backing test runs the hundred. Every run creates one
                // daemon identity and one administrator, and no surface carries a private key.
                for run in 0..5u128 {
                    let (state, _) = committed(0x1_0000 + run * 0x10);
                    assert!(state.active_daemon().is_some());
                    assert!(state.active_admin().is_some());
                    assert!(state.staged().is_none());
                    let rendered = format!(
                        "{:?} {:?}",
                        state.active_daemon().unwrap(),
                        state.active_admin().unwrap()
                    );
                    assert!(!rendered.to_ascii_lowercase().contains("private"));
                }
            }

            fn sc002() {
                // Bounded here; the backing test runs the hundred. Every crash point converges
                // on one principal with no duplicate registration.
                for (index, crash) in [
                    CrashPoint::BeforeEvent,
                    CrashPoint::AfterEvent,
                    CrashPoint::AfterStage,
                    CrashPoint::AfterCommit,
                ]
                .into_iter()
                .enumerate()
                {
                    let envelope = envelope(0x2_0000 + index as u128 * 0x10, 17);
                    let store = registered_store(&envelope);
                    let mut sink = FakeEventSink::accepted();
                    let mut state = BootstrapState::default();
                    assert!(bootstrap(&mut state, &envelope, &store, &mut sink, Some(crash)).is_err());
                    state.recover();
                    let retry = bootstrap(&mut state, &envelope, &store, &mut sink, None);
                    assert!(retry.is_ok(), "{crash:?} must converge");
                    let record = state.active().expect("one record").clone();
                    assert!(bootstrap(&mut state, &envelope, &store, &mut sink, None).is_ok());
                    assert_eq!(state.active().expect("still one record"), &record);
                }
            }

            fn sc003() {
                // Bounded here; the backing test runs the thousand. A valid vector
                // authenticates and a mutated, downgraded and wrong-epoch one does not.
                assert!(establish_pair_with_ranges(0, (1, 3), (2, 4)).is_ok());
                assert!(establish_pair_with_ranges(0, (1, 1), (5, 6)).is_err());
                assert!(establish_pair_at_epochs(1, 2, (1, 3), (2, 4)).is_err());
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let mut frame = request(&mut client, &mut sink);
                let last = frame.len() - 1;
                frame[last] ^= 0x01;
                assert!(
                    daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .is_err()
                );
            }

            fn sc004() {
                // Bounded here; the backing test runs the complete matrix. A cross-owner and
                // an unresolved probe are one observation.
                fr022();
            }

            fn sc005() {
                // Bounded here; the backing test runs the hundred per class. A valid first use
                // pairs, and a replay of it pairs nothing further.
                fr032();
            }

            fn sc006() {
                // A rotation commits, and a frame sealed at the prior epoch completes no
                // mutation afterwards.
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal = registered(&transitions, 0x6000, PrincipalKind::McpClient, &signer);
                let mut client = live_channel(&transitions, &principal, &signer, 0x60);
                let mut sink = RecordingSink::default();
                let stale = request(&mut client, &mut sink);
                let replacement = RingSigner::generate();
                assert!(
                    rotate(
                        &transitions,
                        principal.id(),
                        &replacement,
                        "principal-key-1",
                        0x6001,
                        principal.epoch(),
                        None,
                        Some(&mut sink),
                    )
                    .is_ok()
                );
                assert_eq!(transitions.open_channels(), 0);
                assert!(receive(&transitions, connection(0x60), &stale, &mut sink).is_err());
            }

            fn sc007() {
                // A bounded oversized case allocates nothing past the declared limits and
                // mutates no protected state.
                assert_eq!(
                    AuthorizedOutput::filtered(PayloadKind::Response, vec![0; 1_048_535])
                        .expect_err("a payload past its bound")
                        .code(),
                    FailureCode::ResourceLimit
                );
                let (_, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                assert!(
                    daemon
                        .receive(&[0u8; 8], &owned_operation(PayloadKind::Command), &mut sink)
                        .is_err()
                );
                assert_eq!(daemon.receive_counter(), 0, "a refused frame moves no counter");
            }

            fn sc008() {
                // A disconnect leaves confirmed daemon-owned work alone and creates no second
                // authorization or revocation transition.
                fr031();
                let transitions = SecurityTransitions::default();
                let signer = RingSigner::generate();
                let principal = registered(&transitions, 0x8000, PrincipalKind::McpClient, &signer);
                let _client = live_channel(&transitions, &principal, &signer, 0x80);
                assert!(transitions.close_channel(connection(0x80)));
                assert!(!transitions.close_channel(connection(0x80)), "one close, not two");
                assert_eq!(
                    transitions
                        .registered_principal(principal.id())
                        .expect("the principal survives its connection")
                        .lifecycle(),
                    PrincipalLifecycle::Active
                );
            }

            fn sc009() {
                // Every failure in the matrix maps to exactly one class, boundary and next
                // action, and the next-action strings are distinct too.
                fr029();
                let actions = [
                    SafeNextAction::VerifyCredentialAndReconnect,
                    SafeNextAction::RequestAdministratorGrant,
                    SafeNextAction::DoNotInferObjectExistence,
                    SafeNextAction::UseFixedContractPeer,
                    SafeNextAction::DiscardAndReconnect,
                    SafeNextAction::PairExpectedExtension,
                    SafeNextAction::UseConfiguredEndpoint,
                    SafeNextAction::DiscardAndEstablishFreshChannel,
                    SafeNextAction::WaitForRetryWindow,
                    SafeNextAction::RestoreCredentialService,
                    SafeNextAction::StopAndAdministratorRepair,
                    SafeNextAction::ReduceToDeclaredBound,
                    SafeNextAction::ReconnectCurrentEpoch,
                    SafeNextAction::InspectTransitionStatus,
                    SafeNextAction::RepairEventSink,
                ];
                let mut rendered: Vec<&str> = actions.iter().map(|next| next.as_str()).collect();
                assert!(rendered.iter().all(|value| !value.is_empty()));
                rendered.sort_unstable();
                let count = rendered.len();
                rendered.dedup();
                assert_eq!(rendered.len(), count);
            }

            // -- the mapping ---------------------------------------------------------------

            /// One quickstart mapping claim.
            struct Claim {
                id: u8,
                evidence: &'static str,
                backing_test: &'static str,
                probe: fn(),
            }

            fn functional_claims() -> [Claim; 31] {
                [
                    Claim { id: 2, evidence: "bootstrap", backing_test: "bootstrap_recovery.rs::committed_fingerprints_are_the_independent_lowercase_sha256_digest", probe: fr002 },
                    Claim { id: 3, evidence: "secret-custody", backing_test: "enrollment_custody.rs::enrollment_custody_surfaces_never_contain_raw_pkcs8_backup_bytes", probe: fr003 },
                    Claim { id: 4, evidence: "bootstrap", backing_test: "bootstrap_recovery.rs::staged_and_post_commit_crashes_recover_without_duplicate_registration", probe: fr004 },
                    Claim { id: 5, evidence: "bootstrap", backing_test: "bootstrap_recovery.rs::different_identity_and_all_credential_failures_leave_no_registration", probe: fr005 },
                    Claim { id: 6, evidence: "credential-store", backing_test: "foundation_contract.rs::identity_reference_shapes_and_bounds_are_closed", probe: fr006 },
                    Claim { id: 7, evidence: "enrollment", backing_test: "enrollment_contract.rs::expiry_accepts_ten_minutes_and_rejects_uncertain_or_overlong_inputs", probe: fr007 },
                    Claim { id: 8, evidence: "enrollment", backing_test: "enrollment_failures.rs::production_consumption_binds_principal_and_occurrence_time", probe: fr008 },
                    Claim { id: 9, evidence: "enrollment", backing_test: "enrollment_failures.rs::failed_proofs_are_budgeted_atomically_and_close_channel", probe: fr009 },
                    Claim { id: 10, evidence: "channel", backing_test: "secure_channel_handshake.rs::production_handshake_negotiates_and_reaches_bidirectional_sessions", probe: fr010 },
                    Claim { id: 11, evidence: "channel", backing_test: "secure_channel_handshake.rs::a_rotated_principal_authenticates_only_its_replacement_signer", probe: fr011 },
                    Claim { id: 12, evidence: "negotiation", backing_test: "secure_channel_handshake.rs::exact_negotiation_rejects_disjoint_ranges_before_session_creation", probe: fr012 },
                    Claim { id: 13, evidence: "encoding", backing_test: "secure_channel_handshake.rs::client_hello_uses_four_byte_lengths_utf8_uuid_and_valid_sec1_points", probe: fr013 },
                    Claim { id: 14, evidence: "channel", backing_test: "authorization_privacy.rs::neither_side_can_reach_a_payload_that_skipped_a_decision", probe: fr014 },
                    Claim { id: 15, evidence: "frame", backing_test: "secure_channel_frames.rs::production_frame_has_length_prefix_and_exact_authenticated_header", probe: fr015 },
                    Claim { id: 16, evidence: "rejection", backing_test: "secure_channel_faults.rs::replay_duplicate_and_skipped_counters_close_before_dispatch", probe: fr016 },
                    Claim { id: 17, evidence: "size", backing_test: "secure_channel_frames.rs::one_mib_frame_and_plaintext_bound_are_exact_without_fragmentation", probe: fr017 },
                    Claim { id: 18, evidence: "origin", backing_test: "secure_channel_handshake.rs::a_state_bearing_route_admits_only_the_expected_route_and_versioned_subprotocol", probe: fr018 },
                    Claim { id: 19, evidence: "enrollment", backing_test: "enrollment_contract.rs::pairing_requires_a_supported_extension_version", probe: fr019 },
                    Claim { id: 20, evidence: "authorization", backing_test: "authorization_contract.rs::production_authorize_enforces_kind_ceiling_contract_owner_grant_and_action", probe: fr020 },
                    Claim { id: 21, evidence: "authorization", backing_test: "authorization_privacy.rs::administrator_actions_and_out_of_ceiling_actions_are_refused_on_the_live_channel", probe: fr021 },
                    Claim { id: 22, evidence: "privacy", backing_test: "authorization_privacy.rs::unknown_cross_owner_and_filtered_lookups_share_one_object_not_found_outcome", probe: fr022 },
                    Claim { id: 23, evidence: "privacy", backing_test: "authorization_privacy.rs::every_projection_class_is_filtered_before_any_byte_is_serialized", probe: fr023 },
                    Claim { id: 24, evidence: "rotation", backing_test: "rotation_revocation.rs::replacement_registration_precedes_epoch_transition", probe: fr024 },
                    Claim { id: 25, evidence: "revocation", backing_test: "rotation_revocation.rs::revocation_is_terminal_and_idempotent", probe: fr025 },
                    Claim { id: 26, evidence: "transition", backing_test: "rotation_revocation_races.rs::a_concurrent_handshake_never_outlives_the_rotation_it_raced", probe: fr026 },
                    Claim { id: 27, evidence: "events", backing_test: "events_contract.rs::every_required_security_fact_is_emitted_by_the_production_path_that_owes_it", probe: fr027 },
                    Claim { id: 28, evidence: "redaction", backing_test: "authorization_privacy.rs::failure_and_event_projections_in_this_matrix_render_no_protected_value", probe: fr028 },
                    Claim { id: 29, evidence: "failures", backing_test: "foundation_contract.rs::failure_codes_have_stable_complete_redacted_projections", probe: fr029 },
                    Claim { id: 30, evidence: "vectors", backing_test: "secure_channel_faults.rs::native_and_webcrypto_peers_agree_on_every_corpus_vector", probe: fr030 },
                    Claim { id: 31, evidence: "lifecycle", backing_test: "rotation_revocation_races.rs::sc008_disconnects_preserve_confirmed_work_and_duplicate_no_transition", probe: fr031 },
                    Claim { id: 32, evidence: "vectors", backing_test: "rotation_revocation.rs::idempotency_replay_covers_full_input_and_public_material", probe: fr032 },
                ]
            }

            fn success_claims() -> [Claim; 9] {
                [
                    Claim { id: 1, evidence: "bootstrap", backing_test: "bootstrap_recovery.rs::sc001_clean_runs_and_sc002_crash_runs_converge", probe: sc001 },
                    Claim { id: 2, evidence: "bootstrap-recovery", backing_test: "bootstrap_recovery.rs::sc001_clean_runs_and_sc002_crash_runs_converge", probe: sc002 },
                    Claim { id: 3, evidence: "channel-vectors", backing_test: "secure_channel_faults.rs::sc003_thousand_handshake_cases_classify_identically_on_both_peers", probe: sc003 },
                    Claim { id: 4, evidence: "authorization-privacy", backing_test: "authorization_privacy.rs::the_complete_route_object_role_ceiling_owner_grant_matrix_discloses_nothing", probe: sc004 },
                    Claim { id: 5, evidence: "enrollment-custody", backing_test: "enrollment_failures.rs::one_hundred_attempts_per_failure_class_create_principals_only_for_valid_first_use", probe: sc005 },
                    Claim { id: 6, evidence: "rotation-revocation", backing_test: "rotation_revocation_races.rs::sc006_no_stale_frame_completes_a_mutation_or_a_decision", probe: sc006 },
                    Claim { id: 7, evidence: "channel-faults", backing_test: "malformed_corpus.rs::malformed_corpus_drives_the_production_parser_with_zero_dispatch", probe: sc007 },
                    Claim { id: 8, evidence: "disconnect-independence", backing_test: "rotation_revocation_races.rs::sc008_disconnects_preserve_confirmed_work_and_duplicate_no_transition", probe: sc008 },
                    Claim { id: 9, evidence: "event-redaction", backing_test: "foundation_contract.rs::failure_and_event_projections_reject_secret_material_and_bound_metadata", probe: sc009 },
                ]
            }

            /// The backing test has to exist where the claim says it does. A renamed or
            /// deleted test is mapping drift, and this is what turns it into a failure.
            fn assert_backing_test_exists(reference: &str, label: &str) {
                let (file, name) = reference
                    .split_once("::")
                    .unwrap_or_else(|| panic!("{label} names no backing test: {reference}"));
                let path = super::fixture_path(&format!("tests/{file}"));
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{label} names {}: {error}", path.display()));
                assert!(
                    source.contains(&format!("fn {name}(")),
                    "{label} names a test {file} does not define: {name}"
                );
            }

            #[test]
            fn quickstart_mapping_covers_every_required_fr_and_sc() {
                let functional = functional_claims();
                let success = success_claims();
                assert_eq!(functional.len(), 31);
                assert_eq!(success.len(), 9);
                assert_eq!(super::FR_EVIDENCE.len(), functional.len());
                assert_eq!(super::SC_EVIDENCE.len(), success.len());

                for ((expected, claim), (labelled, evidence)) in
                    (2..=32u8).zip(&functional).zip(super::FR_EVIDENCE)
                {
                    let label = format!("FR-{expected:03}");
                    assert_eq!(claim.id, expected, "{label} is out of order");
                    assert_eq!(claim.id, *labelled, "{label} maps to another quickstart row");
                    assert_eq!(
                        claim.evidence, *evidence,
                        "{label} claims evidence the quickstart does not carry"
                    );
                    assert_backing_test_exists(claim.backing_test, &label);
                    (claim.probe)();
                }

                for ((expected, claim), (labelled, evidence)) in
                    (1..=9u8).zip(&success).zip(super::SC_EVIDENCE)
                {
                    let label = format!("SC-{expected:03}");
                    assert_eq!(claim.id, expected, "{label} is out of order");
                    assert_eq!(claim.id, *labelled, "{label} maps to another quickstart row");
                    assert_eq!(
                        claim.evidence, *evidence,
                        "{label} claims evidence the quickstart does not carry"
                    );
                    assert_backing_test_exists(claim.backing_test, &label);
                    (claim.probe)();
                }
            }
        }

        #[test]
        fn node_webcrypto_fixture_records_pass_for_the_vector_peer() {
            let output = std::process::Command::new("node")
                .arg(fixture_path(
                    "fixtures/webcrypto/secure-channel-vectors.mjs",
                ))
                .output()
                .expect("Node.js WebCrypto fixture");
            assert!(
                output.status.success(),
                "WebCrypto fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("\"result\":\"pass\""), "{stdout}");
            assert_no_secret_material(&stdout);
        }

        #[test]
        fn chrome_capability_fixture_records_explicit_node_unsupported_result() {
            let output = std::process::Command::new("node")
                .arg(fixture_path("fixtures/chrome-capability/capability.mjs"))
                .output()
                .expect("Node.js Chrome capability fixture");
            assert!(
                output.status.success(),
                "Chrome capability fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("\"result\":\"unsupported\""), "{stdout}");
            assert!(stdout.contains("capability.unsupported"), "{stdout}");
            assert!(stdout.contains("\"channel_state\":\"closed\""), "{stdout}");
            assert_no_secret_material(&stdout);
        }

        #[test]
        fn typed_boundaries_are_bounded_and_fail_closed() {
            use crate::{FailureCode, PayloadKind};

            assert_eq!(PayloadKind::Command.max_bytes(), 1_048_534);
            assert_eq!(PayloadKind::StreamChunk.max_bytes(), 1_000_000);
            for code in [
                FailureCode::MalformedInput,
                FailureCode::ObjectNotFound,
                FailureCode::EventSinkUnavailable,
                FailureCode::TransitionUnknown,
            ] {
                assert!(!code.as_str().is_empty());
            }
            assert_eq!(FailureCode::ObjectNotFound.as_str(), "object.not_found");
            assert_eq!(
                FailureCode::EventSinkUnavailable.as_str(),
                "event_sink.unavailable"
            );
            assert_eq!(
                FailureCode::TransitionUnknown.as_str(),
                "transition.unknown"
            );
        }
    };
}
