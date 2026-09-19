#[allow(unused_macros)]
macro_rules! secure_channel_handshake_tests {
    () => {
        use crate::test_support_channel::{
            CONNECTION, DAEMON, ENDPOINT, PRINCIPAL, RecordingSink, RingSigner, establish_pair,
            establish_pair_for, establish_pair_with_ranges, fixture_principal, id, owned_operation,
            registered_principal,
        };
        use crate::test_support_transitions::{EXTENSION, admit, ceiling, connection, registered};
        use crate::{
            AuthorizedOutput, ChannelSigner, ClientHandshake, ClientHandshakeConfig, ConnectionId,
            FailureCode, IdentityId, LoopbackHost, PayloadKind, PrincipalKind, SecurityTransitions,
            ServerHandshake, ServerHandshakeConfig, StateBearingRequest, StateBearingRoute,
        };
        use uuid::Uuid;

        const EPOCH: u64 = 7;

        fn configs(
            client_signer: &RingSigner,
            server_signer: &RingSigner,
            client_range: (u16, u16),
            server_range: (u16, u16),
        ) -> (ClientHandshakeConfig, ServerHandshakeConfig) {
            let client = ClientHandshakeConfig::new(
                ENDPOINT,
                id(PRINCIPAL),
                client_signer.public_key().clone(),
                id(DAEMON),
                server_signer.public_key().clone(),
                EPOCH,
                client_range.0,
                client_range.1,
            )
            .unwrap();
            let server = ServerHandshakeConfig::new(
                ENDPOINT,
                fixture_principal(client_signer.public_key().clone(), EPOCH),
                id(DAEMON),
                server_signer.public_key().clone(),
                server_range.0,
                server_range.1,
                ConnectionId::new(Uuid::from_u128(CONNECTION)),
            )
            .unwrap();
            (client, server)
        }

        fn decode_hex(value: &str) -> Vec<u8> {
            assert_eq!(value.len() % 2, 0);
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let text = core::str::from_utf8(pair).unwrap();
                    u8::from_str_radix(text, 16).unwrap()
                })
                .collect()
        }

        fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
            decode_hex(value)
                .try_into()
                .ok()
                .expect("fixed vector length")
        }

        fn json_string<'a>(corpus: &'a str, name: &str) -> &'a str {
            let marker = format!("\"{name}\": \"");
            let start = corpus.find(&marker).expect("vector field") + marker.len();
            let remainder = &corpus[start..];
            &remainder[..remainder.find('"').expect("vector string terminator")]
        }

        #[test]
        fn production_handshake_negotiates_and_reaches_bidirectional_sessions() {
            let (mut client, mut daemon) = establish_pair(7);
            assert_eq!(client.contract(), 3);
            assert_eq!(daemon.contract(), 3);
            assert_eq!(client.connection_id(), daemon.connection_id());
            assert_eq!(client.endpoint(), ENDPOINT);

            let output =
                AuthorizedOutput::filtered(PayloadKind::Command, b"request".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let frame = client.send(&output, &mut sink).unwrap();
            let input = daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            assert_eq!(input.payload(), b"request");
        }

        #[test]
        fn public_metadata_cannot_recompute_traffic_keys() {
            let (mut first_client, first_daemon) = establish_pair(7);
            let (mut second_client, mut second_daemon) = establish_pair(7);
            let output =
                AuthorizedOutput::filtered(PayloadKind::Command, b"same".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let first = first_client.send(&output, &mut sink).unwrap();
            let second = second_client.send(&output, &mut sink).unwrap();
            assert_ne!(
                first, second,
                "independent ECDH secrets produced the same frame"
            );
            let failure = second_daemon
                .receive(&first, &owned_operation(PayloadKind::Command), &mut sink)
                .expect_err("an observed frame cannot be opened with another private ECDH secret");
            assert_eq!(failure.code(), FailureCode::CryptographicFailure);
            assert!(!second_daemon.is_open());
            assert!(first_daemon.is_open());
        }

        #[test]
        fn exact_negotiation_rejects_disjoint_ranges_before_session_creation() {
            let failure =
                establish_pair_with_ranges(7, (1, 2), (3, 4)).expect_err("disjoint contracts");
            assert_eq!(failure.code(), FailureCode::CompatibilityUnsupported);
        }

        #[test]
        fn server_proof_requires_the_bound_daemon_signer() {
            let client_signer = RingSigner::generate();
            let server_signer = RingSigner::generate();
            let wrong_signer = RingSigner::generate();
            let (client_config, server_config) =
                configs(&client_signer, &server_signer, (1, 3), (2, 4));
            let (_, hello) = ClientHandshake::start(client_config).unwrap();
            let mut sink = RecordingSink::default();
            let failure = ServerHandshake::accept(server_config, &hello, &wrong_signer, &mut sink)
                .expect_err("wrong daemon signer");
            assert_eq!(failure.code(), FailureCode::AuthenticationFailed);
            assert_eq!(sink.events.len(), 1);
        }

        #[test]
        fn signature_and_transcript_mutations_fail_before_traffic_keys_exist() {
            let client_signer = RingSigner::generate();
            let server_signer = RingSigner::generate();
            let (client_config, server_config) =
                configs(&client_signer, &server_signer, (1, 3), (2, 4));
            let (client, hello) = ClientHandshake::start(client_config).unwrap();
            let mut sink = RecordingSink::default();
            let (_, mut proof) =
                ServerHandshake::accept(server_config, &hello, &server_signer, &mut sink).unwrap();
            let index = proof.len() - 1;
            proof[index] ^= 1;
            let failure = client
                .finish(&proof, &client_signer, &mut sink)
                .expect_err("mutated server signature");
            assert_eq!(failure.code(), FailureCode::AuthenticationFailed);
            assert_eq!(sink.events.len(), 1);
        }

        /// FR-024, FR-026: a rotation replaces the credential transcripts are verified
        /// against. The retired signer cannot authenticate at the new epoch even though it
        /// authenticated at the old one, the replacement signer can, and the fingerprint,
        /// credential locator, and public key all name that one replacement.
        #[test]
        fn a_rotated_principal_authenticates_only_its_replacement_signer() {
            let retired = RingSigner::generate();
            let replacement = RingSigner::generate();
            let daemon_signer = RingSigner::generate();

            let before = fixture_principal(retired.public_key().clone(), 0);
            assert_eq!(before.epoch(), 0);
            let mut after = before.clone();
            after.begin_rotation().unwrap();
            after
                .complete_rotation(
                    replacement.public_key().clone(),
                    crate::Fingerprint::new("b".repeat(64)).unwrap(),
                    crate::CredentialReference::new(
                        "fixture-store",
                        "principal-key-1",
                        before.owner(),
                        before.credential().state_directory(),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(after.epoch(), 1);
            assert_eq!(after.public_key(), replacement.public_key());
            assert_ne!(after.public_key(), before.public_key());
            assert_ne!(after.fingerprint(), before.fingerprint());
            assert_ne!(
                after.credential().key_locator(),
                before.credential().key_locator()
            );

            // The key the registry holds is checked before the epoch, so each refusal below
            // has exactly one cause. A retired signer is an authentication failure whichever
            // epoch it claims; the replacement signer at the superseded epoch is a stale epoch.
            for (signer, epoch, expected) in [
                (&retired, 0, FailureCode::AuthenticationFailed),
                (&retired, 1, FailureCode::AuthenticationFailed),
                (&replacement, 0, FailureCode::StaleEpoch),
            ] {
                let client = ClientHandshakeConfig::new(
                    ENDPOINT,
                    id(PRINCIPAL),
                    signer.public_key().clone(),
                    id(DAEMON),
                    daemon_signer.public_key().clone(),
                    epoch,
                    1,
                    3,
                )
                .unwrap();
                let server = ServerHandshakeConfig::new(
                    ENDPOINT,
                    after.clone(),
                    id(DAEMON),
                    daemon_signer.public_key().clone(),
                    2,
                    4,
                    ConnectionId::new(Uuid::from_u128(CONNECTION)),
                )
                .unwrap();
                let (_, hello) = ClientHandshake::start(client).unwrap();
                let mut sink = RecordingSink::default();
                let failure = ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink)
                    .expect_err("only the replacement signer at the current epoch authenticates");
                assert_eq!(failure.code(), expected);
                assert_eq!(sink.events.len(), 1);
            }

            // The replacement signer authenticates at the new epoch and reaches a session.
            let client = ClientHandshakeConfig::new(
                ENDPOINT,
                id(PRINCIPAL),
                replacement.public_key().clone(),
                id(DAEMON),
                daemon_signer.public_key().clone(),
                1,
                1,
                3,
            )
            .unwrap();
            let server = ServerHandshakeConfig::new(
                ENDPOINT,
                after,
                id(DAEMON),
                daemon_signer.public_key().clone(),
                2,
                4,
                ConnectionId::new(Uuid::from_u128(CONNECTION)),
            )
            .unwrap();
            let mut sink = RecordingSink::default();
            let (client_pending, hello) = ClientHandshake::start(client).unwrap();
            let (server_pending, proof) =
                ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink).unwrap();
            let (client_session, client_proof) = client_pending
                .finish(&proof, &replacement, &mut sink)
                .unwrap();
            let daemon_session = server_pending.finish(&client_proof, &mut sink).unwrap();
            assert_eq!(daemon_session.epoch(), 1);
            assert_eq!(client_session.epoch(), 1);
            assert!(daemon_session.is_open() && client_session.is_open());
        }

        #[test]
        fn client_hello_uses_four_byte_lengths_utf8_uuid_and_valid_sec1_points() {
            let client_signer = RingSigner::generate();
            let server_signer = RingSigner::generate();
            let (client_config, _) = configs(&client_signer, &server_signer, (1, 3), (2, 4));
            let (_, hello) = ClientHandshake::start(client_config).unwrap();
            let context_len = u32::from_be_bytes(hello[..4].try_into().unwrap()) as usize;
            assert_eq!(&hello[4..4 + context_len], b"matinee.secure-channel.v1");
            assert!(
                hello
                    .windows(ENDPOINT.len())
                    .any(|part| part == ENDPOINT.as_bytes())
            );
            assert!(
                hello
                    .windows(39)
                    .any(|part| part == b"id:00000000-0000-0000-0000-000000000002")
            );
            assert!(hello.windows(65).any(|part| part[0] == 0x04));
            assert_eq!(client_signer.public_key().as_bytes().len(), 65);
        }

        #[test]
        fn fixed_webcrypto_peer_matches_ring_transcripts_signatures_hkdf_and_frame() {
            let corpus = include_str!("../vectors/secure-channel-v1.json");
            let text = |name: &str| json_string(corpus, name);
            let client_hello = decode_hex(text("client_hello_hex"));
            let daemon_key =
                crate::PublicKey::from_uncompressed(fixed_hex(text("daemon_identity_public_hex")))
                    .unwrap();
            let server_signature = fixed_hex(text("server_signature_p1363_hex"));
            let client_signature = fixed_hex(text("client_signature_p1363_hex"));
            let daemon = IdentityId::new(Uuid::from_bytes(fixed_hex(text("daemon_id_hex"))));
            let connection =
                ConnectionId::new(Uuid::from_bytes(fixed_hex(text("connection_id_hex"))));
            let (server, client, salt) =
                crate::channel::vector_transcripts(crate::channel::VectorTranscriptInput {
                    client_hello: &client_hello,
                    selected: 3,
                    server_min: 2,
                    server_max: 4,
                    daemon,
                    daemon_key: &daemon_key,
                    server_nonce: &fixed_hex(text("server_nonce_hex")),
                    server_ephemeral: &fixed_hex(text("server_ephemeral_public_hex")),
                    connection,
                    server_signature: &server_signature,
                    client_signature: &client_signature,
                });
            assert_eq!(server, decode_hex(text("server_proof_input_hex")));
            assert_eq!(client, decode_hex(text("client_proof_input_hex")));
            assert_eq!(salt, fixed_hex(text("hkdf_salt_hex")));
            crate::channel::vector_verify_signature(&daemon_key, &server, &server_signature)
                .unwrap();
            let client_key =
                crate::PublicKey::from_uncompressed(fixed_hex(text("client_identity_public_hex")))
                    .unwrap();
            crate::channel::vector_verify_signature(&client_key, &client, &client_signature)
                .unwrap();
            let (client_to_daemon, daemon_to_client) = crate::channel::vector_material(
                &decode_hex(text("ecdh_shared_secret_hex")),
                &salt,
                3,
            )
            .unwrap();
            assert_eq!(
                client_to_daemon,
                fixed_hex(text("client_to_daemon_key_hex"))
            );
            assert_eq!(
                daemon_to_client,
                fixed_hex(text("daemon_to_client_key_hex"))
            );

            // The vector's principal is registered at the epoch its frame authenticated
            // under, so the session derives epoch 7 rather than accepting it as an argument.
            let principal = IdentityId::new(Uuid::from_bytes(fixed_hex(text("principal_id_hex"))));
            let mut daemon_session = crate::channel::vector_daemon_session(
                connection,
                fixture_principal(client_key, EPOCH),
                3,
                client_to_daemon,
                daemon_to_client,
            )
            .unwrap();
            assert_eq!(daemon_session.principal(), principal);
            assert_eq!(daemon_session.epoch(), EPOCH);
            let frame = decode_hex(text("framed_hex"));
            let mut sink = RecordingSink::default();
            let opened = daemon_session
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            assert_eq!(
                opened.payload(),
                decode_hex(text("application_payload_hex"))
            );

            let output = std::process::Command::new("node")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/fixtures/webcrypto/secure-channel-vectors.mjs"
                ))
                .output()
                .expect("Node.js WebCrypto peer");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("\"result\":\"pass\""));
        }

        /// FR-010, FR-025: a handshake proves custody of the bound key and nothing about
        /// the rest of the snapshot it was configured with. A forged principal kind
        /// therefore completes a valid handshake and still never reaches an accepted
        /// channel, because acceptance is what binds the snapshot to the registry.
        #[test]
        fn a_forged_principal_kind_never_reaches_an_accepted_handshake() {
            let transitions = SecurityTransitions::default();
            let signer = RingSigner::generate();
            let enrolled = registered(&transitions, EXTENSION, PrincipalKind::McpClient, &signer);

            let forged = registered_principal(
                EXTENSION,
                PrincipalKind::NativeAdmin,
                signer.public_key().clone(),
                ceiling(),
                0,
            );
            assert_eq!(forged.id(), enrolled.id());
            assert_eq!(forged.epoch(), enrolled.epoch());
            assert_eq!(forged.public_key(), enrolled.public_key());
            assert_ne!(forged.kind(), enrolled.kind());

            // The transcript carries no evidence of the kind, so the handshake itself
            // succeeds and both halves agree on the connection.
            let (client, daemon) = establish_pair_for(&forged, &signer, connection(1))
                .expect("a forged kind is cryptographically indistinguishable");
            assert_eq!(client.connection_id(), daemon.connection_id());

            assert_eq!(
                admit(&transitions, daemon)
                    .expect_err("a forged principal kind is never accepted")
                    .code(),
                FailureCode::CredentialStoreMismatch
            );
            assert!(!transitions.channel_is_open(connection(1)));
            assert_eq!(transitions.open_channels(), 0);
        }

        const ROUTE: &str = "/v1/session";
        const SUBPROTOCOL: &str = crate::SECURE_CHANNEL_CONTEXT;
        const PAIRED_ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

        fn state_bearing_route() -> StateBearingRoute {
            StateBearingRoute::new(
                LoopbackHost::Ipv4,
                7777,
                ROUTE,
                SUBPROTOCOL,
                [PAIRED_ORIGIN],
            )
            .expect("a configured state-bearing route")
        }

        fn upgrade() -> StateBearingRequest<'static> {
            StateBearingRequest {
                authority: ENDPOINT,
                route: ROUTE,
                subprotocol: SUBPROTOCOL,
                origin: PAIRED_ORIGIN,
            }
        }

        /// FR-018: a state-bearing route accepts only a configured loopback endpoint. A
        /// DNS alias, a wildcard bind, a routable address, an implicit port, and the
        /// loopback family or port that was not configured are all non-loopback bindings
        /// for this route, and each fails closed.
        #[test]
        fn a_state_bearing_route_admits_only_its_configured_loopback_endpoint() {
            let route = state_bearing_route();
            let mut sink = RecordingSink::default();
            for authority in [
                "localhost:7777",
                "0.0.0.0:7777",
                "[::]:7777",
                "192.168.1.9:7777",
                "daemon.example.test:7777",
                "127.0.0.1",
                "127.0.0.1:0",
                "127.0.0.1:07777",
                "127.0.0.1:+7777",
                "[::1]:7777",
                "127.0.0.1:7778",
            ] {
                let request = StateBearingRequest {
                    authority,
                    ..upgrade()
                };
                assert_eq!(
                    route
                        .admit(&request, 1, &mut sink)
                        .expect_err(authority)
                        .code(),
                    FailureCode::EndpointRejected,
                    "{authority}"
                );
            }
            // An endpoint refusal is a configuration mismatch, not one of the facts the
            // event contract enumerates, so it emits nothing.
            assert!(sink.events.is_empty());

            // The same refusal holds at the handshake itself, so an endpoint that never
            // passed admission cannot reach a traffic key by skipping the route.
            let signer = RingSigner::generate();
            assert_eq!(
                ServerHandshakeConfig::new(
                    "daemon.example.test:7777",
                    fixture_principal(signer.public_key().clone(), EPOCH),
                    id(DAEMON),
                    signer.public_key().clone(),
                    1,
                    3,
                    ConnectionId::new(Uuid::from_u128(CONNECTION)),
                )
                .expect_err("a routable endpoint never binds a state-bearing session")
                .code(),
                FailureCode::EndpointRejected
            );
        }

        /// FR-018: the expected route and the expected *versioned* subprotocol are both
        /// required. An unversioned and a differently versioned subprotocol are refused by
        /// the same exact comparison.
        #[test]
        fn a_state_bearing_route_admits_only_the_expected_route_and_versioned_subprotocol() {
            let route = state_bearing_route();
            let mut sink = RecordingSink::default();
            for wrong_route in ["/v1/health", "/v1/session/extra", "/", "/V1/session", ""] {
                let request = StateBearingRequest {
                    route: wrong_route,
                    ..upgrade()
                };
                assert_eq!(
                    route
                        .admit(&request, 1, &mut sink)
                        .expect_err(wrong_route)
                        .code(),
                    FailureCode::EndpointRejected,
                    "route {wrong_route:?}"
                );
            }
            for wrong_subprotocol in [
                "matinee.secure-channel",
                "matinee.secure-channel.v2",
                "matinee.secure-channel.v11",
                "",
            ] {
                let request = StateBearingRequest {
                    subprotocol: wrong_subprotocol,
                    ..upgrade()
                };
                assert_eq!(
                    route
                        .admit(&request, 1, &mut sink)
                        .expect_err(wrong_subprotocol)
                        .code(),
                    FailureCode::EndpointRejected,
                    "subprotocol {wrong_subprotocol:?}"
                );
            }
            assert!(sink.events.is_empty());
        }

        /// FR-018 with the event contract: an unexpected Origin fails closed, and a
        /// rejected Origin is one of the facts the module must emit. The fact carries no
        /// Origin string, and a sink that cannot accept it degrades to the sink failure
        /// rather than to a silent admission.
        #[test]
        fn a_disallowed_origin_is_refused_and_emits_the_required_rejected_origin_fact() {
            let route = state_bearing_route();
            let mut sink = RecordingSink::default();
            let request = StateBearingRequest {
                origin: "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba",
                ..upgrade()
            };
            assert_eq!(
                route
                    .admit(&request, 42, &mut sink)
                    .expect_err("an unpaired Origin never reaches a handshake")
                    .code(),
                FailureCode::OriginRejected
            );
            assert_eq!(sink.events.len(), 1);
            let event = &sink.events[0];
            assert_eq!(event.code(), crate::SecurityCode::OriginRejected);
            assert_eq!(event.outcome(), crate::EventOutcome::Rejected);
            assert_eq!(event.next_action(), crate::EventNextAction::RePair);
            assert_eq!(event.boundary(), crate::EventBoundary::Channel);
            assert_eq!(event.endpoint, crate::EndpointClass::Loopback);
            assert_eq!(event.time, crate::events::EventTime(42));
            assert!(event.metadata().is_empty());

            let mut unavailable = RecordingSink {
                events: vec![],
                unavailable: true,
            };
            assert_eq!(
                route
                    .admit(&request, 42, &mut unavailable)
                    .expect_err("a required fact the sink cannot accept fails closed")
                    .code(),
                FailureCode::EventSinkUnavailable
            );
        }

        /// The configured upgrade is still admitted, and the authority it yields is the one
        /// the handshake transcript binds on both halves.
        #[test]
        fn an_admitted_endpoint_is_the_authority_the_handshake_binds() {
            let route = state_bearing_route();
            let mut sink = RecordingSink::default();
            let admitted = route
                .admit(&upgrade(), 7, &mut sink)
                .expect("the configured upgrade is admitted");
            assert_eq!(admitted.as_str(), ENDPOINT);
            assert!(sink.events.is_empty());

            let client_signer = RingSigner::generate();
            let server_signer = RingSigner::generate();
            let client_config = ClientHandshakeConfig::new(
                admitted.clone(),
                id(PRINCIPAL),
                client_signer.public_key().clone(),
                id(DAEMON),
                server_signer.public_key().clone(),
                EPOCH,
                1,
                3,
            )
            .expect("an admitted endpoint configures a client handshake");
            let server_config = ServerHandshakeConfig::new(
                admitted,
                fixture_principal(client_signer.public_key().clone(), EPOCH),
                id(DAEMON),
                server_signer.public_key().clone(),
                2,
                4,
                ConnectionId::new(Uuid::from_u128(CONNECTION)),
            )
            .expect("an admitted endpoint configures a daemon handshake");

            let (client_pending, hello) = ClientHandshake::start(client_config).unwrap();
            let (server_pending, proof) =
                ServerHandshake::accept(server_config, &hello, &server_signer, &mut sink).unwrap();
            let (client_session, client_proof) = client_pending
                .finish(&proof, &client_signer, &mut sink)
                .unwrap();
            let daemon_session = server_pending.finish(&client_proof, &mut sink).unwrap();
            assert_eq!(client_session.endpoint(), ENDPOINT);
            assert_eq!(daemon_session.endpoint(), ENDPOINT);
            assert!(client_session.is_open() && daemon_session.is_open());
        }

        /// A route that admits nothing, or one whose configured Origin set no browser can
        /// ever match, is a configuration mistake and is refused at construction rather
        /// than presenting later as a per-request rejection.
        #[test]
        fn a_state_bearing_route_refuses_unusable_configuration() {
            for (route, subprotocol, port) in [
                ("v1/session", SUBPROTOCOL, 7777),
                ("/v1/session?upgrade=1", SUBPROTOCOL, 7777),
                ("/v1/session#fragment", SUBPROTOCOL, 7777),
                (ROUTE, "", 7777),
                (ROUTE, "matinee secure channel", 7777),
                (ROUTE, SUBPROTOCOL, 0),
            ] {
                assert_eq!(
                    StateBearingRoute::new(
                        LoopbackHost::Ipv4,
                        port,
                        route,
                        subprotocol,
                        [PAIRED_ORIGIN]
                    )
                    .expect_err("unusable route configuration")
                    .code(),
                    FailureCode::EndpointRejected,
                    "{route:?} {subprotocol:?} {port}"
                );
            }
            for origins in [
                Vec::new(),
                vec!["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
                vec!["abcdefghijklmnopabcdefghijklmnop"],
                vec![""],
            ] {
                assert_eq!(
                    StateBearingRoute::new(LoopbackHost::Ipv4, 7777, ROUTE, SUBPROTOCOL, origins)
                        .expect_err("unusable Origin configuration")
                        .code(),
                    FailureCode::OriginRejected
                );
            }
        }
    };
}
