macro_rules! secure_channel_faults_tests {
    () => {
        mod secure_channel_faults_inner {
            use crate::test_support_channel::{
                CONNECTION, DAEMON, ENDPOINT, PRINCIPAL, RecordingSink, RingSigner, establish_pair,
                establish_pair_at_epochs, fixture_principal, id, owned_operation, owned_projection,
            };
            use crate::{
                AuthorizedOutput, ChannelSigner, ClientHandshake, ClientHandshakeConfig,
                ConnectionId, FailureCode, PayloadKind, ProjectionClass, SecurityCode,
                ServerHandshake, ServerHandshakeConfig,
            };
            use uuid::Uuid;

            const EPOCH: u64 = 7;

            fn handshake_configs(
                client: &RingSigner,
                daemon: &RingSigner,
            ) -> (ClientHandshakeConfig, ServerHandshakeConfig) {
                (
                    ClientHandshakeConfig::new(
                        ENDPOINT,
                        id(PRINCIPAL),
                        client.public_key().clone(),
                        id(DAEMON),
                        daemon.public_key().clone(),
                        EPOCH,
                        1,
                        3,
                    )
                    .unwrap(),
                    ServerHandshakeConfig::new(
                        ENDPOINT,
                        fixture_principal(client.public_key().clone(), EPOCH),
                        id(DAEMON),
                        daemon.public_key().clone(),
                        2,
                        4,
                        ConnectionId::new(Uuid::from_u128(CONNECTION)),
                    )
                    .unwrap(),
                )
            }

            #[test]
            fn endpoint_epoch_nonce_key_and_length_mutations_reject_before_session() {
                for mutation in 0..6 {
                    let client_signer = RingSigner::generate();
                    let daemon_signer = RingSigner::generate();
                    let (client_config, server_config) =
                        handshake_configs(&client_signer, &daemon_signer);
                    let (_, mut hello) = ClientHandshake::start(client_config).unwrap();
                    match mutation {
                        0 => {
                            let needle = ENDPOINT.as_bytes();
                            let at = hello
                                .windows(needle.len())
                                .position(|part| part == needle)
                                .unwrap();
                            hello[at] = 0xff;
                        }
                        1 => {
                            let epoch = 7u64.to_be_bytes();
                            let at = hello.windows(8).position(|part| part == epoch).unwrap();
                            hello[at + 7] ^= 1;
                        }
                        2 => hello[4] ^= 1,
                        3 | 4 => {
                            let marker = [0, 0, 0, 65, 4];
                            let field = hello
                                .windows(marker.len())
                                .enumerate()
                                .filter(|(_, part)| *part == marker)
                                .nth((mutation - 3) as usize)
                                .unwrap()
                                .0;
                            hello[field + 4] = 0x02;
                        }
                        _ => hello[..4].copy_from_slice(&(u32::MAX).to_be_bytes()),
                    }
                    let mut sink = RecordingSink::default();
                    let failure =
                        ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink)
                            .expect_err("mutated hello");
                    assert!(matches!(
                        failure.code(),
                        FailureCode::AuthenticationFailed
                            | FailureCode::MalformedInput
                            | FailureCode::ResourceLimit
                            | FailureCode::StaleEpoch
                    ));
                    assert_eq!(sink.events.len(), 1);
                }
            }

            #[test]
            fn altered_nonce_downgrade_and_non_p1363_signatures_never_create_sessions() {
                let client_signer = RingSigner::generate();
                let daemon_signer = RingSigner::generate();
                let (client_config, server_config) =
                    handshake_configs(&client_signer, &daemon_signer);
                let (client, hello) = ClientHandshake::start(client_config).unwrap();
                let mut altered_hello = hello.clone();
                let nonce_marker = [0, 0, 0, 32];
                let nonce = altered_hello
                    .windows(4)
                    .position(|part| part == nonce_marker)
                    .unwrap()
                    + 4;
                altered_hello[nonce] ^= 1;
                let mut sink = RecordingSink::default();
                let (_, proof) = ServerHandshake::accept(
                    server_config,
                    &altered_hello,
                    &daemon_signer,
                    &mut sink,
                )
                .unwrap();
                assert_eq!(
                    client
                        .finish(&proof, &client_signer, &mut sink)
                        .unwrap_err()
                        .code(),
                    FailureCode::AuthenticationFailed
                );

                let (client_config, server_config) =
                    handshake_configs(&client_signer, &daemon_signer);
                let (client, hello) = ClientHandshake::start(client_config).unwrap();
                let (_, mut proof) =
                    ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink)
                        .unwrap();
                let selected = 4 + b"server-proof".len() + hello.len() + 4;
                proof[selected] = b'2';
                assert_eq!(
                    client
                        .finish(&proof, &client_signer, &mut sink)
                        .unwrap_err()
                        .code(),
                    FailureCode::DowngradeRejected
                );

                let (client_config, server_config) =
                    handshake_configs(&client_signer, &daemon_signer);
                let (client, hello) = ClientHandshake::start(client_config).unwrap();
                let (server, mut proof) =
                    ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink)
                        .unwrap();
                let signature_length = proof.len() - 68;
                proof[signature_length..signature_length + 4].copy_from_slice(&63u32.to_be_bytes());
                assert_eq!(
                    client
                        .finish(&proof, &client_signer, &mut sink)
                        .unwrap_err()
                        .code(),
                    FailureCode::MalformedInput
                );
                assert_eq!(
                    server.finish(&[0u8; 70], &mut sink).unwrap_err().code(),
                    FailureCode::MalformedInput
                );
            }

            #[test]
            fn replay_duplicate_and_skipped_counters_close_before_dispatch() {
                let (mut client, mut daemon) = establish_pair(7);
                let output =
                    AuthorizedOutput::filtered(PayloadKind::Command, b"one".to_vec()).unwrap();
                let mut sink = RecordingSink::default();
                let frame = client.send(&output, &mut sink).unwrap();
                daemon
                    .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                    .unwrap();
                let failure = daemon
                    .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                    .expect_err("replay");
                assert_eq!(failure.code(), FailureCode::ReplayDetected);
                assert_eq!(
                    sink.events.last().unwrap().code(),
                    SecurityCode::ReplayDetected
                );
                assert!(!daemon.is_open());

                let (mut client, mut daemon) = establish_pair(7);
                let mut skipped = client.send(&output, &mut sink).unwrap();
                skipped[21..29].copy_from_slice(&1u64.to_be_bytes());
                let failure = daemon
                    .receive(&skipped, &owned_operation(PayloadKind::Command), &mut sink)
                    .expect_err("skipped counter");
                assert_eq!(failure.code(), FailureCode::CounterMismatch);
                assert!(!daemon.is_open());
            }

            #[test]
            fn wrong_direction_connection_tag_and_stale_epoch_fail_closed() {
                let output =
                    AuthorizedOutput::filtered(PayloadKind::Command, b"one".to_vec()).unwrap();
                let mut sink = RecordingSink::default();

                let (_, mut daemon) = establish_pair(7);
                let wrong_direction = daemon
                    .send_projection(
                        &owned_projection(ProjectionClass::Response, b"one"),
                        &mut sink,
                    )
                    .unwrap();
                let failure = daemon
                    .receive(
                        &wrong_direction,
                        &owned_operation(PayloadKind::Response),
                        &mut sink,
                    )
                    .expect_err("wrong direction");
                assert_eq!(failure.code(), FailureCode::CryptographicFailure);

                let (mut client, mut daemon) = establish_pair(7);
                let mut wrong_connection = client.send(&output, &mut sink).unwrap();
                wrong_connection[5] ^= 1;
                let failure = daemon
                    .receive(
                        &wrong_connection,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("wrong connection");
                assert_eq!(failure.code(), FailureCode::MalformedInput);

                let (mut client, mut daemon) = establish_pair(7);
                let mut wrong_tag = client.send(&output, &mut sink).unwrap();
                *wrong_tag.last_mut().unwrap() ^= 1;
                let failure = daemon
                    .receive(
                        &wrong_tag,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("wrong tag");
                assert_eq!(failure.code(), FailureCode::CryptographicFailure);

                // No session exists at a stale epoch to begin with: the daemon authenticates
                // the hello against the epoch the registered principal carries.
                let failure = establish_pair_at_epochs(6, 7, (1, 3), (2, 4))
                    .expect_err("client epoch the registry moved past");
                assert_eq!(failure.code(), FailureCode::StaleEpoch);
                assert_eq!(
                    failure.safe_next_action().as_str(),
                    "reconnect-current-epoch"
                );
            }

            #[test]
            fn malformed_and_oversized_frames_emit_required_event_before_close() {
                let (_, mut daemon) = establish_pair(7);
                let mut sink = RecordingSink::default();
                let failure = daemon
                    .receive(
                        &[0, 0, 0, 1, 1],
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("short frame");
                assert_eq!(failure.code(), FailureCode::MalformedInput);
                assert_eq!(sink.events.len(), 1);
                assert_eq!(sink.events[0].code(), SecurityCode::MalformedInput);
                assert!(!daemon.is_open());

                let (_, mut daemon) = establish_pair(7);
                let mut oversized = vec![0u8; 4];
                oversized.copy_from_slice(&(1_048_577u32).to_be_bytes());
                let failure = daemon
                    .receive(
                        &oversized,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("oversized declaration");
                assert_eq!(failure.code(), FailureCode::ResourceLimit);
                assert!(!daemon.is_open());
            }
        }
    };
}
