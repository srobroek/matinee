macro_rules! secure_channel_faults_tests {
    () => {
        mod secure_channel_faults_inner {
            use crate::test_support_channel::{
                CONNECTION, DAEMON, ENDPOINT, PRINCIPAL, RecordingSink, RingSigner, capability,
                establish_pair, establish_pair_at_epochs, establish_pair_with_ranges,
                fixture_principal, id, owned_operation, owned_projection, registered_principal,
            };
            use crate::{
                AuthorizedOutput, CapabilityAction, ChannelSigner, ClientHandshake,
                ClientHandshakeConfig, ConnectionId, FailureBoundary, FailureCode, PayloadKind,
                Principal, PrincipalKind, ProjectionClass, PublicKey, SafeNextAction, SecurityCode,
                ServerHandshake, ServerHandshakeConfig,
            };
            use std::collections::BTreeMap;
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

            /// The first byte of the length-prefixed selected-contract field inside a
            /// server proof: `LP("server-proof") || client_hello || LP(selected)`.
            fn selected_contract_field(hello: &[u8]) -> usize {
                4 + b"server-proof".len() + hello.len()
            }

            /// FR-032: a handshake that already completed never replays. Both halves of
            /// the recorded proof pair are bound to the nonce and ephemeral key of the
            /// exact run that produced them, so replaying either one into a second
            /// transcript is refused before any traffic key exists.
            ///
            /// Every other field a peer could check is deliberately held constant here:
            /// the replay reuses the recorded hello, so endpoint, principal selector,
            /// epoch, contract range and both long-term keys still match. Only the
            /// per-run nonce and ephemeral context moved, and that alone must refuse it.
            #[test]
            fn fr032_a_completed_handshake_never_replays_into_another_session() {
                let client_signer = RingSigner::generate();
                let daemon_signer = RingSigner::generate();
                let mut sink = RecordingSink::default();

                let (client_config, server_config) =
                    handshake_configs(&client_signer, &daemon_signer);
                let (client_pending, hello) = ClientHandshake::start(client_config).unwrap();
                let (server_pending, server_proof) =
                    ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink)
                        .unwrap();
                let (client_session, client_proof) = client_pending
                    .finish(&server_proof, &client_signer, &mut sink)
                    .expect("the production handshake completes");
                let daemon_session = server_pending
                    .finish(&client_proof, &mut sink)
                    .expect("the production handshake completes");
                // The handshake is complete, not merely started: both peers hold a live
                // session, so what follows replays a finished transcript.
                assert!(client_session.is_open(), "the client half completed");
                assert!(daemon_session.is_open(), "the daemon half completed");
                assert!(
                    sink.events.is_empty(),
                    "a completed handshake records no failure"
                );

                // The recorded client proof, replayed into a second server transcript.
                let (_, replay_server_config) = handshake_configs(&client_signer, &daemon_signer);
                let (replayed_server, second_proof) = ServerHandshake::accept(
                    replay_server_config,
                    &hello,
                    &daemon_signer,
                    &mut sink,
                )
                .expect("the recorded hello still satisfies every stated field");
                assert_ne!(
                    second_proof, server_proof,
                    "each accept mints its own nonce and ephemeral key"
                );
                let failure = replayed_server
                    .finish(&client_proof, &mut sink)
                    .expect_err("a completed handshake's client proof never authenticates twice");
                assert_eq!(failure.code(), FailureCode::AuthenticationFailed);
                assert_eq!(failure.boundary(), FailureBoundary::Authentication);
                assert_eq!(
                    failure.safe_next_action(),
                    SafeNextAction::VerifyCredentialAndReconnect
                );
                assert_eq!(sink.events.len(), 1, "the refused replay is recorded");
                assert_eq!(
                    sink.events.last().unwrap().code(),
                    SecurityCode::AuthenticationFailed
                );

                // The recorded server proof, replayed to a client that started fresh. The
                // proof carries the transcript it was signed over, so it cannot be lifted
                // onto another hello even when every configured field is identical.
                let (replay_client_config, _) = handshake_configs(&client_signer, &daemon_signer);
                let (replay_client, replay_hello) =
                    ClientHandshake::start(replay_client_config).unwrap();
                assert_eq!(
                    replay_hello.len(),
                    hello.len(),
                    "the two hellos differ only in nonce and ephemeral key"
                );
                assert_ne!(replay_hello, hello, "each hello carries its own nonce");
                let failure = replay_client
                    .finish(&server_proof, &client_signer, &mut sink)
                    .expect_err("a completed handshake's server proof never binds a new hello");
                assert_eq!(failure.code(), FailureCode::AuthenticationFailed);
                assert_eq!(failure.boundary(), FailureBoundary::Authentication);
                assert_eq!(sink.events.len(), 2, "both refusals are recorded");
            }

            /// FR-032: the negotiated contract never replays out of the transcript that
            /// selected it. The selection is signed inside the server proof and it is both
            /// an HKDF info input and a frame AAD input, so a contract lifted from another
            /// completed handshake is refused before key derivation, and a frame sealed
            /// under one contract is refused by a channel that negotiated another.
            #[test]
            fn fr032_a_replayed_contract_selection_and_cross_contract_frame_are_refused() {
                let client_signer = RingSigner::generate();
                let daemon_signer = RingSigner::generate();
                let mut sink = RecordingSink::default();

                // One completed handshake at the fixture range, which selects contract 3.
                let (reference_client, reference_daemon) =
                    establish_pair_with_ranges(EPOCH, (1, 3), (2, 4))
                        .expect("the fixture range negotiates a contract");
                assert_eq!(reference_client.contract(), 3);
                assert_eq!(reference_daemon.contract(), 3);

                // A second completed handshake over a narrower range, which selects
                // contract 2. Its committed selection is the value replayed below.
                let (donor_client, donor_daemon) =
                    establish_pair_with_ranges(EPOCH, (1, 2), (1, 2))
                        .expect("the narrow range negotiates a contract");
                assert_eq!(donor_client.contract(), 2);
                assert_eq!(donor_daemon.contract(), 2);

                // Rebuild both transcripts so the exact signed bytes are in hand: the
                // donor's selection field, and a victim proof still awaiting its client.
                let (donor_config, donor_server_config) = (
                    ClientHandshakeConfig::new(
                        ENDPOINT,
                        id(PRINCIPAL),
                        client_signer.public_key().clone(),
                        id(DAEMON),
                        daemon_signer.public_key().clone(),
                        EPOCH,
                        1,
                        2,
                    )
                    .unwrap(),
                    ServerHandshakeConfig::new(
                        ENDPOINT,
                        fixture_principal(client_signer.public_key().clone(), EPOCH),
                        id(DAEMON),
                        daemon_signer.public_key().clone(),
                        1,
                        2,
                        ConnectionId::new(Uuid::from_u128(CONNECTION)),
                    )
                    .unwrap(),
                );
                let (donor_pending, donor_hello) = ClientHandshake::start(donor_config).unwrap();
                let (donor_server, donor_proof) = ServerHandshake::accept(
                    donor_server_config,
                    &donor_hello,
                    &daemon_signer,
                    &mut sink,
                )
                .unwrap();
                let (_, donor_client_proof) = donor_pending
                    .finish(&donor_proof, &client_signer, &mut sink)
                    .expect("the donor handshake completes at contract 2");
                donor_server
                    .finish(&donor_client_proof, &mut sink)
                    .expect("the donor handshake completes at contract 2");

                let (victim_config, victim_server_config) =
                    handshake_configs(&client_signer, &daemon_signer);
                let (victim_client, victim_hello) = ClientHandshake::start(victim_config).unwrap();
                let (_, victim_proof) = ServerHandshake::accept(
                    victim_server_config,
                    &victim_hello,
                    &daemon_signer,
                    &mut sink,
                )
                .unwrap();
                assert!(
                    sink.events.is_empty(),
                    "both transcripts were built without a refusal"
                );

                // Replay the donor's committed selection into the victim transcript. Both
                // hellos are the same length, so this substitutes exactly the signed
                // contract field and leaves every other byte of the victim proof intact.
                let donor_field = selected_contract_field(&donor_hello);
                let victim_field = selected_contract_field(&victim_hello);
                assert_eq!(donor_hello.len(), victim_hello.len());
                let replayed_selection = donor_proof[donor_field..donor_field + 5].to_vec();
                assert_eq!(
                    replayed_selection,
                    [0, 0, 0, 1, b'2'],
                    "the donor daemon committed to contract 2"
                );
                assert_eq!(
                    &victim_proof[victim_field..victim_field + 5],
                    [0, 0, 0, 1, b'3'],
                    "the victim daemon committed to contract 3"
                );
                let mut spliced = victim_proof.clone();
                spliced[victim_field..victim_field + 5].copy_from_slice(&replayed_selection);
                assert_eq!(spliced.len(), victim_proof.len());

                let failure = victim_client
                    .finish(&spliced, &client_signer, &mut sink)
                    .expect_err("a contract replayed from another handshake is refused");
                assert_eq!(failure.code(), FailureCode::DowngradeRejected);
                assert_eq!(failure.boundary(), FailureBoundary::Compatibility);
                assert_eq!(
                    failure.safe_next_action(),
                    SafeNextAction::UseFixedContractPeer
                );
                assert_eq!(sink.events.len(), 1, "the refused replay is recorded");
                assert_eq!(sink.events.last().unwrap().code(), SecurityCode::Downgrade);

                // A sealed frame carries its contract in the AAD and in the key it was
                // sealed under, so it cannot be replayed onto a channel that negotiated a
                // different one. Both fixture pairs run on the same connection at counter
                // zero in the same direction: the contract is the only context that moved.
                let (mut low_client, mut low_daemon) =
                    establish_pair_with_ranges(EPOCH, (1, 2), (1, 2)).unwrap();
                let (_high_client, mut high_daemon) =
                    establish_pair_with_ranges(EPOCH, (1, 3), (2, 4)).unwrap();
                assert_eq!(low_daemon.contract(), 2);
                assert_eq!(high_daemon.contract(), 3);
                assert_eq!(
                    low_daemon.connection_id(),
                    high_daemon.connection_id(),
                    "the connection context is identical"
                );
                assert_eq!(low_daemon.epoch(), high_daemon.epoch());
                let output =
                    AuthorizedOutput::filtered(PayloadKind::Command, b"cross-contract".to_vec())
                        .unwrap();
                let sealed_at_two = low_client.send(&output, &mut sink).unwrap();
                let failure = high_daemon
                    .receive(
                        &sealed_at_two,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect_err("a frame sealed under another contract is refused");
                assert_eq!(failure.code(), FailureCode::CryptographicFailure);
                assert!(
                    !high_daemon.is_open(),
                    "the channel closed before any payload dispatched"
                );

                // The positive control: the identical bytes inside their own contract
                // context still open, so the refusal above is the contract and not the
                // frame.
                let accepted = low_daemon
                    .receive(
                        &sealed_at_two,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect("the frame is valid inside the contract that sealed it");
                assert_eq!(accepted.payload(), b"cross-contract");
                assert!(low_daemon.is_open());
            }

            // ---------------------------------------------------------------
            // A strict reader for the vector corpus. `vectors/README.txt` §1
            // and §6 make duplicate-key rejection and canonical numbers part of
            // the contract, so the corpus is read with a parser that refuses
            // both rather than with a substring scan.
            // ---------------------------------------------------------------
            #[derive(Clone, Debug, PartialEq)]
            enum Json {
                Null,
                Bool(bool),
                Number(u64),
                Text(String),
                Array(Vec<Json>),
                Object(Vec<(String, Json)>),
            }

            impl Json {
                fn get(&self, name: &str) -> Option<&Json> {
                    match self {
                        Json::Object(entries) => entries
                            .iter()
                            .find(|(key, _)| key == name)
                            .map(|(_, value)| value),
                        _ => None,
                    }
                }

                fn keys(&self) -> Vec<&str> {
                    match self {
                        Json::Object(entries) => {
                            entries.iter().map(|(key, _)| key.as_str()).collect()
                        }
                        _ => panic!("not an object"),
                    }
                }

                fn items(&self) -> &[Json] {
                    match self {
                        Json::Array(items) => items,
                        _ => panic!("not an array"),
                    }
                }

                fn as_text(&self) -> &str {
                    match self {
                        Json::Text(value) => value,
                        other => panic!("not a string: {other:?}"),
                    }
                }

                fn text(&self, name: &str) -> &str {
                    self.get(name)
                        .unwrap_or_else(|| panic!("missing string field {name}"))
                        .as_text()
                }

                fn maybe_text(&self, name: &str) -> Option<&str> {
                    match self.get(name) {
                        Some(Json::Text(value)) => Some(value),
                        _ => None,
                    }
                }

                fn integer(&self, name: &str) -> u64 {
                    match self.get(name) {
                        Some(Json::Number(value)) => *value,
                        other => panic!("missing integer field {name}: {other:?}"),
                    }
                }

                fn flag(&self, name: &str) -> bool {
                    matches!(self.get(name), Some(Json::Bool(true)))
                }

                fn is_null(&self, name: &str) -> bool {
                    matches!(self.get(name), Some(Json::Null))
                }
            }

            struct Parser<'a> {
                bytes: &'a [u8],
                at: usize,
            }

            impl<'a> Parser<'a> {
                fn skip(&mut self) {
                    while matches!(self.bytes.get(self.at), Some(b' ' | b'\n' | b'\r' | b'\t')) {
                        self.at += 1;
                    }
                }

                fn byte(&self) -> Result<u8, String> {
                    self.bytes
                        .get(self.at)
                        .copied()
                        .ok_or_else(|| "unexpected end of input".to_owned())
                }

                fn expect(&mut self, expected: u8) -> Result<(), String> {
                    if self.byte()? != expected {
                        return Err(format!(
                            "expected {:?} at offset {}",
                            expected as char, self.at
                        ));
                    }
                    self.at += 1;
                    Ok(())
                }

                fn literal(&mut self, word: &str) -> Result<(), String> {
                    if !self.bytes[self.at..].starts_with(word.as_bytes()) {
                        return Err(format!("expected {word} at offset {}", self.at));
                    }
                    self.at += word.len();
                    Ok(())
                }

                fn string(&mut self) -> Result<String, String> {
                    self.expect(b'"')?;
                    let mut out = String::new();
                    loop {
                        let byte = self.byte()?;
                        self.at += 1;
                        match byte {
                            b'"' => return Ok(out),
                            b'\\' => {
                                let escape = self.byte()?;
                                self.at += 1;
                                out.push(match escape {
                                    b'"' => '"',
                                    b'\\' => '\\',
                                    b'/' => '/',
                                    b'n' => '\n',
                                    b'r' => '\r',
                                    b't' => '\t',
                                    other => {
                                        return Err(format!(
                                            "unsupported escape \\{}",
                                            other as char
                                        ));
                                    }
                                });
                            }
                            control if control < 0x20 => {
                                return Err(format!("raw control byte {control:#04x} in string"));
                            }
                            other => out.push(other as char),
                        }
                    }
                }

                /// Canonical, non-negative decimal integers only: a sign, a
                /// fraction, an exponent, or a leading zero is a schema failure.
                fn number(&mut self) -> Result<u64, String> {
                    let start = self.at;
                    while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                        self.at += 1;
                    }
                    let text = core::str::from_utf8(&self.bytes[start..self.at])
                        .map_err(|_| "non-utf8 number".to_owned())?;
                    if text.is_empty() {
                        return Err(format!("expected a digit at offset {start}"));
                    }
                    if text.len() > 1 && text.starts_with('0') {
                        return Err(format!("non-canonical number {text}"));
                    }
                    if matches!(self.bytes.get(self.at), Some(b'.' | b'e' | b'E')) {
                        return Err(format!("non-integer number at offset {start}"));
                    }
                    text.parse().map_err(|_| format!("number {text} overflows"))
                }

                fn value(&mut self) -> Result<Json, String> {
                    self.skip();
                    match self.byte()? {
                        b'{' => {
                            self.at += 1;
                            let mut entries: Vec<(String, Json)> = Vec::new();
                            self.skip();
                            if self.byte()? == b'}' {
                                self.at += 1;
                                return Ok(Json::Object(entries));
                            }
                            loop {
                                self.skip();
                                let key = self.string()?;
                                if entries.iter().any(|(seen, _)| *seen == key) {
                                    return Err(format!("duplicate key {key}"));
                                }
                                self.skip();
                                self.expect(b':')?;
                                let value = self.value()?;
                                entries.push((key, value));
                                self.skip();
                                match self.byte()? {
                                    b',' => self.at += 1,
                                    b'}' => {
                                        self.at += 1;
                                        return Ok(Json::Object(entries));
                                    }
                                    other => {
                                        return Err(format!(
                                            "expected , or }} at offset {} got {:?}",
                                            self.at, other as char
                                        ));
                                    }
                                }
                            }
                        }
                        b'[' => {
                            self.at += 1;
                            let mut items = Vec::new();
                            self.skip();
                            if self.byte()? == b']' {
                                self.at += 1;
                                return Ok(Json::Array(items));
                            }
                            loop {
                                items.push(self.value()?);
                                self.skip();
                                match self.byte()? {
                                    b',' => self.at += 1,
                                    b']' => {
                                        self.at += 1;
                                        return Ok(Json::Array(items));
                                    }
                                    other => {
                                        return Err(format!(
                                            "expected , or ] at offset {} got {:?}",
                                            self.at, other as char
                                        ));
                                    }
                                }
                            }
                        }
                        b'"' => Ok(Json::Text(self.string()?)),
                        b't' => {
                            self.literal("true")?;
                            Ok(Json::Bool(true))
                        }
                        b'f' => {
                            self.literal("false")?;
                            Ok(Json::Bool(false))
                        }
                        b'n' => {
                            self.literal("null")?;
                            Ok(Json::Null)
                        }
                        b'-' => Err("negative numbers are not permitted".to_owned()),
                        _ => Ok(Json::Number(self.number()?)),
                    }
                }
            }

            fn parse_json(text: &str) -> Result<Json, String> {
                let mut parser = Parser {
                    bytes: text.as_bytes(),
                    at: 0,
                };
                let value = parser.value()?;
                parser.skip();
                if parser.at != parser.bytes.len() {
                    return Err(format!("trailing content at offset {}", parser.at));
                }
                Ok(value)
            }

            const CORPUS: &str = include_str!("../vectors/secure-channel-v1.json");
            const FIXTURE: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/webcrypto/secure-channel-vectors.mjs"
            );
            /// Recorded so the campaign is reproducible: rerun the peer with
            /// `--campaign --seed 0x5ec0000600035c03 --cases 1000`.
            const CAMPAIGN_SEED: &str = "0x5ec0000600035c03";
            const CAMPAIGN_CASES: usize = 1_000;
            const EXTENSION_PRINCIPAL: u128 = 4;
            const MAX_PAYLOAD: usize = 1_048_534;

            const STABLE_CODES: [&str; 9] = [
                "authentication.failed",
                "authentication.cryptographic",
                "malformed.input",
                "resource_limit",
                "stale_epoch",
                "compatibility.downgrade",
                "compatibility.unsupported",
                "replay.detected",
                "replay.counter",
            ];

            fn corpus() -> Json {
                parse_json(CORPUS).expect("the vector corpus parses strictly")
            }

            fn vectors(corpus: &Json) -> &[Json] {
                corpus.get("vectors").expect("vectors array").items()
            }

            fn decode_hex(value: &str) -> Vec<u8> {
                assert_eq!(value.len() % 2, 0, "hex fields have whole bytes");
                assert!(
                    value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "hex fields are lower case: {value}"
                );
                (0..value.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&value[at..at + 2], 16).expect("hex pair"))
                    .collect()
            }

            fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
                decode_hex(value)
                    .try_into()
                    .unwrap_or_else(|_| panic!("expected {N} bytes"))
            }

            fn run_peer(args: &[&str]) -> String {
                let output = std::process::Command::new("node")
                    .arg(FIXTURE)
                    .args(args)
                    .output()
                    .expect("Node.js WebCrypto peer");
                assert!(
                    output.status.success(),
                    "peer {args:?} failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout).expect("peer emits utf-8")
            }

            /// The named inputs of `valid.handshake`, and the traffic keys the
            /// production derivation reproduces from them.
            struct Reference {
                client_key: PublicKey,
                daemon_key: PublicKey,
                connection: ConnectionId,
                client_to_daemon: [u8; 32],
                daemon_to_client: [u8; 32],
                contract: u16,
            }

            fn reference(corpus: &Json) -> Reference {
                let valid = vectors(corpus)
                    .iter()
                    .find(|vector| vector.text("id") == "valid.handshake")
                    .expect("valid.handshake");
                let inputs = valid.get("inputs").expect("inputs");
                let client_key = PublicKey::from_uncompressed(fixed_hex(
                    inputs.text("client_identity_public_hex"),
                ))
                .expect("uncompressed client point");
                let daemon_key = PublicKey::from_uncompressed(fixed_hex(
                    inputs.text("daemon_identity_public_hex"),
                ))
                .expect("uncompressed daemon point");
                let contract = inputs.integer("selected_contract") as u16;
                let (server, client, salt) =
                    crate::channel::vector_transcripts(crate::channel::VectorTranscriptInput {
                        client_hello: &decode_hex(inputs.text("client_hello_hex")),
                        selected: contract,
                        server_min: inputs.integer("server_contract_min") as u16,
                        server_max: inputs.integer("server_contract_max") as u16,
                        daemon: crate::IdentityId::new(Uuid::from_bytes(fixed_hex(
                            inputs.text("daemon_id_hex"),
                        ))),
                        daemon_key: &daemon_key,
                        server_nonce: &fixed_hex(inputs.text("server_nonce_hex")),
                        server_ephemeral: &fixed_hex(inputs.text("server_ephemeral_public_hex")),
                        connection: ConnectionId::new(Uuid::from_bytes(fixed_hex(
                            inputs.text("connection_id_hex"),
                        ))),
                        server_signature: &fixed_hex(inputs.text("server_signature_p1363_hex")),
                        client_signature: &fixed_hex(inputs.text("client_signature_p1363_hex")),
                    });
                // The corpus records these transcripts, so a drifting encoder is
                // caught here rather than as an opaque signature failure later.
                assert_eq!(server, decode_hex(inputs.text("transcript_hex")));
                assert_eq!(server, decode_hex(inputs.text("server_proof_input_hex")));
                assert_eq!(client, decode_hex(inputs.text("client_proof_input_hex")));
                assert_eq!(salt, fixed_hex::<32>(inputs.text("hkdf_salt_hex")));
                let (client_to_daemon, daemon_to_client) = crate::channel::vector_material(
                    &decode_hex(inputs.text("ecdh_shared_secret_hex")),
                    &salt,
                    contract,
                )
                .expect("vector traffic keys");
                assert_eq!(
                    client_to_daemon,
                    fixed_hex::<32>(inputs.text("client_to_daemon_key_hex"))
                );
                assert_eq!(
                    daemon_to_client,
                    fixed_hex::<32>(inputs.text("daemon_to_client_key_hex"))
                );
                Reference {
                    client_key,
                    daemon_key,
                    connection: ConnectionId::new(Uuid::from_bytes(fixed_hex(
                        inputs.text("connection_id_hex"),
                    ))),
                    client_to_daemon,
                    daemon_to_client,
                    contract,
                }
            }

            fn vector_session(
                reference: &Reference,
                principal: Principal,
            ) -> crate::ChannelSession {
                crate::channel::vector_daemon_session(
                    reference.connection,
                    principal,
                    reference.contract,
                    reference.client_to_daemon,
                    reference.daemon_to_client,
                )
                .expect("a daemon session on the vector traffic keys")
            }

            /// Drive one handshake vector through the production admission path
            /// and report the stable failure code, or `None` for an acceptance.
            fn classify_handshake(
                vector: &Json,
                reference: &Reference,
                daemon_signer: &RingSigner,
            ) -> Option<String> {
                let inputs = vector.get("inputs").expect("inputs");
                if inputs.flag("rebuild_transcript") {
                    let (transcript, _, _) =
                        crate::channel::vector_transcripts(crate::channel::VectorTranscriptInput {
                            client_hello: &decode_hex(inputs.text("client_hello_hex")),
                            selected: inputs.integer("selected_contract") as u16,
                            server_min: inputs.integer("server_contract_min") as u16,
                            server_max: inputs.integer("server_contract_max") as u16,
                            daemon: crate::IdentityId::new(Uuid::from_bytes(fixed_hex(
                                inputs.text("daemon_id_hex"),
                            ))),
                            daemon_key: &PublicKey::from_uncompressed(fixed_hex(
                                inputs.text("daemon_identity_public_hex"),
                            ))
                            .expect("uncompressed point"),
                            server_nonce: &fixed_hex(inputs.text("server_nonce_hex")),
                            server_ephemeral: &fixed_hex(
                                inputs.text("server_ephemeral_public_hex"),
                            ),
                            connection: ConnectionId::new(Uuid::from_bytes(fixed_hex(
                                inputs.text("connection_id_hex"),
                            ))),
                            server_signature: &fixed_hex(inputs.text("server_signature_p1363_hex")),
                            client_signature: &[0u8; 64],
                        });
                    // The daemon key the transcript names is the one the signature
                    // has to verify under, so a substituted key fails here too.
                    return crate::channel::vector_verify_signature(
                        &reference.daemon_key,
                        &transcript,
                        &decode_hex(inputs.text("server_signature_p1363_hex")),
                    )
                    .err()
                    .map(|failure| failure.code().as_str().to_owned());
                }
                if inputs.get("client_hello_hex").is_none() {
                    return crate::channel::vector_verify_signature(
                        &reference.daemon_key,
                        &decode_hex(inputs.text("transcript_hex")),
                        &decode_hex(inputs.text("server_signature_p1363_hex")),
                    )
                    .err()
                    .map(|failure| failure.code().as_str().to_owned());
                }
                let hello = decode_hex(inputs.text("client_hello_hex"));
                let config = ServerHandshakeConfig::new(
                    ENDPOINT,
                    fixture_principal(reference.client_key.clone(), EPOCH),
                    id(DAEMON),
                    daemon_signer.public_key().clone(),
                    2,
                    4,
                    reference.connection,
                )
                .expect("server configuration");
                let mut sink = RecordingSink::default();
                match ServerHandshake::accept(config, &hello, daemon_signer, &mut sink) {
                    Ok(_) => None,
                    Err(failure) => {
                        assert_eq!(sink.events.len(), 1, "one bounded event per rejection");
                        Some(failure.code().as_str().to_owned())
                    }
                }
            }

            /// Drive one frame vector through the production frame path.
            ///
            /// A client-to-daemon frame is opened by a daemon session, which is
            /// `ChannelState::open`. A daemon-to-client frame has no client-role
            /// seam on vector keys, so it is proved by sealing: AES-GCM is
            /// deterministic, so reproducing the recorded bytes proves the native
            /// nonce, associated data, and key match the extension peer's.
            fn classify_frame(
                vector: &Json,
                reference: &Reference,
                principal: &Principal,
            ) -> Option<String> {
                let inputs = vector.get("inputs").expect("inputs");
                if let Some(text) = inputs.maybe_text("counter_text") {
                    // An out-of-range counter is refused, never wrapped into u64.
                    assert!(
                        text.parse::<u64>().is_err(),
                        "{text} must not parse as a counter"
                    );
                    assert!(text.parse::<u128>().expect("decimal") > u128::from(u64::MAX));
                    return Some("malformed.input".to_owned());
                }
                let direction = inputs.text("direction");
                let counter: u64 = inputs
                    .maybe_text("counter")
                    .map(|text| text.parse().expect("decimal counter"))
                    .unwrap_or(0);
                let receive: u64 = inputs
                    .text("receive_counter")
                    .parse()
                    .expect("decimal counter");
                let payload_len = inputs
                    .get("payload_len")
                    .map(|_| inputs.integer("payload_len"));

                if direction == "daemon-to-client" && inputs.get("framed_hex").is_some() {
                    let mut session = vector_session(reference, principal.clone());
                    session.channel.set_counters(counter, receive);
                    let sealed = session
                        .channel
                        .seal(
                            reference.connection,
                            EPOCH,
                            reference.contract,
                            PayloadKind::Command,
                            &decode_hex(inputs.text("payload_hex")),
                        )
                        .expect("the daemon seals its own direction");
                    assert_eq!(
                        sealed,
                        decode_hex(inputs.text("framed_hex")),
                        "{}: native and extension frame bytes must be identical",
                        vector.text("id")
                    );
                    return None;
                }

                if let Some(len) = payload_len {
                    // A megabyte of hex does not belong in a checked-in corpus, so
                    // the size boundaries carry a repeat rule and are materialised.
                    let byte = decode_hex(inputs.text("payload_repeat_byte_hex"))[0];
                    let payload = vec![byte; len as usize];
                    let (mut client, mut daemon) = establish_pair(EPOCH);
                    let mut sink = RecordingSink::default();
                    let output = match AuthorizedOutput::filtered(PayloadKind::Command, payload) {
                        Ok(output) => output,
                        Err(failure) => return Some(failure.code().as_str().to_owned()),
                    };
                    let frame = match client.send(&output, &mut sink) {
                        Ok(frame) => frame,
                        Err(failure) => return Some(failure.code().as_str().to_owned()),
                    };
                    assert_eq!(
                        frame.len(),
                        1_048_580,
                        "the exact maximum payload encodes the exact maximum frame"
                    );
                    return daemon
                        .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                        .err()
                        .map(|failure| failure.code().as_str().to_owned());
                }

                let framed = decode_hex(inputs.text("framed_hex"));
                let mut session = vector_session(reference, principal.clone());
                session.channel.set_counters(0, receive);
                if inputs.flag("receive_exhausted") {
                    // There is no setter for exhaustion: the session reaches it by
                    // consuming the maximum counter, which is how production does.
                    let mut sink = RecordingSink::default();
                    session
                        .receive(&framed, &owned_operation(PayloadKind::Command), &mut sink)
                        .expect("the receiver accepts the maximum counter exactly once");
                }
                let mut sink = RecordingSink::default();
                match session.receive(&framed, &owned_operation(PayloadKind::Command), &mut sink) {
                    Ok(opened) => {
                        assert_eq!(opened.payload(), decode_hex(inputs.text("payload_hex")));
                        assert!(session.is_open());
                        None
                    }
                    Err(failure) => {
                        assert!(!session.is_open(), "a rejected frame closes the channel");
                        assert_eq!(
                            session.receive_counter(),
                            receive,
                            "a reject never advances"
                        );
                        assert_eq!(sink.events.len(), 1, "one bounded event per rejection");
                        Some(failure.code().as_str().to_owned())
                    }
                }
            }

            /// FR-030: the corpus is the versioned schema `vectors/README.txt`
            /// specifies, read with duplicate-key and canonical-number rejection.
            #[test]
            fn vector_schema() {
                assert_eq!(
                    parse_json("{\"a\": 1, \"a\": 2}"),
                    Err("duplicate key a".to_owned()),
                    "the reader must refuse duplicate keys"
                );
                assert_eq!(
                    parse_json("{\"a\": 01}"),
                    Err("non-canonical number 01".to_owned())
                );
                assert!(parse_json("{\"a\": 1.5}").is_err());
                assert!(parse_json("{\"a\": 1e3}").is_err());
                assert!(parse_json("{\"a\": -1}").is_err());
                assert!(parse_json("{\"a\": 1} trailing").is_err());

                let corpus = corpus();
                assert_eq!(
                    corpus.keys(),
                    ["schema", "schema_version", "vectors", "evidence_schema"]
                );
                assert_eq!(corpus.text("schema"), "matinee.secure-channel.v1");
                assert_eq!(corpus.integer("schema_version"), 1);
                assert_eq!(
                    corpus.text("evidence_schema"),
                    "matinee.security.evidence.v1"
                );

                let mut ids = std::collections::BTreeSet::new();
                for vector in vectors(&corpus) {
                    let id = vector.text("id");
                    assert!(ids.insert(id.to_owned()), "{id} appears twice");
                    assert!(
                        id.bytes().all(|byte| byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'.'),
                        "{id} is not lower-case kebab"
                    );
                    let valid = matches!(vector.get("valid"), Some(Json::Bool(true)));
                    let expected: &[&str] = if valid {
                        &["id", "kind", "valid", "inputs", "expect"]
                    } else {
                        &["id", "kind", "valid", "mutation", "inputs", "expect"]
                    };
                    assert_eq!(vector.keys(), expected, "{id} key order");
                    assert!(matches!(vector.text("kind"), "handshake" | "frame"), "{id}");
                    let expect = vector.get("expect").expect("expect");
                    assert_eq!(
                        expect.keys(),
                        [
                            "result",
                            "failure_code",
                            "channel_state",
                            "dispatch_count",
                            "allocation",
                            "secret_scan"
                        ],
                        "{id} expect key order"
                    );
                    assert_eq!(expect.text("secret_scan"), "pass", "{id}");
                    assert!(
                        matches!(expect.text("allocation"), "none" | "bounded" | "maximum"),
                        "{id} allocation"
                    );
                    if valid {
                        assert_eq!(expect.text("result"), "accept", "{id}");
                        assert_eq!(expect.text("channel_state"), "open", "{id}");
                        assert!(expect.is_null("failure_code"), "{id}");
                        assert!(vector.get("mutation").is_none(), "{id}");
                    } else {
                        assert_eq!(expect.text("result"), "reject", "{id}");
                        assert_eq!(expect.text("channel_state"), "closed", "{id}");
                        assert_eq!(expect.integer("dispatch_count"), 0, "{id}");
                        let code = expect.text("failure_code");
                        assert!(STABLE_CODES.contains(&code), "{id} code {code}");
                        let mutation = vector.get("mutation").expect("mutation");
                        assert_eq!(mutation.keys(), ["field", "boundary", "operation"], "{id}");
                        assert_eq!(
                            id,
                            format!(
                                "mutate.{}.{}.{}",
                                vector.text("kind"),
                                mutation.text("field"),
                                mutation.text("boundary")
                            ),
                            "{id} does not name its own field and boundary"
                        );
                    }
                    // Byte fields decode, and no value carries a fixture scalar.
                    let inputs = vector.get("inputs").expect("inputs");
                    if let Json::Object(entries) = inputs {
                        for (key, value) in entries {
                            if let Json::Text(text) = value {
                                if key.ends_with("_hex") && key != "counter_text" {
                                    let _ = decode_hex(text);
                                }
                                for scalar in [
                                    "1".repeat(1),
                                    format!("{:064x}", 1),
                                    format!("{:064x}", 2),
                                    format!("{:064x}", 3),
                                    format!("{:064x}", 4),
                                ]
                                .iter()
                                .skip(1)
                                {
                                    assert_ne!(text, scalar, "{id}.{key} is a fixture scalar");
                                }
                            }
                        }
                    }
                }
                assert!(ids.contains("valid.handshake") && ids.contains("valid.frame"));
            }

            /// FR-030: one isolated mutation at every field boundary the contract
            /// lists, plus the counter, direction, and allocation boundaries.
            #[test]
            fn mutation_coverage() {
                let corpus = corpus();
                let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
                let mut allocations = std::collections::BTreeSet::new();
                for vector in vectors(&corpus) {
                    allocations.insert(
                        vector
                            .get("expect")
                            .expect("expect")
                            .text("allocation")
                            .to_owned(),
                    );
                    if let Some(mutation) = vector.get("mutation") {
                        fields
                            .entry(format!(
                                "{}.{}",
                                vector.text("kind"),
                                mutation.text("field")
                            ))
                            .or_default()
                            .push(mutation.text("boundary").to_owned());
                    }
                }

                // `vectors/README.txt` §2 names these fields explicitly.
                let required = [
                    "handshake.context",
                    "handshake.hello-label",
                    "handshake.endpoint",
                    "handshake.principal-selector",
                    "handshake.epoch",
                    "handshake.minimum-contract",
                    "handshake.maximum-contract",
                    "handshake.client-nonce",
                    "handshake.client-key",
                    "handshake.client-ephemeral-key",
                    "handshake.selected-contract",
                    "handshake.daemon-id",
                    "handshake.server-nonce",
                    "handshake.server-key",
                    "handshake.connection-id",
                    "handshake.daemon-key",
                    "handshake.signature",
                    "frame.version",
                    "frame.connection-id",
                    "frame.direction",
                    "frame.counter",
                    "frame.ciphertext",
                    "frame.tag",
                    "frame.payload-kind",
                    "frame.declared-length",
                    "frame.payload",
                ];
                for field in required {
                    let boundaries = fields
                        .get(field)
                        .unwrap_or_else(|| panic!("{field} has no single-field mutation"));
                    assert!(!boundaries.is_empty(), "{field}");
                }

                // §2's boundary vocabulary, §3's counter and allocation rules.
                let all: Vec<&String> = fields.values().flatten().collect();
                for boundary in [
                    "empty",
                    "short",
                    "exact-boundary",
                    "one-over",
                    "one-under",
                    "substitution",
                    "truncation",
                    "extension",
                    "malformed-utf8",
                    "der-key",
                    "compressed-key",
                    "invalid-uuid",
                    "bad-length-prefix",
                    "altered-tag",
                    "altered-ciphertext",
                    "downgraded",
                    "substituted",
                    "disjoint",
                    "duplicate",
                    "skipped",
                    "wrapped",
                ] {
                    assert!(
                        all.iter().any(|seen| *seen == boundary),
                        "no vector exercises the {boundary} boundary"
                    );
                }
                assert_eq!(
                    allocations,
                    ["bounded", "maximum", "none"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect()
                );

                // Both directions at 0, 1, and the maximum, and the exact payload
                // and frame maxima, are present as accepted vectors.
                let ids: Vec<&str> = vectors(&corpus)
                    .iter()
                    .map(|vector| vector.text("id"))
                    .collect();
                for required in [
                    "valid.frame",
                    "valid.frame.client-to-daemon.counter-1",
                    "valid.frame.client-to-daemon.counter-maximum",
                    "valid.frame.daemon-to-client.counter-0",
                    "valid.frame.daemon-to-client.counter-1",
                    "valid.frame.daemon-to-client.counter-maximum",
                    "valid.frame.payload.zero",
                    "valid.frame.payload.one",
                    "valid.frame.payload.exact-maximum",
                    "mutate.frame.counter.overflow",
                ] {
                    assert!(ids.contains(&required), "{required} is missing");
                }
            }

            /// FR-030, SC-003, SC-007: every corpus vector runs on both peers and
            /// classifies to the same stable code.
            #[test]
            fn native_and_webcrypto_peers_agree_on_every_corpus_vector() {
                let corpus = corpus();
                let reference = reference(&corpus);
                let daemon_signer = RingSigner::generate();
                let principal = fixture_principal(reference.client_key.clone(), EPOCH);

                let mut peer: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
                let peer_output = run_peer(&[]);
                let mut summary = None;
                for line in peer_output.lines() {
                    let record = parse_json(line).expect("peer emits strict json");
                    if record.get("vector_id").is_none() {
                        summary = Some(record);
                        continue;
                    }
                    peer.insert(
                        record.text("vector_id").to_owned(),
                        (
                            record.text("result").to_owned(),
                            record.maybe_text("failure_code").map(str::to_owned),
                        ),
                    );
                }
                let summary = summary.expect("peer summary line");
                assert_eq!(summary.text("result"), "pass");
                assert_eq!(
                    summary.integer("unsupported"),
                    0,
                    "unsupported is never pass"
                );
                assert_eq!(
                    summary.integer("vectors") as usize,
                    vectors(&corpus).len(),
                    "the peer classified every vector"
                );

                let mut accepted = 0usize;
                let mut rejected = 0usize;
                for vector in vectors(&corpus) {
                    let id = vector.text("id");
                    let expect = vector.get("expect").expect("expect");
                    let native = if vector.text("kind") == "handshake" {
                        classify_handshake(vector, &reference, &daemon_signer)
                    } else {
                        classify_frame(vector, &reference, &principal)
                    };
                    match (&native, expect.get("failure_code")) {
                        (None, Some(Json::Null)) => accepted += 1,
                        (Some(code), Some(Json::Text(expected))) => {
                            assert_eq!(code, expected, "{id}: native code");
                            rejected += 1;
                        }
                        (native, expected) => {
                            panic!("{id}: native {native:?} against corpus {expected:?}")
                        }
                    }
                    let (peer_result, peer_code) =
                        peer.get(id).unwrap_or_else(|| panic!("{id} unrun by peer"));
                    assert_eq!(peer_result, "pass", "{id}: peer result");
                    assert_eq!(peer_code, &native, "{id}: peer and native codes differ");
                }
                assert_eq!(accepted, 10, "valid vectors");
                assert_eq!(rejected, 62, "mutation vectors");
                assert_eq!(accepted + rejected, 72, "corpus size");
            }

            /// SC-003: 1,000 seeded valid and invalid native and extension
            /// handshake cases, every one classified identically by both peers.
            #[test]
            fn sc003_thousand_handshake_cases_classify_identically_on_both_peers() {
                let started = std::time::Instant::now();
                let corpus = corpus();
                let reference = reference(&corpus);
                let daemon_signer = RingSigner::generate();
                let ceiling = vec![capability(CapabilityAction::Read, "matinee")];
                let mcp = fixture_principal(reference.client_key.clone(), EPOCH);
                let extension = registered_principal(
                    EXTENSION_PRINCIPAL,
                    PrincipalKind::BrowserExtension,
                    reference.client_key.clone(),
                    ceiling,
                    EPOCH,
                );

                let output = run_peer(&[
                    "--campaign",
                    "--seed",
                    CAMPAIGN_SEED,
                    "--cases",
                    &CAMPAIGN_CASES.to_string(),
                ]);
                let mut families: BTreeMap<String, (usize, usize)> = BTreeMap::new();
                let mut accepted = 0usize;
                let mut rejected = 0usize;
                let mut cases = 0usize;
                let mut summary = None;
                for line in output.lines() {
                    let record = parse_json(line).expect("peer emits strict json");
                    if record.get("case").is_none() {
                        summary = Some(record);
                        continue;
                    }
                    let index = record.integer("case");
                    let family = record.text("family").to_owned();
                    let expected_accept = record.text("expected") == "accept";
                    let expected_code = record
                        .maybe_text("expected_failure_code")
                        .map(str::to_owned);
                    let peer_code = record.maybe_text("failure_code").map(str::to_owned);
                    assert!(
                        record.flag("agrees"),
                        "case {index} ({family}): the peer disagreed with its own family"
                    );

                    let principal = if record.text("peer") == "browser-extension" {
                        extension.clone()
                    } else {
                        mcp.clone()
                    };
                    let config = ServerHandshakeConfig::new(
                        ENDPOINT,
                        principal,
                        id(DAEMON),
                        daemon_signer.public_key().clone(),
                        2,
                        4,
                        reference.connection,
                    )
                    .expect("server configuration");
                    let mut sink = RecordingSink::default();
                    let hello = decode_hex(record.text("hello_hex"));
                    let native = ServerHandshake::accept(config, &hello, &daemon_signer, &mut sink)
                        .err()
                        .map(|failure| failure.code().as_str().to_owned());

                    assert_eq!(
                        native.is_none(),
                        expected_accept,
                        "case {index} ({family}): native outcome against the declared family"
                    );
                    assert_eq!(
                        native, expected_code,
                        "case {index} ({family}): native code against the declared family"
                    );
                    assert_eq!(
                        native, peer_code,
                        "case {index} ({family}): native and extension peers disagree"
                    );
                    if native.is_none() {
                        accepted += 1;
                        assert!(
                            sink.events.is_empty(),
                            "case {index} accepted with an event"
                        );
                    } else {
                        rejected += 1;
                        assert_eq!(sink.events.len(), 1, "case {index} bounded event");
                    }
                    let entry = families.entry(family).or_default();
                    if native.is_none() {
                        entry.0 += 1;
                    } else {
                        entry.1 += 1;
                    }
                    cases += 1;
                }

                let summary = summary.expect("campaign summary line");
                assert_eq!(summary.text("seed"), CAMPAIGN_SEED);
                assert_eq!(cases, CAMPAIGN_CASES, "every case ran");
                assert_eq!(summary.integer("cases") as usize, CAMPAIGN_CASES);
                assert_eq!(summary.integer("accepted") as usize, accepted);
                assert_eq!(summary.integer("rejected") as usize, rejected);
                assert_eq!(
                    accepted + rejected,
                    CAMPAIGN_CASES,
                    "zero unclassified cases"
                );
                assert_eq!(accepted, 78, "seeded valid cases");
                assert_eq!(rejected, 922, "seeded invalid cases");
                // Every family contributed, and no family is silently all-accept.
                assert_eq!(families.len(), 26, "families in the seeded corpus");
                for (family, (ok, bad)) in &families {
                    assert_eq!(
                        ok * bad,
                        0,
                        "{family} mixes outcomes, so its expectation is not fixed"
                    );
                    assert!(ok + bad >= 38, "{family} ran {} cases", ok + bad);
                }
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(120),
                    "the campaign must stay a test, not a benchmark: {:?}",
                    started.elapsed()
                );
            }

            /// SC-003, FR-017: the exact payload maximum and one byte past it.
            #[test]
            fn exact_maximum_payload_round_trips_and_one_over_never_encodes() {
                let (mut client, mut daemon) = establish_pair(EPOCH);
                let mut sink = RecordingSink::default();
                let output =
                    AuthorizedOutput::filtered(PayloadKind::Command, vec![0x5a; MAX_PAYLOAD])
                        .expect("the exact maximum is permitted");
                let frame = client
                    .send(&output, &mut sink)
                    .expect("exact maximum seals");
                assert_eq!(frame.len(), 1_048_580);
                assert_eq!(
                    u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
                    1_048_576,
                    "the exact encoded-frame maximum"
                );
                let opened = daemon
                    .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                    .expect("the exact maximum opens");
                assert_eq!(opened.payload().len(), MAX_PAYLOAD);
                assert_eq!(
                    AuthorizedOutput::filtered(PayloadKind::Command, vec![0x5a; MAX_PAYLOAD + 1])
                        .expect_err("one over the maximum")
                        .code(),
                    FailureCode::ResourceLimit
                );
            }
        }
    };
}
