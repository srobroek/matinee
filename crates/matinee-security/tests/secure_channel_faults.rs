macro_rules! secure_channel_faults_tests {
    () => {
        mod secure_channel_faults_inner {
            use crate::test_support_channel::{
                CONNECTION, DAEMON, ENDPOINT, OWNER, PRINCIPAL, RecordingSink, RingSigner, SCOPE,
                capability, establish_pair, establish_pair_at_epochs, establish_pair_for,
                establish_pair_with_ranges, fixture_principal, id, owned_operation,
                owned_projection, registered_principal,
            };
            use crate::{
                AuthorizedOutput, CapabilityAction, ChannelSigner, ClientHandshake,
                ClientHandshakeConfig, ConnectionId, ExtensionGrant, FailureBoundary, FailureCode,
                ObjectOwner, PayloadKind, Principal, PrincipalKind, ProjectionClass, PublicKey,
                SafeNextAction, SecurityCode, ServerHandshake, ServerHandshakeConfig, SessionInput,
                SessionProjection,
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

            /// The families whose refusal lands after the hello. Each one carries a
            /// hello both peers admit, because a replay is only reachable through an
            /// admitted hello.
            const REPLAY_CLIENT_PROOF: &str = "replay.client-proof";
            const REPLAY_SERVER_PROOF: &str = "replay.server-proof";
            const REPLAY_COMPLETED: &str = "replay.completed-handshake";
            const REPLAY_PRODUCT_FRAME: &str = "replay.product-frame";

            /// The seeded mix: 30 families drawn by `index % 30`, so the first ten
            /// families take 34 cases and the remaining twenty take 33. Exactly two
            /// families accept, `valid` and `nonce-rotate` at indices zero and one, so 68
            /// cases complete a session and 932 are refused at the stage their family
            /// names.
            const CAMPAIGN_FAMILY_COUNT: usize = 30;
            const CAMPAIGN_ACCEPTED: usize = 68;
            const CAMPAIGN_REJECTED: usize = 932;
            /// The four replay families carry valid hellos, so 132 refused cases are
            /// admitted at the hello stage and refused later.
            const CAMPAIGN_PER_FAMILY: usize = 33;
            const CAMPAIGN_HELLO_ADMITTED: usize = CAMPAIGN_ACCEPTED + 4 * CAMPAIGN_PER_FAMILY;
            /// Every admitted case asks the peer for the client half except the
            /// frame-stage family, whose session is the corpus one both peers already key.
            const CAMPAIGN_CLIENT_REQUESTS: usize =
                CAMPAIGN_HELLO_ADMITTED - CAMPAIGN_PER_FAMILY;
            /// Two product payloads per accepted case cross between the native daemon and
            /// the extension peer, and two more cross the native pair.
            const CAMPAIGN_DISPATCHES: usize = 4;

            fn encode_hex(bytes: &[u8]) -> String {
                use std::fmt::Write as _;
                let mut out = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    write!(out, "{byte:02x}").expect("a string never fails to write");
                }
                out
            }

            /// Run the peer with one JSON request document on its standard input. The peer
            /// reads to end of file before it answers, so the write cannot deadlock.
            fn run_peer_with_input(args: &[&str], input: &str) -> String {
                use std::io::Write as _;
                let mut child = std::process::Command::new("node")
                    .arg(FIXTURE)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("Node.js WebCrypto peer");
                child
                    .stdin
                    .take()
                    .expect("peer standard input")
                    .write_all(input.as_bytes())
                    .expect("the peer reads its request");
                let output = child.wait_with_output().expect("peer exit status");
                assert!(
                    output.status.success(),
                    "peer {args:?} failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout).expect("peer emits utf-8")
            }

            /// One peer run: every case-keyed record by index, plus the summary line.
            fn peer_records(output: &str) -> (BTreeMap<u64, Json>, Json) {
                let mut records = BTreeMap::new();
                let mut summary = None;
                for line in output.lines() {
                    let record = parse_json(line).expect("peer emits strict json");
                    let index = match record.get("case") {
                        Some(Json::Number(value)) => Some(*value),
                        _ => None,
                    };
                    match index {
                        Some(index) => assert!(
                            records.insert(index, record).is_none(),
                            "case {index} recorded twice"
                        ),
                        None => summary = Some(record),
                    }
                }
                (records, summary.expect("peer summary line"))
            }

            fn campaign_server_config(
                principal: Principal,
                daemon_signer: &RingSigner,
                reference: &Reference,
            ) -> ServerHandshakeConfig {
                ServerHandshakeConfig::new(
                    ENDPOINT,
                    principal,
                    id(DAEMON),
                    daemon_signer.public_key().clone(),
                    2,
                    4,
                    reference.connection,
                )
                .expect("server configuration")
            }

            fn campaign_client_config(
                client: &RingSigner,
                daemon: &RingSigner,
            ) -> ClientHandshakeConfig {
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
                .expect("client configuration")
            }

            /// The operation a campaign case authorizes. A browser-extension principal
            /// reaches a product payload only through a grant, so the extension half of
            /// the campaign carries one and the MCP half carries none.
            fn case_operation(grant: Option<&ExtensionGrant>) -> SessionInput<'_> {
                SessionInput::new(
                    capability(CapabilityAction::Read, SCOPE),
                    PayloadKind::Command,
                    ObjectOwner::Owned(id(OWNER)),
                    grant,
                )
            }

            fn case_projection<'a>(
                grant: Option<&'a ExtensionGrant>,
                payload: &'a [u8],
            ) -> SessionProjection<'a> {
                SessionProjection::new(
                    ProjectionClass::Response,
                    capability(CapabilityAction::Read, SCOPE),
                    ObjectOwner::Owned(id(OWNER)),
                    grant,
                    payload,
                )
            }

            /// What one campaign case's subject artifact reached.
            ///
            /// SC-003 fixes the frontier at product payload acceptance, so a case is
            /// recorded by the stages it crossed and not by a failure code alone. A replay
            /// needs a premise — the donor handshake a proof was lifted from, or the first
            /// product frame a duplicate follows — and that premise is scaffolding whose
            /// dispatch is counted in `dispatched_before_reject`. What the replayed or
            /// mutated artifact itself reached is `dispatched_after_reject`, which SC-003
            /// fixes at zero for every invalid vector however valid its premise.
            #[derive(Debug, Default)]
            struct CaseReach {
                session_created: bool,
                traffic_keys_agreed: bool,
                dispatched_before_reject: usize,
                dispatched_after_reject: usize,
                channel_open: bool,
                code: Option<String>,
            }

            /// One finished case: the family it was drawn from, the stage that family fixes
            /// its outcome at, the failure code the family declares there, and what the
            /// case actually reached.
            struct CaseOutcome {
                family: String,
                stage: String,
                expected: Option<String>,
                reach: CaseReach,
            }

            /// The artifact whose outcome one case is about, held between the hello pass
            /// and the completion pass because the peer answers all of them in one run.
            enum CaseSubject {
                /// The case's own admitted handshake, completed with the peer.
                Complete(ServerHandshake),
                /// A second transcript for the same hello, which the donor's client proof
                /// is replayed into. `donor` is present when the family requires the donor
                /// handshake to complete first.
                ClientProofReplay {
                    victim: ServerHandshake,
                    donor: Option<ServerHandshake>,
                },
                /// A fresh native client, to which a foreign server proof is replayed.
                ServerProofReplay {
                    client: ClientHandshake,
                    proof: Vec<u8>,
                },
                /// A product frame replayed on the corpus session both peers key.
                ProductFrameReplay { framed: Vec<u8>, payload: Vec<u8> },
                /// The hello never reached a later stage.
                Refused,
            }

            struct CasePlan {
                index: usize,
                family: String,
                stage: String,
                extension: bool,
                expected: Option<String>,
                hello_code: Option<String>,
                subject: CaseSubject,
            }

            /// SC-003: 1,000 seeded valid and invalid native and extension handshake
            /// cases. Every accepted case completes a session and round-trips a product
            /// frame in both directions, and every invalid case is refused before product
            /// payload acceptance: no session, no traffic key, no dispatch, no open
            /// channel.
            ///
            /// Peer agreement is per stage and it is deliberately not uniform. Both peers
            /// classify every hello. The extension peer also runs the client half of every
            /// admitted case, so an accepted case's traffic keys are derived twice and
            /// independently, and the product frames the daemon opens and seals are the
            /// peer's own; it classifies the server-proof replay as a client and the
            /// product-frame replay from its own counter state. It cannot classify the
            /// daemon-side client-proof replay or the session replay, because it holds no
            /// daemon role and keeps no session state across invocations. For those two
            /// families the peer supplies the replayed artifact instead — a valid client
            /// signature over the donor transcript — and the production path owns the
            /// verdict, checked against the code its family declares.
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
                    ceiling.clone(),
                    EPOCH,
                );
                let grant = ExtensionGrant::new(
                    id(EXTENSION_PRINCIPAL),
                    id(OWNER),
                    vec![capability(CapabilityAction::Read, SCOPE)],
                    EPOCH,
                )
                .expect("a grant at the registered epoch");
                // The campaign's registered principals hold the extension peer's identity
                // key, so a native pair needs its own principals under a key the native
                // side can sign with.
                let native_signer = RingSigner::generate();
                let native_mcp = fixture_principal(native_signer.public_key().clone(), EPOCH);
                let native_extension = registered_principal(
                    EXTENSION_PRINCIPAL,
                    PrincipalKind::BrowserExtension,
                    native_signer.public_key().clone(),
                    ceiling,
                    EPOCH,
                );

                let (records, summary) = peer_records(&run_peer(&[
                    "--campaign",
                    "--seed",
                    CAMPAIGN_SEED,
                    "--cases",
                    &CAMPAIGN_CASES.to_string(),
                ]));

                // Pass one: the daemon's hello admission, on the peer's exact bytes.
                let mut plans = Vec::with_capacity(CAMPAIGN_CASES);
                let mut finish_requests: Vec<String> = Vec::new();
                for (index, record) in &records {
                    let index = *index as usize;
                    let family = record.text("family").to_owned();
                    let stage = record.text("stage").to_owned();
                    let extension_peer = record.text("peer") == "browser-extension";
                    let principal = if extension_peer {
                        extension.clone()
                    } else {
                        mcp.clone()
                    };
                    let hello = decode_hex(record.text("hello_hex"));
                    let mut sink = RecordingSink::default();
                    let admitted = ServerHandshake::accept(
                        campaign_server_config(principal, &daemon_signer, &reference),
                        &hello,
                        &daemon_signer,
                        &mut sink,
                    );
                    let hello_code = admitted
                        .as_ref()
                        .err()
                        .map(|failure| failure.code().as_str().to_owned());
                    let peer_hello_code =
                        record.maybe_text("hello_failure_code").map(str::to_owned);
                    let declared_hello_code = record
                        .maybe_text("hello_expected_failure_code")
                        .map(str::to_owned);
                    assert!(
                        record.flag("agrees"),
                        "case {index} ({family}): the peer disagreed with its own family"
                    );
                    assert_eq!(
                        hello_code.is_none(),
                        record.text("hello_expected") == "accept",
                        "case {index} ({family}): native admission against the declared family"
                    );
                    assert_eq!(
                        hello_code, declared_hello_code,
                        "case {index} ({family}): native code against the declared family"
                    );
                    assert_eq!(
                        hello_code, peer_hello_code,
                        "case {index} ({family}): native and extension peers disagree"
                    );

                    let subject = match admitted {
                        Err(_) => {
                            assert_eq!(sink.events.len(), 1, "case {index} bounded event");
                            CaseSubject::Refused
                        }
                        Ok((pending, proof)) => {
                            assert!(
                                sink.events.is_empty(),
                                "case {index} admitted with an event"
                            );
                            match family.as_str() {
                                REPLAY_CLIENT_PROOF | REPLAY_COMPLETED => {
                                    let principal = if extension_peer {
                                        extension.clone()
                                    } else {
                                        mcp.clone()
                                    };
                                    let (victim, second) = ServerHandshake::accept(
                                        campaign_server_config(
                                            principal,
                                            &daemon_signer,
                                            &reference,
                                        ),
                                        &hello,
                                        &daemon_signer,
                                        &mut sink,
                                    )
                                    .expect("the recorded hello still satisfies every field");
                                    assert_ne!(
                                        second, proof,
                                        "case {index}: each accept mints its own nonce"
                                    );
                                    // The peer signs the donor transcript, so the replayed
                                    // proof is a valid one from the registered principal.
                                    finish_requests.push(format!(
                                        "{{\"case\":{index},\"hello_hex\":\"{}\",\"proof_hex\":\"{}\"}}",
                                        encode_hex(&hello),
                                        encode_hex(&proof)
                                    ));
                                    CaseSubject::ClientProofReplay {
                                        victim,
                                        donor: (family == REPLAY_COMPLETED).then_some(pending),
                                    }
                                }
                                REPLAY_SERVER_PROOF => {
                                    let (client, client_hello) = ClientHandshake::start(
                                        campaign_client_config(&native_signer, &daemon_signer),
                                    )
                                    .expect("a fresh client hello");
                                    // The peer classifies the same replay from its own
                                    // client half, against the same fresh hello.
                                    finish_requests.push(format!(
                                        "{{\"case\":{index},\"hello_hex\":\"{}\",\"proof_hex\":\"{}\"}}",
                                        encode_hex(&client_hello),
                                        encode_hex(&proof)
                                    ));
                                    CaseSubject::ServerProofReplay { client, proof }
                                }
                                REPLAY_PRODUCT_FRAME => CaseSubject::ProductFrameReplay {
                                    framed: decode_hex(record.text("frame_hex")),
                                    payload: decode_hex(record.text("frame_payload_hex")),
                                },
                                _ => {
                                    finish_requests.push(format!(
                                        "{{\"case\":{index},\"hello_hex\":\"{}\",\"proof_hex\":\"{}\"}}",
                                        encode_hex(&hello),
                                        encode_hex(&proof)
                                    ));
                                    CaseSubject::Complete(pending)
                                }
                            }
                        }
                    };
                    plans.push(CasePlan {
                        index,
                        family,
                        stage,
                        extension: extension_peer,
                        expected: record.maybe_text("expected_failure_code").map(str::to_owned),
                        hello_code,
                        subject,
                    });
                }
                assert_eq!(
                    plans.iter().filter(|plan| plan.hello_code.is_none()).count(),
                    CAMPAIGN_HELLO_ADMITTED,
                    "the admitted hellos are the accepting families plus the replay families"
                );
                assert_eq!(
                    finish_requests.len(),
                    CAMPAIGN_CLIENT_REQUESTS,
                    "every admitted case needing a client proof asks the peer for one"
                );

                // The peer completes the client half of every admitted case: it verifies
                // the server proof, signs the client proof, and derives its own traffic
                // keys from the completed transcript.
                let (answers, finish_summary) = peer_records(&run_peer_with_input(
                    &["--campaign-finish"],
                    &format!(
                        "{{\"daemon_key_hex\":\"{}\",\"daemon_hex\":\"{}\",\"requests\":[{}]}}",
                        encode_hex(daemon_signer.public_key().as_bytes()),
                        encode_hex(id(DAEMON).get().as_bytes()),
                        finish_requests.join(",")
                    ),
                ));
                assert_eq!(
                    finish_summary.integer("requests") as usize,
                    CAMPAIGN_CLIENT_REQUESTS
                );
                assert_eq!(answers.len(), CAMPAIGN_CLIENT_REQUESTS);

                // Pass two: complete every admitted case, or drive its replay.
                let mut outcomes: BTreeMap<usize, CaseOutcome> = BTreeMap::new();
                let mut open_requests: Vec<String> = Vec::new();
                let mut open_expectations: Vec<(usize, Vec<u8>)> = Vec::new();
                for plan in plans {
                    let index = plan.index;
                    let family = plan.family;
                    let grant = plan.extension.then_some(&grant);
                    let mut reach = CaseReach {
                        code: plan.hello_code,
                        ..CaseReach::default()
                    };
                    let mut sink = RecordingSink::default();
                    match plan.subject {
                        CaseSubject::Refused => {}
                        CaseSubject::Complete(pending) => {
                            let answer = &answers[&(index as u64)];
                            assert_eq!(
                                answer.text("result"),
                                "accept",
                                "case {index}: the peer refused a valid transcript: {:?}",
                                answer.maybe_text("failure_code")
                            );
                            let signature = decode_hex(answer.text("client_signature_hex"));
                            let mut session = pending
                                .finish(&signature, &mut sink)
                                .unwrap_or_else(|failure| {
                                    panic!(
                                        "case {index}: the daemon refused the peer's client proof: {:?}",
                                        failure.code()
                                    )
                                });
                            reach.session_created = true;
                            assert!(
                                sink.events.is_empty(),
                                "case {index}: a completed handshake records no failure"
                            );
                            assert!(session.is_open(), "case {index}: the daemon half completed");
                            assert_eq!(session.contract(), reference.contract);
                            assert_eq!(session.epoch(), EPOCH);
                            assert_eq!(session.connection_id(), reference.connection);

                            // Client to daemon. The peer sealed this product frame under
                            // the traffic key it derived itself, so an open proves both
                            // peers reached the same key from the same transcript.
                            let command = decode_hex(answer.text("client_payload_hex"));
                            let opened = session
                                .receive(
                                    &decode_hex(answer.text("client_frame_hex")),
                                    &case_operation(grant),
                                    &mut sink,
                                )
                                .unwrap_or_else(|failure| {
                                    panic!(
                                        "case {index}: the peer's product frame was refused: {:?}",
                                        failure.code()
                                    )
                                });
                            assert_eq!(
                                opened.payload(),
                                command,
                                "case {index}: the client-to-daemon payload did not round-trip"
                            );
                            reach.traffic_keys_agreed = true;
                            reach.dispatched_before_reject += 1;

                            // Daemon to client, through the only path that authorizes and
                            // then serializes a projection.
                            let response = decode_hex(answer.text("daemon_payload_hex"));
                            let sealed = session
                                .send_projection(&case_projection(grant, &response), &mut sink)
                                .unwrap_or_else(|failure| {
                                    panic!(
                                        "case {index}: the daemon refused its own projection: {:?}",
                                        failure.code()
                                    )
                                });
                            assert_eq!(
                                encode_hex(&sealed),
                                answer.text("expected_daemon_frame_hex"),
                                "case {index}: the peers disagree on the daemon-to-client frame"
                            );
                            open_requests.push(format!(
                                "{{\"case\":{index},\"key_hex\":\"{}\",\"framed_hex\":\"{}\",\"connection_hex\":\"{}\",\"counter\":0,\"direction\":\"daemon-to-client\",\"kind\":2}}",
                                answer.text("daemon_to_client_key_hex"),
                                encode_hex(&sealed),
                                answer.text("connection_hex")
                            ));
                            open_expectations.push((index, response.clone()));
                            assert!(session.is_open(), "case {index}: the channel stays open");
                            reach.channel_open = true;

                            // The same case on both production halves: the client
                            // handshake finishes, derives its own traffic keys, and the
                            // pair round-trips a product frame in both directions.
                            let native_principal = if plan.extension {
                                &native_extension
                            } else {
                                &native_mcp
                            };
                            let (mut client, mut daemon) = establish_pair_for(
                                native_principal,
                                &native_signer,
                                ConnectionId::new(Uuid::from_u128(CONNECTION + index as u128)),
                            )
                            .unwrap_or_else(|failure| {
                                panic!(
                                    "case {index}: the production handshake failed: {:?}",
                                    failure.code()
                                )
                            });
                            assert!(client.is_open() && daemon.is_open());
                            let output =
                                AuthorizedOutput::filtered(PayloadKind::Command, command.clone())
                                    .expect("a bounded product command");
                            let frame = client.send(&output, &mut sink).expect("the client seals");
                            let opened = daemon
                                .receive(&frame, &case_operation(grant), &mut sink)
                                .expect("the daemon opens and authorizes");
                            assert_eq!(opened.payload(), command);
                            reach.dispatched_before_reject += 1;
                            let reply = daemon
                                .send_projection(&case_projection(grant, &response), &mut sink)
                                .expect("the daemon discloses");
                            let filtered = client
                                .receive_filtered(&reply, PayloadKind::Response, &mut sink)
                                .expect("the client opens the response");
                            assert_eq!(filtered.payload(), response);
                            reach.dispatched_before_reject += 1;
                            assert!(client.is_open() && daemon.is_open());
                            // No failure was recorded, and every payload that crossed
                            // passed the required decision gate on its way.
                            assert_eq!(
                                sink.events.len(),
                                CAMPAIGN_DISPATCHES,
                                "case {index}: one decision per dispatched payload"
                            );
                            assert!(
                                sink.events
                                    .iter()
                                    .all(|event| event.code()
                                        == SecurityCode::AuthorizationAccepted),
                                "case {index}: a dispatch bypassed the decision gate"
                            );
                        }
                        CaseSubject::ClientProofReplay { victim, donor } => {
                            let answer = &answers[&(index as u64)];
                            assert_eq!(
                                answer.text("result"),
                                "accept",
                                "case {index}: the donor transcript is a valid one"
                            );
                            let signature = decode_hex(answer.text("client_signature_hex"));
                            if let Some(donor) = donor {
                                // The premise: the donor handshake completes, so what
                                // follows replays a finished transcript.
                                let mut completed = donor
                                    .finish(&signature, &mut sink)
                                    .expect("the donor handshake completes");
                                assert!(
                                    completed.is_open(),
                                    "case {index}: the replayed handshake completed first"
                                );
                                assert!(sink.events.is_empty());
                                completed.close();
                            }
                            match victim.finish(&signature, &mut sink) {
                                Ok(session) => {
                                    // A replay that authenticates is the SC-003 failure,
                                    // so it is recorded and the invariant below reports it.
                                    reach.session_created = true;
                                    reach.channel_open = session.is_open();
                                }
                                Err(failure) => {
                                    reach.code = Some(failure.code().as_str().to_owned());
                                    assert_eq!(
                                        sink.events.len(),
                                        1,
                                        "case {index}: one bounded event per rejection"
                                    );
                                }
                            }
                        }
                        CaseSubject::ServerProofReplay { client, proof } => {
                            let answer = &answers[&(index as u64)];
                            assert_eq!(
                                answer.text("result"),
                                "reject",
                                "case {index}: the peer accepted a replayed server proof"
                            );
                            let peer_code = answer.maybe_text("failure_code").map(str::to_owned);
                            match client.finish(&proof, &native_signer, &mut sink) {
                                Ok((session, _)) => {
                                    reach.session_created = true;
                                    reach.channel_open = session.is_open();
                                }
                                Err(failure) => {
                                    reach.code = Some(failure.code().as_str().to_owned());
                                    assert_eq!(
                                        sink.events.len(),
                                        1,
                                        "case {index}: one bounded event per rejection"
                                    );
                                }
                            }
                            assert_eq!(
                                reach.code, peer_code,
                                "case {index}: native and extension peers disagree on the replay"
                            );
                        }
                        CaseSubject::ProductFrameReplay { framed, payload } => {
                            // The corpus session both peers hold the keys for. The first
                            // frame is the premise: a legitimate product payload that
                            // dispatches and advances the receive counter.
                            let principal = if plan.extension {
                                extension.clone()
                            } else {
                                mcp.clone()
                            };
                            let mut session = vector_session(&reference, principal);
                            reach.session_created = true;
                            let opened = session
                                .receive(&framed, &case_operation(grant), &mut sink)
                                .expect("the first product frame dispatches");
                            assert_eq!(opened.payload(), payload);
                            reach.traffic_keys_agreed = true;
                            reach.dispatched_before_reject += 1;
                            assert_eq!(session.receive_counter(), 1);
                            assert_eq!(
                                sink.events.len(),
                                1,
                                "case {index}: the premise frame passed the decision gate"
                            );
                            assert_eq!(
                                sink.events[0].code(),
                                SecurityCode::AuthorizationAccepted
                            );
                            match session.receive(&framed, &case_operation(grant), &mut sink) {
                                Ok(twice) => {
                                    assert_eq!(twice.payload(), payload);
                                    reach.dispatched_after_reject += 1;
                                    reach.channel_open = session.is_open();
                                }
                                Err(failure) => {
                                    reach.code = Some(failure.code().as_str().to_owned());
                                    assert!(
                                        !session.is_open(),
                                        "case {index}: a replayed frame closes the channel"
                                    );
                                    assert_eq!(
                                        session.receive_counter(),
                                        1,
                                        "case {index}: a reject never advances"
                                    );
                                    // The premise decision, then the refusal. Nothing
                                    // else reached the sink, so nothing else was decided.
                                    assert_eq!(
                                        sink.events.len(),
                                        2,
                                        "case {index}: one bounded event per rejection"
                                    );
                                    assert_eq!(
                                        sink.events[1].code(),
                                        SecurityCode::ReplayDetected
                                    );
                                }
                            }
                            let peer_code = records[&(index as u64)]
                                .maybe_text("frame_replay_failure_code")
                                .map(str::to_owned);
                            assert_eq!(
                                reach.code, peer_code,
                                "case {index}: native and extension peers disagree on the replay"
                            );
                        }
                    }
                    assert!(
                        outcomes
                            .insert(
                                index,
                                CaseOutcome {
                                    family: family.clone(),
                                    stage: plan.stage,
                                    expected: plan.expected,
                                    reach,
                                },
                            )
                            .is_none(),
                        "case {index} ({family}): one outcome per case"
                    );
                }

                // The peer opens every product frame the daemon sealed, under the key it
                // derived for that case. This is the far half of the round trip: the
                // plaintext the daemon disclosed arrives at the extension peer.
                let (opens, open_summary) = peer_records(&run_peer_with_input(
                    &["--campaign-open"],
                    &format!("{{\"frames\":[{}]}}", open_requests.join(",")),
                ));
                assert_eq!(open_summary.integer("frames") as usize, CAMPAIGN_ACCEPTED);
                assert_eq!(open_summary.integer("opened") as usize, CAMPAIGN_ACCEPTED);
                assert_eq!(open_summary.integer("refused"), 0);
                for (index, expected) in open_expectations {
                    let record = &opens[&(index as u64)];
                    assert_eq!(
                        record.text("result"),
                        "open",
                        "case {index}: the peer refused the daemon's product frame: {:?}",
                        record.maybe_text("failure_code")
                    );
                    assert_eq!(
                        decode_hex(record.text("payload_hex")),
                        expected,
                        "case {index}: the daemon-to-client payload did not round-trip"
                    );
                    outcomes
                        .get_mut(&index)
                        .expect("an outcome per case")
                        .reach
                        .dispatched_before_reject += 1;
                }

                // Every case, against the frontier SC-003 fixes.
                let mut families: BTreeMap<String, (usize, usize)> = BTreeMap::new();
                let mut stages: BTreeMap<String, usize> = BTreeMap::new();
                let mut accepted = 0usize;
                let mut rejected = 0usize;
                for (index, outcome) in &outcomes {
                    let CaseOutcome {
                        family,
                        stage,
                        expected,
                        reach,
                    } = outcome;
                    assert_eq!(
                        &reach.code, expected,
                        "case {index} ({family}): outcome against the declared family"
                    );
                    if reach.code.is_none() {
                        assert!(
                            reach.session_created,
                            "case {index} ({family}): an accepted case creates a session"
                        );
                        assert!(
                            reach.traffic_keys_agreed,
                            "case {index} ({family}): both peers derived the same traffic keys"
                        );
                        assert_eq!(
                            reach.dispatched_before_reject, CAMPAIGN_DISPATCHES,
                            "case {index} ({family}): product frames round-tripped both ways"
                        );
                        assert!(reach.channel_open, "case {index}: the channel stays open");
                        accepted += 1;
                    } else {
                        assert_eq!(
                            reach.dispatched_after_reject, 0,
                            "case {index} ({family}): a refused artifact dispatched a payload"
                        );
                        assert!(
                            !reach.channel_open,
                            "case {index} ({family}): a refused case left an open channel"
                        );
                        if stage == "frame" {
                            assert_eq!(
                                reach.dispatched_before_reject, 1,
                                "case {index}: the premise frame dispatched exactly once"
                            );
                        } else {
                            assert!(
                                !reach.session_created,
                                "case {index} ({family}): a refused case created a session"
                            );
                            assert!(
                                !reach.traffic_keys_agreed,
                                "case {index} ({family}): a refused case derived a traffic key"
                            );
                            assert_eq!(
                                reach.dispatched_before_reject, 0,
                                "case {index} ({family}): a refused case dispatched a payload"
                            );
                        }
                        rejected += 1;
                    }
                    let entry = families.entry(family.clone()).or_default();
                    if reach.code.is_none() {
                        entry.0 += 1;
                    } else {
                        entry.1 += 1;
                    }
                    *stages.entry(stage.clone()).or_default() += 1;
                }

                assert_eq!(summary.text("seed"), CAMPAIGN_SEED);
                assert_eq!(outcomes.len(), CAMPAIGN_CASES, "every case ran");
                assert_eq!(summary.integer("cases") as usize, CAMPAIGN_CASES);
                assert_eq!(summary.integer("accepted") as usize, accepted);
                assert_eq!(summary.integer("rejected") as usize, rejected);
                assert_eq!(
                    summary.integer("hello_accepted") as usize,
                    CAMPAIGN_HELLO_ADMITTED
                );
                assert_eq!(
                    accepted + rejected,
                    CAMPAIGN_CASES,
                    "zero unclassified cases"
                );
                assert_eq!(accepted, CAMPAIGN_ACCEPTED, "seeded valid cases");
                assert_eq!(rejected, CAMPAIGN_REJECTED, "seeded invalid cases");
                // Every family contributed, and no family is silently all-accept.
                assert_eq!(
                    families.len(),
                    CAMPAIGN_FAMILY_COUNT,
                    "families in the seeded corpus"
                );
                for (family, (ok, bad)) in &families {
                    assert_eq!(
                        ok * bad,
                        0,
                        "{family} mixes outcomes, so its expectation is not fixed"
                    );
                    assert!(
                        ok + bad >= CAMPAIGN_PER_FAMILY,
                        "{family} ran {} cases",
                        ok + bad
                    );
                }
                // SC-003 enumerates replay alongside the mutation classes, so the
                // campaign carries a case at every stage a replay is reachable at.
                assert_eq!(
                    stages.keys().map(String::as_str).collect::<Vec<_>>(),
                    vec!["client-proof", "frame", "hello", "server-proof", "session"],
                    "every stage SC-003 names is represented"
                );
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
