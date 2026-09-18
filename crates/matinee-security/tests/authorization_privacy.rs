macro_rules! authorization_privacy_tests {
    () => {
        mod authorization_privacy_inner {
            use crate::test_support_channel::{
                CONNECTION, OWNER, PRINCIPAL, RecordingSink, RingSigner, SCOPE, STATE_DIRECTORY,
                capability, establish_pair, id, owned_operation, owned_projection,
                registered_principal,
            };
            use crate::{
                AuthorizedOutput, CapabilityAction, ChannelSession, ChannelSigner, ClientHandshake,
                ClientHandshakeConfig, ConnectionId, EventBoundary, EventOutcome, ExtensionGrant,
                FailureCode, ObjectOwner, PayloadKind, PrincipalKind, ProjectionClass,
                SafeNextAction, SecurityCode, ServerHandshake, ServerHandshakeConfig, SessionInput,
                SessionProjection,
            };
            use uuid::Uuid;

            const EPOCH: u64 = 4;
            /// The bytes a probe would learn if any protected value reached a projection.
            const PROTECTED: &[u8] = b"protected-object-identifier";

            /// Establish a daemon session for one principal kind and ceiling, so a probe runs
            /// against the same path production uses rather than against the policy function.
            fn daemon_session(
                kind: PrincipalKind,
                ceiling: &str,
            ) -> (ChannelSession, ChannelSession) {
                let client_signer = RingSigner::generate();
                let daemon_signer = RingSigner::generate();
                let client = ClientHandshakeConfig::new(
                    "127.0.0.1:7777",
                    id(PRINCIPAL),
                    client_signer.public_key().clone(),
                    id(OWNER),
                    daemon_signer.public_key().clone(),
                    EPOCH,
                    1,
                    3,
                )
                .unwrap();
                let server = ServerHandshakeConfig::new(
                    "127.0.0.1:7777",
                    registered_principal(
                        PRINCIPAL,
                        kind,
                        client_signer.public_key().clone(),
                        vec![capability(CapabilityAction::Read, ceiling)],
                        EPOCH,
                    ),
                    id(OWNER),
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
                    .finish(&proof, &client_signer, &mut sink)
                    .unwrap();
                let daemon_session = server_pending.finish(&client_proof, &mut sink).unwrap();
                (client_session, daemon_session)
            }

            fn request_frame(
                client: &mut ChannelSession,
                kind: PayloadKind,
                payload: &[u8],
            ) -> Vec<u8> {
                let mut sink = RecordingSink::default();
                client
                    .send(
                        &AuthorizedOutput::filtered(kind, payload.to_vec()).unwrap(),
                        &mut sink,
                    )
                    .unwrap()
            }

            /// FR-022, FR-029, SC-004: an unknown object, a cross-owner object, and an object a
            /// filter removed are one outcome on the receive path, and the failure never says
            /// which. Every payload shape a lookup can arrive on is covered.
            #[test]
            fn unknown_cross_owner_and_filtered_lookups_share_one_object_not_found_outcome() {
                for kind in [
                    PayloadKind::Command,
                    PayloadKind::Response,
                    PayloadKind::Event,
                    PayloadKind::StreamChunk,
                ] {
                    let mut observed = Vec::new();
                    for owner in [ObjectOwner::Unknown, ObjectOwner::Owned(id(0x1234))] {
                        let (mut client, mut daemon) = establish_pair(0);
                        let frame = request_frame(&mut client, kind, PROTECTED);
                        let mut sink = RecordingSink::default();
                        let operation = SessionInput::new(
                            capability(CapabilityAction::Read, SCOPE),
                            kind,
                            owner,
                            None,
                        );
                        let failure = daemon
                            .receive(&frame, &operation, &mut sink)
                            .expect_err("an unresolved or foreign object discloses nothing");
                        assert_eq!(failure.code(), FailureCode::ObjectNotFound);
                        assert_eq!(
                            failure.safe_next_action(),
                            SafeNextAction::DoNotInferObjectExistence
                        );
                        assert_eq!(sink.events.len(), 1);
                        assert_eq!(sink.events[0].boundary(), EventBoundary::Authorization);
                        assert_eq!(sink.events[0].code(), SecurityCode::AuthorizationDenied);
                        assert_eq!(sink.events[0].metadata()[0].value(), "object-not_found");
                        // A denial is an answer: the frame is consumed and the channel lives.
                        assert!(daemon.is_open());
                        assert_eq!(daemon.receive_counter(), 1);
                        observed.push(format!("{failure} {:?}", sink.events[0]));
                    }
                    assert_eq!(
                        observed[0], observed[1],
                        "an unknown object and a foreign object must be indistinguishable"
                    );
                    assert!(!observed[0].contains("protected"));
                    assert!(!observed[0].contains("1234"));
                }
            }

            /// FR-020, FR-021: the receive gate reads principal kind, ceiling, owner, requested
            /// action, and grant. An administrator action is refused to an MCP client and to an
            /// extension even when the ceiling names it.
            #[test]
            fn administrator_actions_and_out_of_ceiling_actions_are_refused_on_the_live_channel() {
                for (kind, ceiling, action) in [
                    (PrincipalKind::McpClient, "matinee", CapabilityAction::Write),
                    (
                        PrincipalKind::McpClient,
                        "matinee",
                        CapabilityAction::ManagePrincipals,
                    ),
                    (
                        PrincipalKind::BrowserExtension,
                        "matinee",
                        CapabilityAction::Administer,
                    ),
                ] {
                    let (mut client, mut daemon) = daemon_session(kind, ceiling);
                    let frame = request_frame(&mut client, PayloadKind::Command, PROTECTED);
                    let mut sink = RecordingSink::default();
                    let operation = SessionInput::new(
                        capability(action, SCOPE),
                        PayloadKind::Command,
                        ObjectOwner::Owned(id(OWNER)),
                        None,
                    );
                    let failure = daemon
                        .receive(&frame, &operation, &mut sink)
                        .expect_err("the requested action exceeds the principal ceiling");
                    assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
                    assert_eq!(
                        failure.safe_next_action(),
                        SafeNextAction::RequestAdministratorGrant
                    );
                    assert!(!format!("{failure}").contains("protected"));
                    assert_eq!(sink.events.len(), 1);
                    assert_eq!(sink.events[0].outcome(), EventOutcome::Rejected);
                }
            }

            /// FR-021: an extension is limited to its granted sessions. A missing grant, a grant
            /// for another extension, a revoked grant, and a grant bound to another epoch are all
            /// refused; the matching grant is the only one that answers.
            #[test]
            fn extension_grants_bind_to_the_extension_owner_epoch_and_active_lifecycle() {
                let granted = capability(CapabilityAction::Read, SCOPE);
                let matching =
                    ExtensionGrant::new(id(PRINCIPAL), id(OWNER), vec![granted.clone()], EPOCH)
                        .unwrap();
                let foreign =
                    ExtensionGrant::new(id(0x99), id(OWNER), vec![granted.clone()], EPOCH).unwrap();
                let stale =
                    ExtensionGrant::new(id(PRINCIPAL), id(OWNER), vec![granted.clone()], EPOCH + 1)
                        .unwrap();
                let mut revoked = matching.clone();
                revoked.revoke();

                for grant in [None, Some(&foreign), Some(&stale), Some(&revoked)] {
                    let (mut client, mut daemon) =
                        daemon_session(PrincipalKind::BrowserExtension, "matinee");
                    let frame = request_frame(&mut client, PayloadKind::Event, PROTECTED);
                    let mut sink = RecordingSink::default();
                    let operation = SessionInput::new(
                        granted.clone(),
                        PayloadKind::Event,
                        ObjectOwner::Owned(id(OWNER)),
                        grant,
                    );
                    assert_eq!(
                        daemon
                            .receive(&frame, &operation, &mut sink)
                            .expect_err("only the extension's own active current grant answers")
                            .code(),
                        FailureCode::AuthorizationDenied
                    );
                }

                let (mut client, mut daemon) =
                    daemon_session(PrincipalKind::BrowserExtension, "matinee");
                let frame = request_frame(&mut client, PayloadKind::Event, b"granted");
                let mut sink = RecordingSink::default();
                let operation = SessionInput::new(
                    granted,
                    PayloadKind::Event,
                    ObjectOwner::Owned(id(OWNER)),
                    Some(&matching),
                );
                assert_eq!(
                    daemon
                        .receive(&frame, &operation, &mut sink)
                        .expect("the extension's own grant")
                        .payload(),
                    b"granted"
                );
            }

            /// FR-023, SC-004: every disclosure class passes the gate before serialization. An
            /// unauthorized projection produces no frame at all, so no identifier, count, or
            /// payload byte is ever written for the client to observe.
            #[test]
            fn every_projection_class_is_filtered_before_any_byte_is_serialized() {
                for class in [
                    ProjectionClass::Response,
                    ProjectionClass::Status,
                    ProjectionClass::Event,
                    ProjectionClass::Artifact,
                    ProjectionClass::StreamChunk,
                ] {
                    let (mut client, mut daemon) = establish_pair(0);
                    let mut sink = RecordingSink::default();

                    // An authorized projection is disclosed, and the client reads exactly it.
                    let frame = daemon
                        .send_projection(&owned_projection(class, b"disclosed"), &mut sink)
                        .expect("an owned object inside the ceiling");
                    assert_eq!(sink.events.len(), 1);
                    assert_eq!(sink.events[0].code(), SecurityCode::AuthorizationAccepted);
                    assert_eq!(
                        client
                            .receive_filtered(&frame, class.payload_kind(), &mut sink)
                            .unwrap()
                            .payload(),
                        b"disclosed"
                    );

                    // An unresolved owner and an out-of-ceiling action each serialize nothing.
                    for projection in [
                        SessionProjection::new(
                            class,
                            capability(CapabilityAction::Read, SCOPE),
                            ObjectOwner::Unknown,
                            None,
                            PROTECTED,
                        ),
                        SessionProjection::new(
                            class,
                            capability(CapabilityAction::Write, SCOPE),
                            ObjectOwner::Owned(id(OWNER)),
                            None,
                            PROTECTED,
                        ),
                    ] {
                        let mut sink = RecordingSink::default();
                        let failure = daemon
                            .send_projection(&projection, &mut sink)
                            .expect_err("an unauthorized projection is never serialized");
                        assert!(matches!(
                            failure.code(),
                            FailureCode::ObjectNotFound | FailureCode::AuthorizationDenied
                        ));
                        assert_eq!(sink.events.len(), 1);
                        assert!(!format!("{failure} {:?}", sink.events[0]).contains("protected"));
                        assert!(daemon.is_open());
                    }
                }
            }

            /// FR-027, FR-028, SC-009: every decision emits exactly one authorization event that
            /// names a boundary, a reason class, a safe next action, the state directory, and the
            /// safe principal and connection identifiers -- and no payload or object identifier.
            #[test]
            fn every_decision_emits_one_redacted_authorization_event() {
                let (mut client, mut daemon) = establish_pair(0);
                let accepted_frame = request_frame(&mut client, PayloadKind::Command, b"request");
                let mut sink = RecordingSink::default();
                daemon
                    .receive(
                        &accepted_frame,
                        &owned_operation(PayloadKind::Command),
                        &mut sink,
                    )
                    .expect("an owned object inside the ceiling");
                let denied_frame = request_frame(&mut client, PayloadKind::Command, PROTECTED);
                daemon
                    .receive(
                        &denied_frame,
                        &SessionInput::new(
                            capability(CapabilityAction::Read, SCOPE),
                            PayloadKind::Command,
                            ObjectOwner::Unknown,
                            None,
                        ),
                        &mut sink,
                    )
                    .expect_err("an unresolved object");

                assert_eq!(sink.events.len(), 2);
                let codes: Vec<_> = sink.events.iter().map(|event| event.code()).collect();
                assert_eq!(
                    codes,
                    vec![
                        SecurityCode::AuthorizationAccepted,
                        SecurityCode::AuthorizationDenied
                    ]
                );
                for event in &sink.events {
                    assert_eq!(event.boundary(), EventBoundary::Authorization);
                    assert_eq!(event.principal_id(), Some(Uuid::from_u128(PRINCIPAL)));
                    assert_eq!(event.connection_id(), Some(Uuid::from_u128(CONNECTION)));
                    assert_eq!(event.state_directory_id(), Uuid::from_u128(STATE_DIRECTORY));
                    assert_eq!(event.metadata().len(), 1);
                    assert_eq!(event.metadata()[0].key(), "reason");
                    assert!(event.encoded_len() <= 2_048);
                    let rendered = format!("{event:?}");
                    assert!(!rendered.contains("protected"));
                    assert!(!rendered.contains("request"));
                }
                assert_eq!(
                    sink.events[0].next_action(),
                    crate::EventNextAction::Continue
                );
                assert_eq!(
                    sink.events[1].next_action(),
                    crate::EventNextAction::FailClosed
                );
            }

            /// FR-027, FR-029: the decision event is required. When its sink is unavailable the
            /// operation fails closed, the channel closes, and the receive counter never moves,
            /// so no payload is disclosed and no protected state is mutated.
            #[test]
            fn an_unavailable_decision_sink_fails_closed_without_consuming_the_frame() {
                let (mut client, mut daemon) = establish_pair(0);
                let frame = request_frame(&mut client, PayloadKind::Command, b"request");
                let mut unavailable = RecordingSink {
                    events: Vec::new(),
                    unavailable: true,
                };
                let failure = daemon
                    .receive(
                        &frame,
                        &owned_operation(PayloadKind::Command),
                        &mut unavailable,
                    )
                    .expect_err("the required decision event never reached its sink");
                assert_eq!(failure.code(), FailureCode::EventSinkUnavailable);
                assert_eq!(daemon.receive_counter(), 0);
                assert!(!daemon.is_open());

                let (_, mut daemon) = establish_pair(0);
                let failure = daemon
                    .send_projection(
                        &owned_projection(ProjectionClass::Artifact, PROTECTED),
                        &mut unavailable,
                    )
                    .expect_err("the required decision event never reached its sink");
                assert_eq!(failure.code(), FailureCode::EventSinkUnavailable);
                assert!(!daemon.is_open());
            }

            /// FR-023: a bounded stream chunk is filtered on the same gate as every other class
            /// and stays inside its own declared bound, which is below the frame maximum.
            #[test]
            fn a_bounded_stream_chunk_is_filtered_and_stays_within_its_own_bound() {
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let chunk = vec![0x5a; ProjectionClass::StreamChunk.max_bytes()];
                let frame = daemon
                    .send_projection(
                        &owned_projection(ProjectionClass::StreamChunk, &chunk),
                        &mut sink,
                    )
                    .expect("a chunk at its declared bound");
                assert_eq!(
                    client
                        .receive_filtered(&frame, PayloadKind::StreamChunk, &mut sink)
                        .unwrap()
                        .payload()
                        .len(),
                    ProjectionClass::StreamChunk.max_bytes()
                );
                assert!(ProjectionClass::StreamChunk.max_bytes() < 1_048_534);

                let oversize = vec![0x5a; ProjectionClass::StreamChunk.max_bytes() + 1];
                let failure = daemon
                    .send_projection(
                        &owned_projection(ProjectionClass::StreamChunk, &oversize),
                        &mut sink,
                    )
                    .expect_err("a chunk past its declared bound");
                assert_eq!(failure.code(), FailureCode::ResourceLimit);
                assert_eq!(
                    failure.safe_next_action(),
                    SafeNextAction::ReduceToDeclaredBound
                );
            }

            /// SC-004: the gate cannot be reached from the side that holds no principal, and the
            /// side that does hold one cannot take an unauthorized path. A probe therefore has no
            /// route to a payload that skipped a decision.
            #[test]
            fn neither_side_can_reach_a_payload_that_skipped_a_decision() {
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request_frame(&mut client, PayloadKind::Command, PROTECTED);

                let failure = daemon
                    .receive_filtered(&frame, PayloadKind::Command, &mut sink)
                    .expect_err("a daemon must authorize what it accepts");
                assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
                assert!(!daemon.is_open());

                let (_, mut daemon) = establish_pair(0);
                let failure = daemon
                    .send(
                        &AuthorizedOutput::filtered(PayloadKind::Response, PROTECTED.to_vec())
                            .unwrap(),
                        &mut sink,
                    )
                    .expect_err("a daemon must authorize what it discloses");
                assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
                assert!(!daemon.is_open());

                let (mut client, _) = establish_pair(0);
                let failure = client
                    .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                    .expect_err("a client holds no principal to authorize against");
                assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
                assert!(!client.is_open());

                let (mut client, _) = establish_pair(0);
                let failure = client
                    .send_projection(
                        &owned_projection(ProjectionClass::Status, PROTECTED),
                        &mut sink,
                    )
                    .expect_err("a client holds no principal to authorize against");
                assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
                assert!(!client.is_open());
            }

            /// FR-028: no failure projection and no event projection in this matrix renders a
            /// payload byte, an object identifier, or a key.
            #[test]
            fn failure_and_event_projections_in_this_matrix_render_no_protected_value() {
                let forbidden = [
                    "protected",
                    "private",
                    "secret",
                    "credential",
                    "pkcs8",
                    "object_id",
                    "identifier",
                ];
                let (mut client, mut daemon) = establish_pair(0);
                let mut sink = RecordingSink::default();
                let frame = request_frame(&mut client, PayloadKind::Command, PROTECTED);
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
                    .expect_err("an unresolved object");
                let rendered = format!("{failure} {failure:?} {:?}", sink.events);
                let lowered = rendered.to_ascii_lowercase();
                for word in forbidden {
                    assert!(!lowered.contains(word), "{rendered} disclosed {word}");
                }
                assert!(rendered.contains("object.not_found"));
            }

            /// FR-023, SC-004: the decision runs strictly before serialization, so a denied
            /// projection costs the channel nothing. The send counter is the observable proof:
            /// a denial must not consume one, and the next authorized projection must therefore
            /// carry the counter the client is still expecting.
            ///
            /// If sealing or the counter increment moved ahead of the decision, the denial
            /// below would burn counter 0 and this authorized frame would arrive at counter 1,
            /// which the client's receive path rejects.
            #[test]
            fn a_denied_projection_consumes_no_send_counter_and_the_next_one_still_arrives() {
                let (mut client, mut daemon) = establish_pair(0);
                assert_eq!(daemon.send_counter(), 0);

                let denied = SessionProjection::new(
                    ProjectionClass::Status,
                    capability(CapabilityAction::Read, SCOPE),
                    ObjectOwner::Unknown,
                    None,
                    PROTECTED,
                );
                for _ in 0..3 {
                    let mut sink = RecordingSink::default();
                    let failure = daemon
                        .send_projection(&denied, &mut sink)
                        .expect_err("an unresolved object is never serialized");
                    assert_eq!(failure.code(), FailureCode::ObjectNotFound);
                    // The decision was recorded, but nothing was framed.
                    assert_eq!(sink.events.len(), 1);
                    assert_eq!(sink.events[0].code(), SecurityCode::AuthorizationDenied);
                    assert_eq!(
                        daemon.send_counter(),
                        0,
                        "a refused projection must not consume a frame counter"
                    );
                    assert!(daemon.is_open(), "a denial must leave the channel usable");
                }

                let mut sink = RecordingSink::default();
                let frame = daemon
                    .send_projection(
                        &owned_projection(ProjectionClass::Status, b"ready"),
                        &mut sink,
                    )
                    .expect("the same projection over an owned object");
                assert_eq!(sink.events.len(), 1);
                assert_eq!(sink.events[0].code(), SecurityCode::AuthorizationAccepted);
                // The authorized frame is the channel's first: the denials cost no counter.
                assert_eq!(
                    u64::from_be_bytes(frame[21..29].try_into().unwrap()),
                    0,
                    "the first authorized projection must carry counter zero"
                );
                assert_eq!(daemon.send_counter(), 1);
                let filtered = client
                    .receive_filtered(&frame, PayloadKind::Response, &mut sink)
                    .expect("the client is still at the counter the daemon sealed under");
                assert_eq!(filtered.payload(), b"ready");
                assert_eq!(client.receive_counter(), 1);
                assert!(client.is_open() && daemon.is_open());
            }
        }
    };
}
