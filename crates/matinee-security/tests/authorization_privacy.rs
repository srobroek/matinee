macro_rules! authorization_privacy_tests {
    () => {
        mod authorization_privacy_inner {
            use crate::test_support_channel::{
                CONNECTION, OWNER, PRINCIPAL, RecordingSink, RingSigner, SCOPE, STATE_DIRECTORY,
                capability, establish_pair, id, owned_operation, owned_projection,
                registered_principal,
            };
            use crate::{
                AuthorizedOutput, Capability, CapabilityAction, ChannelSession, ChannelSigner,
                ClientHandshake, ClientHandshakeConfig, ConnectionId, EventBoundary, EventOutcome,
                ExtensionGrant, FailureCode, LoopbackHost, ObjectOwner, PayloadKind, PrincipalKind,
                ProjectionClass, SafeNextAction, SecurityCode, ServerHandshake,
                ServerHandshakeConfig, SessionInput, SessionProjection, StateBearingRequest,
                StateBearingRoute,
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

            // ---------------------------------------------------------------------------
            // SC-004, in full: the complete route/object/role/ceiling/owner/grant matrix.
            // ---------------------------------------------------------------------------

            /// The epoch every matrix principal is registered at. A grant bound to any other
            /// epoch is one of the grant shapes below.
            const MATRIX_EPOCH: u64 = 0;
            /// An owner no matrix principal holds. Its hexadecimal tail is searched for in
            /// every rendering a probe can observe.
            const FOREIGN_OWNER: u128 = 0xfeed_face;
            /// An extension identity no matrix principal holds.
            const FOREIGN_EXTENSION: u128 = 0x0bad_0001;
            const ROUTE_AUTHORITY: &str = "127.0.0.1:7777";
            const ROUTE_PATH: &str = "/v1/session";
            const ROUTE_SUBPROTOCOL: &str = "matinee.v1";
            const ROUTE_ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

            /// The state-bearing route FR-018 configures: one loopback authority, one exact
            /// path, one versioned subprotocol, one allowed Origin.
            fn configured_route() -> StateBearingRoute {
                StateBearingRoute::new(
                    LoopbackHost::Ipv4,
                    7777,
                    ROUTE_PATH,
                    ROUTE_SUBPROTOCOL,
                    [ROUTE_ORIGIN],
                )
                .expect("a configured state-bearing route")
            }

            /// The route dimension: the upgrade production admits, and every shape
            /// `StateBearingRoute::admit` refuses.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            enum RouteCase {
                Admitted,
                UnexpectedPath,
                UnexpectedSubprotocol,
                NonLoopbackAuthority,
                ForeignOrigin,
            }

            const MATRIX_ROUTES: [RouteCase; 5] = [
                RouteCase::Admitted,
                RouteCase::UnexpectedPath,
                RouteCase::UnexpectedSubprotocol,
                RouteCase::NonLoopbackAuthority,
                RouteCase::ForeignOrigin,
            ];

            fn route_request(case: RouteCase) -> StateBearingRequest<'static> {
                let mut request = StateBearingRequest {
                    authority: ROUTE_AUTHORITY,
                    route: ROUTE_PATH,
                    subprotocol: ROUTE_SUBPROTOCOL,
                    origin: ROUTE_ORIGIN,
                };
                match case {
                    RouteCase::Admitted => {}
                    RouteCase::UnexpectedPath => request.route = "/v1/session/admin",
                    RouteCase::UnexpectedSubprotocol => request.subprotocol = "matinee.v2",
                    RouteCase::NonLoopbackAuthority => request.authority = "10.0.0.5:7777",
                    RouteCase::ForeignOrigin => request.origin = "https://attacker.example",
                }
                request
            }

            /// The object-type dimension: every daemon projection class production names, so
            /// every shape an object lookup can arrive on and be disclosed through.
            const MATRIX_CLASSES: [ProjectionClass; 5] = [
                ProjectionClass::Response,
                ProjectionClass::Status,
                ProjectionClass::Event,
                ProjectionClass::Artifact,
                ProjectionClass::StreamChunk,
            ];

            /// The role dimension: every principal kind.
            const MATRIX_ROLES: [PrincipalKind; 3] = [
                PrincipalKind::NativeAdmin,
                PrincipalKind::McpClient,
                PrincipalKind::BrowserExtension,
            ];

            /// The ownership dimension, as the daemon's own lookup resolved it.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            enum OwnerCase {
                Owned,
                CrossOwner,
                Unresolved,
            }

            const MATRIX_OWNERS: [OwnerCase; 3] = [
                OwnerCase::Owned,
                OwnerCase::CrossOwner,
                OwnerCase::Unresolved,
            ];

            /// One capability-ceiling cell: the ceiling the principal is registered with and
            /// the capability the probe requests against it.
            ///
            /// `covers` and `administrative` are authored labels of the cell itself, never
            /// values read back out of the gate: `covers` states the scope relation the
            /// contract's ceiling rules give this pair, and `administrative` states whether
            /// FR-021 reserves the requested action for the native administrator.
            struct CeilingCase {
                name: &'static str,
                ceiling_action: CapabilityAction,
                ceiling_scope: &'static str,
                requested_action: CapabilityAction,
                requested_scope: &'static str,
                covers: bool,
                administrative: bool,
            }

            impl CeilingCase {
                fn ceiling(&self) -> Capability {
                    capability(self.ceiling_action.clone(), self.ceiling_scope)
                }
                fn requested(&self) -> Capability {
                    capability(self.requested_action.clone(), self.requested_scope)
                }
            }

            /// Every `CapabilityAction` appears, and every scope relation the ceiling rules
            /// distinguish: exact, parent prefix, global, disjoint, a sibling prefix that is
            /// not a path boundary, and a matching scope under the wrong action.
            fn matrix_ceilings() -> [CeilingCase; 11] {
                [
                    CeilingCase {
                        name: "exact-scope-read",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: SCOPE,
                        requested_action: CapabilityAction::Read,
                        requested_scope: SCOPE,
                        covers: true,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "parent-scope-read",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: "matinee",
                        requested_action: CapabilityAction::Read,
                        requested_scope: SCOPE,
                        covers: true,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "global-scope-read",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: "global",
                        requested_action: CapabilityAction::Read,
                        requested_scope: SCOPE,
                        covers: true,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "disjoint-scope-read",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: "other",
                        requested_action: CapabilityAction::Read,
                        requested_scope: SCOPE,
                        covers: false,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "sibling-prefix-read",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: "matinee",
                        requested_action: CapabilityAction::Read,
                        requested_scope: "matinee-secret/status",
                        covers: false,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "write-ceiling-read-request",
                        ceiling_action: CapabilityAction::Write,
                        ceiling_scope: "matinee",
                        requested_action: CapabilityAction::Read,
                        requested_scope: SCOPE,
                        covers: false,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "manage-principals",
                        ceiling_action: CapabilityAction::ManagePrincipals,
                        ceiling_scope: "global",
                        requested_action: CapabilityAction::ManagePrincipals,
                        requested_scope: "global",
                        covers: true,
                        administrative: true,
                    },
                    CeilingCase {
                        name: "revoke-without-admin-ceiling",
                        ceiling_action: CapabilityAction::Read,
                        ceiling_scope: "global",
                        requested_action: CapabilityAction::Revoke,
                        requested_scope: "global",
                        covers: false,
                        administrative: true,
                    },
                    CeilingCase {
                        name: "rotate-with-rotate-ceiling",
                        ceiling_action: CapabilityAction::Rotate,
                        ceiling_scope: "global",
                        requested_action: CapabilityAction::Rotate,
                        requested_scope: "global",
                        covers: true,
                        administrative: true,
                    },
                    CeilingCase {
                        name: "execute-parent-scope",
                        ceiling_action: CapabilityAction::Execute,
                        ceiling_scope: "matinee",
                        requested_action: CapabilityAction::Execute,
                        requested_scope: SCOPE,
                        covers: true,
                        administrative: false,
                    },
                    CeilingCase {
                        name: "administer-with-admin-ceiling",
                        ceiling_action: CapabilityAction::Administer,
                        ceiling_scope: "global",
                        requested_action: CapabilityAction::Administer,
                        requested_scope: "global",
                        covers: true,
                        administrative: true,
                    },
                ]
            }

            /// The grant dimension: an absent grant, the grant that binds, and every binding
            /// an extension grant can miss.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            enum GrantCase {
                Absent,
                Matching,
                ForeignExtension,
                ForeignOwner,
                StaleEpoch,
                Revoked,
                ExceedsCeiling,
                MissesRequest,
            }

            const MATRIX_GRANTS: [GrantCase; 8] = [
                GrantCase::Absent,
                GrantCase::Matching,
                GrantCase::ForeignExtension,
                GrantCase::ForeignOwner,
                GrantCase::StaleEpoch,
                GrantCase::Revoked,
                GrantCase::ExceedsCeiling,
                GrantCase::MissesRequest,
            ];

            /// The grant a cell presents, built from that cell's own requested capability so
            /// a matching grant is exactly a subset of the ceiling that covers the request.
            ///
            /// `ExceedsCeiling` adds a `Revoke` capability at global scope, which no ceiling
            /// in the matrix names, and `MissesRequest` names the requested action at a scope
            /// no requested scope sits under. Neither defect is ceiling-dependent.
            fn matrix_grant(case: GrantCase, requested: &Capability) -> Option<ExtensionGrant> {
                let mut grant = match case {
                    GrantCase::Absent => return None,
                    GrantCase::ForeignExtension => ExtensionGrant::new(
                        id(FOREIGN_EXTENSION),
                        id(OWNER),
                        vec![requested.clone()],
                        MATRIX_EPOCH,
                    ),
                    GrantCase::ForeignOwner => ExtensionGrant::new(
                        id(PRINCIPAL),
                        id(FOREIGN_OWNER),
                        vec![requested.clone()],
                        MATRIX_EPOCH,
                    ),
                    GrantCase::StaleEpoch => ExtensionGrant::new(
                        id(PRINCIPAL),
                        id(OWNER),
                        vec![requested.clone()],
                        MATRIX_EPOCH + 1,
                    ),
                    GrantCase::ExceedsCeiling => ExtensionGrant::new(
                        id(PRINCIPAL),
                        id(OWNER),
                        vec![
                            requested.clone(),
                            capability(CapabilityAction::Revoke, "global"),
                        ],
                        MATRIX_EPOCH,
                    ),
                    GrantCase::MissesRequest => ExtensionGrant::new(
                        id(PRINCIPAL),
                        id(OWNER),
                        vec![capability(requested.action().clone(), "unrelated")],
                        MATRIX_EPOCH,
                    ),
                    GrantCase::Matching | GrantCase::Revoked => ExtensionGrant::new(
                        id(PRINCIPAL),
                        id(OWNER),
                        vec![requested.clone()],
                        MATRIX_EPOCH,
                    ),
                }
                .expect("a grant fixture always names capabilities");
                if case == GrantCase::Revoked {
                    grant.revoke();
                }
                Some(grant)
            }

            /// FR-021: only an extension presents a grant, and only its own active one.
            fn grant_admits(role: PrincipalKind, case: GrantCase) -> bool {
                if role == PrincipalKind::BrowserExtension {
                    case == GrantCase::Matching
                } else {
                    case == GrantCase::Absent
                }
            }

            /// One observation with the per-emission event identifier elided.
            ///
            /// A freshly minted event UUID is not a coordinate of the cell and carries no
            /// object fact; everything else about two observations still has to match byte
            /// for byte. The leak scan always runs on the unedited rendering.
            fn without_event_ids(rendered: &str) -> String {
                const MARKER: &str = "event_id: ";
                const UUID_LEN: usize = 36;
                let mut out = String::with_capacity(rendered.len());
                let mut rest = rendered;
                while let Some(at) = rest.find(MARKER) {
                    let (head, tail) = rest.split_at(at + MARKER.len());
                    out.push_str(head);
                    out.push_str("<elided>");
                    rest = &tail[UUID_LEN..];
                }
                out.push_str(rest);
                out
            }

            /// One authenticated pair on the endpoint route admission produced.
            ///
            /// The daemon identity is the fixture owner identity, which is the identity the
            /// fixture credential registers objects under.
            fn matrix_pair(
                role: PrincipalKind,
                ceiling: Capability,
                endpoint: &str,
            ) -> (ChannelSession, ChannelSession) {
                let client_signer = RingSigner::generate();
                let daemon_signer = RingSigner::generate();
                let client = ClientHandshakeConfig::new(
                    endpoint,
                    id(PRINCIPAL),
                    client_signer.public_key().clone(),
                    id(OWNER),
                    daemon_signer.public_key().clone(),
                    MATRIX_EPOCH,
                    1,
                    3,
                )
                .expect("a client bound to the admitted endpoint");
                let server = ServerHandshakeConfig::new(
                    endpoint,
                    registered_principal(
                        PRINCIPAL,
                        role,
                        client_signer.public_key().clone(),
                        vec![ceiling],
                        MATRIX_EPOCH,
                    ),
                    id(OWNER),
                    daemon_signer.public_key().clone(),
                    2,
                    4,
                    ConnectionId::new(Uuid::from_u128(CONNECTION)),
                )
                .expect("a daemon bound to the admitted endpoint");
                let mut sink = RecordingSink::default();
                let (client_pending, hello) = ClientHandshake::start(client).expect("client hello");
                let (server_pending, proof) =
                    ServerHandshake::accept(server, &hello, &daemon_signer, &mut sink)
                        .expect("daemon proof");
                let (client_session, client_proof) = client_pending
                    .finish(&proof, &client_signer, &mut sink)
                    .expect("client completes the transcript");
                let daemon_session = server_pending
                    .finish(&client_proof, &mut sink)
                    .expect("daemon completes the transcript");
                (client_session, daemon_session)
            }

            /// Nothing a probe can observe may name a protected value: not the payload, not
            /// the owner it did not own, not the scope or ceiling it probed.
            fn assert_discloses_nothing(rendered: &str, label: &str) {
                let lowered = rendered.to_ascii_lowercase();
                for forbidden in [
                    "protected", "feedface", "matinee", "secret", "unrelated", "global",
                ] {
                    assert!(
                        !lowered.contains(forbidden),
                        "cell {label} disclosed {forbidden} through {rendered}"
                    );
                }
            }

            /// SC-004, quoted: "In a matrix covering every route, object type, role,
            /// capability ceiling, ownership, and grant, 100% of unauthorized probes disclose
            /// neither protected data nor object existence."
            ///
            /// The matrix is the complete cross-product of those six dimensions as production
            /// spells them: 5 route admissions x 5 object projection classes x 3 principal
            /// kinds x 11 ceiling/request pairs x 3 ownership resolutions x 8 grant shapes =
            /// 19,800 cells. 3,960 sit on the admitted route and reach the gate; the other
            /// 15,840 are refused at admission, which yields no `AdmittedEndpoint` and so no
            /// session for any inner coordinate to run on.
            ///
            /// Every cell drives production: `StateBearingRoute::admit` for the route, and
            /// both disclosure directions of the real gate -- `ChannelSession::receive` and
            /// `ChannelSession::send_projection` -- for the rest.
            ///
            /// The criterion is asserted three ways, none depending on the gate's internal
            /// ordering:
            ///
            /// 1. A cell is authorized exactly when all six of its own coordinates admit it,
            ///    which is 75 of the 3,960 reachable cells.
            /// 2. Every denial carries a code from the closed denial set and renders no
            ///    protected value, and a denied projection serializes no byte at all.
            /// 3. For fixed route, object type, role, ceiling, and grant, the cross-owner cell
            ///    and the unresolved cell render identically -- failure and event alike -- so
            ///    no probe can infer that a protected object exists.
            #[test]
            fn the_complete_route_object_role_ceiling_owner_grant_matrix_discloses_nothing() {
                let started = std::time::Instant::now();
                let route = configured_route();
                let ceilings = matrix_ceilings();
                let mut cells = 0usize;
                let mut unreachable = 0usize;
                let mut authorized = 0usize;
                let mut object_not_found = 0usize;
                let mut authorization_denied = 0usize;
                let mut authorized_by_role = [0usize; 3];

                for route_case in MATRIX_ROUTES {
                    let request = route_request(route_case);
                    if route_case != RouteCase::Admitted {
                        // A refused upgrade carries no object, role, ceiling, owner, or grant.
                        // Re-admitting it once per inner cell is what proves those coordinates
                        // cannot reach admission: every refusal must render identically, and
                        // none of them yields an endpoint to bind a session to.
                        let expected = if route_case == RouteCase::ForeignOrigin {
                            FailureCode::OriginRejected
                        } else {
                            FailureCode::EndpointRejected
                        };
                        let mut reference: Option<String> = None;
                        for class in MATRIX_CLASSES {
                            for role in MATRIX_ROLES {
                                for ceiling_case in &ceilings {
                                    for owner_case in MATRIX_OWNERS {
                                        for grant_case in MATRIX_GRANTS {
                                            let label = format!(
                                                "{route_case:?}/{class:?}/{role:?}/{}/{owner_case:?}/{grant_case:?}",
                                                ceiling_case.name
                                            );
                                            let mut sink = RecordingSink::default();
                                            let failure = route
                                                .admit(&request, 1, &mut sink)
                                                .expect_err("a refused upgrade admits nothing");
                                            assert_eq!(failure.code(), expected, "cell {label}");
                                            let rendered =
                                                format!("{failure} {failure:?} {:?}", sink.events);
                                            assert_discloses_nothing(&rendered, &label);
                                            let comparable = without_event_ids(&rendered);
                                            match &reference {
                                                None => reference = Some(comparable),
                                                Some(first) => assert_eq!(
                                                    first, &comparable,
                                                    "cell {label} refused distinguishably"
                                                ),
                                            }
                                            cells += 1;
                                            unreachable += 1;
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }

                    let mut admission_sink = RecordingSink::default();
                    let admitted = route
                        .admit(&request, 1, &mut admission_sink)
                        .expect("the configured upgrade is admitted");
                    assert!(
                        admission_sink.events.is_empty(),
                        "an admitted upgrade is not a rejection fact"
                    );

                    for (role_index, role) in MATRIX_ROLES.into_iter().enumerate() {
                        for ceiling_case in &ceilings {
                            // Ownership, grant, and object type are named per operation, so
                            // one session per (role, ceiling) carries every inner cell.
                            let (mut client, mut daemon) =
                                matrix_pair(role, ceiling_case.ceiling(), admitted.as_str());
                            assert_eq!(daemon.endpoint(), admitted.as_str());
                            let requested = ceiling_case.requested();
                            let role_admits =
                                !ceiling_case.administrative || role == PrincipalKind::NativeAdmin;

                            for class in MATRIX_CLASSES {
                                for grant_case in MATRIX_GRANTS {
                                    let grant = matrix_grant(grant_case, &requested);
                                    let mut renderings = Vec::with_capacity(3);
                                    for owner_case in MATRIX_OWNERS {
                                        let label = format!(
                                            "Admitted/{class:?}/{role:?}/{}/{owner_case:?}/{grant_case:?}",
                                            ceiling_case.name
                                        );
                                        let owner = match owner_case {
                                            OwnerCase::Owned => ObjectOwner::Owned(id(OWNER)),
                                            OwnerCase::CrossOwner => {
                                                ObjectOwner::Owned(id(FOREIGN_OWNER))
                                            }
                                            OwnerCase::Unresolved => ObjectOwner::Unknown,
                                        };
                                        let expected_ok = owner_case == OwnerCase::Owned
                                            && ceiling_case.covers
                                            && role_admits
                                            && grant_admits(role, grant_case);

                                        // Direction one: the object lookup the probe sends.
                                        let frame =
                                            request_frame(&mut client, class.payload_kind(), PROTECTED);
                                        let operation = SessionInput::new(
                                            requested.clone(),
                                            class.payload_kind(),
                                            owner,
                                            grant.as_ref(),
                                        );
                                        let mut sink = RecordingSink::default();
                                        let received = daemon.receive(&frame, &operation, &mut sink);
                                        assert_eq!(sink.events.len(), 1, "cell {label}");
                                        assert_eq!(
                                            sink.events[0].boundary(),
                                            EventBoundary::Authorization,
                                            "cell {label}"
                                        );
                                        match &received {
                                            Ok(input) => {
                                                assert!(
                                                    expected_ok,
                                                    "cell {label} was authorized but its own coordinates deny it"
                                                );
                                                assert_eq!(input.payload(), PROTECTED);
                                                assert_eq!(input.owner(), owner);
                                                assert_eq!(
                                                    sink.events[0].code(),
                                                    SecurityCode::AuthorizationAccepted
                                                );
                                                assert_eq!(
                                                    sink.events[0].outcome(),
                                                    EventOutcome::Accepted
                                                );
                                            }
                                            Err(failure) => {
                                                assert!(
                                                    !expected_ok,
                                                    "cell {label} was denied but its own coordinates admit it"
                                                );
                                                assert!(
                                                    matches!(
                                                        failure.code(),
                                                        FailureCode::AuthorizationDenied
                                                            | FailureCode::ObjectNotFound
                                                    ),
                                                    "cell {label} left the closed denial set with {}",
                                                    failure.code().as_str()
                                                );
                                                if failure.code() == FailureCode::ObjectNotFound {
                                                    assert_eq!(
                                                        failure.safe_next_action(),
                                                        SafeNextAction::DoNotInferObjectExistence,
                                                        "cell {label}"
                                                    );
                                                }
                                                assert_eq!(
                                                    sink.events[0].code(),
                                                    SecurityCode::AuthorizationDenied
                                                );
                                                assert_eq!(
                                                    sink.events[0].outcome(),
                                                    EventOutcome::Rejected
                                                );
                                            }
                                        }
                                        assert!(
                                            daemon.is_open(),
                                            "cell {label} cost the channel its life"
                                        );

                                        // Direction two: the disclosure the daemon would make.
                                        let projection = SessionProjection::new(
                                            class,
                                            requested.clone(),
                                            owner,
                                            grant.as_ref(),
                                            PROTECTED,
                                        );
                                        let before = daemon.send_counter();
                                        let mut send_sink = RecordingSink::default();
                                        let sent = daemon.send_projection(&projection, &mut send_sink);
                                        assert_eq!(sent.is_ok(), expected_ok, "cell {label}");
                                        match &sent {
                                            Ok(frame) => {
                                                assert_eq!(daemon.send_counter(), before + 1);
                                                let mut client_sink = RecordingSink::default();
                                                let filtered = client
                                                    .receive_filtered(
                                                        frame,
                                                        class.payload_kind(),
                                                        &mut client_sink,
                                                    )
                                                    .expect("an authorized projection arrives");
                                                assert_eq!(filtered.payload(), PROTECTED);
                                                authorized += 1;
                                                authorized_by_role[role_index] += 1;
                                            }
                                            Err(failure) => {
                                                assert_eq!(
                                                    daemon.send_counter(),
                                                    before,
                                                    "cell {label} serialized a refused projection"
                                                );
                                                if failure.code() == FailureCode::ObjectNotFound {
                                                    object_not_found += 1;
                                                } else {
                                                    authorization_denied += 1;
                                                }
                                            }
                                        }

                                        let rendered = format!(
                                            "{received:?} {sent:?} {:?} {:?}",
                                            sink.events, send_sink.events
                                        );
                                        if !expected_ok {
                                            assert_discloses_nothing(&rendered, &label);
                                        }
                                        renderings.push(without_event_ids(&rendered));
                                        cells += 1;
                                    }
                                    // SC-004 itself: a cross-owner object and an object that did
                                    // not resolve are one observation, so existence never leaks.
                                    assert_eq!(
                                        renderings[1], renderings[2],
                                        "a cross-owner object and an unresolved object must be \
                                         indistinguishable at {}/{class:?}/{role:?}/{grant_case:?}",
                                        ceiling_case.name
                                    );
                                }
                            }
                        }
                    }
                }

                assert_eq!(cells, 19_800, "the matrix must be the complete cross-product");
                assert_eq!(unreachable, 15_840);
                assert_eq!(cells - unreachable, 3_960);
                assert_eq!(
                    authorized + object_not_found + authorization_denied,
                    3_960,
                    "every reachable cell must be authorized or denied"
                );
                // Seven of the eleven ceilings cover their request; four of those name an
                // administrator-only action. Five object types, one admitting owner, one
                // admitting grant shape per role.
                assert_eq!(authorized, 75, "exactly the admitting cells are authorized");
                assert_eq!(authorized_by_role, [35, 20, 20]);
                assert!(
                    object_not_found > 0 && authorization_denied > 0,
                    "both denial classes must be exercised"
                );
                println!(
                    "SC-004 matrix: {cells} cells ({} reachable, {unreachable} refused at \
                     admission), {authorized} authorized, {object_not_found} object.not_found, \
                     {authorization_denied} authorization.denied, {:?}",
                    cells - unreachable,
                    started.elapsed()
                );
            }
        }
    };
}
