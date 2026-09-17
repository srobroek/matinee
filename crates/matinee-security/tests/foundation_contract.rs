macro_rules! foundation_contract_tests {
    () => {
        use crate::adapters::credential_store::{CredentialBinding, CredentialStore};
        use crate::adapters::os_pipe::OsPipe;
        use crate::events::{self, SecurityEventSink};
        use crate::identity::CapabilityAction;
        use crate::test_support_fakes::{FakeCredentialStore, FakeEventSink, FakeOsPipe};
        use uuid::Uuid;

        fn connection(epoch: u64) -> crate::identity::Connection {
            let mut c = crate::identity::Connection::new(
                crate::identity::ConnectionId::new(Uuid::from_u128(1)),
                crate::identity::IdentityId::new(Uuid::from_u128(2)),
                1,
                epoch,
                [0; 12],
                [1; 12],
                Uuid::from_u128(3),
                Uuid::from_u128(4),
            );
            c.authenticate().expect("authenticated fixture");
            c
        }

        fn context(epoch: u64, kind: crate::PayloadKind) -> crate::SessionInput {
            crate::SessionInput::new(
                crate::identity::ConnectionId::new(Uuid::from_u128(1)),
                crate::identity::IdentityId::new(Uuid::from_u128(2)),
                epoch,
                crate::identity::Capability::new(CapabilityAction::Read, "matinee/status").unwrap(),
                kind,
            )
        }

        #[test]
        fn foundational_boundary_accepts_valid_session_and_rejects_mutations() {
            let mut session =
                crate::ChannelSession::establish(connection(7), 1, "127.0.0.1:7777").unwrap();
            assert!(session.is_open());
            assert!(
                session
                    .binds(&context(7, crate::PayloadKind::Command))
                    .is_ok()
            );
            assert_eq!(
                session
                    .binds(&context(6, crate::PayloadKind::Command))
                    .unwrap_err()
                    .code(),
                crate::FailureCode::StaleEpoch
            );
            assert_eq!(session.next_send_counter().unwrap(), 0);
            session.close();
            assert!(!session.is_open());
            assert_eq!(
                session.next_send_counter().unwrap_err().code(),
                crate::FailureCode::CounterMismatch
            );
        }

        #[test]
        fn payload_bounds_and_debug_redaction_are_observable() {
            let input = crate::AuthorizedInput::authorized(
                &context(0, crate::PayloadKind::Event),
                b"secret-plaintext".to_vec(),
            )
            .unwrap();
            assert_eq!(input.payload(), b"secret-plaintext");
            let rendered = format!("{input:?}");
            assert!(!rendered.contains("secret-plaintext"));
            assert!(rendered.contains("payload_bytes: 16"));
            assert_eq!(
                crate::AuthorizedInput::authorized(
                    &context(0, crate::PayloadKind::Command),
                    vec![0; crate::MAX_PAYLOAD_BYTES + 1]
                )
                .unwrap_err()
                .code(),
                crate::FailureCode::ResourceLimit
            );
        }

        #[test]
        fn failure_and_event_projections_reject_secret_material_and_bound_metadata() {
            let failure = crate::SecurityFailure::new(crate::FailureCode::MalformedInput);
            let text = failure.to_string();
            assert!(!text.contains("secret"));
            assert!(!text.contains("payload"));
            let event = events::SecurityEvent::new(
                Uuid::from_u128(1),
                events::EventBoundary::Authentication,
                events::SecurityCode::MalformedInput,
                events::EventOutcome::Rejected,
                events::SafeNextAction::FailClosed,
                None,
                None,
                events::EndpointClass::Loopback,
                events::EventTime(1),
                Uuid::from_u128(2),
                vec![events::MetadataEntry {
                    key: "token".into(),
                    value: "redacted".into(),
                }],
            );
            assert_eq!(event, Err(events::EventBuildError::Redacted));
            let too_many = (0..9)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i}"),
                    value: "v".into(),
                })
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Authentication,
                    events::SecurityCode::MalformedInput,
                    events::EventOutcome::Rejected,
                    events::SafeNextAction::FailClosed,
                    None,
                    None,
                    events::EndpointClass::Loopback,
                    events::EventTime(1),
                    Uuid::nil(),
                    too_many
                ),
                Err(events::EventBuildError::TooManyMetadata)
            );
        }

        #[test]
        fn adapter_fakes_preserve_opaque_and_closed_outcomes() {
            let binding = CredentialBinding::new([7; 32]);
            let store = FakeCredentialStore::new().registered(binding, 42);
            assert_eq!(store.lookup(binding).unwrap().slot(), 42);
            assert_eq!(
                FakeCredentialStore::new().lookup(binding).unwrap_err(),
                crate::adapters::credential_store::CredentialStoreError::Missing
            );
            assert!(FakeOsPipe::present(9).acquire().unwrap().is_present());
            assert_eq!(
                FakeOsPipe::error(crate::adapters::os_pipe::OsPipeError::Unavailable)
                    .acquire()
                    .unwrap_err(),
                crate::adapters::os_pipe::OsPipeError::Unavailable
            );
        }

        #[test]
        fn required_event_delivery_fails_closed_without_a_sink_or_on_unavailable() {
            let event = events::SecurityEvent::new(
                Uuid::nil(),
                events::EventBoundary::Authentication,
                events::SecurityCode::MalformedInput,
                events::EventOutcome::Rejected,
                events::SafeNextAction::FailClosed,
                None,
                None,
                events::EndpointClass::Loopback,
                events::EventTime(0),
                Uuid::nil(),
                vec![],
            )
            .unwrap();
            assert_eq!(
                events::emit_required::<FakeEventSink>(None, event.clone()),
                Err(events::RequiredEventError::Unavailable)
            );
            let mut sink = FakeEventSink::unavailable();
            assert_eq!(
                events::emit_required(Some(&mut sink), event),
                Err(events::RequiredEventError::Unavailable)
            );
            assert_eq!(sink.received().len(), 1);
        }
    };
}
