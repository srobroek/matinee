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

        #[test]
        fn identity_reference_shapes_and_bounds_are_closed() {
            let key = crate::identity::PublicKey::from_uncompressed([
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
                0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
                0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ]).unwrap();
            assert_eq!(key.as_bytes()[0], 4);
            assert_eq!(key.uncompressed_hex().len(), 130);
            assert!(crate::identity::PublicKey::from_uncompressed([3; crate::identity::UNCOMPRESSED_KEY_BYTES]).is_err());
            let fingerprint = crate::identity::Fingerprint::new("a".repeat(64)).unwrap();
            assert_eq!(fingerprint.as_str().len(), 64);
            for value in ["", "A".repeat(64).as_str(), "a".repeat(63).as_str()] {
                assert!(crate::identity::Fingerprint::new(value).is_err());
            }
            let daemon = crate::identity::IdentityId::new(Uuid::from_u128(8));
            let reference = crate::identity::CredentialReference::new("keychain", "daemon/key", daemon, daemon).unwrap();
            assert_eq!(reference.provider(), "keychain");
            assert_eq!(reference.key_locator(), "daemon/key");
            assert!(crate::identity::CredentialReference::new("", "key", daemon, daemon).is_err());
            assert!(crate::identity::CredentialReference::new("p", "k".repeat(257), daemon, daemon).is_err());
        }

        #[test]
        fn failure_codes_have_stable_complete_redacted_projections() {
            let codes = [
                crate::FailureCode::AuthenticationFailed, crate::FailureCode::AuthorizationDenied,
                crate::FailureCode::ObjectNotFound, crate::FailureCode::CompatibilityUnsupported,
                crate::FailureCode::DowngradeRejected, crate::FailureCode::MalformedInput,
                crate::FailureCode::OriginRejected, crate::FailureCode::EndpointRejected,
                crate::FailureCode::ReplayDetected, crate::FailureCode::CounterMismatch,
                crate::FailureCode::RateLimited, crate::FailureCode::CredentialStoreUnavailable,
                crate::FailureCode::CredentialStoreMismatch, crate::FailureCode::ResourceLimit,
                crate::FailureCode::StaleEpoch, crate::FailureCode::Revoked,
                crate::FailureCode::TransitionUnknown, crate::FailureCode::EventSinkUnavailable,
                crate::FailureCode::CryptographicFailure,
            ];
            for code in codes {
                let failure = crate::SecurityFailure::new(code);
                let (boundary, projected, action) = failure.redacted();
                assert_eq!(projected, code);
                assert_eq!(failure.boundary(), boundary);
                assert_eq!(failure.safe_next_action(), action);
                assert!(!code.as_str().is_empty());
                let display = failure.to_string();
                assert!(display.contains(code.as_str()));
                assert!(display.contains(boundary.as_str()));
                assert!(display.contains(action.as_str()));
                assert!(!display.contains("secret"));
                assert!(!format!("{failure:?}").contains("secret"));
            }
        }

        #[test]
        fn event_vocabulary_and_size_boundaries_fail_closed() {
            for word in ["private", "secret", "credential", "password", "cookie", "token", "authorization", "pkcs8", "payload", "https://", "http://", "url", "object_id", "artifact_id", "stream_id"] {
                let result = events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: word.into(), value: "x".into() }]);
                assert_eq!(result, Err(events::EventBuildError::Redacted), "forbidden key {word}");
                let result = events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: "safe".into(), value: word.into() }]);
                assert_eq!(result, Err(events::EventBuildError::Redacted), "forbidden value {word}");
            }
            assert_eq!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: "k".repeat(33), value: "v".into() }]), Err(events::EventBuildError::MetadataKeyTooLong));
            assert_eq!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: "k".into(), value: "v".repeat(129) }]), Err(events::EventBuildError::MetadataValueTooLong));
            let too_large = (0..8).map(|i| events::MetadataEntry { key: format!("k{i}"), value: "v".repeat(100) }).collect();
            assert_eq!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), too_large), Err(events::EventBuildError::MetadataTooLarge));
            assert!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: "k".repeat(32), value: "v".into() }]).is_ok());
            assert!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), vec![events::MetadataEntry { key: "k".into(), value: "v".repeat(128) }]).is_ok());
            let eight_entries = (0..8).map(|i| events::MetadataEntry { key: format!("k{i}"), value: "v".into() }).collect();
            assert!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), eight_entries).is_ok());
            let exact_metadata = (0..8).map(|i| events::MetadataEntry { key: format!("k{i}"), value: "v".repeat(62) }).collect();
            assert!(events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), exact_metadata).is_ok());
            // Seven entries total 7 * (2-byte key + 62-byte value) plus one 2-byte key + 63-byte value = 513 bytes.
            let one_over_metadata = (0..8)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i}"),
                    value: "v".repeat(if i == 7 { 63 } else { 62 }),
                })
                .collect();
            assert_eq!(
                events::SecurityEvent::new(Uuid::nil(), events::EventBoundary::Input, events::SecurityCode::MalformedInput, events::EventOutcome::Rejected, events::SafeNextAction::FailClosed, None, None, events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(), one_over_metadata),
                Err(events::EventBuildError::MetadataTooLarge)
            );
        }

        #[test]
        fn every_adapter_closed_outcome_remains_distinct_and_opaque() {
            let binding = CredentialBinding::new([1; 32]);
            for error in [crate::adapters::credential_store::CredentialStoreError::Missing, crate::adapters::credential_store::CredentialStoreError::Mismatch, crate::adapters::credential_store::CredentialStoreError::Revoked, crate::adapters::credential_store::CredentialStoreError::Duplicate, crate::adapters::credential_store::CredentialStoreError::Unavailable] {
                assert_eq!(FakeCredentialStore::new().with_error(binding, error).lookup(binding), Err(error));
            }
            for error in [crate::adapters::os_pipe::OsPipeError::Missing, crate::adapters::os_pipe::OsPipeError::Mismatch, crate::adapters::os_pipe::OsPipeError::Duplicate, crate::adapters::os_pipe::OsPipeError::Unavailable, crate::adapters::os_pipe::OsPipeError::Malformed, crate::adapters::os_pipe::OsPipeError::Oversized] {
                assert_eq!(FakeOsPipe::error(error).acquire(), Err(error));
            }
            assert_eq!(format!("{:?}", crate::adapters::credential_store::CredentialHandle::from_slot(9)), "CredentialHandle(REDACTED)");
            assert_eq!(format!("{:?}", crate::adapters::os_pipe::InheritedPipe::from_handle(9)), "InheritedPipe(REDACTED)");
        }

        #[test]
        fn commands_are_closed_idempotent_and_operation_mapped() {
            let id = crate::identity::IdentityId::new(Uuid::from_u128(1));
            let transition = crate::identity::TransitionId::new(Uuid::from_u128(2));
            let key = |n| crate::identity::IdempotencyKey::new(Uuid::from_u128(n));
            let commands = [
                crate::SecurityCommand::Bootstrap { state_directory: id, idempotency: key(1) },
                crate::SecurityCommand::CreateEnrollment { enrollment: transition, daemon: id, idempotency: key(2) },
                crate::SecurityCommand::ConsumeEnrollment { enrollment: transition, idempotency: key(3) },
                crate::SecurityCommand::Rotate { principal: id, new_fingerprint: crate::identity::Fingerprint::new("a".repeat(64)).unwrap(), idempotency: key(4) },
                crate::SecurityCommand::Revoke { principal: id, idempotency: key(5) },
            ];
            let expected = [crate::identity::TransitionOperation::Bootstrap, crate::identity::TransitionOperation::EnrollmentCreate, crate::identity::TransitionOperation::EnrollmentConsume, crate::identity::TransitionOperation::Rotation, crate::identity::TransitionOperation::Revocation];
            for (command, operation) in commands.iter().zip(expected) {
                assert_eq!(command.operation(), operation);
                assert_eq!(command.idempotency(), key((commands.iter().position(|candidate| candidate == command).unwrap() + 1) as u128));
                assert_eq!(command, &command.clone());
            }
        }
    };
}