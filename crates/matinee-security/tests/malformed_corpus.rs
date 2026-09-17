macro_rules! malformed_corpus_tests {
    () => {
        use std::fmt::Write as _;

        use crate::events::{
            EndpointClass, EventBoundary, EventBuildError, EventOutcome, EventTime, MetadataEntry,
            SafeNextAction, SecurityCode, SecurityEvent,
        };
        use crate::failures::{FailureCode, SecurityFailure};
        use crate::identity::{Capability, CapabilityAction, Connection, ConnectionId, IdentityId};
        use crate::{AuthorizedInput, AuthorizedOutput, ChannelSession, PayloadKind, SessionInput};
        use uuid::Uuid;

        const MALFORMED_CASE_COUNT: usize = 100_000;
        const MAX_FRAME_BYTES: usize = 1_048_535;

        /// A bounded, deterministic malformed frame corpus. The bytes are deliberately
        /// small: the declared length is checked before any frame-sized allocation.
        #[derive(Clone, Debug)]
        pub(crate) struct MalformedCase {
            pub(crate) bytes: [u8; 8],
        }

        pub(crate) fn malformed_corpus_cases() -> impl Iterator<Item = MalformedCase> {
            (0..MALFORMED_CASE_COUNT).map(|index| {
                let mut bytes = [0u8; 8];
                match index % 5 {
                    0 => bytes[..4].copy_from_slice(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes()),
                    1 => bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes()),
                    2 => bytes[..4].copy_from_slice(&2u32.to_be_bytes()),
                    3 => bytes[..4].copy_from_slice(&0x7fff_ffffu32.to_be_bytes()),
                    _ => bytes[..4].copy_from_slice(&((index as u32) | 0x8000_0000).to_be_bytes()),
                }
                bytes[4] = 0xff; // invalid UTF-8 marker in every malformed variant
                bytes[5] = (index & 0xff) as u8;
                MalformedCase { bytes }
            })
        }

        fn bounded_declared_payload(frame: &[u8]) -> Result<&[u8], SecurityFailure> {
            if frame.len() < 4 {
                return Err(SecurityFailure::new(FailureCode::MalformedInput));
            }
            let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            if declared > MAX_FRAME_BYTES || declared > frame.len() - 4 {
                return Err(SecurityFailure::new(FailureCode::ResourceLimit));
            }
            std::str::from_utf8(&frame[4..4 + declared])
                .map(|_| &frame[4..4 + declared])
                .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))
        }

        fn projected_event(failure: SecurityFailure) -> SecurityEvent {
            let code = match failure.code() {
                FailureCode::MalformedInput => SecurityCode::MalformedInput,
                FailureCode::ResourceLimit => SecurityCode::ResourceLimit,
                other => panic!("unexpected malformed corpus code: {other:?}"),
            };
            SecurityEvent::new(
                Uuid::nil(),
                EventBoundary::Channel,
                code,
                EventOutcome::Rejected,
                SafeNextAction::Discard,
                None,
                None,
                EndpointClass::Unknown,
                EventTime(0),
                Uuid::nil(),
                vec![],
            )
            .expect("bounded rejected event")
        }

        fn reject_before_dispatch(
            frame: &[u8],
            dispatch_count: &mut usize,
        ) -> Result<(), SecurityFailure> {
            let payload = bounded_declared_payload(frame)?;
            *dispatch_count += 1;
            let _ = payload.len();
            Ok(())
        }

        fn forbidden(value: &str) -> bool {
            [
                "private", "secret", "credential", "password", "cookie", "token",
                "authorization", "header", "pkcs8", "payload", "https://", "http://",
                "url", "object_id", "identifier", "artifact_id", "stream_id",
            ]
            .iter()
            .any(|word| value.to_ascii_lowercase().contains(word))
        }

        fn connection(epoch: u64) -> Connection {
            let mut connection = Connection::new(
                ConnectionId::new(Uuid::from_u128(1)),
                IdentityId::new(Uuid::from_u128(2)),
                1,
                epoch,
                [0u8; 12],
                [1u8; 12],
                Uuid::from_u128(3),
                Uuid::from_u128(4),
            );
            connection.authenticate().expect("authenticated fixture");
            connection
        }

        fn context(epoch: u64, kind: PayloadKind) -> SessionInput {
            SessionInput::new(
                ConnectionId::new(Uuid::from_u128(1)),
                IdentityId::new(Uuid::from_u128(2)),
                epoch,
                Capability::new(CapabilityAction::Read, "matinee/status").expect("bounded scope"),
                kind,
            )
        }

        #[test]
        fn malformed_corpus_has_deterministic_100000_fail_closed_cases() {
            let cases: Vec<_> = malformed_corpus_cases().collect();
            assert_eq!(cases.len(), MALFORMED_CASE_COUNT);
            for case in &cases {
                let failure = bounded_declared_payload(&case.bytes)
                    .expect_err("malformed input must fail closed");
                assert!(matches!(
                    failure.code(),
                    FailureCode::ResourceLimit | FailureCode::MalformedInput
                ));
                assert!(failure.principal_id().is_none());
                assert!(failure.connection_id().is_none());
            }
        }

        #[test]
        fn preallocation_rejection_preserves_bounds_and_channel_state() {
            let context = context(7, PayloadKind::StreamChunk);
            let oversized = vec![0u8; context.kind().max_bytes() + 1];
            let failure =
                AuthorizedInput::authorized(&context, oversized).expect_err("oversized input");
            assert_eq!(failure.code(), FailureCode::ResourceLimit);

            let output = AuthorizedOutput::filtered(
                PayloadKind::StreamChunk,
                vec![0u8; PayloadKind::StreamChunk.max_bytes() + 1],
            )
            .expect_err("oversized output");
            assert_eq!(output.code(), FailureCode::ResourceLimit);

            let mut session = ChannelSession::establish(connection(7), 1, "127.0.0.1:7777")
                .expect("bound session");
            session.close();
            assert!(!session.is_open());
            assert_eq!(
                session.binds(&context).unwrap_err().code(),
                FailureCode::AuthenticationFailed
            );
        }

        #[test]
        fn malformed_corpus_streaming_has_zero_frame_allocations_and_dispatches() {
            let mut dispatch_count = 0usize;
            let mut malformed = 0usize;
            let mut resource_limited = 0usize;
            for case in malformed_corpus_cases() {
                let failure = reject_before_dispatch(&case.bytes, &mut dispatch_count)
                    .expect_err("every deterministic case is rejected");
                match failure.code() {
                    FailureCode::MalformedInput => {
                        malformed += 1;
                        assert_eq!(failure.boundary().as_str(), "malformed");
                        assert_eq!(failure.safe_next_action().as_str(), "discard-and-reconnect");
                    }
                    FailureCode::ResourceLimit => {
                        resource_limited += 1;
                        assert_eq!(failure.boundary().as_str(), "resource-limit");
                        assert_eq!(failure.safe_next_action().as_str(), "reduce-to-declared-bound");
                    }
                    code => panic!("unexpected failure code: {code:?}"),
                }
                assert!(failure.principal_id().is_none());
                assert!(failure.connection_id().is_none());
                let event = projected_event(failure);
                assert_eq!(event.boundary, EventBoundary::Channel);
                assert_eq!(event.outcome, EventOutcome::Rejected);
                assert_eq!(event.next_action, SafeNextAction::Discard);
                assert!(event.principal_id.is_none());
                assert!(event.connection_id.is_none());
                assert!(event.metadata().is_empty());
                assert!(event.encoded_len() <= 2_048);
                assert!(!forbidden(&format!("{failure} {event:?}")));
            }
            assert_eq!(malformed + resource_limited, MALFORMED_CASE_COUNT);
            assert_eq!(malformed, MALFORMED_CASE_COUNT / 5);
            assert_eq!(resource_limited, MALFORMED_CASE_COUNT - malformed);
            assert_eq!(dispatch_count, 0, "rejected frames never dispatch");
        }

        #[test]
        fn exact_and_one_over_payload_bounds_reject_without_mutating_session() {
            for kind in [
                PayloadKind::Command,
                PayloadKind::Response,
                PayloadKind::Event,
                PayloadKind::StreamChunk,
            ] {
                let context = context(7, kind);
                assert!(AuthorizedInput::authorized(&context, vec![]).is_ok());
                assert!(AuthorizedOutput::filtered(kind, vec![]).is_ok());
                assert!(AuthorizedInput::authorized(&context, vec![0; kind.max_bytes()]).is_ok());
                assert!(AuthorizedOutput::filtered(kind, vec![0; kind.max_bytes()]).is_ok());
                let input = AuthorizedInput::authorized(&context, vec![0; kind.max_bytes() + 1])
                    .expect_err("one-over input bound");
                let output = AuthorizedOutput::filtered(kind, vec![0; kind.max_bytes() + 1])
                    .expect_err("one-over output bound");
                for failure in [input, output] {
                    assert_eq!(failure.code(), FailureCode::ResourceLimit);
                    assert_eq!(failure.boundary().as_str(), "resource-limit");
                    assert_eq!(failure.safe_next_action().as_str(), "reduce-to-declared-bound");
                    assert!(failure.principal_id().is_none());
                    assert!(failure.connection_id().is_none());
                }

                let mut session = ChannelSession::establish(connection(7), 1, "127.0.0.1:7777")
                    .expect("bound session");
                assert_eq!(session.next_receive_counter().unwrap(), 0);
                let failure = AuthorizedInput::authorized(&context, vec![0; kind.max_bytes() + 1])
                    .expect_err("rejection before channel mutation");
                let event = projected_event(failure);
                assert_eq!(event.code, SecurityCode::ResourceLimit);
                assert!(session.is_open());
                assert_eq!(session.next_receive_counter().unwrap(), 1);
                session.close();
                assert!(!session.is_open());
            }
        }

        #[test]
        fn malformed_fields_encodings_and_redaction_are_bounded() {
            assert_eq!(
                bounded_declared_payload(&[0, 0, 0, 1, 0xff])
                    .unwrap_err()
                    .code(),
                FailureCode::MalformedInput
            );
            assert_eq!(
                bounded_declared_payload(&[0, 0, 0, 9, b'a'])
                    .unwrap_err()
                    .code(),
                FailureCode::ResourceLimit
            );

            let event = SecurityEvent::new(
                Uuid::from_u128(10),
                EventBoundary::Input,
                SecurityCode::MalformedInput,
                EventOutcome::Rejected,
                SafeNextAction::Discard,
                None,
                None,
                EndpointClass::Unknown,
                EventTime(11),
                Uuid::from_u128(12),
                vec![MetadataEntry {
                    key: "reason".into(),
                    value: "invalid-utf8".into(),
                }],
            )
            .expect("safe event");
            assert_eq!(event.metadata().len(), 1);
            assert!(event.encoded_len() <= 2_048);

            let secret = SecurityEvent::new(
                Uuid::from_u128(13),
                EventBoundary::Input,
                SecurityCode::MalformedInput,
                EventOutcome::Rejected,
                SafeNextAction::Discard,
                None,
                None,
                EndpointClass::Unknown,
                EventTime(14),
                Uuid::from_u128(15),
                vec![MetadataEntry {
                    key: "payload".into(),
                    value: "secret-token".into(),
                }],
            )
            .unwrap_err();
            assert_eq!(secret, EventBuildError::Redacted);

            let failure = SecurityFailure::new(FailureCode::MalformedInput);
            let mut rendered = String::new();
            write!(&mut rendered, "{failure}").unwrap();
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains("payload"));
        }
    };
}
