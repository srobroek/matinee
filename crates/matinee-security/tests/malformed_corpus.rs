#[allow(unused_macros)]
macro_rules! malformed_corpus_tests {
    () => {
        use std::fmt::Write as _;

        use crate::events::{
            EndpointClass, EventBoundary, EventBuildError, EventOutcome, EventTime, MetadataEntry,
            SafeNextAction, SecurityCode, SecurityEvent,
        };
        use crate::failures::{FailureCode, SecurityFailure};
        use crate::test_support_channel::{
            CONNECTION, RecordingSink, RingSigner, establish_pair, fixture_principal,
            owned_operation,
        };
        use crate::{AuthorizedOutput, ChannelSigner, ConnectionId, PayloadKind};
        use uuid::Uuid;

        const MALFORMED_CASE_COUNT: usize = 100_000;
        /// The production frame limits: `open` refuses a declared length past
        /// `MAX_FRAME` and a declared length below one header plus one tag.
        const MAX_FRAME_BYTES: usize = 1_048_576;
        const HEADER_LEN: usize = 25;
        const TAG_LEN: usize = 16;
        const MIN_FRAME_BODY: usize = HEADER_LEN + TAG_LEN;
        const EPOCH: u64 = 7;
        const SHAPE_FAMILIES: usize = 8;

        /// One malformed or oversized frame, with the bounded failure the
        /// production parser owes it. The bytes stay small on purpose: a declared
        /// length is checked before allocation, so a four-gigabyte declaration is
        /// carried by a handful of bytes.
        #[derive(Clone, Debug)]
        pub(crate) struct MalformedCase {
            pub(crate) family: &'static str,
            pub(crate) bytes: Vec<u8>,
            pub(crate) expected: FailureCode,
        }

        fn header_bytes(counter: u64) -> [u8; HEADER_LEN] {
            let mut header = [0u8; HEADER_LEN];
            header[0] = 1;
            header[1..17].copy_from_slice(Uuid::from_u128(CONNECTION).as_bytes());
            header[17..25].copy_from_slice(&counter.to_be_bytes());
            header
        }

        fn declared(length: u32, body: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(4 + body.len());
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(body);
            out
        }

        /// A well-formed envelope carrying a garbage body, so the case reaches the
        /// version, connection, counter, and AEAD branches rather than stopping at
        /// the length prefix.
        fn minimal_body(counter: u64, index: usize) -> Vec<u8> {
            let mut body = header_bytes(counter).to_vec();
            body.extend((0..TAG_LEN).map(|at| (index.wrapping_add(at) & 0xff) as u8));
            body
        }

        /// The corpus is a deterministic function of the case index, so a failing
        /// case is reproducible by index alone. Every family drives a different
        /// branch of the production parser.
        fn malformed_case(index: usize) -> MalformedCase {
            match index % SHAPE_FAMILIES {
                0 => {
                    let length = match index % 32 {
                        0 => u32::MAX,
                        8 => MAX_FRAME_BYTES as u32 + 1,
                        16 => 0x7fff_ffff,
                        _ => (index as u32) | 0x8000_0000,
                    };
                    MalformedCase {
                        family: "declared-past-the-frame-maximum",
                        bytes: declared(length, &[0xff, 0x00, 0xff, 0x00]),
                        expected: FailureCode::ResourceLimit,
                    }
                }
                1 => MalformedCase {
                    family: "declared-below-header-plus-tag",
                    bytes: declared((index % MIN_FRAME_BODY) as u32, &[0xff, 0x00, 0xff, 0x00]),
                    expected: FailureCode::MalformedInput,
                },
                2 => {
                    let body = minimal_body(0, index);
                    let skew = if index % 2 == 0 { 1 } else { -1i32 };
                    MalformedCase {
                        family: "declared-disagrees-with-the-body",
                        bytes: declared((body.len() as i32 + skew) as u32, &body),
                        expected: FailureCode::MalformedInput,
                    }
                }
                3 => MalformedCase {
                    family: "shorter-than-a-length-prefix",
                    bytes: vec![0xff; index % 4],
                    expected: FailureCode::MalformedInput,
                },
                4 => {
                    let mut body = minimal_body(0, index);
                    body[0] = if index % 2 == 0 { 2 } else { 0xff };
                    MalformedCase {
                        family: "unsupported-frame-version",
                        bytes: declared(body.len() as u32, &body),
                        expected: FailureCode::MalformedInput,
                    }
                }
                5 => {
                    let mut body = minimal_body(0, index);
                    body[1 + (index % 16)] ^= 1;
                    MalformedCase {
                        family: "foreign-connection-id",
                        bytes: declared(body.len() as u32, &body),
                        expected: FailureCode::MalformedInput,
                    }
                }
                6 => {
                    let body = minimal_body(1 + (index as u64 % 4096), index);
                    MalformedCase {
                        family: "counter-ahead-of-the-receiver",
                        bytes: declared(body.len() as u32, &body),
                        expected: FailureCode::CounterMismatch,
                    }
                }
                _ => {
                    let body = minimal_body(0, index);
                    MalformedCase {
                        family: "unauthenticated-ciphertext",
                        bytes: declared(body.len() as u32, &body),
                        expected: FailureCode::CryptographicFailure,
                    }
                }
            }
        }

        pub(crate) fn malformed_corpus_cases() -> impl Iterator<Item = MalformedCase> {
            (0..MALFORMED_CASE_COUNT).map(malformed_case)
        }

        fn forbidden(value: &str) -> bool {
            [
                "private",
                "secret",
                "credential",
                "password",
                "cookie",
                "token",
                "authorization",
                "pkcs8",
                "payload",
                "https://",
                "http://",
                "object_id",
                "artifact_id",
                "stream_id",
            ]
            .iter()
            .any(|word| value.to_ascii_lowercase().contains(word))
        }

        /// Seal `payload` from the client side without honouring the declared per-shape
        /// bound, then hand it to the daemon. This is the only way a non-conforming peer's
        /// oversize payload reaches the receiving bound check.
        fn oversize_from_peer(kind: PayloadKind, payload: Vec<u8>) -> SecurityFailure {
            let (mut client, mut daemon) = establish_pair(EPOCH);
            let mut sink = RecordingSink::default();
            let frame = match client.seal_unbounded(kind, &payload) {
                Ok(frame) => frame,
                // Past the v1 plaintext limit no frame exists at all: the sender rejects it.
                Err(failure) => return failure,
            };
            let failure = daemon
                .receive(&frame, &owned_operation(kind), &mut sink)
                .expect_err("payload past the declared bound");
            assert_eq!(
                daemon.receive_counter(),
                0,
                "rejected frames never dispatch"
            );
            assert!(!daemon.is_open());
            failure
        }

        /// A fresh daemon session per case. A rejected frame closes the channel, so
        /// reusing one session would answer every later case with
        /// `authentication.failed` and never reach the parser again. The handshake
        /// is not repeated 100,000 times: the session is assembled straight from
        /// traffic keys, which is the same `ChannelState` a handshake produces.
        fn parser_session(principal: &crate::Principal) -> crate::ChannelSession {
            crate::channel::vector_daemon_session(
                ConnectionId::new(Uuid::from_u128(CONNECTION)),
                principal.clone(),
                3,
                [0x11; 32],
                [0x22; 32],
            )
            .expect("a daemon session on fixed traffic keys")
        }

        fn corpus_principal() -> crate::Principal {
            fixture_principal(RingSigner::generate().public_key().clone(), EPOCH)
        }

        #[test]
        fn malformed_corpus_is_deterministic_and_covers_every_parser_branch() {
            let cases: Vec<_> = malformed_corpus_cases().collect();
            assert_eq!(cases.len(), MALFORMED_CASE_COUNT);
            let mut families: std::collections::BTreeMap<&str, usize> = Default::default();
            for (index, case) in cases.iter().enumerate() {
                *families.entry(case.family).or_default() += 1;
                assert_eq!(
                    case.bytes,
                    malformed_case(index).bytes,
                    "case {index} is not a function of its index"
                );
            }
            assert_eq!(
                families.len(),
                SHAPE_FAMILIES,
                "every parser branch has a family: {families:?}"
            );
            for (family, count) in &families {
                assert_eq!(
                    *count,
                    MALFORMED_CASE_COUNT / SHAPE_FAMILIES,
                    "{family} is unevenly weighted"
                );
            }
            // Every expected code is one the production parser actually returns.
            for case in &cases {
                assert!(
                    matches!(
                        case.expected,
                        FailureCode::MalformedInput
                            | FailureCode::ResourceLimit
                            | FailureCode::CounterMismatch
                            | FailureCode::CryptographicFailure
                    ),
                    "{} declares {:?}",
                    case.family,
                    case.expected
                );
            }
        }

        #[test]
        fn preallocation_rejection_preserves_bounds_and_channel_state() {
            assert_eq!(
                oversize_from_peer(
                    PayloadKind::StreamChunk,
                    vec![0u8; PayloadKind::StreamChunk.max_bytes() + 1]
                )
                .code(),
                FailureCode::ResourceLimit
            );
            assert_eq!(
                AuthorizedOutput::filtered(
                    PayloadKind::StreamChunk,
                    vec![0u8; PayloadKind::StreamChunk.max_bytes() + 1],
                )
                .expect_err("oversized output")
                .code(),
                FailureCode::ResourceLimit
            );
        }

        /// SC-007: a forged length prefix is refused before any allocation.
        ///
        /// The observable is that the call returns at all. Each case hands the
        /// parser a frame of a few dozen bytes whose prefix declares up to four
        /// gigabytes; an implementation that sized a buffer from the declaration
        /// before validating it would abort instead of answering `resource_limit`.
        #[test]
        fn a_forged_length_prefix_rejects_before_allocating_what_it_declares() {
            let principal = corpus_principal();
            let operation = owned_operation(PayloadKind::Command);
            for (declared_length, expected) in [
                (u32::MAX, FailureCode::ResourceLimit),
                (MAX_FRAME_BYTES as u32 + 1, FailureCode::ResourceLimit),
                // Exactly at the maximum the length is permitted, so the frame is
                // refused for disagreeing with its body rather than for its size,
                // and the megabyte it claims is still never allocated.
                (MAX_FRAME_BYTES as u32, FailureCode::MalformedInput),
                (MIN_FRAME_BODY as u32 - 1, FailureCode::MalformedInput),
            ] {
                let body = minimal_body(0, 0);
                let frame = declared(declared_length, &body);
                assert!(frame.len() < 64, "the probe stays tiny: {}", frame.len());
                let mut session = parser_session(&principal);
                let mut sink = RecordingSink::default();
                let failure = session
                    .receive(&frame, &operation, &mut sink)
                    .expect_err("a forged length prefix is never honoured");
                assert_eq!(failure.code(), expected, "declared {declared_length}");
                assert!(!session.is_open());
                assert_eq!(session.receive_counter(), 0);
            }
        }

        /// SC-007: 100,000 bounded malformed and oversized inputs through the
        /// production frame parser (`ChannelState::open`, reached by
        /// `ChannelSession::receive`). No case dispatches a payload, advances a
        /// counter, leaves the channel open, or renders secret material.
        #[test]
        fn malformed_corpus_drives_the_production_parser_with_zero_dispatch() {
            let started = std::time::Instant::now();
            let principal = corpus_principal();
            let expected_principal = principal.id();
            let connection = Uuid::from_u128(CONNECTION);
            let operation = owned_operation(PayloadKind::Command);
            let mut counts: std::collections::HashMap<FailureCode, usize> = Default::default();

            for (index, case) in malformed_corpus_cases().enumerate() {
                let mut session = parser_session(&principal);
                let mut sink = RecordingSink::default();
                let failure = match session.receive(&case.bytes, &operation, &mut sink) {
                    Ok(_) => {
                        panic!("case {index} ({}) dispatched a payload", case.family);
                    }
                    Err(failure) => failure,
                };
                assert_eq!(
                    failure.code(),
                    case.expected,
                    "case {index} ({})",
                    case.family
                );
                *counts.entry(failure.code()).or_default() += 1;

                // Fail closed, and leave the session exactly where it was.
                assert!(!session.is_open(), "case {index} left the channel open");
                assert_eq!(session.receive_counter(), 0, "case {index} advanced");
                assert_eq!(
                    session.send_counter(),
                    0,
                    "case {index} advanced the sender"
                );

                // One bounded, redacted event per rejection.
                assert_eq!(sink.events.len(), 1, "case {index} event count");
                let event = &sink.events[0];
                assert_eq!(event.boundary, EventBoundary::Channel);
                assert_eq!(event.outcome, EventOutcome::Rejected);
                assert_eq!(event.principal_id, Some(expected_principal.get()));
                assert_eq!(event.connection_id, Some(connection));
                assert!(event.metadata().is_empty(), "case {index} carried metadata");
                assert!(event.encoded_len() <= 2_048, "case {index} event size");
                assert!(
                    !forbidden(&format!("{failure} {event:?}")),
                    "case {index} rendered forbidden content"
                );
            }

            let per_family = MALFORMED_CASE_COUNT / SHAPE_FAMILIES;
            assert_eq!(counts[&FailureCode::ResourceLimit], per_family);
            assert_eq!(counts[&FailureCode::CounterMismatch], per_family);
            assert_eq!(counts[&FailureCode::CryptographicFailure], per_family);
            assert_eq!(counts[&FailureCode::MalformedInput], per_family * 5);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(300),
                "the campaign must stay a test, not a benchmark: {:?}",
                started.elapsed()
            );
        }

        #[test]
        fn exact_and_one_over_payload_bounds_reject_without_mutating_session() {
            for kind in [
                PayloadKind::Command,
                PayloadKind::Response,
                PayloadKind::Event,
                PayloadKind::StreamChunk,
            ] {
                assert!(AuthorizedOutput::filtered(kind, vec![]).is_ok());
                assert!(AuthorizedOutput::filtered(kind, vec![0; kind.max_bytes()]).is_ok());
                let input = oversize_from_peer(kind, vec![0; kind.max_bytes() + 1]);
                let output = AuthorizedOutput::filtered(kind, vec![0; kind.max_bytes() + 1])
                    .expect_err("one-over output bound");
                for failure in [input, output] {
                    assert_eq!(failure.code(), FailureCode::ResourceLimit);
                    assert_eq!(failure.boundary().as_str(), "resource-limit");
                    assert_eq!(
                        failure.safe_next_action().as_str(),
                        "reduce-to-declared-bound"
                    );
                }
            }
        }

        #[test]
        fn malformed_fields_encodings_and_redaction_are_bounded() {
            // The two shapes this used to assert against a local helper, now put
            // to the production parser: a body that disagrees with its prefix, and
            // a prefix that declares more than the body carries.
            let principal = corpus_principal();
            let operation = owned_operation(PayloadKind::Command);
            for (frame, expected) in [
                (vec![0, 0, 0, 1, 0xff], FailureCode::MalformedInput),
                (vec![0, 0, 0, 9, b'a'], FailureCode::MalformedInput),
            ] {
                let mut session = parser_session(&principal);
                let mut sink = RecordingSink::default();
                assert_eq!(
                    session
                        .receive(&frame, &operation, &mut sink)
                        .expect_err("a frame below one header plus one tag")
                        .code(),
                    expected
                );
                assert!(!session.is_open());
            }

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
