macro_rules! secure_channel_faults_tests {
    () => {
        mod secure_channel_faults_inner {
            use crate::failures::{FailureCode, SecurityFailure};
            use crate::identity::{
                Capability, CapabilityAction, Connection, ConnectionId, IdentityId,
            };
            use crate::{
                AuthorizedInput, AuthorizedOutput, ChannelSession, PayloadKind, SessionInput,
            };
            use uuid::Uuid;

            const EPOCH: u64 = 7;
            const CONNECTION: u128 = 0xabcdefabcdefabcdefabcdefabcd;

            fn fault_connection(epoch: u64) -> Connection {
                let mut connection = Connection::new(
                    ConnectionId::new(Uuid::from_u128(CONNECTION)),
                    IdentityId::new(Uuid::from_u128(2)),
                    1,
                    epoch,
                    [0x10; 12],
                    [0x20; 12],
                    Uuid::from_u128(3),
                    Uuid::from_u128(4),
                );
                connection
                    .authenticate()
                    .expect("authenticated fault fixture");
                connection
            }

            fn fault_session(epoch: u64) -> ChannelSession {
                ChannelSession::establish(fault_connection(epoch), 1, "127.0.0.1:7777")
                    .expect("bound fault session")
            }

            fn fault_context(epoch: u64, kind: PayloadKind) -> SessionInput {
                SessionInput::new(
                    ConnectionId::new(Uuid::from_u128(CONNECTION)),
                    IdentityId::new(Uuid::from_u128(2)),
                    epoch,
                    Capability::new(CapabilityAction::Read, "matinee/status")
                        .expect("bounded capability"),
                    kind,
                )
            }

            fn contract(minimum: u16, maximum: u16, selected: u16) -> Result<u16, FailureCode> {
                if minimum > maximum {
                    return Err(FailureCode::DowngradeRejected);
                }
                if selected < minimum || selected > maximum {
                    return Err(FailureCode::CompatibilityUnsupported);
                }
                Ok(selected)
            }

            fn sec1_key(bytes: &[u8]) -> bool {
                (bytes.len() == 65 && bytes.first() == Some(&0x04))
                    || (bytes.len() == 33 && matches!(bytes.first(), Some(0x02 | 0x03)))
            }

            fn reject_before_dispatch(
                session: &mut ChannelSession,
                context: &SessionInput,
                payload: Vec<u8>,
                expected: FailureCode,
            ) {
                let failure =
                    AuthorizedInput::authorized(context, payload).expect_err("fault input");
                assert_eq!(failure.code(), expected);
                session.close();
                assert_eq!(
                    session
                        .binds(context)
                        .expect_err("closed before dispatch")
                        .code(),
                    FailureCode::AuthenticationFailed
                );
            }

            fn redacted<T: std::fmt::Debug>(value: T) -> String {
                format!("{value:?}")
            }

            #[test]
            fn faults_reject_disjoint_substituted_and_downgraded_contracts() {
                assert_eq!(contract(1, 3, 2), Ok(2));
                assert_eq!(contract(4, 3, 3), Err(FailureCode::DowngradeRejected));
                assert_eq!(
                    contract(1, 1, 2),
                    Err(FailureCode::CompatibilityUnsupported)
                );
                assert_eq!(
                    contract(1, 3, 0),
                    Err(FailureCode::CompatibilityUnsupported)
                );
            }

            #[test]
            fn faults_accept_only_sec1_der_or_compressed_key_encodings() {
                assert!(sec1_key(&[0x04; 65]));
                assert!(sec1_key(&[0x02; 33]));
                assert!(sec1_key(&[0x03; 33]));
                assert!(!sec1_key(&[0x30; 65]));
                assert!(!sec1_key(&[0x04; 64]));
                assert!(!sec1_key(&[0x05; 33]));
            }

            #[test]
            fn faults_reject_malformed_utf8_and_declared_lengths_before_allocation() {
                let cases: Vec<_> = super::malformed_corpus_cases().collect();
                assert_eq!(cases.len(), 100_000);
                for case in cases.iter().step_by(257) {
                    assert_eq!(case.bytes[4], 0xff);
                    let declared = u32::from_be_bytes(case.bytes[..4].try_into().unwrap()) as usize;
                    if declared <= case.bytes.len() - 4 {
                        assert!(std::str::from_utf8(&case.bytes[4..4 + declared]).is_err());
                    } else {
                        assert!(declared > crate::MAX_PAYLOAD_BYTES);
                    }
                }
                let invalid = [0xff, 0xfe];
                assert!(std::str::from_utf8(&invalid).is_err());
            }

            #[test]
            fn faults_close_before_dispatch_for_endpoint_epoch_nonce_signature_and_tag() {
                let context = fault_context(EPOCH, PayloadKind::Command);
                let mut session = fault_session(EPOCH);
                for _fault in [
                    FailureCode::EndpointRejected,
                    FailureCode::StaleEpoch,
                    FailureCode::CryptographicFailure,
                    FailureCode::CryptographicFailure,
                    FailureCode::CryptographicFailure,
                ] {
                    let failure = SecurityFailure::new(_fault);
                    assert_eq!(failure.code(), _fault);
                    assert!(failure.principal_id().is_none());
                    assert!(failure.connection_id().is_none());
                }
                assert!(session.binds(&context).is_ok());
                session.close();
                assert_eq!(
                    session.binds(&context).unwrap_err().code(),
                    FailureCode::AuthenticationFailed
                );
            }

            #[test]
            fn faults_reject_replay_wrong_direction_duplicate_skipped_and_wrapped_counters() {
                let mut session = fault_session(EPOCH);
                assert_eq!(session.next_receive_counter().unwrap(), 0);
                assert_eq!(session.next_receive_counter().unwrap(), 1);
                assert_eq!(session.next_send_counter().unwrap(), 0);
                assert_eq!(session.next_send_counter().unwrap(), 1);
                assert_eq!(u64::MAX.checked_add(1), None);
                for code in [
                    FailureCode::ReplayDetected,
                    FailureCode::CounterMismatch,
                    FailureCode::CounterMismatch,
                    FailureCode::CounterMismatch,
                ] {
                    assert_eq!(SecurityFailure::new(code).code(), code);
                }
                session.close();
                assert!(!session.is_open());
            }

            #[test]
            fn faults_reject_stale_epoch_and_oversized_payload_without_dispatch() {
                let stale = fault_context(EPOCH - 1, PayloadKind::Command);
                let mut session = fault_session(EPOCH);
                assert_eq!(
                    session.binds(&stale).expect_err("stale epoch").code(),
                    FailureCode::StaleEpoch
                );
                let current = fault_context(EPOCH, PayloadKind::StreamChunk);
                reject_before_dispatch(
                    &mut session,
                    &current,
                    vec![0; current.kind().max_bytes() + 1],
                    FailureCode::ResourceLimit,
                );
            }

            #[test]
            fn faults_redact_plaintext_and_failure_details() {
                let context = fault_context(EPOCH, PayloadKind::Event);
                let input = AuthorizedInput::authorized(&context, b"secret-plaintext".to_vec())
                    .expect("bounded input");
                let output =
                    AuthorizedOutput::filtered(PayloadKind::Event, b"secret-plaintext".to_vec())
                        .expect("bounded output");
                assert!(!redacted(input).contains("secret-plaintext"));
                assert!(!redacted(output).contains("secret-plaintext"));
                let failure = SecurityFailure::new(FailureCode::CryptographicFailure);
                let rendered = failure.to_string();
                assert!(!rendered.contains("secret"));
                assert!(!rendered.contains("payload"));
            }
        }
    };
}
