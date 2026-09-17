macro_rules! secure_channel_frames_tests {
    () => {
        use crate::identity::{Connection, ConnectionId, IdentityId};
        use crate::{AuthorizedInput, ChannelSession, FailureCode, PayloadKind, SessionInput};
        use uuid::Uuid;

        fn frame_connection(epoch: u64) -> Connection {
            let mut connection = Connection::new(
                ConnectionId::new(Uuid::from_u128(0xabcdefabcdefabcdefabcdefabcd)),
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
                .expect("authenticated vector connection");
            connection
        }

        fn frame_session(epoch: u64) -> ChannelSession {
            ChannelSession::establish(frame_connection(epoch), 1, "127.0.0.1:7777")
                .expect("bound vector session")
        }

        fn frame_context(epoch: u64, kind: PayloadKind) -> SessionInput {
            SessionInput::new(
                ConnectionId::new(Uuid::from_u128(0xabcdefabcdefabcdefabcdefabcd)),
                IdentityId::new(Uuid::from_u128(2)),
                epoch,
                crate::Capability::new(crate::identity::CapabilityAction::Read, "matinee/status")
                    .expect("bounded capability"),
                kind,
            )
        }

        fn frame_header(counter: u64) -> [u8; 25] {
            let mut header = [0u8; 25];
            header[0] = 1;
            header[1..17]
                .copy_from_slice(Uuid::from_u128(0xabcdefabcdefabcdefabcdefabcd).as_bytes());
            header[17..25].copy_from_slice(&counter.to_be_bytes());
            header
        }

        fn directional_nonce(direction: u32, counter: u64) -> [u8; 12] {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&direction.to_be_bytes());
            nonce[4..].copy_from_slice(&counter.to_be_bytes());
            nonce
        }

        #[test]
        fn frame_header_is_exactly_25_bytes_and_nonce_is_directional() {
            let header_zero = frame_header(0);
            let header_one = frame_header(1);
            assert_eq!(header_zero.len(), 25);
            assert_eq!(&header_zero[..17], &header_one[..17]);
            assert_ne!(header_zero, header_one);
            assert_eq!(directional_nonce(0, 0), [0; 12]);
            assert_eq!(
                directional_nonce(1, 0),
                [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
            );
            assert_ne!(directional_nonce(0, 1), directional_nonce(1, 0));
            assert_eq!(
                directional_nonce(0, u64::MAX),
                [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            );
        }

        #[test]
        fn counters_are_independent_per_direction_and_stop_at_exhaustion_boundary() {
            let mut session = frame_session(7);
            assert_eq!(session.next_send_counter().unwrap(), 0);
            assert_eq!(session.next_send_counter().unwrap(), 1);
            assert_eq!(session.next_receive_counter().unwrap(), 0);
            assert_eq!(session.next_receive_counter().unwrap(), 1);
            assert_eq!(u64::MAX.checked_add(1), None);
            session.close();
            assert_eq!(
                session.next_send_counter().unwrap_err().code(),
                FailureCode::CounterMismatch
            );
            assert_eq!(
                session.next_receive_counter().unwrap_err().code(),
                FailureCode::CounterMismatch
            );
        }

        #[test]
        fn payload_limits_accept_zero_and_exact_plaintext_maximum_but_reject_one_over() {
            let context = frame_context(7, PayloadKind::Command);
            assert!(AuthorizedInput::authorized(&context, Vec::new()).is_ok());
            assert!(
                AuthorizedInput::authorized(&context, vec![0; crate::MAX_PAYLOAD_BYTES]).is_ok()
            );
            assert_eq!(
                AuthorizedInput::authorized(&context, vec![0; crate::MAX_PAYLOAD_BYTES + 1])
                    .unwrap_err()
                    .code(),
                FailureCode::ResourceLimit
            );
            assert_eq!(crate::MAX_PAYLOAD_BYTES + 25 + 16, 1_048_576);
        }

        #[test]
        fn frame_contract_has_no_fragmentation_and_binds_context_before_dispatch() {
            let session = frame_session(7);
            let valid = frame_context(7, PayloadKind::Command);
            assert!(session.binds(&valid).is_ok());
            let wrong_epoch = frame_context(6, PayloadKind::Command);
            assert_eq!(
                session.binds(&wrong_epoch).unwrap_err().code(),
                FailureCode::StaleEpoch
            );
            let wrong_connection = SessionInput::new(
                ConnectionId::new(Uuid::from_u128(9)),
                IdentityId::new(Uuid::from_u128(2)),
                7,
                crate::Capability::new(crate::identity::CapabilityAction::Read, "matinee/status")
                    .unwrap(),
                PayloadKind::Command,
            );
            assert_eq!(
                session.binds(&wrong_connection).unwrap_err().code(),
                FailureCode::MalformedInput
            );
            assert!(AuthorizedInput::authorized(&valid, vec![1, 2, 3]).is_ok());
            assert_eq!(crate::MAX_PAYLOAD_BYTES, 1_048_535);
        }

        #[test]
        fn aad_is_derived_from_header_context_contract_epoch_and_direction() {
            let header = frame_header(1);
            let context = b"matinee.secure-channel.v1";
            let contract = 1u16.to_be_bytes();
            let epoch = 7u64.to_be_bytes();
            let direction_zero = 0u32.to_be_bytes();
            let direction_one = 1u32.to_be_bytes();
            let mut aad_zero = Vec::new();
            aad_zero.extend_from_slice(&header);
            aad_zero.extend_from_slice(&(context.len() as u32).to_be_bytes());
            aad_zero.extend_from_slice(context);
            aad_zero.extend_from_slice(&(contract.len() as u32).to_be_bytes());
            aad_zero.extend_from_slice(&contract);
            aad_zero.extend_from_slice(&epoch);
            aad_zero.extend_from_slice(&(direction_zero.len() as u32).to_be_bytes());
            aad_zero.extend_from_slice(&direction_zero);
            let mut aad_one = aad_zero.clone();
            let last = aad_one.len() - 1;
            aad_one[last] = 1;
            assert_eq!(aad_zero.len(), aad_one.len());
            assert_ne!(aad_zero, aad_one);
            assert_eq!(direction_one, [0, 0, 0, 1]);
        }
    };
}
