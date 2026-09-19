#[allow(unused_macros)]
macro_rules! secure_channel_frames_tests {
    () => {
        use crate::test_support_channel::{
            CONNECTION, RecordingSink, establish_pair, owned_operation, owned_projection,
        };
        use crate::{AuthorizedOutput, FailureCode, PayloadKind, ProjectionClass, SecurityCode};
        use uuid::Uuid;

        #[test]
        fn production_frame_has_length_prefix_and_exact_authenticated_header() {
            let (mut client, mut daemon) = establish_pair(7);
            let output =
                AuthorizedOutput::filtered(PayloadKind::Command, b"payload".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let frame = client.send(&output, &mut sink).unwrap();
            let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(declared, frame.len() - 4);
            assert_eq!(frame[4], 1);
            assert_eq!(&frame[5..21], Uuid::from_u128(CONNECTION).as_bytes());
            assert_eq!(u64::from_be_bytes(frame[21..29].try_into().unwrap()), 0);
            let input = daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            assert_eq!(input.payload(), b"payload");
        }

        #[test]
        fn directional_counters_start_at_zero_and_are_independent() {
            let (mut client, mut daemon) = establish_pair(7);
            let output = AuthorizedOutput::filtered(PayloadKind::Command, b"x".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let c0 = client.send(&output, &mut sink).unwrap();
            let c1 = client.send(&output, &mut sink).unwrap();
            let d0 = daemon
                .send_projection(
                    &owned_projection(ProjectionClass::Response, b"x"),
                    &mut sink,
                )
                .unwrap();
            assert_eq!(u64::from_be_bytes(c0[21..29].try_into().unwrap()), 0);
            assert_eq!(u64::from_be_bytes(c1[21..29].try_into().unwrap()), 1);
            assert_eq!(u64::from_be_bytes(d0[21..29].try_into().unwrap()), 0);
            daemon
                .receive(&c0, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            daemon
                .receive(&c1, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            client
                .receive_filtered(&d0, PayloadKind::Response, &mut sink)
                .unwrap();
        }

        #[test]
        fn one_mib_frame_and_plaintext_bound_are_exact_without_fragmentation() {
            let (mut client, mut daemon) = establish_pair(7);
            let payload = vec![0x5a; 1_048_534];
            let output = AuthorizedOutput::filtered(PayloadKind::Command, payload.clone()).unwrap();
            let mut sink = RecordingSink::default();
            let frame = client.send(&output, &mut sink).unwrap();
            assert_eq!(frame.len(), 4 + 1_048_576);
            let input = daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            assert_eq!(input.payload(), payload);
            assert_eq!(
                AuthorizedOutput::filtered(PayloadKind::Command, vec![0; 1_048_535])
                    .unwrap_err()
                    .code(),
                FailureCode::ResourceLimit
            );
        }

        #[test]
        fn declared_length_is_checked_before_ciphertext_allocation() {
            let (mut client, mut daemon) = establish_pair(7);
            let output = AuthorizedOutput::filtered(PayloadKind::Command, b"x".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let mut frame = client.send(&output, &mut sink).unwrap();
            frame[..4].copy_from_slice(&(1_048_577u32).to_be_bytes());
            let failure = daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .expect_err("oversized declared frame");
            assert_eq!(failure.code(), FailureCode::ResourceLimit);
            assert!(!daemon.is_open());
            assert_eq!(
                sink.events.last().unwrap().code(),
                SecurityCode::ResourceLimit
            );
        }

        #[test]
        fn maximum_counter_is_accepted_once_then_exhausts_without_wrap() {
            let (mut client, mut daemon) = establish_pair(7);
            client.set_counters(u64::MAX, 0);
            daemon.set_counters(0, u64::MAX);
            let output =
                AuthorizedOutput::filtered(PayloadKind::Command, b"last".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let frame = client.send(&output, &mut sink).unwrap();
            assert_eq!(
                u64::from_be_bytes(frame[21..29].try_into().unwrap()),
                u64::MAX
            );
            daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .unwrap();
            let failure = client
                .send(&output, &mut sink)
                .expect_err("counter exhausted");
            assert_eq!(failure.code(), FailureCode::CounterMismatch);
            assert!(!client.is_open());
        }

        #[test]
        fn failure_event_outage_closes_and_returns_sink_failure() {
            let (mut client, mut daemon) = establish_pair(7);
            let output = AuthorizedOutput::filtered(PayloadKind::Command, b"x".to_vec()).unwrap();
            let mut accepting = RecordingSink::default();
            let mut frame = client.send(&output, &mut accepting).unwrap();
            *frame.last_mut().unwrap() ^= 1;
            let mut unavailable = RecordingSink {
                events: vec![],
                unavailable: true,
            };
            let failure = daemon
                .receive(
                    &frame,
                    &owned_operation(PayloadKind::Command),
                    &mut unavailable,
                )
                .expect_err("required failure event unavailable");
            assert_eq!(failure.code(), FailureCode::EventSinkUnavailable);
            assert!(!daemon.is_open());
        }

        #[test]
        fn typed_payload_failure_emits_before_receive_counter_mutation() {
            let (mut client, mut daemon) = establish_pair(7);
            let output = AuthorizedOutput::filtered(PayloadKind::Event, b"x".to_vec()).unwrap();
            let mut sink = RecordingSink::default();
            let frame = client.send(&output, &mut sink).unwrap();
            let failure = daemon
                .receive(&frame, &owned_operation(PayloadKind::Command), &mut sink)
                .expect_err("wire payload kind differs from authorized shape");
            assert_eq!(failure.code(), FailureCode::MalformedInput);
            assert_eq!(sink.events.len(), 1);
            assert_eq!(daemon.receive_counter(), 0);
            assert!(!daemon.is_open());
        }
    };
}
