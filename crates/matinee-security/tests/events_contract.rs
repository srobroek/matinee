macro_rules! events_contract_tests {
    () => {
        use crate::events;
        use crate::test_support_fakes::FakeEventSink;
        use uuid::Uuid;

        fn event(code: events::SecurityCode) -> events::SecurityEvent {
            events::SecurityEvent::new(
                Uuid::from_u128(1),
                events::EventBoundary::Authentication,
                code,
                events::EventOutcome::Rejected,
                events::SafeNextAction::FailClosed,
                None,
                None,
                events::EndpointClass::Loopback,
                events::EventTime(7),
                Uuid::from_u128(2),
                vec![],
            )
            .expect("valid event fixture")
        }

        #[test]
        fn every_cross_story_security_code_is_constructible_and_sink_emits_it() {
            let codes = [
                events::SecurityCode::EnrollmentAccepted,
                events::SecurityCode::AuthorizationAccepted,
                events::SecurityCode::ProofRejected,
                events::SecurityCode::OriginRejected,
                events::SecurityCode::AuthenticationFailed,
                events::SecurityCode::AuthorizationDenied,
                events::SecurityCode::Rotation,
                events::SecurityCode::Revocation,
                events::SecurityCode::ReplayDetected,
                events::SecurityCode::Downgrade,
                events::SecurityCode::CounterRejected,
                events::SecurityCode::CryptographicFailure,
                events::SecurityCode::MalformedInput,
                events::SecurityCode::ResourceLimit,
                events::SecurityCode::RateLimited,
                events::SecurityCode::EventSinkUnavailable,
            ];
            let mut sink = FakeEventSink::accepted();
            for code in codes {
                assert_eq!(
                    events::emit_required(Some(&mut sink), event(code)),
                    Ok(events::SecurityEventSinkResult::Accepted)
                );
            }
            assert_eq!(sink.received().len(), 16);
        }

        #[test]
        fn authorization_success_tuple_is_explicit() {
            let event = events::SecurityEvent::new(
                Uuid::from_u128(1),
                events::EventBoundary::Authorization,
                events::SecurityCode::AuthorizationAccepted,
                events::EventOutcome::Accepted,
                events::SafeNextAction::Continue,
                Some(Uuid::from_u128(3)),
                Some(Uuid::from_u128(4)),
                events::EndpointClass::Loopback,
                events::EventTime(7),
                Uuid::from_u128(2),
                vec![events::MetadataEntry {
                    key: "reason".into(),
                    value: "accepted".into(),
                }],
            )
            .expect("valid authorization success event");
            let mut sink = FakeEventSink::accepted();
            assert_eq!(
                events::emit_required(Some(&mut sink), event),
                Ok(events::SecurityEventSinkResult::Accepted)
            );
            assert_eq!(
                sink.received()[0].boundary,
                events::EventBoundary::Authorization
            );
            assert_eq!(
                sink.received()[0].code,
                events::SecurityCode::AuthorizationAccepted
            );
            assert_eq!(sink.received()[0].outcome, events::EventOutcome::Accepted);
            assert_eq!(
                sink.received()[0].next_action,
                events::SafeNextAction::Continue
            );
        }
        #[test]
        fn event_and_metadata_bounds_accept_edges_and_reject_overflows() {
            let metadata = (0..8)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i:0>31}"),
                    value: "v".repeat(32),
                })
                .collect();
            let bounded = events::SecurityEvent::new(
                Uuid::nil(),
                events::EventBoundary::Bootstrap,
                events::SecurityCode::EnrollmentAccepted,
                events::EventOutcome::Accepted,
                events::SafeNextAction::Retry,
                Some(Uuid::from_u128(3)),
                Some(Uuid::from_u128(4)),
                events::EndpointClass::Native,
                events::EventTime(0),
                Uuid::nil(),
                metadata,
            )
            .expect("512 metadata bytes are accepted");
            assert_eq!(bounded.metadata().len(), 8);
            assert_eq!(bounded.metadata().iter().map(|m| m.key.len() + m.value.len()).sum::<usize>(), 512);
            assert!(bounded.encoded_len() <= 2_048);

            let too_many = (0..9)
                .map(|i| events::MetadataEntry { key: format!("k{i}"), value: "v".into() })
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(), events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted, events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry, None, None, events::EndpointClass::Native,
                    events::EventTime(0), Uuid::nil(), too_many,
                ),
                Err(events::EventBuildError::TooManyMetadata)
            );

            let metadata_over = (0..7)
                .map(|i| events::MetadataEntry { key: format!("k{i:0>31}"), value: "v".repeat(32) })
                .chain(std::iter::once(events::MetadataEntry { key: "k".repeat(32), value: "v".repeat(33) }))
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(), events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted, events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry, None, None, events::EndpointClass::Native,
                    events::EventTime(0), Uuid::nil(), metadata_over,
                ),
                Err(events::EventBuildError::MetadataTooLarge)
            );

            let base = |entry| events::SecurityEvent::new(
                Uuid::nil(), events::EventBoundary::Bootstrap,
                events::SecurityCode::EnrollmentAccepted, events::EventOutcome::Accepted,
                events::SafeNextAction::Retry, None, None, events::EndpointClass::Native,
                events::EventTime(0), Uuid::nil(), vec![entry],
            );
            assert_eq!(base(events::MetadataEntry { key: "k".repeat(33), value: "v".into() }), Err(events::EventBuildError::MetadataKeyTooLong));
            assert_eq!(base(events::MetadataEntry { key: "k".into(), value: "v".repeat(129) }), Err(events::EventBuildError::MetadataValueTooLong));

            // Metadata is capped at 512 bytes, so the fixed event fields plus metadata
            // can never reach 2,048; EventTooLarge is mathematically unreachable.
            assert!(bounded.encoded_len() <= 16 + 1 + 1 + 1 + 1 + 1 + 8 + 16 + 1 + 16 + 16 + 512 + (8 * 4));
            assert!(bounded.encoded_len() < 2_048);
        }

        #[test]
        fn event_and_sink_failure_redaction_rejects_secret_vocabulary() {
            let words = [
                "private_key", "pkcs8", "enrollment_secret", "credential", "password",
                "cookie", "authorization_header", "payload_text", "https://host/path",
                "object_id", "artifact_id", "stream_id",
            ];
            for word in words {
                for (field, entry) in [
                    ("key", events::MetadataEntry { key: word.into(), value: "safe".into() }),
                    ("value", events::MetadataEntry { key: "reason".into(), value: word.into() }),
                ] {
                    let result = events::SecurityEvent::new(
                        Uuid::nil(), events::EventBoundary::Input,
                        events::SecurityCode::MalformedInput, events::EventOutcome::Rejected,
                        events::SafeNextAction::FailClosed, None, None,
                        events::EndpointClass::Unknown, events::EventTime(0), Uuid::nil(),
                        vec![entry],
                    );
                    assert_eq!(result, Err(events::EventBuildError::Redacted), "{field}: {word}");
                }
            }

            let mut sink = FakeEventSink::unavailable();
            assert_eq!(
                events::emit_required(Some(&mut sink), event(events::SecurityCode::EventSinkUnavailable)),
                Err(events::RequiredEventError::Unavailable)
            );
            let failure = &sink.received()[0];
            assert!(failure.metadata().is_empty());
            assert_eq!(failure.code, events::SecurityCode::EventSinkUnavailable);
        }

        #[test]
        fn aggregation_is_bounded_by_64_buckets_and_saturates_at_255() {
            use crate::events::SecurityEventSink;
            let make = |i: u128| events::SecurityEvent::new(
                Uuid::from_u128(i), events::EventBoundary::Authentication,
                events::SecurityCode::AuthenticationFailed, events::EventOutcome::Failed,
                events::SafeNextAction::FailClosed, Some(Uuid::from_u128(i)), None,
                events::EndpointClass::Loopback, events::EventTime(0), Uuid::nil(), vec![],
            ).unwrap();
            let repeated = make(1);
            let mut state = events::AggregationState::default();
            for _ in 0..255 { assert_eq!(state.emit(repeated.clone()), events::SecurityEventSinkResult::Aggregated); }
            assert_eq!(state.count_for(&repeated), Some(255));
            assert_eq!(state.emit(repeated.clone()), events::SecurityEventSinkResult::Aggregated);
            assert_eq!(state.count_for(&repeated), Some(255));

            for i in 2..=64 {
                assert_eq!(state.emit(make(i)), events::SecurityEventSinkResult::Aggregated);
            }
            assert_eq!(state.bucket_count(), 64);
            let before = state.bucket_count();
            let overflow = make(65);
            assert_eq!(state.emit(overflow.clone()), events::SecurityEventSinkResult::Unavailable);
            assert_eq!(state.bucket_count(), before, "overflow leaves aggregation unchanged");
            assert_eq!(state.count_for(&overflow), None);
        }

        fn guarded_increment(
            sink: Option<&mut FakeEventSink>,
            protected_state: &mut u8,
        ) -> Result<(), events::SecurityCode> {
            match events::emit_required(sink, event(events::SecurityCode::AuthenticationFailed)) {
                Ok(_) => {
                    *protected_state += 1;
                    Ok(())
                }
                Err(events::RequiredEventError::Unavailable) => {
                    Err(events::SecurityCode::EventSinkUnavailable)
                }
            }
        }

        #[test]
        fn required_sink_gates_mutation_and_projects_unavailable_failure() {
            let mut protected_state = 0u8;
            let mut accepted = FakeEventSink::accepted();
            assert_eq!(guarded_increment(Some(&mut accepted), &mut protected_state), Ok(()));
            assert_eq!(protected_state, 1);
            assert_eq!(accepted.received().len(), 1);

            let mut unavailable = FakeEventSink::unavailable();
            assert_eq!(
                guarded_increment(Some(&mut unavailable), &mut protected_state),
                Err(events::SecurityCode::EventSinkUnavailable)
            );
            assert_eq!(protected_state, 1);
            assert_eq!(unavailable.received().len(), 1);
        }
    };
}
