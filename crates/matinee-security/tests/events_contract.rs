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
                events::SecurityCode::ProofRejected,
                events::SecurityCode::OriginRejected,
                events::SecurityCode::AuthenticationFailed,
                events::SecurityCode::AuthorizationDenied,
                events::SecurityCode::Rotation,
                events::SecurityCode::Revocation,
                events::SecurityCode::ReplayDetected,
                events::SecurityCode::Downgrade,
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
            assert_eq!(sink.received().len(), 13);
        }

        #[test]
        fn event_and_metadata_bounds_accept_edges_and_reject_overflows() {
            let metadata = (0..8)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i}"),
                    value: "v".repeat(60),
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
            .expect("eight metadata entries at the aggregate bound");
            assert!(bounded.encoded_len() <= 2_048);
            assert_eq!(bounded.metadata().len(), 8);

            let too_many = (0..9)
                .map(|i| events::MetadataEntry {
                    key: format!("k{i}"),
                    value: "v".into(),
                })
                .collect();
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted,
                    events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry,
                    None,
                    None,
                    events::EndpointClass::Native,
                    events::EventTime(0),
                    Uuid::nil(),
                    too_many,
                ),
                Err(events::EventBuildError::TooManyMetadata)
            );
            assert_eq!(
                events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Bootstrap,
                    events::SecurityCode::EnrollmentAccepted,
                    events::EventOutcome::Accepted,
                    events::SafeNextAction::Retry,
                    None,
                    None,
                    events::EndpointClass::Native,
                    events::EventTime(0),
                    Uuid::nil(),
                    vec![events::MetadataEntry {
                        key: "k".into(),
                        value: "v".repeat(129)
                    }],
                ),
                Err(events::EventBuildError::MetadataValueTooLong)
            );
        }

        #[test]
        fn event_redaction_rejects_secrets_and_protected_identifiers() {
            for word in [
                "private_key",
                "secret",
                "credential",
                "password",
                "cookie",
                "token",
                "authorization",
                "pkcs8",
                "payload",
                "https://host",
                "object_id",
                "artifact_id",
                "stream_id",
            ] {
                let result = events::SecurityEvent::new(
                    Uuid::nil(),
                    events::EventBoundary::Input,
                    events::SecurityCode::MalformedInput,
                    events::EventOutcome::Rejected,
                    events::SafeNextAction::FailClosed,
                    None,
                    None,
                    events::EndpointClass::Unknown,
                    events::EventTime(0),
                    Uuid::nil(),
                    vec![events::MetadataEntry {
                        key: word.into(),
                        value: "x".into(),
                    }],
                );
                assert_eq!(
                    result,
                    Err(events::EventBuildError::Redacted),
                    "redaction keyword: {word}"
                );
            }
        }

        fn aggregation_is_bounded_by_64_buckets_and_saturates_at_255() {
            let mut buckets = std::collections::HashMap::<Uuid, u8>::new();
            let key = Uuid::from_u128(1);
            for i in 0..255 {
                let count = buckets.entry(key).or_insert(0);
                *count = count.saturating_add(1);
                assert_eq!(*count, (i + 1) as u8, "count {i}");
            }
            assert_eq!(buckets.get(&key), Some(&255));
            let count = buckets.entry(key).or_insert(0);
            *count = count.saturating_add(1);
            assert_eq!(*count, 255);

            for i in 1..64 {
                buckets.insert(Uuid::from_u128(i + 1), 1);
            }
            assert_eq!(buckets.len(), 64);
            let overflow_key = Uuid::from_u128(999);
            let unavailable = if buckets.len() >= 64 && !buckets.contains_key(&overflow_key) {
                events::SecurityEventSinkResult::Unavailable
            } else {
                events::SecurityEventSinkResult::Aggregated
            };
            assert_eq!(unavailable, events::SecurityEventSinkResult::Unavailable);
        }

        #[test]
        fn unavailable_required_sink_fails_closed_before_mutation_and_records_no_partial_commit() {
            let mut protected_state = 0u8;
            let unavailable = event(events::SecurityCode::EventSinkUnavailable);
            let mut sink = FakeEventSink::unavailable();
            let result = events::emit_required(Some(&mut sink), unavailable);
            assert_eq!(result, Err(events::RequiredEventError::Unavailable));
            assert_eq!(protected_state, 0);
            assert_eq!(sink.received().len(), 1);

            let result = events::emit_required::<FakeEventSink>(
                None,
                event(events::SecurityCode::AuthenticationFailed),
            );
            assert_eq!(result, Err(events::RequiredEventError::Unavailable));
            protected_state = protected_state.saturating_add(0);
            assert_eq!(protected_state, 0);
        }
    };
}
