macro_rules! authorization_privacy_tests {
    () => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum ObjectClass {
            Object,
            Event,
            Status,
            Artifact,
            Stream,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct PrivateObject {
            id: u64,
            owner: u64,
            class: ObjectClass,
            secret: String,
            mutated: bool,
        }

        struct PrivacyStore {
            objects: Vec<PrivateObject>,
            trace: Vec<&'static str>,
        }

        #[derive(Clone, Copy)]
        struct ReadRequest {
            principal: u64,
            object: u64,
            class: ObjectClass,
            authorized: bool,
        }

        #[derive(Debug, Eq, PartialEq)]
        enum PrivacyResponse {
            NotFound(&'static str),
            Authorized(String),
            Denied(crate::failures::FailureCode),
        }

        impl PrivacyStore {
            fn new() -> Self {
                Self {
                    objects: vec![
                        PrivateObject { id: 10, owner: 7, class: ObjectClass::Object, secret: "object-secret".into(), mutated: false },
                        PrivateObject { id: 11, owner: 7, class: ObjectClass::Event, secret: "event-token".into(), mutated: false },
                        PrivateObject { id: 12, owner: 7, class: ObjectClass::Status, secret: "status-cookie".into(), mutated: false },
                        PrivateObject { id: 13, owner: 7, class: ObjectClass::Artifact, secret: "artifact-payload".into(), mutated: false },
                        PrivateObject { id: 14, owner: 7, class: ObjectClass::Stream, secret: "stream-private".into(), mutated: false },
                    ],
                    trace: Vec::new(),
                }
            }

            fn read(&mut self, request: ReadRequest) -> PrivacyResponse {
                self.trace.push("authorize");
                if !request.authorized {
                    return PrivacyResponse::NotFound("object.not_found");
                }
                self.trace.push("lookup");
                let Some(object) = self.objects.iter_mut().find(|candidate| {
                    candidate.id == request.object && candidate.class == request.class
                }) else {
                    return PrivacyResponse::NotFound("object.not_found");
                };
                if object.owner != request.principal {
                    return PrivacyResponse::NotFound("object.not_found");
                }
                self.trace.push("filter");
                let body = format!("class={:?};id={}", object.class, object.id);
                self.trace.push("serialize");
                PrivacyResponse::Authorized(body)
            }

            fn unauthorized_mutation_probe(&mut self, request: ReadRequest) -> PrivacyResponse {
                let response = self.read(request);
                if matches!(response, PrivacyResponse::NotFound(_)) {
                    // A mutation here would violate the authorization-before-mutation contract.
                    self.trace.push("mutation-blocked");
                }
                response
            }
        }

        #[test]
        fn unknown_cross_owner_and_denied_reads_are_indistinguishable_not_found() {
            let mut store = PrivacyStore::new();
            let unknown = store.read(ReadRequest { principal: 7, object: 999, class: ObjectClass::Object, authorized: true });
            let cross_owner = store.read(ReadRequest { principal: 8, object: 10, class: ObjectClass::Object, authorized: true });
            let denied = store.read(ReadRequest { principal: 7, object: 10, class: ObjectClass::Object, authorized: false });
            assert_eq!(unknown, PrivacyResponse::NotFound("object.not_found"));
            assert_eq!(unknown, cross_owner);
            assert_eq!(unknown, denied);
        }

        #[test]
        fn every_filtered_object_class_authorizes_before_lookup_and_serialization() {
            for (object, class) in [(10, ObjectClass::Object), (11, ObjectClass::Event), (12, ObjectClass::Status), (13, ObjectClass::Artifact), (14, ObjectClass::Stream)] {
                let mut store = PrivacyStore::new();
                let response = store.read(ReadRequest { principal: 7, object, class, authorized: true });
                assert!(matches!(response, PrivacyResponse::Authorized(_)));
                assert_eq!(store.trace, ["authorize", "lookup", "filter", "serialize"]);
                assert!(!store.objects.iter().any(|candidate| candidate.mutated));
                if let PrivacyResponse::Authorized(body) = response {
                    assert!(!body.contains("secret"));
                    assert!(!body.contains("token"));
                    assert!(!body.contains("cookie"));
                    assert!(!body.contains("payload"));
                    assert!(!body.contains("private"));
                }
            }
        }

        #[test]
        fn denied_reads_filter_before_lookup_serialization_or_mutation() {
            let mut store = PrivacyStore::new();
            let response = store.unauthorized_mutation_probe(ReadRequest { principal: 8, object: 10, class: ObjectClass::Object, authorized: false });
            assert_eq!(response, PrivacyResponse::NotFound("object.not_found"));
            assert_eq!(store.trace, ["authorize", "mutation-blocked"]);
            assert!(!store.objects.iter().any(|candidate| candidate.mutated));
        }

        #[test]
        fn authorization_failures_are_redacted_and_event_metadata_rejects_secrets() {
            let failure = crate::failures::SecurityFailure::with_safe_ids(
                crate::failures::FailureCode::AuthorizationDenied,
                Some(uuid::Uuid::from_u128(1)),
                Some(uuid::Uuid::from_u128(2)),
            );
            let display = failure.to_string();
            assert_eq!(failure.redacted().1, crate::failures::FailureCode::AuthorizationDenied);
            assert!(!display.contains("object-secret"));
            assert!(!display.contains("event-token"));
            assert!(!display.contains("artifact-payload"));
            let event = crate::events::SecurityEvent::new(
                uuid::Uuid::from_u128(3),
                crate::events::EventBoundary::Authorization,
                crate::events::SecurityCode::AuthorizationDenied,
                crate::events::EventOutcome::Rejected,
                crate::events::SafeNextAction::FailClosed,
                None,
                None,
                crate::events::EndpointClass::Loopback,
                crate::events::EventTime(1),
                uuid::Uuid::from_u128(4),
                vec![crate::events::MetadataEntry { key: "reason".into(), value: "filtered".into() }],
            ).expect("safe authorization event");
            assert!(event.metadata().iter().all(|entry| !entry.value.contains("secret")));
            assert!(matches!(crate::events::SecurityEvent::new(
                uuid::Uuid::from_u128(5), crate::events::EventBoundary::Authorization,
                crate::events::SecurityCode::AuthorizationDenied, crate::events::EventOutcome::Rejected,
                crate::events::SafeNextAction::FailClosed, None, None,
                crate::events::EndpointClass::Loopback, crate::events::EventTime(1), uuid::Uuid::from_u128(4),
                vec![crate::events::MetadataEntry { key: "reason".into(), value: "artifact-payload".into() }],
            ), Err(crate::events::EventBuildError::Redacted)));
        }

        #[test]
        fn named_lookup_before_authorization_mutation_fails_the_contract() {
            let mut store = PrivacyStore::new();
            let response = store.read(ReadRequest { principal: 8, object: 10, class: ObjectClass::Object, authorized: false });
            assert_eq!(response, PrivacyResponse::NotFound("object.not_found"));
            assert_ne!(store.trace.first().copied(), Some("lookup"));
            assert!(!store.objects.iter().any(|candidate| candidate.mutated));
        }
    };
}
