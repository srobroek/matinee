macro_rules! rotation_revocation_tests {
    () => {
        use crate::events::{self, SecurityEventSink};
        use crate::identity::{
            Capability, CapabilityAction, Connection, ConnectionId, ConnectionLifecycle,
            CredentialReference, Fingerprint, GrantLifecycle, IdentityId, IdempotencyKey,
            Principal, PrincipalKind, PrincipalLifecycle, PublicKey, RevocationTransition,
            RotationTransition, TransitionId, TransitionInput, TransitionOperation,
            TransitionOutcome,
        };
        use crate::test_support_fakes::FakeEventSink;
        use uuid::Uuid;

        fn ids(n: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(n))
        }

        fn fingerprint(ch: char) -> Fingerprint {
            Fingerprint::new(ch.to_string().repeat(64)).unwrap()
        }

        fn key() -> PublicKey {
            let mut bytes = [0; crate::identity::UNCOMPRESSED_KEY_BYTES];
            bytes[0] = 4;
            PublicKey::from_uncompressed(bytes).unwrap()
        }

        fn credential(daemon: IdentityId, locator: &str) -> CredentialReference {
            CredentialReference::new("platform-store", locator, daemon, ids(99)).unwrap()
        }

        fn principal() -> Principal {
            let daemon = ids(1);
            Principal::new(
                ids(2),
                PrincipalKind::BrowserExtension,
                key(),
                fingerprint('a'),
                daemon,
                vec![Capability::new(CapabilityAction::Read, "status").unwrap()],
                credential(daemon, "key-old"),
            )
            .unwrap()
        }

        fn connection(epoch: u64) -> Connection {
            let mut connection = Connection::new(
                ConnectionId::new(Uuid::from_u128(3)),
                ids(2),
                1,
                epoch,
                [0; 12],
                [1; 12],
                Uuid::from_u128(4),
                Uuid::from_u128(5),
            );
            connection.authenticate().unwrap();
            connection
        }

        #[derive(Debug, Eq, PartialEq)]
        enum RotationStep {
            ReplacementRegistered,
            EpochAdvanced,
        }

        #[test]
        fn replacement_registration_precedes_epoch_transition() {
            let mut principal = principal();
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Pending);
            principal.activate().unwrap();
            principal.begin_rotation().unwrap();

            let mut steps = Vec::new();
            steps.push(RotationStep::ReplacementRegistered);
            principal
                .complete_rotation(fingerprint('b'), credential(ids(1), "key-new"))
                .unwrap();
            steps.push(RotationStep::EpochAdvanced);

            assert_eq!(steps, [RotationStep::ReplacementRegistered, RotationStep::EpochAdvanced]);
            assert_eq!(principal.epoch(), 1);
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Active);
            assert_eq!(principal.fingerprint(), &fingerprint('b'));
        }

        #[test]
        fn old_channels_close_at_the_new_epoch_boundary() {
            let mut old = connection(0);
            assert_eq!(old.lifecycle(), ConnectionLifecycle::Authenticated);
            old.close();
            assert_eq!(old.lifecycle(), ConnectionLifecycle::Closed);
            assert!(old.next_send().is_none());
            assert!(old.next_receive().is_none());
        }

        #[test]
        fn stale_key_grant_and_decision_are_rejected_after_rotation() {
            let mut principal = principal();
            principal.activate().unwrap();
            principal.begin_rotation().unwrap();
            principal
                .complete_rotation(fingerprint('b'), credential(ids(1), "key-new"))
                .unwrap();
            assert_eq!(principal.epoch(), 1);
            assert_ne!(principal.fingerprint(), &fingerprint('a'));

            let capability = Capability::new(CapabilityAction::Read, "status").unwrap();
            let mut grant = crate::identity::ExtensionGrant::new(ids(2), ids(1), vec![capability], 0).unwrap();
            assert_eq!(grant.lifecycle(), GrantLifecycle::Active);
            grant.revoke();
            assert_eq!(grant.lifecycle(), GrantLifecycle::Revoked);

            let decision = TransitionInput::new(
                ids(99),
                TransitionId::new(Uuid::from_u128(8)),
                TransitionOperation::Rotation,
                IdempotencyKey::new(Uuid::from_u128(9)),
                0,
                TransitionOutcome::Rejected,
            );
            assert_eq!(decision.outcome(), TransitionOutcome::Rejected);
            assert!(!decision.may_persist());
        }

        #[test]
        fn revocation_is_terminal_and_idempotent() {
            let mut principal = principal();
            principal.activate().unwrap();
            principal.revoke();
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Revoked);
            principal.revoke();
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Revoked);
            assert!(principal.begin_rotation().is_err());
        }

        #[test]
        fn typed_transition_outcomes_are_closed_and_idempotent() {
            let outcomes = [
                TransitionOutcome::Committed,
                TransitionOutcome::AlreadyCommitted,
                TransitionOutcome::Rejected,
                TransitionOutcome::Unknown,
            ];
            for outcome in outcomes {
                let input = TransitionInput::new(
                    ids(99),
                    TransitionId::new(Uuid::from_u128(10)),
                    TransitionOperation::Revocation,
                    IdempotencyKey::new(Uuid::from_u128(11)),
                    1,
                    outcome,
                );
                assert_eq!(input.outcome(), outcome);
                assert_eq!(input.may_persist(), matches!(outcome, TransitionOutcome::Committed | TransitionOutcome::AlreadyCommitted));
                assert_eq!(input.is_fail_closed(), outcome == TransitionOutcome::Unknown);
            }
        }
        #[test]
        fn rotation_and_revocation_carriers_preserve_typed_outcomes() {
            let rotation = RotationTransition::new(
                IdempotencyKey::new(Uuid::from_u128(15)),
                ids(2),
                fingerprint('a'),
                fingerprint('b'),
                4,
                5,
                5,
                TransitionOutcome::Committed,
            )
            .unwrap();
            assert_eq!(rotation.outcome(), TransitionOutcome::Committed);
            assert!(RotationTransition::new(
                IdempotencyKey::new(Uuid::from_u128(15)), ids(2), fingerprint('a'),
                fingerprint('a'), 4, 5, 5, TransitionOutcome::Committed
            ).is_err());

            let revocation = RevocationTransition::new(
                IdempotencyKey::new(Uuid::from_u128(16)), ids(2), "administrator", 5, 2, 1,
                TransitionOutcome::AlreadyCommitted,
            )
            .unwrap();
            assert_eq!(revocation.outcome(), TransitionOutcome::AlreadyCommitted);
            assert!(RevocationTransition::new(
                IdempotencyKey::new(Uuid::from_u128(16)), ids(2), "", 5, 2, 1,
                TransitionOutcome::Unknown
            ).is_err());
        }


        fn rotation_event() -> events::SecurityEvent {
            events::SecurityEvent::new(
                Uuid::from_u128(12),
                events::EventBoundary::Rotation,
                events::SecurityCode::Rotation,
                events::EventOutcome::Committed,
                events::SafeNextAction::Reconnect,
                Some(Uuid::from_u128(2)),
                None,
                events::EndpointClass::Extension,
                events::EventTime(1),
                Uuid::from_u128(99),
                vec![],
            )
            .unwrap()
        }

        #[test]
        fn rotation_fails_closed_when_required_event_sink_is_missing_or_unavailable() {
            assert_eq!(events::emit_required::<FakeEventSink>(None, rotation_event()), Err(events::RequiredEventError::Unavailable));
            let mut sink = FakeEventSink::unavailable();
            assert_eq!(events::emit_required(Some(&mut sink), rotation_event()), Err(events::RequiredEventError::Unavailable));
            assert_eq!(sink.received().len(), 1);
        }

        #[test]
        fn revocation_event_uses_redacted_bounded_metadata() {
            let event = events::SecurityEvent::new(
                Uuid::from_u128(13),
                events::EventBoundary::Revocation,
                events::SecurityCode::Revocation,
                events::EventOutcome::Committed,
                events::SafeNextAction::Reconnect,
                Some(Uuid::from_u128(2)),
                None,
                events::EndpointClass::Extension,
                events::EventTime(2),
                Uuid::from_u128(99),
                vec![events::MetadataEntry { key: "reason_class".into(), value: "administrator".into() }],
            )
            .unwrap();
            assert!(event.encoded_len() <= 2_048);
            assert!(!format!("{event:?}").contains("key-new"));
            assert!(events::SecurityEvent::new(
                Uuid::from_u128(14), events::EventBoundary::Revocation,
                events::SecurityCode::Revocation, events::EventOutcome::Committed,
                events::SafeNextAction::Reconnect, None, None, events::EndpointClass::Extension,
                events::EventTime(2), Uuid::from_u128(99),
                vec![events::MetadataEntry { key: "credential".into(), value: "secret".into() }]
            ).is_err());
        }
    };
}
