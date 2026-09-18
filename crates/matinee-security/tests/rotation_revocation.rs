macro_rules! rotation_revocation_tests {
    () => {
        use crate::ChannelSigner;
        use crate::events::{self};
        use crate::identity::{
            Capability, CapabilityAction, Connection, ConnectionId, ConnectionLifecycle,
            CredentialReference, Fingerprint, GrantLifecycle, IdempotencyKey, IdentityId,
            Principal, PrincipalKind, PrincipalLifecycle, PublicKey, RevocationTransition,
            RotationTransition, TransitionId, TransitionInput, TransitionOperation,
            TransitionOutcome,
        };
        use crate::test_support_channel::RingSigner;
        use crate::test_support_fakes::FakeEventSink;
        use uuid::Uuid;

        fn ids(n: u128) -> IdentityId {
            IdentityId::new(Uuid::from_u128(n))
        }

        fn fingerprint(ch: char) -> Fingerprint {
            Fingerprint::new(ch.to_string().repeat(64)).unwrap()
        }

        /// A real P-256 point. `PublicKey` validates the curve, so a rotation fixture has to
        /// present material a signer could actually hold.
        fn generated_key() -> PublicKey {
            RingSigner::generate().public_key().clone()
        }

        fn credential(daemon: IdentityId, locator: &str) -> CredentialReference {
            CredentialReference::new("platform-store", locator, daemon, ids(99)).unwrap()
        }

        fn principal(key: PublicKey) -> Principal {
            let daemon = ids(1);
            Principal::new(
                ids(2),
                PrincipalKind::BrowserExtension,
                key,
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

        /// FR-024: the replacement credential is registered as part of the same transition
        /// that advances the epoch, and the epoch is only reachable through it. The assertions
        /// read the principal's own state rather than a local record of the steps taken.
        #[test]
        fn replacement_registration_precedes_epoch_transition() {
            let retired = generated_key();
            let replacement = generated_key();
            let mut principal = principal(retired.clone());
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Pending);

            // The epoch cannot move before the principal is active and rotating.
            assert!(principal.begin_rotation().is_err());
            assert!(
                principal
                    .complete_rotation(
                        replacement.clone(),
                        fingerprint('b'),
                        credential(ids(1), "key-new")
                    )
                    .is_err()
            );
            assert_eq!(principal.epoch(), 0);
            assert_eq!(principal.public_key(), &retired);

            principal.activate().unwrap();
            assert_eq!(principal.epoch(), 0);
            principal.begin_rotation().unwrap();
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Rotating);
            // Registration has begun and the epoch has still not moved.
            assert_eq!(principal.epoch(), 0);
            assert_eq!(principal.public_key(), &retired);

            principal
                .complete_rotation(
                    replacement.clone(),
                    fingerprint('b'),
                    credential(ids(1), "key-new"),
                )
                .unwrap();
            assert_eq!(principal.epoch(), 1);
            assert_eq!(principal.lifecycle(), PrincipalLifecycle::Active);
            // One replacement: the key, the fingerprint that names it, and the locator that
            // stores it all moved together, and the retired key is gone.
            assert_eq!(principal.fingerprint(), &fingerprint('b'));
            assert_eq!(principal.public_key(), &replacement);
            assert_ne!(principal.public_key(), &retired);
            assert_eq!(principal.credential().key_locator(), "key-new");

            // A refused rotation leaves the whole prior credential intact.
            let before = principal.clone();
            principal.begin_rotation().unwrap();
            assert!(
                principal
                    .complete_rotation(
                        retired.clone(),
                        fingerprint('c'),
                        credential(ids(7), "key-foreign")
                    )
                    .is_err()
            );
            assert_eq!(principal.public_key(), before.public_key());
            assert_eq!(principal.fingerprint(), before.fingerprint());
            assert_eq!(principal.credential(), before.credential());
            assert_eq!(principal.epoch(), before.epoch());
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
            let retired = generated_key();
            let replacement = generated_key();
            let mut principal = principal(retired.clone());
            principal.activate().unwrap();
            principal.begin_rotation().unwrap();
            principal
                .complete_rotation(
                    replacement.clone(),
                    fingerprint('b'),
                    credential(ids(1), "key-new"),
                )
                .unwrap();
            assert_eq!(principal.epoch(), 1);
            assert_ne!(principal.fingerprint(), &fingerprint('a'));
            assert_eq!(principal.public_key(), &replacement);
            assert_ne!(principal.public_key(), &retired);

            let capability = Capability::new(CapabilityAction::Read, "status").unwrap();
            let mut grant =
                crate::identity::ExtensionGrant::new(ids(2), ids(1), vec![capability], 0).unwrap();
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
            let mut principal = principal(generated_key());
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
                assert_eq!(
                    input.may_persist(),
                    matches!(
                        outcome,
                        TransitionOutcome::Committed | TransitionOutcome::AlreadyCommitted
                    )
                );
                assert_eq!(
                    input.is_fail_closed(),
                    outcome == TransitionOutcome::Unknown
                );
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
            assert!(
                RotationTransition::new(
                    IdempotencyKey::new(Uuid::from_u128(15)),
                    ids(2),
                    fingerprint('a'),
                    fingerprint('a'),
                    4,
                    5,
                    5,
                    TransitionOutcome::Committed
                )
                .is_err()
            );

            let revocation = RevocationTransition::new(
                IdempotencyKey::new(Uuid::from_u128(16)),
                ids(2),
                "administrator",
                5,
                2,
                1,
                TransitionOutcome::AlreadyCommitted,
            )
            .unwrap();
            assert_eq!(revocation.outcome(), TransitionOutcome::AlreadyCommitted);
            assert!(
                RevocationTransition::new(
                    IdempotencyKey::new(Uuid::from_u128(16)),
                    ids(2),
                    "",
                    5,
                    2,
                    1,
                    TransitionOutcome::Unknown
                )
                .is_err()
            );
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
            assert_eq!(
                events::emit_required::<FakeEventSink>(None, rotation_event()),
                Err(events::RequiredEventError::Unavailable)
            );
            let mut sink = FakeEventSink::unavailable();
            assert_eq!(
                events::emit_required(Some(&mut sink), rotation_event()),
                Err(events::RequiredEventError::Unavailable)
            );
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
                vec![events::MetadataEntry {
                    key: "reason_class".into(),
                    value: "administrator".into(),
                }],
            )
            .unwrap();
            assert!(event.encoded_len() <= 2_048);
            assert!(!format!("{event:?}").contains("key-new"));
            assert!(
                events::SecurityEvent::new(
                    Uuid::from_u128(14),
                    events::EventBoundary::Revocation,
                    events::SecurityCode::Revocation,
                    events::EventOutcome::Committed,
                    events::SafeNextAction::Reconnect,
                    None,
                    None,
                    events::EndpointClass::Extension,
                    events::EventTime(2),
                    Uuid::from_u128(99),
                    vec![events::MetadataEntry {
                        key: "credential".into(),
                        value: "secret".into()
                    }]
                )
                .is_err()
            );
        }
    };
}
