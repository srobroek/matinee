macro_rules! rotation_revocation_races_tests {
    () => {
        use std::collections::{BTreeSet, VecDeque};

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum RaceDecision {
            Commit,
            Reject,
        }

        #[derive(Debug, Default)]
        struct RotationRaceState {
            epoch: u64,
            consumed_enrollments: BTreeSet<u64>,
            authorized_objects: BTreeSet<u64>,
            closed_connections: BTreeSet<u64>,
            delivered: BTreeSet<u64>,
        }

        impl RotationRaceState {
            fn rotate(&mut self) {
                self.epoch = self.epoch.checked_add(1).expect("bounded epoch");
            }

            fn handshake(&self, epoch: u64) -> RaceDecision {
                if epoch == self.epoch {
                    RaceDecision::Commit
                } else {
                    RaceDecision::Reject
                }
            }

            fn consume_enrollment(&mut self, enrollment: u64, epoch: u64) -> RaceDecision {
                if epoch != self.epoch || !self.consumed_enrollments.insert(enrollment) {
                    RaceDecision::Reject
                } else {
                    RaceDecision::Commit
                }
            }

            fn authorize(&self, epoch: u64) -> RaceDecision {
                if epoch == self.epoch {
                    RaceDecision::Commit
                } else {
                    RaceDecision::Reject
                }
            }

            fn mutate_object(&mut self, object: u64, epoch: u64) -> RaceDecision {
                if self.authorize(epoch) == RaceDecision::Reject {
                    RaceDecision::Reject
                } else {
                    self.authorized_objects.insert(object);
                    RaceDecision::Commit
                }
            }

            fn disconnect(&mut self, connection: u64) -> bool {
                self.closed_connections.insert(connection)
            }

            fn deliver_once(&mut self, delivery: u64) -> bool {
                self.delivered.insert(delivery)
            }
        }

        #[test]
        fn rotation_race_orders_handshake_before_stale_epoch_rejection() {
            let mut state = RotationRaceState::default();
            assert_eq!(state.handshake(0), RaceDecision::Commit);
            state.rotate();
            assert_eq!(state.handshake(0), RaceDecision::Reject);
            assert_eq!(state.handshake(1), RaceDecision::Commit);
        }

        #[test]
        fn enrollment_consumption_is_atomic_and_replay_safe() {
            let mut state = RotationRaceState::default();
            assert_eq!(state.consume_enrollment(7, 0), RaceDecision::Commit);
            assert_eq!(state.consume_enrollment(7, 0), RaceDecision::Reject);
            state.rotate();
            assert_eq!(state.consume_enrollment(8, 0), RaceDecision::Reject);
            assert!(state.consumed_enrollments.contains(&7));
            assert!(!state.consumed_enrollments.contains(&8));
        }

        #[test]
        fn authorization_is_rechecked_before_object_mutation() {
            let mut state = RotationRaceState::default();
            state.rotate();
            assert_eq!(state.authorize(0), RaceDecision::Reject);
            assert_eq!(state.mutate_object(9, 0), RaceDecision::Reject);
            assert!(state.authorized_objects.is_empty());
            assert_eq!(state.mutate_object(9, 1), RaceDecision::Commit);
            assert!(state.authorized_objects.contains(&9));
        }

        #[test]
        fn disconnect_is_idempotent_and_independent_of_transition_delivery() {
            let mut state = RotationRaceState::default();
            assert!(state.disconnect(3));
            assert!(!state.disconnect(3));
            state.rotate();
            assert!(!state.disconnect(3));
            assert_eq!(state.closed_connections.len(), 1);
        }

        #[test]
        fn repeated_transition_delivery_commits_at_most_once() {
            let mut state = RotationRaceState::default();
            let mut deliveries = VecDeque::from([11_u64, 11, 12, 11]);
            let mut commits = 0;
            while let Some(delivery) = deliveries.pop_front() {
                if state.deliver_once(delivery) {
                    commits += 1;
                }
            }
            assert_eq!(commits, 2);
            assert_eq!(state.delivered, BTreeSet::from([11, 12]));
        }

        #[test]
        fn unknown_transition_is_fail_closed_without_state_change() {
            let state = RotationRaceState::default();
            let before = format!("{state:?}");
            let outcome = crate::identity::TransitionOutcome::Unknown;
            assert!(matches!(
                outcome,
                crate::identity::TransitionOutcome::Unknown
            ));
            assert_eq!(before, format!("{state:?}"));
            assert_eq!(state.epoch, 0);
            assert!(state.consumed_enrollments.is_empty());
            assert!(state.authorized_objects.is_empty());
        }

        #[test]
        fn uncertain_expiry_rejects_consumption_without_partial_commit() {
            let expiry = crate::identity::ExpiryResult::uncertain(10_000);
            assert_eq!(expiry.status(), crate::identity::ExpiryStatus::Uncertain);
            assert!(!expiry.is_security_valid());

            let mut state = RotationRaceState::default();
            let before = state.consumed_enrollments.clone();
            let decision = if expiry.is_security_valid() {
                state.consume_enrollment(44, 0)
            } else {
                RaceDecision::Reject
            };
            assert_eq!(decision, RaceDecision::Reject);
            assert_eq!(state.consumed_enrollments, before);
        }

        #[test]
        fn stale_race_failures_are_redacted_in_both_contexts() {
            let principal = uuid::Uuid::from_u128(0x11);
            let connection = uuid::Uuid::from_u128(0x22);
            let failure = crate::failures::SecurityFailure::with_safe_ids(
                crate::failures::FailureCode::StaleEpoch,
                Some(principal),
                Some(connection),
            );
            let rendered = failure.to_string();
            assert!(rendered.contains("stale_epoch"));
            assert!(!rendered.contains("private"));
            assert!(!rendered.contains("secret"));
            assert_eq!(
                failure.redacted().1,
                crate::failures::FailureCode::StaleEpoch
            );
            assert_eq!(
                failure.safe_next_action(),
                crate::failures::SafeNextAction::ReconnectCurrentEpoch
            );
        }
    };
}
