macro_rules! enrollment_failure_tests {
    () => {
        use crate::enrollment::{
            create_enrollment, validate_enrollment_binding, DevelopmentIdentityAllowance,
            EnrollmentBinding, EnrollmentBindingError, EnrollmentCreation, EnrollmentCreateError,
        };
        use crate::identity::{EnrollmentLifecycle, ExpiryResult, IdentityId, TransitionId};
        use uuid::Uuid;

        fn input() -> EnrollmentCreation {
            EnrollmentCreation::new(
                TransitionId::new(Uuid::from_u128(1)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                "Chrome Web Store",
                "https://updates.example.test/ext.xml",
                "normal",
                IdentityId::new(Uuid::from_u128(2)),
                "127.0.0.1:7777",
                ExpiryResult::valid(600_000).unwrap(),
            )
        }

        fn binding<'a>(input: &'a EnrollmentCreation) -> EnrollmentBinding<'a> {
            EnrollmentBinding {
                origin: input.origin.as_str(),
                endpoint: input.daemon_endpoint.as_str(),
                store_metadata: input.store_metadata.as_str(),
                update_metadata: input.update_metadata.as_str(),
                install_metadata: input.install_metadata.as_str(),
                development_allowance: DevelopmentIdentityAllowance::None,
            }
        }

        #[test]
        fn malformed_creation_and_uncertain_clock_fail_closed_before_key_generation() {
            let mut malformed = input();
            malformed.origin = "http://not-an-extension".into();
            assert_eq!(
                create_enrollment(malformed).unwrap_err(),
                EnrollmentCreateError::InvalidOrigin
            );
            let mut uncertain = input();
            uncertain.expiry = ExpiryResult::uncertain(600_000);
            assert_eq!(
                create_enrollment(uncertain).unwrap_err(),
                EnrollmentCreateError::InvalidExpiry
            );
        }

        #[test]
        fn wrong_origin_endpoint_and_metadata_are_distinct_fail_closed_outcomes() {
            let expected = input();
            let mut attempt = binding(&expected);
            attempt.origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnox";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Origin));
            attempt.origin = expected.origin.as_str();
            attempt.endpoint = "127.0.0.1:1";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Endpoint));
            attempt.endpoint = expected.daemon_endpoint.as_str();
            attempt.store_metadata = "different-store";
            assert_eq!(validate_enrollment_binding(&expected, &attempt), Err(EnrollmentBindingError::Metadata));
        }

        #[test]
        fn revoked_expired_and_consumed_enrollments_reject_replay_mutations() {
            fn enrollment() -> crate::identity::ExtensionEnrollment {
                let i = input();
                crate::identity::ExtensionEnrollment::new(
                    i.enrollment,
                    i.origin,
                    "store=Chrome Web Store;update=https://updates.example.test/ext.xml;install=normal",
                    i.daemon,
                    i.daemon_endpoint,
                    crate::identity::Fingerprint::new("a".repeat(64)).unwrap(),
                    i.expiry,
                ).unwrap()
            }
            let mut consumed = enrollment();
            consumed.consume().unwrap();
            assert_eq!(consumed.consume(), Err("enrollment is not pending"));
            let mut expired = enrollment();
            expired.expire();
            assert_eq!(expired.lifecycle(), EnrollmentLifecycle::Expired);
            assert_eq!(expired.consume(), Err("enrollment is not pending"));
            let mut revoked = enrollment();
            revoked.revoke();
            assert_eq!(revoked.lifecycle(), EnrollmentLifecycle::Revoked);
            assert_eq!(revoked.consume(), Err("enrollment is not pending"));
        }
    };
}
