macro_rules! enrollment_failure_tests {
    () => {
        use crate::enrollment::{
            create_enrollment, enrollment_proof_message, validate_enrollment_binding,
            ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentBindingError, EnrollmentChannel,
            EnrollmentChannelState, EnrollmentClock, EnrollmentConsumeError, EnrollmentConsumptionService,
            EnrollmentCreation, EnrollmentCreateError, EnrollmentProof,
        };
        use crate::adapters::credential_store::{CredentialBinding, CredentialHandle, CredentialStore, CredentialStoreError};
        use crate::events::{SecurityEvent, SecurityEventSink, SecurityEventSinkResult};
        use crate::identity::{ConnectionId, EnrollmentLifecycle, ExpiryResult, Fingerprint, IdentityId, PublicKey, TransitionId};
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair};
        use ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
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

        struct RecordingSink { events: Vec<SecurityEvent>, available: bool }
        impl SecurityEventSink for RecordingSink {
            fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
                if self.available { self.events.push(event); SecurityEventSinkResult::Accepted }
                else { SecurityEventSinkResult::Unavailable }
            }
        }
        fn bundle(id: u128) -> crate::enrollment::EnrollmentBundle {
            let mut value = input(); value.enrollment = TransitionId::new(Uuid::from_u128(id)); create_enrollment(value).unwrap()
        }
        fn bundle_binding(_bundle: &crate::enrollment::EnrollmentBundle) -> EnrollmentBinding<'static> {
            EnrollmentBinding { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop", endpoint: "127.0.0.1:7777", store_metadata: "Chrome Web Store", update_metadata: "https://updates.example.test/ext.xml", install_metadata: "normal", development_allowance: DevelopmentIdentityAllowance::None }
        }
        fn capability(bundle: &crate::enrollment::EnrollmentBundle) -> ChromeCapability {
            let binding = bundle_binding(bundle); ChromeCapability::new(&binding).unwrap()
        }
        fn signed_proof(bundle: &mut crate::enrollment::EnrollmentBundle, identity: IdentityId) -> EnrollmentProof {
            let mut connection = crate::identity::Connection::new(ConnectionId::new(Uuid::from_u128(0x9000)), identity, 1, 1, [0; 12], [1; 12], Uuid::from_u128(0x901), Uuid::from_u128(0x902));
            connection.authenticate().unwrap();
            let session = crate::ChannelSession::establish(connection, 1, "127.0.0.1:7777").unwrap();
            let capability = session.enrollment_output_capability().unwrap();
            let transfer = bundle.encrypted_private_key_output(&capability).unwrap();
            let private = transfer.decrypt_for_channel(&capability).unwrap();
            let rng = SystemRandom::new();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng).unwrap();
            let mut bytes = [0u8; crate::identity::UNCOMPRESSED_KEY_BYTES]; bytes.copy_from_slice(signer.public_key().as_ref());
            let public = PublicKey::from_uncompressed(bytes).unwrap();
            let signature = signer.sign(&rng, &enrollment_proof_message(bundle, &public)).unwrap().as_ref().to_vec();
            EnrollmentProof { identity, signature, long_term_public_key: public }
        }
        fn invalid_proof(identity: IdentityId) -> EnrollmentProof {
            EnrollmentProof { identity, signature: vec![0; 8], long_term_public_key: PublicKey::from_uncompressed([0x04; crate::identity::UNCOMPRESSED_KEY_BYTES]).unwrap() }
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
        #[test]
        fn update_and_install_metadata_mismatches_fail_independently() {
            let expected = input();
            let mut update = binding(&expected);
            update.update_metadata = "https://other.example.test/ext.xml";
            assert_eq!(validate_enrollment_binding(&expected, &update), Err(EnrollmentBindingError::Metadata));

            let mut install = binding(&expected);
            install.install_metadata = "development";
            assert_eq!(validate_enrollment_binding(&expected, &install), Err(EnrollmentBindingError::Metadata));
        }

        #[test]
        fn wrong_identity_is_rejected_by_production_credential_binding() {
            let daemon = IdentityId::new(Uuid::from_u128(2));
            let other = IdentityId::new(Uuid::from_u128(3));
            let reference = crate::identity::CredentialReference::new(
                "platform", "slot", other, IdentityId::new(Uuid::from_u128(4)),
            ).unwrap();
            let key = PublicKey::from_uncompressed([
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
                0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
                0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
                0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ]).unwrap();
            let fingerprint = Fingerprint::new("a".repeat(64)).unwrap();
            assert_eq!(crate::identity::DaemonIdentity::new(
                daemon, key, fingerprint, "127.0.0.1:7777", 1, 1, reference,
            ), Err("invalid daemon identity binding"));
        }

        struct MissingCredentialStore;
        impl CredentialStore for MissingCredentialStore {
            fn lookup(&self, _: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError> {
                Err(CredentialStoreError::Missing)
            }
        }

        #[test]
        fn missing_credential_fails_closed_at_the_production_store_seam() {
            let store = MissingCredentialStore;
            assert_eq!(store.lookup(CredentialBinding::new([0; 32])), Err(CredentialStoreError::Missing));
        }

        #[test]
        fn concurrent_consumers_have_one_winner() {
            use std::sync::{Arc, Mutex};
            let enrollment = Arc::new(Mutex::new({
                let i = input();
                crate::identity::ExtensionEnrollment::new(
                    i.enrollment, i.origin, "metadata", i.daemon, i.daemon_endpoint,
                    Fingerprint::new("a".repeat(64)).unwrap(), i.expiry,
                ).unwrap()
            }));
            let handles: Vec<_> = (0..2).map(|_| {
                let enrollment = Arc::clone(&enrollment);
                std::thread::spawn(move || enrollment.lock().unwrap().consume().is_ok())
            }).collect();
            let wins = handles.into_iter().map(|handle| handle.join().unwrap()).filter(|won| *won).count();
            assert_eq!(wins, 1);
            assert_eq!(enrollment.lock().unwrap().lifecycle(), EnrollmentLifecycle::Consumed);
        }

        #[test]
        fn production_consumption_binds_principal_and_occurrence_time() {
            let identity = IdentityId::new(Uuid::from_u128(0x777)); let mut bundle = bundle(0x710);
            let binding = bundle_binding(&bundle); let capability = ChromeCapability::new(&binding).unwrap();
            let proof = signed_proof(&mut bundle, identity); let clock = EnrollmentClock::new(1_000, ExpiryResult::valid(600_000).unwrap());
            let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            let service = EnrollmentConsumptionService::default();
            let fingerprint = service.consume_proof(&mut bundle, &proof, identity, &clock, &binding, &capability, &mut channel, Some(&mut sink)).unwrap();
            assert_eq!(service.registered_fingerprint(identity), Some(fingerprint)); assert_eq!(service.registered_public_key(identity), Some(proof.long_term_public_key));
            assert_eq!(sink.events[0].time, crate::events::EventTime(1_000)); assert_eq!(bundle.lifecycle(), EnrollmentLifecycle::Consumed);
        }
        #[test]
        fn failed_proofs_are_budgeted_atomically_and_close_channel() {
            let identity = IdentityId::new(Uuid::from_u128(0x778)); let mut bundle = bundle(0x711);
            let binding = bundle_binding(&bundle); let capability = ChromeCapability::new(&binding).unwrap(); let service = EnrollmentConsumptionService::default();
            for attempt in 0..5 { let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut bundle, &invalid_proof(identity), identity, &EnrollmentClock::new(1_000 + attempt, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof)); assert_eq!(channel.state(), EnrollmentChannelState::Closed); }
            assert_eq!(bundle.enrollment().failed_proofs(), 5); assert_eq!(service.host_failures("127.0.0.1:7777"), 5); assert_eq!(bundle.lifecycle(), EnrollmentLifecycle::Closed);
        }
        #[test]
        fn event_outage_leaves_failure_and_registry_state_unchanged() {
            let identity = IdentityId::new(Uuid::from_u128(0x779)); let mut bundle = bundle(0x712); let binding = bundle_binding(&bundle); let capability = ChromeCapability::new(&binding).unwrap(); let service = EnrollmentConsumptionService::default(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: false };
            assert_eq!(service.consume_proof(&mut bundle, &invalid_proof(identity), identity, &EnrollmentClock::new(2_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::EventUnavailable)); assert_eq!(bundle.enrollment().failed_proofs(), 0); assert_eq!(service.host_failures("127.0.0.1:7777"), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
        }
        #[test]
        fn host_budget_window_uses_occurrence_time_and_rate_limits() {
            let identity = IdentityId::new(Uuid::from_u128(0x780)); let service = EnrollmentConsumptionService::default();
            for attempt in 0..10 { let mut current = bundle(0x720 + attempt); let binding = bundle_binding(&current); let capability = ChromeCapability::new(&binding).unwrap(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut current, &invalid_proof(identity), identity, &EnrollmentClock::new(5_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof)); }
            let mut limited = bundle(0x730); let binding = bundle_binding(&limited); let capability = ChromeCapability::new(&binding).unwrap(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut limited, &invalid_proof(identity), identity, &EnrollmentClock::new(5_001, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::RateLimited)); assert_eq!(channel.state(), EnrollmentChannelState::Closed);
            let mut after = bundle(0x731); let binding = bundle_binding(&after); let capability = ChromeCapability::new(&binding).unwrap(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut after, &invalid_proof(identity), identity, &EnrollmentClock::new(65_001, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof));
        }
        #[test]
        fn stale_key_quarantine_reconnect_update_and_revocation_are_closed() {
            let identity = IdentityId::new(Uuid::from_u128(0x781)); let service = EnrollmentConsumptionService::default(); let mut bundle = bundle(0x740); let binding = bundle_binding(&bundle); let capability = ChromeCapability::new(&binding).unwrap(); let proof = signed_proof(&mut bundle, identity); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            let old_fp = service.consume_proof(&mut bundle, &proof, identity, &EnrollmentClock::new(6_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)).unwrap(); assert_eq!(service.reconnect(identity, &old_fp), crate::enrollment::ChromeReconnectOutcome::Reconnected);
            let new_key = PublicKey::from_uncompressed([0x04; crate::identity::UNCOMPRESSED_KEY_BYTES]).unwrap(); let new_fp = service.update_custody(identity, &new_key).unwrap(); assert!(service.is_quarantined(&old_fp)); assert_eq!(service.reconnect(identity, &old_fp), crate::enrollment::ChromeReconnectOutcome::Mismatch); assert_eq!(service.reconnect(identity, &new_fp), crate::enrollment::ChromeReconnectOutcome::Reconnected); service.revoke(identity).unwrap(); assert_eq!(service.reconnect(identity, &new_fp), crate::enrollment::ChromeReconnectOutcome::Revoked);
        }

        #[test]
        fn concurrent_production_consumers_have_one_principal_winner() {
            let identity = IdentityId::new(Uuid::from_u128(0x782));
            let service = EnrollmentConsumptionService::default();
            let mut first = bundle(0x750); let mut second = bundle(0x751);
            let first_proof = signed_proof(&mut first, identity); let second_proof = signed_proof(&mut second, identity);
            let first_binding = bundle_binding(&first); let second_binding = bundle_binding(&second);
            let first_capability = ChromeCapability::new(&first_binding).unwrap(); let second_capability = ChromeCapability::new(&second_binding).unwrap();
            std::thread::scope(|scope| {
                let first_handle = scope.spawn(|| {
                    let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
                    service.consume_proof(&mut first, &first_proof, identity, &EnrollmentClock::new(7_000, ExpiryResult::valid(600_000).unwrap()), &first_binding, &first_capability, &mut channel, Some(&mut sink))
                });
                let second_handle = scope.spawn(|| {
                    let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
                    service.consume_proof(&mut second, &second_proof, identity, &EnrollmentClock::new(7_001, ExpiryResult::valid(600_000).unwrap()), &second_binding, &second_capability, &mut channel, Some(&mut sink))
                });
                let first_result = first_handle.join().unwrap(); let second_result = second_handle.join().unwrap();
                assert_eq!(first_result.is_ok() as u8 + second_result.is_ok() as u8, 1);
            });
            assert!(service.registered_fingerprint(identity).is_some());
        }

        #[test]
        fn production_consumption_fails_closed_on_expiry_and_uncertainty() {
            let identity = IdentityId::new(Uuid::from_u128(0x783)); let service = EnrollmentConsumptionService::default();
            let mut expired = bundle(0x760); let binding = bundle_binding(&expired); let capability = ChromeCapability::new(&binding).unwrap(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            assert_eq!(service.consume_proof(&mut expired, &invalid_proof(identity), identity, &EnrollmentClock::new(600_000, ExpiryResult::expired(600_000)), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::Expired));
            assert_eq!(expired.enrollment().failed_proofs(), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
            let mut uncertain = bundle(0x761); let binding = bundle_binding(&uncertain); let capability = ChromeCapability::new(&binding).unwrap(); let mut channel = EnrollmentChannel::new(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            assert_eq!(service.consume_proof(&mut uncertain, &invalid_proof(identity), identity, &EnrollmentClock::new(10, ExpiryResult::uncertain(600_000)), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::UncertainExpiry));
            assert_eq!(uncertain.enrollment().failed_proofs(), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
        }
    };
}
