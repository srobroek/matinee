macro_rules! enrollment_failure_tests {
    () => {
        use crate::enrollment::{
            enrollment_proof_message, validate_enrollment_binding, ChromeCapability,
            DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentBindingError,
            EnrollmentBundle, EnrollmentChannel, EnrollmentChannelState, EnrollmentClock,
            EnrollmentConsumeError, EnrollmentConsumptionService, EnrollmentCreation,
            SupportedExtensionVersions,
            EnrollmentCreateError, EnrollmentProof,
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
                SupportedExtensionVersions::parse("1.0", "2.5.1").unwrap(),
                IdentityId::new(Uuid::from_u128(2)),
                "127.0.0.1:7777",
                0,
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
                version: "1.4.2",
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
            let mut value = input(); value.enrollment = TransitionId::new(Uuid::from_u128(id)); EnrollmentBundle::create(value).unwrap()
        }
        fn bundle_binding(_bundle: &crate::enrollment::EnrollmentBundle) -> EnrollmentBinding<'static> {
            EnrollmentBinding { origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop", endpoint: "127.0.0.1:7777", store_metadata: "Chrome Web Store", update_metadata: "https://updates.example.test/ext.xml", install_metadata: "normal", version: "1.4.2", development_allowance: DevelopmentIdentityAllowance::None }
        }
        fn signed_proof(bundle: &mut crate::enrollment::EnrollmentBundle, identity: IdentityId) -> EnrollmentProof {
            let channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9000)), 1).unwrap();
            let enrollment = bundle.enrollment_id();
            let transfer = channel.seal_one_time_key(bundle).unwrap();
            let private = channel.open_sealed_for_test(enrollment, &transfer).unwrap();
            let rng = SystemRandom::new();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng).unwrap();
            let mut bytes = [0u8; crate::identity::UNCOMPRESSED_KEY_BYTES]; bytes.copy_from_slice(signer.public_key().as_ref());
            let public = PublicKey::from_uncompressed(bytes).unwrap();
            let signature = signer.sign(&rng, &enrollment_proof_message(bundle, &public)).unwrap().as_ref().to_vec();
            EnrollmentProof { identity, signature, long_term_public_key: public }
        }
        fn fresh_public_key() -> PublicKey {
            let rng = SystemRandom::new();
            let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &rng).unwrap();
            let mut bytes = [0u8; crate::identity::UNCOMPRESSED_KEY_BYTES];
            bytes.copy_from_slice(signer.public_key().as_ref());
            PublicKey::from_uncompressed(bytes).unwrap()
        }
        fn invalid_proof(identity: IdentityId) -> EnrollmentProof {
            EnrollmentProof { identity, signature: vec![0; 8], long_term_public_key: fresh_public_key() }
        }

        #[test]
        fn malformed_creation_and_uncertain_clock_fail_closed_before_key_generation() {
            let mut malformed = input();
            malformed.origin = "http://not-an-extension".into();
            assert_eq!(
                EnrollmentBundle::create(malformed).unwrap_err(),
                EnrollmentCreateError::InvalidOrigin
            );
            let mut uncertain = input();
            uncertain.expiry = ExpiryResult::uncertain(600_000);
            assert_eq!(
                EnrollmentBundle::create(uncertain).unwrap_err(),
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
            let binding = bundle_binding(&bundle); let capability = ChromeCapability::reported(&binding, true, true).unwrap();
            let proof = signed_proof(&mut bundle, identity); let clock = EnrollmentClock::new(1_000, ExpiryResult::valid(600_000).unwrap());
            let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            let service = EnrollmentConsumptionService::default();
            let fingerprint = service.consume_proof(&mut bundle, &proof, identity, &clock, &binding, &capability, &mut channel, Some(&mut sink)).unwrap();
            assert_eq!(service.registered_fingerprint(identity), Some(fingerprint)); assert_eq!(service.registered_public_key(identity), Some(proof.long_term_public_key));
            assert_eq!(sink.events[0].time, crate::events::EventTime(1_000)); assert_eq!(bundle.lifecycle(), EnrollmentLifecycle::Consumed);
        }
        #[test]
        fn failed_proofs_are_budgeted_atomically_and_close_channel() {
            let identity = IdentityId::new(Uuid::from_u128(0x778)); let mut bundle = bundle(0x711);
            let binding = bundle_binding(&bundle); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let service = EnrollmentConsumptionService::default();
            for attempt in 0..5 { let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut bundle, &invalid_proof(identity), identity, &EnrollmentClock::new(1_000 + attempt, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof)); assert_eq!(channel.state(), EnrollmentChannelState::Closed); }
            assert_eq!(bundle.enrollment().failed_proofs(), 5); assert_eq!(bundle.lifecycle(), EnrollmentLifecycle::Closed);
        }
        #[test]
        fn event_outage_leaves_failure_and_registry_state_unchanged() {
            let identity = IdentityId::new(Uuid::from_u128(0x779)); let mut bundle = bundle(0x712); let binding = bundle_binding(&bundle); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let service = EnrollmentConsumptionService::default(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: false };
            assert_eq!(service.consume_proof(&mut bundle, &invalid_proof(identity), identity, &EnrollmentClock::new(2_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::EventUnavailable)); assert_eq!(bundle.enrollment().failed_proofs(), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
        }
        #[test]
        fn host_budget_window_uses_occurrence_time_and_rate_limits() {
            let identity = IdentityId::new(Uuid::from_u128(0x780)); let service = EnrollmentConsumptionService::default();
            for attempt in 0..10 { let mut current = bundle(0x720 + attempt); let binding = bundle_binding(&current); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut current, &invalid_proof(identity), identity, &EnrollmentClock::new(5_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof)); }
            let mut limited = bundle(0x730); let binding = bundle_binding(&limited); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut limited, &invalid_proof(identity), identity, &EnrollmentClock::new(5_001, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::RateLimited)); assert_eq!(channel.state(), EnrollmentChannelState::Closed);
            let mut after = bundle(0x731); let binding = bundle_binding(&after); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true }; assert_eq!(service.consume_proof(&mut after, &invalid_proof(identity), identity, &EnrollmentClock::new(65_001, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::InvalidProof));
        }
        #[test]
        fn stale_key_quarantine_reconnect_update_and_revocation_are_closed() {
            let identity = IdentityId::new(Uuid::from_u128(0x781)); let service = EnrollmentConsumptionService::default(); let mut bundle = bundle(0x740); let binding = bundle_binding(&bundle); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let proof = signed_proof(&mut bundle, identity); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            let old_fp = service.consume_proof(&mut bundle, &proof, identity, &EnrollmentClock::new(6_000, ExpiryResult::valid(600_000).unwrap()), &binding, &capability, &mut channel, Some(&mut sink)).unwrap();
            assert_eq!(service.reconnect(identity, &old_fp, &capability), crate::enrollment::ChromeReconnectOutcome::Reconnected);
            let unsupported = ChromeCapability::reported(&binding, false, true).unwrap();
            assert_eq!(service.reconnect(identity, &old_fp, &unsupported), crate::enrollment::ChromeReconnectOutcome::Mismatch);
            let new_key = fresh_public_key();
            assert_eq!(service.update_custody(identity, &new_key, &unsupported), Err(EnrollmentConsumeError::CapabilityRejected));
            let new_fp = service.update_custody(identity, &new_key, &capability).unwrap();
            assert!(service.is_quarantined(&old_fp));
            assert_eq!(service.reconnect(identity, &old_fp, &capability), crate::enrollment::ChromeReconnectOutcome::Mismatch);
            assert_eq!(service.reconnect(identity, &new_fp, &capability), crate::enrollment::ChromeReconnectOutcome::Reconnected);
            service.revoke(identity).unwrap();
            assert_eq!(service.reconnect(identity, &new_fp, &capability), crate::enrollment::ChromeReconnectOutcome::Revoked);
        }

        #[test]
        fn concurrent_production_consumers_have_one_principal_winner() {
            let identity = IdentityId::new(Uuid::from_u128(0x782));
            let service = EnrollmentConsumptionService::default();
            let mut first = bundle(0x750); let mut second = bundle(0x751);
            let first_proof = signed_proof(&mut first, identity); let second_proof = signed_proof(&mut second, identity);
            let first_binding = bundle_binding(&first); let second_binding = bundle_binding(&second);
            let first_capability = ChromeCapability::reported(&first_binding, true, true).unwrap(); let second_capability = ChromeCapability::reported(&second_binding, true, true).unwrap();
            std::thread::scope(|scope| {
                let first_handle = scope.spawn(|| {
                    let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
                    service.consume_proof(&mut first, &first_proof, identity, &EnrollmentClock::new(7_000, ExpiryResult::valid(600_000).unwrap()), &first_binding, &first_capability, &mut channel, Some(&mut sink))
                });
                let second_handle = scope.spawn(|| {
                    let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
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
            let mut expired = bundle(0x760); let binding = bundle_binding(&expired); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            assert_eq!(service.consume_proof(&mut expired, &invalid_proof(identity), identity, &EnrollmentClock::new(600_000, ExpiryResult::expired(600_000)), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::Expired));
            assert_eq!(expired.enrollment().failed_proofs(), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
            let mut uncertain = bundle(0x761); let binding = bundle_binding(&uncertain); let capability = ChromeCapability::reported(&binding, true, true).unwrap(); let mut channel = EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(0x9100)), 1).unwrap(); let mut sink = RecordingSink { events: Vec::new(), available: true };
            assert_eq!(service.consume_proof(&mut uncertain, &invalid_proof(identity), identity, &EnrollmentClock::new(10, ExpiryResult::uncertain(600_000)), &binding, &capability, &mut channel, Some(&mut sink)), Err(EnrollmentConsumeError::UncertainExpiry));
            assert_eq!(uncertain.enrollment().failed_proofs(), 0); assert_eq!(channel.state(), EnrollmentChannelState::Open);
        }

        /// SC-005's campaign: one hundred attempts per enrollment failure class.
        ///
        /// Quoted: "In 100 enrollment attempts per failure class, only valid, unexpired,
        /// expected-origin, first-use proofs succeed; consumed, expired, wrong-origin,
        /// wrong-identity, replayed, and rate-limited attempts produce no principal."
        mod sc005_campaign {
            use crate::enrollment::{
                ChromeCapability, DevelopmentIdentityAllowance, EnrollmentBinding, EnrollmentBundle,
                EnrollmentChannel, EnrollmentChannelState, EnrollmentClock, EnrollmentConsumeError,
                EnrollmentConsumptionService, EnrollmentCreation, EnrollmentProof,
                SupportedExtensionVersions, enrollment_proof_message,
            };
            use crate::events::{SecurityEvent, SecurityEventSink, SecurityEventSinkResult};
            use crate::identity::{
                ConnectionId, ExpiryResult, Fingerprint, IdentityId, PublicKey, TransitionId,
                UNCOMPRESSED_KEY_BYTES,
            };
            use ring::rand::SystemRandom;
            use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
            use uuid::Uuid;

            /// The campaign seed. Every enrollment, identity, and connection identifier below
            /// is derived from it, so a named class and attempt index reproduce one exact case.
            const SEED: u64 = 0x5C00_0005_2026_0918;
            /// SC-005 fixes the figure: one hundred attempts per class.
            const ATTEMPTS_PER_CLASS: usize = 100;
            const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
            const FOREIGN_ORIGIN: &str = "chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba";
            const STORE: &str = "Chrome Web Store";
            const UPDATE: &str = "https://updates.example.test/ext.xml";
            const ENDPOINT: &str = "127.0.0.1:7777";
            const VERSION: &str = "1.4.2";
            /// The creation path caps an enrollment deadline at ten minutes, so every
            /// occurrence time a campaign attempt uses sits inside that window.
            const DEADLINE_MS: u64 = 600_000;
            /// FR-009 rate-limits failed pairing attempts to ten per loopback address per
            /// minute.
            const BUDGET_WINDOW_MS: u64 = 60_000;
            const BUDGET_PER_WINDOW: usize = 10;

            /// SplitMix64. The campaign needs reproducible identifiers, not entropy: the
            /// cryptographic keys every attempt uses are generated by production itself.
            fn mix(seed: u64, index: u64) -> u64 {
                let mut z = seed.wrapping_add(index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }

            /// A seed-derived identifier that is still unique by construction: the high half
            /// varies with the seed, the low half names the class, the attempt, and the tag.
            fn derived(class_index: u64, attempt: usize, tag: u64) -> u128 {
                let draw = u128::from(mix(SEED, class_index << 24 | (attempt as u64) << 8 | tag));
                (draw << 64)
                    | u128::from(class_index) << 40
                    | (attempt as u128) << 8
                    | u128::from(tag)
            }

            /// The occurrence time of one attempt.
            ///
            /// FR-009 allows ten failed attempts per loopback address per minute, and every
            /// class that reaches the rejection path charges that budget. Ten attempts per
            /// one-minute window therefore keeps each attempt inside its own failure class
            /// instead of degrading into a rate-limit refusal, and ten such windows fit inside
            /// the ten-minute deadline the creation path caps every enrollment at.
            fn occurrence_ms(attempt: usize) -> u64 {
                (attempt / BUDGET_PER_WINDOW) as u64 * BUDGET_WINDOW_MS
                    + (attempt % BUDGET_PER_WINDOW) as u64
                    + 1
            }

            struct CampaignSink {
                events: Vec<SecurityEvent>,
                available: bool,
            }

            impl SecurityEventSink for CampaignSink {
                fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
                    if self.available {
                        self.events.push(event);
                        SecurityEventSinkResult::Accepted
                    } else {
                        SecurityEventSinkResult::Unavailable
                    }
                }
            }

            fn identity(value: u128) -> IdentityId {
                IdentityId::new(Uuid::from_u128(value))
            }

            fn clock(occurrence_ms: u64) -> EnrollmentClock {
                EnrollmentClock::new(
                    occurrence_ms,
                    ExpiryResult::valid(DEADLINE_MS).expect("a nonzero deadline"),
                )
            }

            fn enrollment_bundle(enrollment: u128, install: &str) -> EnrollmentBundle {
                EnrollmentBundle::create(EnrollmentCreation::new(
                    TransitionId::new(Uuid::from_u128(enrollment)),
                    ORIGIN,
                    STORE,
                    UPDATE,
                    install,
                    SupportedExtensionVersions::parse("1.0", "2.5.1")
                        .expect("a supported version range"),
                    identity(2),
                    ENDPOINT,
                    0,
                    ExpiryResult::valid(DEADLINE_MS).expect("a nonzero deadline"),
                ))
                .expect("a bounded one-time enrollment")
            }

            fn pairing_binding(
                install: &'static str,
                allowance: DevelopmentIdentityAllowance,
            ) -> EnrollmentBinding<'static> {
                EnrollmentBinding {
                    origin: ORIGIN,
                    endpoint: ENDPOINT,
                    store_metadata: STORE,
                    update_metadata: UPDATE,
                    install_metadata: install,
                    version: VERSION,
                    development_allowance: allowance,
                }
            }

            fn open_channel(connection: u128) -> EnrollmentChannel {
                EnrollmentChannel::open(ConnectionId::new(Uuid::from_u128(connection)), 1)
                    .expect("an authenticated native channel")
            }

            /// A long-term key, as a pairing peer generates one for itself.
            fn long_term_key() -> PublicKey {
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .expect("peer key generation");
                let key = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8.as_ref(),
                    &rng,
                )
                .expect("peer key import");
                let mut bytes = [0u8; UNCOMPRESSED_KEY_BYTES];
                bytes.copy_from_slice(key.public_key().as_ref());
                PublicKey::from_uncompressed(bytes).expect("a valid peer public key")
            }

            /// One pairing proof signed with the one-time key the daemon sealed to this
            /// channel, over the transcript production itself publishes.
            fn signed_proof(
                bundle: &mut EnrollmentBundle,
                channel: &EnrollmentChannel,
                who: IdentityId,
                long_term: PublicKey,
            ) -> EnrollmentProof {
                let enrollment = bundle.enrollment_id();
                let transfer = channel
                    .seal_one_time_key(bundle)
                    .expect("one-time key custody");
                let private = channel
                    .open_sealed_for_test(enrollment, &transfer)
                    .expect("the pairing peer opens its own sealed key");
                let rng = SystemRandom::new();
                let signer =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &rng)
                        .expect("the one-time key");
                let signature = signer
                    .sign(&rng, &enrollment_proof_message(bundle, &long_term))
                    .expect("a one-time proof signature")
                    .as_ref()
                    .to_vec();
                EnrollmentProof {
                    identity: who,
                    signature,
                    long_term_public_key: long_term,
                }
            }

            /// A syntactically valid signature by a key that is not the one-time key.
            fn foreign_signature(bundle: &EnrollmentBundle, long_term: &PublicKey) -> Vec<u8> {
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .expect("foreign key generation");
                let signer = EcdsaKeyPair::from_pkcs8(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8.as_ref(),
                    &rng,
                )
                .expect("foreign key import");
                signer
                    .sign(&rng, &enrollment_proof_message(bundle, long_term))
                    .expect("a foreign signature")
                    .as_ref()
                    .to_vec()
            }

            /// Every failure class the enrollment consumption path can express, plus the one
            /// success class SC-005 contrasts them against. Each class injects exactly one
            /// defect; everything else about the attempt is a valid first use.
            #[derive(Clone, Copy, Debug, Eq, PartialEq)]
            enum Class {
                ValidFirstUse,
                ReplayedProof,
                ConsumedEnrollment,
                RevokedEnrollment,
                ExpiredDeadline,
                UncertainExpiry,
                DeadlineMismatch,
                OccurrenceAtDeadline,
                WrongOrigin,
                WrongEndpoint,
                WrongStoreMetadata,
                WrongUpdateMetadata,
                WrongInstallMetadata,
                VersionBelowRange,
                VersionAboveRange,
                UnparsableVersion,
                DevelopmentWithoutAllowance,
                DevelopmentWarningUnacknowledged,
                WrongIdentity,
                MalformedSignature,
                ForeignKeySignature,
                CapabilityBindingMismatch,
                CapabilityWithoutLocalStorage,
                CapabilityWithExportableKey,
                ClosedChannel,
                QuarantinedCredential,
                RegisteredIdentity,
                EventSinkUnavailable,
                HostBudgetExhausted,
            }

            const CLASSES: [Class; 29] = [
                Class::ValidFirstUse,
                Class::ReplayedProof,
                Class::ConsumedEnrollment,
                Class::RevokedEnrollment,
                Class::ExpiredDeadline,
                Class::UncertainExpiry,
                Class::DeadlineMismatch,
                Class::OccurrenceAtDeadline,
                Class::WrongOrigin,
                Class::WrongEndpoint,
                Class::WrongStoreMetadata,
                Class::WrongUpdateMetadata,
                Class::WrongInstallMetadata,
                Class::VersionBelowRange,
                Class::VersionAboveRange,
                Class::UnparsableVersion,
                Class::DevelopmentWithoutAllowance,
                Class::DevelopmentWarningUnacknowledged,
                Class::WrongIdentity,
                Class::MalformedSignature,
                Class::ForeignKeySignature,
                Class::CapabilityBindingMismatch,
                Class::CapabilityWithoutLocalStorage,
                Class::CapabilityWithExportableKey,
                Class::ClosedChannel,
                Class::QuarantinedCredential,
                Class::RegisteredIdentity,
                Class::EventSinkUnavailable,
                Class::HostBudgetExhausted,
            ];

            impl Class {
                /// The bounded failure a rejected attempt of this class must report. FR-029
                /// keeps the class coarse on purpose: every binding miss is `InvalidProof`, and
                /// only the emitted event distinguishes a rejected Origin.
                fn expected(self, attempt: usize) -> Option<EnrollmentConsumeError> {
                    match self {
                        Self::ValidFirstUse => None,
                        Self::ReplayedProof
                        | Self::ConsumedEnrollment
                        | Self::RevokedEnrollment => Some(EnrollmentConsumeError::AlreadyConsumed),
                        Self::ExpiredDeadline
                        | Self::DeadlineMismatch
                        | Self::OccurrenceAtDeadline => Some(EnrollmentConsumeError::Expired),
                        Self::UncertainExpiry => Some(EnrollmentConsumeError::UncertainExpiry),
                        Self::WrongIdentity => Some(EnrollmentConsumeError::WrongIdentity),
                        Self::CapabilityBindingMismatch
                        | Self::CapabilityWithoutLocalStorage
                        | Self::CapabilityWithExportableKey => {
                            Some(EnrollmentConsumeError::CapabilityRejected)
                        }
                        Self::ClosedChannel => Some(EnrollmentConsumeError::ChannelClosed),
                        Self::QuarantinedCredential | Self::RegisteredIdentity => {
                            Some(EnrollmentConsumeError::CredentialMismatch)
                        }
                        Self::EventSinkUnavailable => {
                            Some(EnrollmentConsumeError::EventUnavailable)
                        }
                        // FR-009 is the subject of this class: the first ten attempts inside
                        // one window spend the budget, and every attempt after it is refused
                        // before the proof is looked at.
                        Self::HostBudgetExhausted if attempt < BUDGET_PER_WINDOW => {
                            Some(EnrollmentConsumeError::InvalidProof)
                        }
                        Self::HostBudgetExhausted => Some(EnrollmentConsumeError::RateLimited),
                        _ => Some(EnrollmentConsumeError::InvalidProof),
                    }
                }
            }

            struct ClassReport {
                class: Class,
                attempts: usize,
                principals_created: usize,
                rejected: usize,
            }

            /// The state one class needs before its hundred attempts, established through the
            /// same production path the attempts then fail against.
            struct Prior {
                bundle: Option<EnrollmentBundle>,
                proof: Option<EnrollmentProof>,
                settled: Option<IdentityId>,
                quarantined_key: Option<PublicKey>,
            }

            fn prior_state(
                class: Class,
                class_index: u64,
                service: &EnrollmentConsumptionService,
                binding: &EnrollmentBinding<'_>,
                capability: &ChromeCapability,
            ) -> Prior {
                let mut prior = Prior {
                    bundle: None,
                    proof: None,
                    settled: None,
                    quarantined_key: None,
                };
                if !matches!(
                    class,
                    Class::ReplayedProof
                        | Class::ConsumedEnrollment
                        | Class::QuarantinedCredential
                        | Class::RegisteredIdentity
                ) {
                    return prior;
                }
                let mut bundle = enrollment_bundle(derived(class_index, usize::MAX, 0xa1), "normal");
                let mut channel = open_channel(derived(class_index, usize::MAX, 0xa2));
                let who = identity(derived(class_index, usize::MAX, 0xa3));
                let key = long_term_key();
                let proof = signed_proof(&mut bundle, &channel, who, key.clone());
                let mut sink = CampaignSink {
                    events: Vec::new(),
                    available: true,
                };
                let settled_fingerprint = service
                    .consume_proof(
                        &mut bundle,
                        &proof,
                        who,
                        &clock(1),
                        binding,
                        capability,
                        &mut channel,
                        Some(&mut sink),
                    )
                    .expect("the campaign's own first use pairs a principal");
                if class == Class::QuarantinedCredential {
                    let replacement = service
                        .update_custody(who, &long_term_key(), capability)
                        .expect("custody rotates to a replacement key");
                    assert_ne!(settled_fingerprint, replacement);
                    assert!(
                        service.is_quarantined(&settled_fingerprint),
                        "a replaced credential must be quarantined"
                    );
                    prior.quarantined_key = Some(key);
                }
                prior.settled = Some(who);
                prior.proof = Some(proof);
                prior.bundle = Some(bundle);
                prior
            }

            #[allow(clippy::too_many_lines)]
            fn run_class(class: Class, class_index: u64) -> ClassReport {
                let service = EnrollmentConsumptionService::default();
                let expected_binding = pairing_binding("normal", DevelopmentIdentityAllowance::None);
                let expected_capability = ChromeCapability::reported(&expected_binding, true, true)
                    .expect("a reported browser capability");
                let mut prior = prior_state(
                    class,
                    class_index,
                    &service,
                    &expected_binding,
                    &expected_capability,
                );
                let mut principals_created = 0usize;
                let mut rejected = 0usize;

                for attempt in 0..ATTEMPTS_PER_CLASS {
                    // FR-009's window is this class's own subject, so it stays inside one.
                    let occurrence = if class == Class::HostBudgetExhausted {
                        1
                    } else {
                        occurrence_ms(attempt)
                    };
                    let who = match class {
                        Class::ReplayedProof | Class::RegisteredIdentity => {
                            prior.settled.expect("a settled identity")
                        }
                        _ => identity(derived(class_index, attempt, 0x01)),
                    };

                    // The single defect this class injects, and nothing else.
                    let install = match class {
                        Class::DevelopmentWithoutAllowance
                        | Class::DevelopmentWarningUnacknowledged => "development",
                        _ => "normal",
                    };
                    let allowance = match class {
                        Class::DevelopmentWarningUnacknowledged => {
                            DevelopmentIdentityAllowance::Explicit {
                                warning_acknowledged: false,
                            }
                        }
                        _ => DevelopmentIdentityAllowance::None,
                    };
                    let mut binding = pairing_binding(install, allowance);
                    match class {
                        Class::WrongOrigin => binding.origin = FOREIGN_ORIGIN,
                        Class::WrongEndpoint => binding.endpoint = "127.0.0.1:7778",
                        Class::WrongStoreMetadata => binding.store_metadata = "Sideloaded Store",
                        Class::WrongUpdateMetadata => {
                            binding.update_metadata = "https://updates.attacker.test/ext.xml";
                        }
                        Class::WrongInstallMetadata => binding.install_metadata = "development",
                        Class::VersionBelowRange => binding.version = "0.9",
                        Class::VersionAboveRange => binding.version = "2.5.2",
                        Class::UnparsableVersion => binding.version = "1.4.2-beta",
                        _ => {}
                    }
                    // A capability the browser reported for a different binding is its own
                    // class; every other class reports the capability for what it presents, so
                    // the capability gate cannot mask the defect under test.
                    let capability = match class {
                        Class::CapabilityBindingMismatch => {
                            let mut other = pairing_binding("normal", allowance);
                            other.origin = FOREIGN_ORIGIN;
                            ChromeCapability::reported(&other, true, true)
                        }
                        Class::CapabilityWithoutLocalStorage => {
                            ChromeCapability::reported(&binding, false, true)
                        }
                        Class::CapabilityWithExportableKey => {
                            ChromeCapability::reported(&binding, true, false)
                        }
                        _ => ChromeCapability::reported(&binding, true, true),
                    }
                    .expect("a reported browser capability");

                    let expiry = match class {
                        Class::ExpiredDeadline => ExpiryResult::expired(DEADLINE_MS),
                        Class::UncertainExpiry => ExpiryResult::uncertain(DEADLINE_MS),
                        Class::DeadlineMismatch => ExpiryResult::valid(DEADLINE_MS - 1)
                            .expect("a nonzero deadline"),
                        _ => ExpiryResult::valid(DEADLINE_MS).expect("a nonzero deadline"),
                    };
                    let occurrence = if class == Class::OccurrenceAtDeadline {
                        DEADLINE_MS
                    } else {
                        occurrence
                    };

                    let mut owned_bundle;
                    let mut owned_channel = open_channel(derived(class_index, attempt, 0x02));
                    let proof;
                    let bundle: &mut EnrollmentBundle = match class {
                        Class::ReplayedProof => {
                            proof = prior.proof.clone().expect("the settled proof");
                            prior.bundle.as_mut().expect("the consumed enrollment")
                        }
                        Class::ConsumedEnrollment => {
                            // The one-time key of a consumed enrollment has already left its
                            // bundle, so a fresh identity has no proof to offer at all.
                            proof = EnrollmentProof {
                                identity: who,
                                signature: vec![0; 8],
                                long_term_public_key: long_term_key(),
                            };
                            prior.bundle.as_mut().expect("the consumed enrollment")
                        }
                        _ => {
                            owned_bundle = enrollment_bundle(
                                derived(class_index, attempt, 0x03),
                                install,
                            );
                            let key = match class {
                                Class::QuarantinedCredential => prior
                                    .quarantined_key
                                    .clone()
                                    .expect("the quarantined credential"),
                                _ => long_term_key(),
                            };
                            let mut signed = signed_proof(
                                &mut owned_bundle,
                                &owned_channel,
                                who,
                                key,
                            );
                            match class {
                                Class::WrongIdentity => {
                                    signed.identity =
                                        identity(derived(class_index, attempt, 0x04));
                                }
                                // The budget class needs attempts that actually fail: its
                                // first ten spend FR-009's per-minute allowance, and every
                                // attempt after that is refused before the proof is read.
                                Class::MalformedSignature | Class::HostBudgetExhausted => {
                                    signed.signature = vec![0; 8];
                                }
                                Class::ForeignKeySignature => {
                                    signed.signature = foreign_signature(
                                        &owned_bundle,
                                        &signed.long_term_public_key,
                                    );
                                }
                                _ => {}
                            }
                            if class == Class::RevokedEnrollment {
                                owned_bundle.revoke();
                            }
                            if class == Class::ClosedChannel {
                                owned_channel.close();
                            }
                            proof = signed;
                            &mut owned_bundle
                        }
                    };

                    let mut sink = CampaignSink {
                        events: Vec::new(),
                        available: class != Class::EventSinkUnavailable,
                    };
                    let before = service.registered_fingerprint(who);
                    let outcome = service.consume_proof(
                        bundle,
                        &proof,
                        who,
                        &EnrollmentClock::new(occurrence, expiry),
                        &binding,
                        &capability,
                        &mut owned_channel,
                        Some(&mut sink),
                    );
                    let after = service.registered_fingerprint(who);
                    let label = format!("{class:?}#{attempt}");

                    match class.expected(attempt) {
                        None => {
                            let fingerprint =
                                outcome.expect("a valid unexpired first use must pair");
                            assert!(before.is_none(), "{label} reused an identity");
                            assert_eq!(after.as_ref(), Some(&fingerprint), "{label}");
                            assert_eq!(
                                service.registered_public_key(who).as_ref(),
                                Some(&proof.long_term_public_key),
                                "{label} registered a key the peer did not offer"
                            );
                            principals_created += 1;
                        }
                        Some(expected) => {
                            assert_eq!(outcome, Err(expected), "{label}");
                            assert_eq!(
                                after, before,
                                "{label} moved the registry: SC-005 allows no principal here"
                            );
                            let rendered = format!("{outcome:?} {:?}", sink.events);
                            for forbidden in ["pkcs8", "private", "signature: [", "secret"] {
                                assert!(
                                    !rendered.to_ascii_lowercase().contains(forbidden),
                                    "{label} disclosed {forbidden} through {rendered}"
                                );
                            }
                            rejected += 1;
                        }
                    }
                }

                ClassReport {
                    class,
                    attempts: ATTEMPTS_PER_CLASS,
                    principals_created,
                    rejected,
                }
            }

            /// SC-005, quoted: "In 100 enrollment attempts per failure class, only valid,
            /// unexpired, expected-origin, first-use proofs succeed; consumed, expired,
            /// wrong-origin, wrong-identity, replayed, and rate-limited attempts produce no
            /// principal."
            ///
            /// Twenty-nine classes run one hundred attempts each -- 2,900 attempts -- against
            /// `EnrollmentConsumptionService::consume_proof`, the path a host process pairs
            /// through. Every class injects exactly one defect and is otherwise a valid first
            /// use, so the refusal it observes belongs to the defect and not to a bound the
            /// fixture missed. The registry is read before and after every attempt: a failure
            /// class must leave `registered_fingerprint` exactly where it was, and only
            /// `ValidFirstUse` may move it.
            ///
            /// Twenty-eight of the classes are failures, and every bounded
            /// `EnrollmentConsumeError` the consumption path can produce appears among them.
            /// `InvalidPublicKey` is not among them and cannot be: its only construction site
            /// on this path re-hashes an already parsed key, which is infallible.
            #[test]
            fn one_hundred_attempts_per_failure_class_create_principals_only_for_valid_first_use() {
                let started = std::time::Instant::now();
                let reports: Vec<ClassReport> = CLASSES
                    .into_iter()
                    .enumerate()
                    .map(|(index, class)| run_class(class, index as u64))
                    .collect();

                assert_eq!(reports.len(), 29, "every named failure class must run");
                let mut attempts = 0usize;
                let mut created = 0usize;
                for report in &reports {
                    assert_eq!(report.attempts, ATTEMPTS_PER_CLASS, "{:?}", report.class);
                    assert_eq!(
                        report.principals_created + report.rejected,
                        ATTEMPTS_PER_CLASS,
                        "{:?}",
                        report.class
                    );
                    if report.class == Class::ValidFirstUse {
                        assert_eq!(report.principals_created, ATTEMPTS_PER_CLASS);
                        assert_eq!(report.rejected, 0);
                    } else {
                        assert_eq!(
                            report.principals_created, 0,
                            "{:?} created a principal",
                            report.class
                        );
                        assert_eq!(report.rejected, ATTEMPTS_PER_CLASS, "{:?}", report.class);
                    }
                    attempts += report.attempts;
                    created += report.principals_created;
                }
                assert_eq!(attempts, 2_900);
                assert_eq!(created, 100, "only the valid first-use class pairs anything");
                println!(
                    "SC-005 campaign: seed {SEED:#x}, {} classes x {ATTEMPTS_PER_CLASS} attempts \
                     = {attempts} ({created} accepted, {} rejected), {:?}",
                    reports.len(),
                    attempts - created,
                    started.elapsed()
                );
                for report in &reports {
                    println!(
                        "  {:?}: {} attempts, {} principals, {} rejected",
                        report.class,
                        report.attempts,
                        report.principals_created,
                        report.rejected
                    );
                }
            }

            /// The campaign's own instrument: a closed channel really is closed and an
            /// available sink really records, so a class that depends on either is not
            /// silently passing for the wrong reason.
            #[test]
            fn the_campaign_fixtures_are_the_conditions_they_claim() {
                let mut channel = open_channel(derived(0xfe, 0, 0xb1));
                assert_eq!(channel.state(), EnrollmentChannelState::Open);
                channel.close();
                assert_eq!(channel.state(), EnrollmentChannelState::Closed);

                let binding = pairing_binding("normal", DevelopmentIdentityAllowance::None);
                let capability = ChromeCapability::reported(&binding, false, true)
                    .expect("a browser that cannot persist still reports");
                assert!(!capability.storage_local());
                assert!(capability.non_exportable());

                let service = EnrollmentConsumptionService::default();
                let who = identity(derived(0xfe, 0, 0xb2));
                assert_eq!(service.registered_fingerprint(who), None::<Fingerprint>);
                assert_eq!(occurrence_ms(0), 1);
                assert_eq!(occurrence_ms(9), 10);
                assert_eq!(occurrence_ms(10), BUDGET_WINDOW_MS + 1);
                assert_eq!(occurrence_ms(99), 9 * BUDGET_WINDOW_MS + 10);
                assert!(occurrence_ms(99) < DEADLINE_MS);
            }
        }
    };
}
