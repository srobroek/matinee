macro_rules! enrollment_custody_tests {
    () => {
        #[test]
        fn production_bundle_exposes_pkcs8_only_as_authenticated_encrypted_output() {
            let input = crate::enrollment::EnrollmentCreation::new(
                crate::identity::TransitionId::new(uuid::Uuid::from_u128(0x40)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop", "Chrome Web Store",
                "https://updates.example.test/ext.xml", "normal",
                crate::identity::IdentityId::new(uuid::Uuid::from_u128(0x41)),
                "127.0.0.1:7777", crate::identity::ExpiryResult::valid(600_000).unwrap(),
            );
            let mut bundle = crate::enrollment::EnrollmentBundle::create(input).unwrap();
            let channel = crate::enrollment::EnrollmentChannel::open(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x42)), 1,
            )
            .expect("open native channel");
            let output = channel.seal_one_time_key(&mut bundle).unwrap();
            assert!(!output.ciphertext().is_empty());
            assert!(channel.seal_one_time_key(&mut bundle).is_err());
            assert!(!channel.open_sealed_for_test(crate::identity::TransitionId::new(uuid::Uuid::from_u128(0x40)), &output).unwrap().is_empty());
            assert!(!format!("{bundle:?}").contains("PKCS#8"));
        }

        #[test]
        fn one_channel_separates_two_enrollment_ciphertext_streams() {
            let create = |enrollment| {
                crate::enrollment::EnrollmentBundle::create(crate::enrollment::EnrollmentCreation::new(
                    crate::identity::TransitionId::new(uuid::Uuid::from_u128(enrollment)),
                    "chrome-extension://abcdefghijklmnopabcdefghijklmnop", "Chrome Web Store",
                    "https://updates.example.test/ext.xml", "normal",
                    crate::identity::IdentityId::new(uuid::Uuid::from_u128(0x51)),
                    "127.0.0.1:7777", crate::identity::ExpiryResult::valid(600_000).unwrap(),
                )).unwrap()
            };
            let mut first_bundle = create(0x50);
            let mut second_bundle = create(0x52);
            let channel = crate::enrollment::EnrollmentChannel::open(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x53)), 7,
            ).unwrap();
            let first = channel.seal_one_time_key(&mut first_bundle).unwrap();
            let second = channel.seal_one_time_key(&mut second_bundle).unwrap();

            let first_enrollment = crate::identity::TransitionId::new(uuid::Uuid::from_u128(0x50));
            let second_enrollment = crate::identity::TransitionId::new(uuid::Uuid::from_u128(0x52));
            assert_ne!(first.nonce(), second.nonce());
            assert_ne!(&first.ciphertext()[..16], &second.ciphertext()[..16]);
            assert_eq!(first.enrollment(), first_enrollment);
            assert_eq!(second.enrollment(), second_enrollment);
            assert_eq!(
                channel.open_sealed_for_test(second_enrollment, &first),
                Err(crate::enrollment::EnrollmentCustodyError::ChannelNotAuthenticated),
            );
            let wrong_connection = crate::enrollment::EnrollmentChannel::open(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x54)), 7,
            ).unwrap();
            assert_eq!(
                wrong_connection.open_sealed_for_test(first_enrollment, &first),
                Err(crate::enrollment::EnrollmentCustodyError::ChannelNotAuthenticated),
            );
            let stale_epoch = crate::enrollment::EnrollmentChannel::open(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x53)), 8,
            ).unwrap();
            assert_eq!(
                stale_epoch.open_sealed_for_test(first_enrollment, &first),
                Err(crate::enrollment::EnrollmentCustodyError::ChannelNotAuthenticated),
            );
            assert!(!channel.open_sealed_for_test(first_enrollment, &first).unwrap().is_empty());
            assert!(!channel.open_sealed_for_test(second_enrollment, &second).unwrap().is_empty());
        }
    };
}
