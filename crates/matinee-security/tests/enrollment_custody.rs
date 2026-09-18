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
            let mut bundle = crate::enrollment::create_enrollment(input).unwrap();
            let channel = crate::enrollment::EnrollmentChannel::open(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x42)), 1,
            )
            .expect("open native channel");
            let output = channel.seal_one_time_key(&mut bundle).unwrap();
            assert!(!output.ciphertext().is_empty());
            assert!(channel.seal_one_time_key(&mut bundle).is_err());
            assert!(!channel.open_sealed(&output).unwrap().is_empty());
            assert!(!format!("{bundle:?}").contains("PKCS#8"));
        }
    };
}
