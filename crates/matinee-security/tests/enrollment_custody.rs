macro_rules! enrollment_custody_tests {
    () => {
        #[test]
        fn production_bundle_exposes_pkcs8_only_through_one_time_take() {
            let input = crate::enrollment::EnrollmentCreation::new(
                crate::identity::TransitionId::new(uuid::Uuid::from_u128(0x40)),
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
                "Chrome Web Store",
                "https://updates.example.test/ext.xml",
                "normal",
                crate::identity::IdentityId::new(uuid::Uuid::from_u128(0x41)),
                "127.0.0.1:7777",
                crate::identity::ExpiryResult::valid(600_000).unwrap(),
            );
            let mut bundle = crate::enrollment::create_enrollment(input).unwrap();
            let debug = format!("{bundle:?}");
            assert!(debug.contains("<redacted>"));
            let pkcs8 = bundle.take_one_time_private_key().unwrap();
            assert!(!pkcs8.is_empty());
            assert!(bundle.take_one_time_private_key().is_none());
            assert!(!format!("{bundle:?}").contains("PKCS#8"));
        }
    };
}
