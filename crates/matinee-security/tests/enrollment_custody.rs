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
            let mut connection = crate::identity::Connection::new(
                crate::identity::ConnectionId::new(uuid::Uuid::from_u128(0x42)),
                crate::identity::IdentityId::new(uuid::Uuid::from_u128(0x43)),
                1, 1, [0; 12], [1; 12], uuid::Uuid::from_u128(0x44), uuid::Uuid::from_u128(0x45),
            );
            connection.authenticate().unwrap();
            let session = crate::ChannelSession::establish(connection, 1, "127.0.0.1:7777").unwrap();
            let capability = session.enrollment_output_capability().unwrap();
            let output = bundle.encrypted_private_key_output(&capability).unwrap();
            assert!(!output.ciphertext().is_empty());
            assert!(bundle.encrypted_private_key_output(&capability).is_err());
            assert!(!output.decrypt_for_channel(&capability).unwrap().is_empty());
            assert!(!format!("{bundle:?}").contains("PKCS#8"));
        }
    };
}
