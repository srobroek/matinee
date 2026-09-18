macro_rules! quickstart_evidence_tests {
    () => {
        const FR_EVIDENCE: &[(u8, &str)] = &[
            (2, "bootstrap"),
            (3, "secret-custody"),
            (4, "bootstrap"),
            (5, "bootstrap"),
            (6, "credential-store"),
            (7, "enrollment"),
            (8, "enrollment"),
            (9, "enrollment"),
            (10, "channel"),
            (11, "channel"),
            (12, "negotiation"),
            (13, "encoding"),
            (14, "channel"),
            (15, "frame"),
            (16, "rejection"),
            (17, "size"),
            (18, "origin"),
            (19, "enrollment"),
            (20, "authorization"),
            (21, "authorization"),
            (22, "privacy"),
            (23, "privacy"),
            (24, "rotation"),
            (25, "revocation"),
            (26, "transition"),
            (27, "events"),
            (28, "redaction"),
            (29, "failures"),
            (30, "vectors"),
            (31, "lifecycle"),
            (32, "vectors"),
        ];

        const SC_EVIDENCE: &[(u8, &str)] = &[
            (1, "bootstrap"),
            (2, "bootstrap-recovery"),
            (3, "channel-vectors"),
            (4, "authorization-privacy"),
            (5, "enrollment-custody"),
            (6, "rotation-revocation"),
            (7, "channel-faults"),
            (8, "disconnect-independence"),
            (9, "event-redaction"),
        ];

        fn fixture_path(relative: &str) -> std::path::PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
        }

        fn assert_no_secret_material(output: &str) {
            for forbidden in [
                "private_key",
                "one-time enrollment key",
                "enrollment_secret",
                "cookie",
                "authorization_header",
                "payload_text",
                "https://host/path",
                "object_id",
                "credential",
            ] {
                assert!(
                    !output.to_ascii_lowercase().contains(forbidden),
                    "quickstart evidence leaked forbidden material: {forbidden}"
                );
            }
        }

        #[test]
        fn quickstart_mapping_covers_every_required_fr_and_sc() {
            assert_eq!(FR_EVIDENCE.len(), 31);
            assert_eq!(SC_EVIDENCE.len(), 9);
            for (expected, (actual, evidence)) in (2..=32).zip(FR_EVIDENCE) {
                assert_eq!(expected, u32::from(*actual));
                assert!(!evidence.is_empty());
            }
            for (expected, (actual, evidence)) in (1..=9).zip(SC_EVIDENCE) {
                assert_eq!(expected, u32::from(*actual));
                assert!(!evidence.is_empty());
            }
        }

        #[test]
        fn node_webcrypto_fixture_records_pass_for_the_vector_peer() {
            let output = std::process::Command::new("node")
                .arg(fixture_path(
                    "fixtures/webcrypto/secure-channel-vectors.mjs",
                ))
                .output()
                .expect("Node.js WebCrypto fixture");
            assert!(
                output.status.success(),
                "WebCrypto fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("\"result\":\"pass\""), "{stdout}");
            assert_no_secret_material(&stdout);
        }

        #[test]
        fn chrome_capability_fixture_records_explicit_node_unsupported_result() {
            let output = std::process::Command::new("node")
                .arg(fixture_path("fixtures/chrome-capability/capability.mjs"))
                .output()
                .expect("Node.js Chrome capability fixture");
            assert!(
                output.status.success(),
                "Chrome capability fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("\"result\":\"unsupported\""), "{stdout}");
            assert!(stdout.contains("capability.unsupported"), "{stdout}");
            assert!(stdout.contains("\"channel_state\":\"closed\""), "{stdout}");
            assert_no_secret_material(&stdout);
        }

        #[test]
        fn typed_boundaries_are_bounded_and_fail_closed() {
            use crate::{FailureCode, PayloadKind};

            assert_eq!(PayloadKind::Command.max_bytes(), 1_048_534);
            assert_eq!(PayloadKind::StreamChunk.max_bytes(), 1_000_000);
            for code in [
                FailureCode::MalformedInput,
                FailureCode::ObjectNotFound,
                FailureCode::EventSinkUnavailable,
                FailureCode::TransitionUnknown,
            ] {
                assert!(!code.as_str().is_empty());
            }
            assert_eq!(FailureCode::ObjectNotFound.as_str(), "object.not_found");
            assert_eq!(
                FailureCode::EventSinkUnavailable.as_str(),
                "event_sink.unavailable"
            );
            assert_eq!(
                FailureCode::TransitionUnknown.as_str(),
                "transition.unknown"
            );
        }
    };
}
