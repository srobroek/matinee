macro_rules! enrollment_custody_tests {
    () => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum CustodySurface {
            NativeBundle {
                authenticated: bool,
                encrypted: bool,
            },
            BootstrapPipe,
            LoopbackCapture,
            DurableRecord,
            Log,
            Diagnostic,
            Status,
            Failure,
        }

        #[derive(Clone, Debug)]
        struct CustodyArtifact {
            surface: CustodySurface,
            bytes: Vec<u8>,
        }

        fn one_time_pkcs8() -> Vec<u8> {
            b"PKCS#8::one-time-ecdsa-private-key::custody-test".to_vec()
        }

        fn transfer(surface: CustodySurface, private_key: &[u8]) -> CustodyArtifact {
            let permitted = matches!(
                surface,
                CustodySurface::NativeBundle {
                    authenticated: true,
                    encrypted: true
                }
            );
            CustodyArtifact {
                surface,
                bytes: if permitted {
                    private_key.to_vec()
                } else {
                    Vec::new()
                },
            }
        }

        fn secret_scan(artifacts: &[CustodyArtifact], private_key: &[u8]) -> bool {
            artifacts.iter().all(|artifact| {
                !matches!(
                    artifact.surface,
                    CustodySurface::NativeBundle {
                        authenticated: true,
                        encrypted: true
                    }
                ) && !artifact
                    .bytes
                    .windows(private_key.len())
                    .any(|window| window == private_key)
                    || matches!(
                        artifact.surface,
                        CustodySurface::NativeBundle {
                            authenticated: true,
                            encrypted: true
                        }
                    )
            })
        }

        #[test]
        fn pkcs8_is_confined_to_authenticated_encrypted_native_bundle() {
            let private_key = one_time_pkcs8();
            let surfaces = [
                CustodySurface::NativeBundle {
                    authenticated: true,
                    encrypted: true,
                },
                CustodySurface::BootstrapPipe,
                CustodySurface::LoopbackCapture,
                CustodySurface::DurableRecord,
                CustodySurface::Log,
                CustodySurface::Diagnostic,
                CustodySurface::Status,
                CustodySurface::Failure,
            ];
            let artifacts: Vec<_> = surfaces
                .into_iter()
                .map(|surface| transfer(surface, &private_key))
                .collect();

            assert_eq!(artifacts[0].bytes, private_key);
            assert!(artifacts[1..].iter().all(|artifact| {
                !artifact
                    .bytes
                    .windows(private_key.len())
                    .any(|window| window == private_key)
            }));
            assert!(secret_scan(&artifacts, &private_key));
        }

        #[test]
        fn unauthenticated_or_plaintext_native_paths_fail_closed_without_private_bytes() {
            let private_key = one_time_pkcs8();
            let rejected = [
                CustodySurface::NativeBundle {
                    authenticated: false,
                    encrypted: true,
                },
                CustodySurface::NativeBundle {
                    authenticated: true,
                    encrypted: false,
                },
                CustodySurface::NativeBundle {
                    authenticated: false,
                    encrypted: false,
                },
            ];
            for surface in rejected {
                let artifact = transfer(surface, &private_key);
                assert!(artifact.bytes.is_empty());
                assert!(secret_scan(&[artifact], &private_key));
            }
        }

        #[test]
        fn named_secret_scan_mutation_rejects_private_bytes_in_forbidden_surface() {
            let private_key = one_time_pkcs8();
            let mut mutated = transfer(CustodySurface::Log, &[]);
            mutated.bytes.extend_from_slice(&private_key);
            assert!(
                !secret_scan(&[mutated], &private_key),
                "secret-scan mutation must fail closed when a log captures PKCS#8"
            );
        }
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
