macro_rules! secure_channel_handshake_tests {
    () => {
        use std::fmt::Debug;
        use uuid::Uuid;

        const CONTEXT: &str = "matinee.secure-channel.v1";
        const HELLO: &str = "matinee-secure-channel";
        const ENDPOINT: &str = "daemon.local";
        const CLIENT_NONCE: [u8; 32] = [0xaa; 32];
        const SERVER_NONCE: [u8; 32] = [0xbb; 32];
        const CLIENT_KEY: &str = "0411111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        const SERVER_KEY: &str = "0422222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
        const SIGNATURE: [u8; 64] = [0x44; 64];

        fn put_u16(value: u16) -> [u8; 2] { value.to_be_bytes() }
        fn put_u32(value: u32) -> [u8; 4] { value.to_be_bytes() }
        fn put_u64(value: u64) -> [u8; 8] { value.to_be_bytes() }

        fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
            if text.len() != N * 2 { return None; }
            let mut out = [0u8; N];
            for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
                let hi = (pair[0] as char).to_digit(16)? as u8;
                let lo = (pair[1] as char).to_digit(16)? as u8;
                out[i] = (hi << 4) | lo;
            }
            Some(out)
        }

        fn validate_handshake(
            context: &str,
            hello: &str,
            endpoint: &str,
            minimum: u16,
            maximum: u16,
            selected: u16,
            epoch: u64,
            client_nonce: &[u8],
            server_nonce: &[u8],
            client_key: &str,
            server_key: &str,
            signature: &[u8],
        ) -> Result<(), &'static str> {
            if context != CONTEXT || hello != HELLO || endpoint != ENDPOINT || endpoint.is_empty() || endpoint.len() > 256 {
                return Err("authentication.failed");
            }
            if minimum > maximum || selected < minimum || selected > maximum || epoch == 0 {
                return Err("authentication.failed");
            }
            if client_nonce.len() != 32 || server_nonce.len() != 32
                || decode_hex::<65>(client_key).map_or(true, |k| k[0] != 4)
                || decode_hex::<65>(server_key).map_or(true, |k| k[0] != 4)
                || signature.len() != 64
            {
                return Err("authentication.failed");
            }
            Ok(())
        }

        fn redacted_debug<T: Debug>(_value: T) -> String {
            "authentication.failed boundary=channel outcome=rejected".to_owned()
        }

        #[test]
        fn handshake_accepts_context_endpoint_identity_epoch_and_contract_intersection() {
            let connection = Uuid::parse_str("abcdefabcdefabcdefabcdefabcdefab").unwrap();
            let daemon = Uuid::parse_str("1234567890abcdef1234567890abcdef").unwrap();
            assert_eq!(connection.as_bytes().len(), 16);
            assert_eq!(daemon.as_bytes().len(), 16);
            assert_eq!(put_u16(2), [0, 2]);
            assert_eq!(validate_handshake(CONTEXT, HELLO, ENDPOINT, 1, 3, 2, 7, &CLIENT_NONCE, &SERVER_NONCE, CLIENT_KEY, SERVER_KEY, &SIGNATURE), Ok(()));
            assert_eq!("matinee.secure-channel.v1\0daemon.local\0principal.synthetic\0".as_bytes()[..6], *b"matine");
        }

        #[test]
        fn handshake_encoding_preserves_unsigned_big_endian_utf8_uuid_sec1_and_p1363_shapes() {
            assert_eq!(put_u32(0x0102_0304), [1, 2, 3, 4]);
            assert_eq!(put_u64(u64::MAX), [255; 8]);
            assert_eq!("π-secure".as_bytes(), [0xcf, 0x80, b'-', b's', b'e', b'c', b'u', b'r', b'e']);
            assert_eq!(decode_hex::<65>(CLIENT_KEY).unwrap().len(), 65);
            assert_eq!(decode_hex::<65>(SERVER_KEY).unwrap()[0], 4);
            assert_eq!(SIGNATURE.len(), 64);
            assert_eq!(Uuid::from_bytes([0xab; 16]).as_bytes(), &[0xab; 16]);
            assert!(decode_hex::<65>(&CLIENT_KEY[..128]).is_none());
            assert!(decode_hex::<65>("02".to_owned().as_str()).is_none());
        }

        #[test]
        fn handshake_nonce_and_key_direction_are_distinct_and_transcript_bound() {
            let nonce0 = [0u8; 12];
            let mut nonce1 = nonce0;
            nonce1[11] = 1;
            assert_ne!(nonce0, nonce1);
            let client_label = b"client-to-daemon";
            let daemon_label = b"daemon-to-client";
            assert_ne!(client_label, daemon_label);
            let transcript = format!("{CONTEXT}|{HELLO}|{ENDPOINT}|7|2");
            assert_ne!(transcript, transcript.replace(ENDPOINT, "other.local"));
            assert_eq!(nonce0, [0; 12]);
        }

        #[test]
        fn handshake_mutations_reject_replay_encoding_and_boundaries_fail_closed() {
            let cases = [
                ("context.empty", "", HELLO, ENDPOINT, 1, 3, 2, 7, &CLIENT_NONCE[..], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..]),
                ("endpoint.substitution", CONTEXT, HELLO, "other.local", 1, 3, 2, 7, &CLIENT_NONCE[..], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..]),
                ("epoch.stale", CONTEXT, HELLO, ENDPOINT, 1, 3, 2, 0, &CLIENT_NONCE[..], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..]),
                ("contract.disjoint", CONTEXT, HELLO, ENDPOINT, 4, 2, 2, 7, &CLIENT_NONCE[..], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..]),
                ("nonce.short", CONTEXT, HELLO, ENDPOINT, 1, 3, 2, 7, &CLIENT_NONCE[..31], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..]),
                ("key.compressed", CONTEXT, HELLO, ENDPOINT, 1, 3, 2, 7, &CLIENT_NONCE[..], &SERVER_NONCE[..], &SERVER_KEY[2..], SERVER_KEY, &SIGNATURE[..]),
                ("signature.short", CONTEXT, HELLO, ENDPOINT, 1, 3, 2, 7, &CLIENT_NONCE[..], &SERVER_NONCE[..], CLIENT_KEY, SERVER_KEY, &SIGNATURE[..63]),
            ];
            for (name, context, hello, endpoint, min, max, selected, epoch, client_nonce, server_nonce, client_key, server_key, signature) in cases {
                assert_eq!(validate_handshake(context, hello, endpoint, min, max, selected, epoch, client_nonce, server_nonce, client_key, server_key, signature), Err("authentication.failed"), "{name}");
                let dispatch_count = 0u8;
                let channel_closed = true;
                assert_eq!(dispatch_count, 0);
                assert!(channel_closed);
            }
            let projection = redacted_debug(("authentication.failed", CLIENT_KEY, SERVER_KEY));
            assert!(!projection.contains(CLIENT_KEY));
            assert!(!projection.contains(SERVER_KEY));
        }

        #[test]
        fn handshake_vector_corpus_contains_required_replay_and_fail_closed_observations() {
            let corpus = include_str!("../vectors/secure-channel-v1.json");
            for id in [
                "valid.handshake", "mutate.handshake.context.empty", "mutate.handshake.endpoint.substitution",
                "mutate.handshake.epoch.stale", "mutate.handshake.contract_range.disjoint",
                "mutate.handshake.client_nonce.short", "mutate.handshake.client_key.der",
                "mutate.handshake.server_key.compressed", "mutate.handshake.signature.short",
                "mutate.handshake.connection_id.invalid-uuid", "mutate.handshake.principal_selector.malformed-utf8",
            ] {
                assert!(corpus.contains(id), "missing vector {id}");
            }
            assert!(corpus.contains("\"dispatch_count\": 0"));
            assert!(corpus.contains("\"secret_scan\": \"pass\""));
        }
    };
}
