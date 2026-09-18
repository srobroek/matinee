use matinee_security::{
    AuthorizedOutput, Capability, CapabilityAction, ChannelSigner, ChannelSigningError,
    ClientHandshake, ClientHandshakeConfig, ConnectionId, IdentityId, PayloadKind, PublicKey,
    SecurityEvent, SecurityEventSink, SecurityEventSinkResult, ServerHandshake,
    ServerHandshakeConfig, SessionInput,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

struct Signer {
    key: EcdsaKeyPair,
    public: PublicKey,
}

impl Signer {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public =
            PublicKey::from_uncompressed(key.public_key().as_ref().try_into().unwrap()).unwrap();
        Self { key, public }
    }
}

impl ChannelSigner for Signer {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_p1363(&self, transcript: &[u8]) -> Result<[u8; 64], ChannelSigningError> {
        self.key
            .sign(&SystemRandom::new(), transcript)
            .map_err(|_| ChannelSigningError)?
            .as_ref()
            .try_into()
            .map_err(|_| ChannelSigningError)
    }
}

#[derive(Default)]
struct Sink(Vec<SecurityEvent>);

impl SecurityEventSink for Sink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        self.0.push(event);
        SecurityEventSinkResult::Accepted
    }
}

#[test]
fn external_consumer_establishes_and_uses_only_the_typed_boundary() {
    let client_signer = Signer::generate();
    let daemon_signer = Signer::generate();
    let principal = IdentityId::new(Uuid::from_u128(1));
    let daemon = IdentityId::new(Uuid::from_u128(2));
    let connection = ConnectionId::new(Uuid::from_u128(3));
    let client_config = ClientHandshakeConfig::new(
        "127.0.0.1:7777",
        principal,
        client_signer.public.clone(),
        daemon,
        daemon_signer.public.clone(),
        7,
        1,
        3,
    )
    .unwrap();
    let server_config = ServerHandshakeConfig::new(
        "127.0.0.1:7777",
        principal,
        client_signer.public.clone(),
        daemon,
        daemon_signer.public.clone(),
        7,
        2,
        4,
        connection,
    )
    .unwrap();
    let mut sink = Sink::default();
    let (client_pending, hello) = ClientHandshake::start(client_config).unwrap();
    let (server_pending, proof) =
        ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink).unwrap();
    let (mut client, client_proof) = client_pending
        .finish(&proof, &client_signer, &mut sink)
        .unwrap();
    let mut server = server_pending.finish(&client_proof, &mut sink).unwrap();

    let output = AuthorizedOutput::filtered(PayloadKind::Command, b"status".to_vec()).unwrap();
    let frame = client.send(&output, &mut sink).unwrap();
    let input = SessionInput::new(
        connection,
        principal,
        7,
        Capability::new(CapabilityAction::Read, "matinee/status").unwrap(),
        PayloadKind::Command,
    );
    assert_eq!(
        server.receive(&frame, &input, &mut sink).unwrap().payload(),
        b"status"
    );
}
