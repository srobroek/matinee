use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

use crate::{
    ChannelSession, ChannelSigner, ChannelSigningError, ClientHandshake, ClientHandshakeConfig,
    ConnectionId, IdentityId, PublicKey, SecurityEvent, SecurityEventSink, SecurityEventSinkResult,
    ServerHandshake, ServerHandshakeConfig,
};

pub(crate) const ENDPOINT: &str = "127.0.0.1:7777";
pub(crate) const PRINCIPAL: u128 = 2;
pub(crate) const DAEMON: u128 = 3;
pub(crate) const CONNECTION: u128 = 0xabcdefabcdefabcdefabcdefabcd;

pub(crate) struct RingSigner {
    key: EcdsaKeyPair,
    public: PublicKey,
}

impl RingSigner {
    pub(crate) fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("fixture key generation");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("fixture key import");
        let public = PublicKey::from_uncompressed(
            key.public_key()
                .as_ref()
                .try_into()
                .expect("P-256 public key length"),
        )
        .expect("valid fixture public key");
        Self { key, public }
    }
}

impl ChannelSigner for RingSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_p1363(&self, transcript: &[u8]) -> Result<[u8; 64], ChannelSigningError> {
        let signature = self
            .key
            .sign(&SystemRandom::new(), transcript)
            .map_err(|_| ChannelSigningError)?;
        signature
            .as_ref()
            .try_into()
            .map_err(|_| ChannelSigningError)
    }
}

#[derive(Default)]
pub(crate) struct RecordingSink {
    pub(crate) events: Vec<SecurityEvent>,
    pub(crate) unavailable: bool,
}

impl SecurityEventSink for RecordingSink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        if self.unavailable {
            SecurityEventSinkResult::Unavailable
        } else {
            self.events.push(event);
            SecurityEventSinkResult::Accepted
        }
    }
}

pub(crate) fn establish_pair(epoch: u64) -> (ChannelSession, ChannelSession) {
    establish_pair_with_ranges(epoch, (1, 3), (2, 4)).expect("production handshake fixture")
}

pub(crate) fn establish_pair_with_ranges(
    epoch: u64,
    client_range: (u16, u16),
    server_range: (u16, u16),
) -> Result<(ChannelSession, ChannelSession), crate::SecurityFailure> {
    let principal = IdentityId::new(Uuid::from_u128(PRINCIPAL));
    let daemon = IdentityId::new(Uuid::from_u128(DAEMON));
    let connection = ConnectionId::new(Uuid::from_u128(CONNECTION));
    let client_signer = RingSigner::generate();
    let server_signer = RingSigner::generate();
    let client = ClientHandshakeConfig::new(
        ENDPOINT,
        principal,
        client_signer.public.clone(),
        daemon,
        server_signer.public.clone(),
        epoch,
        client_range.0,
        client_range.1,
    )?;
    let server = ServerHandshakeConfig::new(
        ENDPOINT,
        principal,
        client_signer.public.clone(),
        daemon,
        server_signer.public.clone(),
        epoch,
        server_range.0,
        server_range.1,
        connection,
    )?;
    let mut sink = RecordingSink::default();
    let (client_pending, hello) = ClientHandshake::start(client)?;
    let (server_pending, proof) =
        ServerHandshake::accept(server, &hello, &server_signer, &mut sink)?;
    let (client_session, client_proof) =
        client_pending.finish(&proof, &client_signer, &mut sink)?;
    let server_session = server_pending.finish(&client_proof, &mut sink)?;
    Ok((client_session, server_session))
}
