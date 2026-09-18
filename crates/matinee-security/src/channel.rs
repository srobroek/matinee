//! Private v1 secure-channel transcript, framing, and AEAD state.

use ring::{aead, digest, hkdf};
use uuid::Uuid;

use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{Connection, ConnectionId};

const CONTEXT: &[u8] = b"matinee.secure-channel.v1";
const FRAME_VERSION: u8 = 1;
const HEADER_LEN: usize = 25;
const TAG_LEN: usize = 16;
const MAX_FRAME: usize = 1_048_576;
const MAX_PLAINTEXT: usize = 1_048_535;

#[derive(Debug)]
pub(crate) struct ChannelState {
    send: aead::LessSafeKey,
    receive: aead::LessSafeKey,
    send_counter: u64,
    receive_counter: u64,
    send_exhausted: bool,
    receive_exhausted: bool,
}

impl ChannelState {
    pub(crate) fn derive(connection: &Connection, contract: u16) -> Self {
        let mut seed = Vec::with_capacity(16 + 16 + 8 + 12 + 12 + 4);
        seed.extend_from_slice(connection.id().get().as_bytes());
        seed.extend_from_slice(connection.principal().get().as_bytes());
        seed.extend_from_slice(&connection.epoch().to_be_bytes());
        // The connection's nonces are transcript inputs; they are not secret key material.
        seed.extend_from_slice(&connection.client_nonce());
        seed.extend_from_slice(&connection.daemon_nonce());
        seed.extend_from_slice(&contract.to_be_bytes());
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, CONTEXT).extract(&seed);
        let send = derive_key(&prk, b"daemon-to-client");
        let receive = derive_key(&prk, b"client-to-daemon");
        Self { send, receive, send_counter: 0, receive_counter: 0, send_exhausted: false, receive_exhausted: false }
    }

    pub(crate) fn seal(&mut self, id: ConnectionId, epoch: u64, contract: u16, plaintext: &[u8]) -> Result<Vec<u8>, SecurityFailure> {
        if plaintext.len() > MAX_PLAINTEXT || self.send_exhausted {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        let counter = self.send_counter;
        if counter == u64::MAX { self.send_exhausted = true; }
        else { self.send_counter += 1; }
        let header = header(id, counter);
        let aad = aad(&header, contract, epoch, 1);
        let nonce = nonce(1, counter);
        let mut body = plaintext.to_vec();
        self.send.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(aad.as_slice()), &mut body)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    pub(crate) fn open(&mut self, frame: &[u8], id: ConnectionId, epoch: u64, contract: u16) -> Result<Vec<u8>, SecurityFailure> {
        if frame.len() < HEADER_LEN + TAG_LEN || frame.len() > MAX_FRAME {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let header = &frame[..HEADER_LEN];
        if header[0] != FRAME_VERSION || header[1..17] != *id.get().as_bytes() {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let counter = u64::from_be_bytes(header[17..25].try_into().map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?);
        if self.receive_exhausted || counter != self.receive_counter {
            return Err(SecurityFailure::new(if counter < self.receive_counter { FailureCode::ReplayDetected } else { FailureCode::CounterMismatch }));
        }
        let mut body = frame[HEADER_LEN..].to_vec();
        let aad = aad(header, contract, epoch, 0);
        let plaintext = self.receive.open_in_place(aead::Nonce::assume_unique_for_key(nonce(0, counter)), aead::Aad::from(aad.as_slice()), &mut body)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        if plaintext.len() > MAX_PLAINTEXT { return Err(SecurityFailure::new(FailureCode::ResourceLimit)); }
        if counter == u64::MAX { self.receive_exhausted = true; }
        else { self.receive_counter += 1; }
        Ok(plaintext.to_vec())
    }
}

fn derive_key(prk: &hkdf::Prk, direction: &[u8]) -> aead::LessSafeKey {
    let info = [&b"matinee.secure-channel.v1"[..], direction];
    let okm = prk.expand(&info, AesKey).expect("fixed HKDF info and output");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("fixed HKDF output");
    aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key).expect("32-byte AES key"))
}

struct AesKey;
impl hkdf::KeyType for AesKey { fn len(&self) -> usize { 32 } }

fn header(id: ConnectionId, counter: u64) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = FRAME_VERSION;
    out[1..17].copy_from_slice(id.get().as_bytes());
    out[17..25].copy_from_slice(&counter.to_be_bytes());
    out
}

fn nonce(direction: u32, counter: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&direction.to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn aad(header: &[u8], contract: u16, epoch: u64, direction: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(25 + 4 + CONTEXT.len() + 6 + 8 + 8);
    out.extend_from_slice(header);
    lp(&mut out, CONTEXT);
    lp(&mut out, &contract.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    lp(&mut out, &direction.to_be_bytes());
    out
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[allow(dead_code)]
pub(crate) fn transcript_hash(input: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, input).as_ref().try_into().expect("SHA-256 is 32 bytes")
}

#[allow(dead_code)]
pub(crate) fn validate_contract(minimum: u16, maximum: u16, selected: u16) -> Result<u16, FailureCode> {
    if minimum > maximum { return Err(FailureCode::DowngradeRejected); }
    if selected < minimum || selected > maximum { return Err(FailureCode::CompatibilityUnsupported); }
    Ok(selected)
}
