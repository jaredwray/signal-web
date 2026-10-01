//! Linked-device provisioning ("Link a device" QR flow), browser side.
//!
//! Mirrors the current official implementation:
//! - Signal-Desktop@abe80d3 ts/textsecure/ProvisioningCipher.node.ts (crypto),
//!   ts/textsecure/Provisioner.preload.ts + ts/util/signalRoutes.std.ts (QR URL),
//!   protos/DeviceMessages.proto (ProvisionEnvelope / ProvisionMessage);
//! - libsignal@e8cc2dd rust/net/src/chat/server_requests.rs and
//!   rust/net/src/proto/{chat_websocket,chat_provisioning}.proto (framing).
//!
//! On the provisioning WebSocket (`/v1/websocket/provisioning/`) the server
//! sends WebSocketMessage requests `PUT /v1/address` (ProvisioningAddress) and,
//! after the phone approves, `PUT /v1/message` (ProvisionEnvelope). Each is
//! acknowledged with a 200 response carrying the same request id.
//!
//! Envelope body: version (1) || IV (16) || AES-256-CBC/PKCS7 ciphertext ||
//! HMAC-SHA256 (32) over everything before it. Keys: HKDF-SHA256 over
//! ECDH(our ephemeral private key, envelope.publicKey), salt = 32 zero bytes,
//! info = "TextSecure Provisioning Message"; first 32 bytes AES, next 32 MAC.
//!
//! Decrypted account secrets stay inside WASM memory; JavaScript only receives
//! a non-secret summary.

use base64::Engine as _;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac as _};
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey};
use prost::Message as _;
use rand::Rng as _;
use serde::Serialize;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

const PROVISIONING_INFO: &[u8] = b"TextSecure Provisioning Message";
const BODY_VERSION: u8 = 1;
const MAC_LEN: usize = 32;
const IV_LEN: usize = 16;
/// Capabilities Signal-Desktop advertises when link-and-sync is disabled.
const LINK_CAPABILITIES: &str = "nopni";

pub mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct WebSocketRequestMessage {
        #[prost(string, optional, tag = "1")]
        pub verb: Option<String>,
        #[prost(string, optional, tag = "2")]
        pub path: Option<String>,
        #[prost(bytes = "vec", optional, tag = "3")]
        pub body: Option<Vec<u8>>,
        #[prost(string, repeated, tag = "5")]
        pub headers: Vec<String>,
        #[prost(uint64, optional, tag = "4")]
        pub id: Option<u64>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct WebSocketResponseMessage {
        #[prost(uint64, optional, tag = "1")]
        pub id: Option<u64>,
        #[prost(uint32, optional, tag = "2")]
        pub status: Option<u32>,
        #[prost(string, optional, tag = "3")]
        pub message: Option<String>,
        #[prost(string, repeated, tag = "5")]
        pub headers: Vec<String>,
        #[prost(bytes = "vec", optional, tag = "4")]
        pub body: Option<Vec<u8>>,
    }

    pub const TYPE_REQUEST: i32 = 1;
    pub const TYPE_RESPONSE: i32 = 2;

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct WebSocketMessage {
        #[prost(int32, optional, tag = "1")]
        pub r#type: Option<i32>,
        #[prost(message, optional, tag = "2")]
        pub request: Option<WebSocketRequestMessage>,
        #[prost(message, optional, tag = "3")]
        pub response: Option<WebSocketResponseMessage>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ProvisioningAddress {
        #[prost(string, optional, tag = "1")]
        pub address: Option<String>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ProvisionEnvelope {
        #[prost(bytes = "vec", optional, tag = "1")]
        pub public_key: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "2")]
        pub body: Option<Vec<u8>>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ProvisionMessage {
        #[prost(bytes = "vec", optional, tag = "1")]
        pub aci_identity_key_public: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "2")]
        pub aci_identity_key_private: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "11")]
        pub pni_identity_key_public: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "12")]
        pub pni_identity_key_private: Option<Vec<u8>>,
        #[prost(string, optional, tag = "8")]
        pub aci: Option<String>,
        #[prost(string, optional, tag = "10")]
        pub pni: Option<String>,
        #[prost(string, optional, tag = "3")]
        pub number: Option<String>,
        #[prost(string, optional, tag = "4")]
        pub provisioning_code: Option<String>,
        #[prost(string, optional, tag = "5")]
        pub user_agent: Option<String>,
        #[prost(bytes = "vec", optional, tag = "6")]
        pub profile_key: Option<Vec<u8>>,
        #[prost(bool, optional, tag = "7")]
        pub read_receipts: Option<bool>,
        #[prost(uint32, optional, tag = "9")]
        pub provisioning_version: Option<u32>,
        #[prost(bytes = "vec", optional, tag = "13")]
        pub master_key: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "14")]
        pub ephemeral_backup_key: Option<Vec<u8>>,
        #[prost(string, optional, tag = "15")]
        pub account_entropy_pool: Option<String>,
        #[prost(bytes = "vec", optional, tag = "16")]
        pub media_root_backup_key: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "17")]
        pub aci_binary: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "18")]
        pub pni_binary: Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "19")]
        pub auth_credential_salt: Option<Vec<u8>>,
    }
}

#[derive(Debug, PartialEq)]
pub enum ProvisioningError {
    Frame(&'static str),
    Envelope(&'static str),
    BadVersion(u8),
    BadMac,
    Decrypt,
    Protobuf,
}

impl std::fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(m) => write!(f, "malformed provisioning frame: {m}"),
            Self::Envelope(m) => write!(f, "malformed provision envelope: {m}"),
            Self::BadVersion(v) => write!(f, "unsupported provisioning body version {v}"),
            Self::BadMac => write!(f, "provision envelope MAC verification failed"),
            Self::Decrypt => write!(f, "provision envelope decryption failed"),
            Self::Protobuf => write!(f, "invalid ProvisionMessage protobuf"),
        }
    }
}

fn derive_keys(
    private: &PrivateKey,
    their_public: &PublicKey,
) -> Result<[u8; 64], ProvisioningError> {
    let shared = private
        .calculate_agreement(their_public)
        .map_err(|_| ProvisioningError::Envelope("key agreement failed"))?;
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), &shared)
        .expand(PROVISIONING_INFO, &mut okm)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    Ok(okm)
}

/// Decrypts a serialized ProvisionEnvelope addressed to `private`.
pub fn decrypt_envelope(
    private: &PrivateKey,
    envelope: &[u8],
) -> Result<proto::ProvisionMessage, ProvisioningError> {
    let env = proto::ProvisionEnvelope::decode(envelope)
        .map_err(|_| ProvisioningError::Envelope("not a ProvisionEnvelope"))?;
    let their = PublicKey::deserialize(
        env.public_key
            .as_deref()
            .ok_or(ProvisioningError::Envelope("missing publicKey"))?,
    )
    .map_err(|_| ProvisioningError::Envelope("invalid publicKey"))?;
    let body = env
        .body
        .ok_or(ProvisioningError::Envelope("missing body"))?;
    if body.len() < 1 + IV_LEN + 16 + MAC_LEN {
        return Err(ProvisioningError::Envelope("body too short"));
    }
    if body[0] != BODY_VERSION {
        return Err(ProvisioningError::BadVersion(body[0]));
    }
    let (signed, mac) = body.split_at(body.len() - MAC_LEN);
    let okm = derive_keys(private, &their)?;
    let (aes_key, mac_key) = okm.split_at(32);
    // Constant-time MAC check before touching the ciphertext.
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("any key length");
    hmac.update(signed);
    hmac.verify_slice(mac)
        .map_err(|_| ProvisioningError::BadMac)?;
    let iv = &signed[1..1 + IV_LEN];
    let ciphertext = &signed[1 + IV_LEN..];
    let plaintext = signal_crypto::aes_256_cbc_decrypt(ciphertext, aes_key, iv)
        .map_err(|_| ProvisioningError::Decrypt)?;
    proto::ProvisionMessage::decode(plaintext.as_slice()).map_err(|_| ProvisioningError::Protobuf)
}

/// Phone-side encryption, used only by local tests. (The independent check
/// against a separate implementation is web/testdata/provisioning-vector.json.)
pub fn encrypt_for_test(recipient: &PublicKey, message: &proto::ProvisionMessage) -> Vec<u8> {
    let mut rng = rand::rng();
    let ephemeral = KeyPair::generate(&mut rng);
    let okm = derive_keys(&ephemeral.private_key, recipient).expect("valid keys");
    let (aes_key, mac_key) = okm.split_at(32);
    let iv: [u8; IV_LEN] = rng.random();
    let ciphertext = signal_crypto::aes_256_cbc_encrypt(&message.encode_to_vec(), aes_key, &iv)
        .expect("valid key and iv");
    let mut body = vec![BODY_VERSION];
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("any key length");
    hmac.update(&body);
    body.extend_from_slice(&hmac.finalize().into_bytes());
    proto::ProvisionEnvelope {
        public_key: Some(ephemeral.public_key.serialize().to_vec()),
        body: Some(body),
    }
    .encode_to_vec()
}

/// application/x-www-form-urlencoded serialization, as URLSearchParams does.
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn link_url(address: &str, public_key: &PublicKey) -> String {
    let pub_key = base64::engine::general_purpose::STANDARD.encode(public_key.serialize());
    format!(
        "sgnl://linkdevice?uuid={}&pub_key={}&capabilities={}",
        form_urlencode(address),
        form_urlencode(&pub_key),
        form_urlencode(LINK_CAPABILITIES)
    )
}

pub fn qr_svg(data: &str) -> Result<String, String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build())
}

fn ack(id: u64) -> Vec<u8> {
    proto::WebSocketMessage {
        r#type: Some(proto::TYPE_RESPONSE),
        request: None,
        response: Some(proto::WebSocketResponseMessage {
            id: Some(id),
            status: Some(200),
            message: Some("OK".into()),
            headers: Vec::new(),
            body: None,
        }),
    }
    .encode_to_vec()
}

#[derive(Serialize, Debug, PartialEq)]
pub struct ProvisionSummary {
    pub aci: Option<String>,
    pub pni: Option<String>,
    pub has_number: bool,
    pub has_provisioning_code: bool,
    pub has_aci_identity_key_pair: bool,
    pub has_pni_identity_key_pair: bool,
    pub has_profile_key: bool,
    pub has_account_entropy_pool: bool,
    pub has_master_key: bool,
    pub provisioning_version: Option<u32>,
}

impl From<&proto::ProvisionMessage> for ProvisionSummary {
    fn from(m: &proto::ProvisionMessage) -> Self {
        let present = |b: &Option<Vec<u8>>| b.as_ref().is_some_and(|b| !b.is_empty());
        Self {
            aci: m.aci.clone(),
            pni: m.pni.clone(),
            has_number: m.number.as_ref().is_some_and(|n| !n.is_empty()),
            has_provisioning_code: m.provisioning_code.as_ref().is_some_and(|c| !c.is_empty()),
            has_aci_identity_key_pair: present(&m.aci_identity_key_private)
                && present(&m.aci_identity_key_public),
            has_pni_identity_key_pair: present(&m.pni_identity_key_private)
                && present(&m.pni_identity_key_public),
            has_profile_key: present(&m.profile_key),
            has_account_entropy_pool: m
                .account_entropy_pool
                .as_ref()
                .is_some_and(|a| !a.is_empty()),
            has_master_key: present(&m.master_key),
            provisioning_version: m.provisioning_version,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FrameEvent {
    /// The server assigned a provisioning address: show `link_url` as a QR code.
    Address { link_url: String, ack_b64: String },
    /// The phone approved: the envelope decrypted successfully.
    Provisioned {
        summary: ProvisionSummary,
        ack_b64: String,
    },
    /// A response frame or other message that needs no action.
    Ignored { reason: String },
}

/// One provisioning attempt: an ephemeral key pair plus the state received so far.
#[wasm_bindgen]
pub struct ProvisioningSession {
    key_pair: KeyPair,
    address: Option<String>,
    provisioned: Option<proto::ProvisionMessage>,
}

impl ProvisioningSession {
    pub fn from_key_pair(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            address: None,
            provisioned: None,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key
    }

    pub fn provisioned(&self) -> Option<&proto::ProvisionMessage> {
        self.provisioned.as_ref()
    }

    pub fn handle(&mut self, frame: &[u8]) -> Result<FrameEvent, ProvisioningError> {
        let msg = proto::WebSocketMessage::decode(frame)
            .map_err(|_| ProvisioningError::Frame("not a WebSocketMessage"))?;
        if msg.r#type != Some(proto::TYPE_REQUEST) {
            return Ok(FrameEvent::Ignored {
                reason: format!("frame type {:?}", msg.r#type),
            });
        }
        let req = msg
            .request
            .ok_or(ProvisioningError::Frame("missing request"))?;
        let id = req
            .id
            .ok_or(ProvisioningError::Frame("missing request id"))?;
        if req.verb.as_deref() != Some("PUT") {
            return Err(ProvisioningError::Frame("unexpected verb"));
        }
        let ack_b64 = base64::engine::general_purpose::STANDARD.encode(ack(id));
        match req.path.as_deref() {
            Some("/v1/address") => {
                let addr =
                    proto::ProvisioningAddress::decode(req.body.unwrap_or_default().as_slice())
                        .map_err(|_| ProvisioningError::Frame("bad ProvisioningAddress"))?
                        .address
                        .filter(|a| !a.is_empty())
                        .ok_or(ProvisioningError::Frame("empty provisioning address"))?;
                let link_url = link_url(&addr, &self.key_pair.public_key);
                self.address = Some(addr);
                Ok(FrameEvent::Address { link_url, ack_b64 })
            }
            Some("/v1/message") => {
                let message =
                    decrypt_envelope(&self.key_pair.private_key, &req.body.unwrap_or_default())?;
                let summary = ProvisionSummary::from(&message);
                self.provisioned = Some(message);
                Ok(FrameEvent::Provisioned { summary, ack_b64 })
            }
            _ => Err(ProvisioningError::Frame("unexpected path")),
        }
    }
}

#[wasm_bindgen]
impl ProvisioningSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ProvisioningSession {
        Self::from_key_pair(KeyPair::generate(&mut rand::rng()))
    }

    /// Handles one binary frame from the provisioning WebSocket and returns a
    /// JSON FrameEvent. `ack_b64` must be sent back on the socket.
    #[wasm_bindgen(js_name = handleFrame)]
    pub fn handle_frame(&mut self, frame: &[u8]) -> Result<String, JsError> {
        let event = self
            .handle(frame)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_json::to_string(&event).expect("serializable"))
    }

    /// SVG QR code for the current link URL, only once the server has
    /// assigned a real provisioning address.
    #[wasm_bindgen(js_name = linkQrSvg)]
    pub fn link_qr_svg(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        qr_svg(&link_url(addr, &self.key_pair.public_key)).ok()
    }
}

impl Default for ProvisioningSession {
    fn default() -> Self {
        Self::new()
    }
}
