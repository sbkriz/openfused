use std::fs;
use std::path::Path;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const KEY_DIR: &str = ".keys";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    pub from: String,
    pub timestamp: String,
    pub message: String,
    pub signature: String,
    pub public_key: String,
}

pub fn generate_keys(store_root: &Path) -> Result<String> {
    let key_dir = store_root.join(KEY_DIR);
    fs::create_dir_all(&key_dir)?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Store raw bytes as hex strings
    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    fs::write(key_dir.join("private.key"), &private_hex)?;
    fs::write(key_dir.join("public.key"), &public_hex)?;

    Ok(public_hex)
}

fn load_signing_key(store_root: &Path) -> Result<SigningKey> {
    let key_path = store_root.join(KEY_DIR).join("private.key");
    let hex = fs::read_to_string(key_path)?;
    let bytes = hex::decode(hex.trim())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn load_public_key(store_root: &Path) -> Result<String> {
    let key_path = store_root.join(KEY_DIR).join("public.key");
    Ok(fs::read_to_string(key_path)?.trim().to_string())
}

pub fn sign_message(store_root: &Path, from: &str, message: &str) -> Result<SignedMessage> {
    let signing_key = load_signing_key(store_root)?;
    let public_key = load_public_key(store_root)?;
    let timestamp = chrono::Utc::now().to_rfc3339();

    let payload = format!("{}\n{}\n{}", from, timestamp, message);
    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes());

    Ok(SignedMessage {
        from: from.to_string(),
        timestamp,
        message: message.to_string(),
        signature: signature_b64,
        public_key,
    })
}

pub fn verify_message(signed: &SignedMessage) -> bool {
    let Ok(key_bytes) = hex::decode(signed.public_key.trim()) else { return false };
    let Ok(arr) = key_bytes.try_into() as Result<[u8; 32], _> else { return false };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else { return false };

    let Ok(sig_bytes) = BASE64.decode(&signed.signature) else { return false };
    let Ok(sig_arr) = sig_bytes.try_into() as Result<[u8; 64], _> else { return false };
    let signature = Signature::from_bytes(&sig_arr);

    let payload = format!("{}\n{}\n{}", signed.from, signed.timestamp, signed.message);
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}

pub fn wrap_external_message(signed: &SignedMessage, verified: bool) -> String {
    let status = if verified { "verified" } else { "UNVERIFIED" };
    format!(
        "<external_message from=\"{}\" verified=\"{}\" time=\"{}\" status=\"{}\">\n{}\n</external_message>",
        signed.from, verified, signed.timestamp, status, signed.message
    )
}
