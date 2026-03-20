use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::crypto;

const STORE_DIRS: &[&str] = &["history", "knowledge", "inbox", "outbox", "shared"];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MeshConfig {
    pub id: String,
    pub name: String,
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub peers: Vec<PeerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_keys: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub access: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
}

pub struct StatusInfo {
    pub id: String,
    pub name: String,
    pub peers: usize,
    pub inbox_count: usize,
    pub shared_count: usize,
}

pub struct InboxMessage {
    pub file: String,
    pub content: String,
    pub wrapped_content: String,
    pub from: String,
    pub time: String,
    pub verified: bool,
}

pub struct ContextStore {
    root: PathBuf,
}

impl ContextStore {
    pub fn new(root: &Path) -> Self {
        Self { root: root.to_path_buf() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(".mesh.json")
    }

    pub fn exists(&self) -> bool {
        self.config_path().exists()
    }

    pub fn init(&self, name: &str, id: &str) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        for dir in STORE_DIRS {
            fs::create_dir_all(self.root.join(dir))?;
        }

        // Write template files if they don't exist
        let context_path = self.root.join("CONTEXT.md");
        if !context_path.exists() {
            fs::write(&context_path, "# Context\n\n*Working memory — what's happening right now.*\n")?;
        }

        let soul_path = self.root.join("SOUL.md");
        if !soul_path.exists() {
            fs::write(&soul_path, format!("# Soul\n\n*Agent identity and rules.*\n\n**Name:** {}\n**ID:** {}\n", name, id))?;
        }

        // Generate signing keys
        let public_key = crypto::generate_keys(&self.root)?;

        // Write config
        let config = MeshConfig {
            id: id.to_string(),
            name: name.to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            public_key: Some(public_key),
            peers: vec![],
            trusted_keys: Some(vec![]),
        };
        self.write_config(&config)?;
        Ok(())
    }

    pub fn read_config(&self) -> Result<MeshConfig> {
        let raw = fs::read_to_string(self.config_path())?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn write_config(&self, config: &MeshConfig) -> Result<()> {
        let json = serde_json::to_string_pretty(config)?;
        fs::write(self.config_path(), format!("{}\n", json))?;
        Ok(())
    }

    pub fn read_context(&self) -> Result<String> {
        Ok(fs::read_to_string(self.root.join("CONTEXT.md"))?)
    }

    pub fn write_context(&self, content: &str) -> Result<()> {
        fs::write(self.root.join("CONTEXT.md"), content)?;
        Ok(())
    }

    pub fn read_soul(&self) -> Result<String> {
        Ok(fs::read_to_string(self.root.join("SOUL.md"))?)
    }

    pub fn write_soul(&self, content: &str) -> Result<()> {
        fs::write(self.root.join("SOUL.md"), content)?;
        Ok(())
    }

    pub fn send_inbox(&self, peer_id: &str, message: &str, from: &str) -> Result<()> {
        let signed = crypto::sign_message(&self.root, from, message)?;
        let serialized = serde_json::to_string_pretty(&signed)?;
        let timestamp = chrono::Utc::now().to_rfc3339().replace([':', '.'], "-");
        let filename = format!("{}_{}.json", timestamp, peer_id);
        fs::write(self.root.join("inbox").join(&filename), &serialized)?;
        fs::write(self.root.join("outbox").join(&filename), &serialized)?;
        Ok(())
    }

    pub fn read_inbox(&self) -> Result<Vec<InboxMessage>> {
        let inbox_dir = self.root.join("inbox");
        if !inbox_dir.exists() {
            return Ok(vec![]);
        }

        let config = self.read_config()?;
        let trusted_keys: Vec<String> = config.trusted_keys
            .unwrap_or_default()
            .iter()
            .map(|k| k.trim().to_string())
            .collect();

        let mut messages = vec![];

        for entry in fs::read_dir(&inbox_dir)? {
            let entry = entry?;
            let path = entry.path();
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();

            if !fname.ends_with(".json") && !fname.ends_with(".md") {
                continue;
            }

            let raw = fs::read_to_string(&path)?;

            if let Ok(signed) = serde_json::from_str::<crypto::SignedMessage>(&raw) {
                if signed.from.is_empty() || signed.message.is_empty() {
                    continue;
                }
                let sig_valid = crypto::verify_message(&signed);
                let trusted = trusted_keys.iter().any(|k| k == signed.public_key.trim());
                let verified = sig_valid && trusted;
                let wrapped = crypto::wrap_external_message(&signed, verified);
                messages.push(InboxMessage {
                    file: fname,
                    content: signed.message.clone(),
                    wrapped_content: wrapped,
                    from: signed.from.clone(),
                    time: signed.timestamp.clone(),
                    verified,
                });
            } else {
                // Unsigned fallback
                let stem = fname.trim_end_matches(".json").trim_end_matches(".md");
                let parts: Vec<&str> = stem.splitn(2, '_').collect();
                let from = if parts.len() > 1 { parts[1].to_string() } else { "unknown".to_string() };
                let time = parts[0].to_string();
                let wrapped = format!(
                    "<external_message from=\"{}\" verified=\"false\" time=\"{}\" status=\"UNVERIFIED\">\n{}\n</external_message>",
                    from, time, raw
                );
                messages.push(InboxMessage {
                    file: fname,
                    content: raw,
                    wrapped_content: wrapped,
                    from,
                    time,
                    verified: false,
                });
            }
        }

        messages.sort_by(|a, b| a.time.cmp(&b.time));
        Ok(messages)
    }

    pub fn list_shared(&self) -> Result<Vec<String>> {
        let shared_dir = self.root.join("shared");
        if !shared_dir.exists() {
            return Ok(vec![]);
        }
        let files = fs::read_dir(shared_dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        Ok(files)
    }

    pub fn share(&self, filename: &str, content: &str) -> Result<()> {
        let shared_dir = self.root.join("shared");
        fs::create_dir_all(&shared_dir)?;
        fs::write(shared_dir.join(filename), content)?;
        Ok(())
    }

    pub fn status(&self) -> Result<StatusInfo> {
        let config = self.read_config()?;
        let inbox = self.read_inbox()?;
        let shared = self.list_shared()?;
        Ok(StatusInfo {
            id: config.id,
            name: config.name,
            peers: config.peers.len(),
            inbox_count: inbox.len(),
            shared_count: shared.len(),
        })
    }
}
