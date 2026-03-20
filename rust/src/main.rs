mod store;
mod crypto;
mod watch;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Parser)]
#[command(name = "openfuse", about = "Persistent, shareable, portable context for AI agents", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new context store in the current directory
    Init {
        #[arg(short, long, default_value = "agent")]
        name: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Show context store status
    Status {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Read or update CONTEXT.md
    Context {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        set: Option<String>,
        #[arg(short, long)]
        append: Option<String>,
    },
    /// Read or update SOUL.md
    Soul {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        set: Option<String>,
    },
    /// Manage inbox messages
    Inbox {
        #[command(subcommand)]
        subcommand: InboxCommands,
    },
    /// Watch for inbox messages and context changes
    Watch {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Share a file with the mesh
    Share {
        file: PathBuf,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Manage peers
    Peer {
        #[command(subcommand)]
        subcommand: PeerCommands,
    },
    /// Show this agent's public key
    Key {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum InboxCommands {
    /// List inbox messages
    List {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(long)]
        raw: bool,
    },
    /// Send a message to a peer's inbox
    Send {
        peer_id: String,
        message: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// List connected peers
    List {
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Add a peer by URL
    Add {
        url: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long, default_value = "read")]
        access: String,
    },
    /// Remove a peer by ID or name
    Remove {
        id: String,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// Trust a peer's public key
    Trust {
        public_key_file: PathBuf,
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name, dir } => {
            let dir = dir.canonicalize().unwrap_or(dir.clone());
            let store = store::ContextStore::new(&dir);
            if store.exists() {
                eprintln!("Context store already exists at {}", dir.display());
                std::process::exit(1);
            }
            let id = nanoid::nanoid!(12);
            store.init(&name, &id)?;
            println!("Initialized context store: {}", dir.display());
            println!("  Agent ID: {}", id);
            println!("  Name: {}", name);
            println!("  Signing keys: generated (.keys/)");
            println!("\nStructure:");
            println!("  CONTEXT.md  — working memory (edit this)");
            println!("  SOUL.md     — agent identity & rules");
            println!("  inbox/      — messages from other agents");
            println!("  shared/     — files shared with the mesh");
            println!("  knowledge/  — persistent knowledge base");
            println!("  history/    — conversation & decision logs");
        }

        Commands::Status { dir } => {
            let store = store::ContextStore::new(&dir);
            if !store.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let s = store.status()?;
            println!("Agent: {} ({})", s.name, s.id);
            println!("Peers: {}", s.peers);
            println!("Inbox: {} messages", s.inbox_count);
            println!("Shared: {} files", s.shared_count);
        }

        Commands::Context { dir, set, append } => {
            let store = store::ContextStore::new(&dir);
            if let Some(text) = set {
                store.write_context(&text)?;
                println!("Context updated.");
            } else if let Some(text) = append {
                let existing = store.read_context()?;
                let text = text.replace("\\n", "\n");
                store.write_context(&format!("{}\n{}", existing, text))?;
                println!("Context appended.");
            } else {
                let content = store.read_context()?;
                print!("{}", content);
            }
        }

        Commands::Soul { dir, set } => {
            let store = store::ContextStore::new(&dir);
            if let Some(text) = set {
                store.write_soul(&text)?;
                println!("Soul updated.");
            } else {
                let content = store.read_soul()?;
                print!("{}", content);
            }
        }

        Commands::Inbox { subcommand } => match subcommand {
            InboxCommands::List { dir, raw } => {
                let store = store::ContextStore::new(&dir);
                let messages = store.read_inbox()?;
                if messages.is_empty() {
                    println!("Inbox is empty.");
                    return Ok(());
                }
                for msg in messages {
                    let badge = if msg.verified { "[VERIFIED]" } else { "[UNVERIFIED]" };
                    println!("\n--- {} From: {} | {} ---", badge, msg.from, msg.time);
                    if raw {
                        println!("{}", msg.content);
                    } else {
                        println!("{}", msg.wrapped_content);
                    }
                }
            }
            InboxCommands::Send { peer_id, message, dir } => {
                let store = store::ContextStore::new(&dir);
                let config = store.read_config()?;
                store.send_inbox(&peer_id, &message, &config.id)?;
                println!("Message sent to {}'s inbox.", peer_id);
            }
        },

        Commands::Watch { dir } => {
            let store = store::ContextStore::new(&dir);
            if !store.exists() {
                eprintln!("No context store found. Run `openfuse init` first.");
                std::process::exit(1);
            }
            let config = store.read_config()?;
            println!("Watching context store: {} ({})", config.name, config.id);
            println!("Press Ctrl+C to stop.\n");
            watch::watch_store(store.root())?;
        }

        Commands::Share { file, dir } => {
            let store = store::ContextStore::new(&dir);
            let content = std::fs::read_to_string(&file)?;
            let filename = file.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();
            store.share(&filename, &content)?;
            println!("Shared: {}", filename);
        }

        Commands::Peer { subcommand } => match subcommand {
            PeerCommands::List { dir } => {
                let store = store::ContextStore::new(&dir);
                let config = store.read_config()?;
                if config.peers.is_empty() {
                    println!("No peers connected.");
                    return Ok(());
                }
                for p in config.peers {
                    println!("  {} ({}) — {} [{}]", p.name, p.id, p.url, p.access);
                }
            }
            PeerCommands::Add { url, dir, name, access } => {
                let store = store::ContextStore::new(&dir);
                let mut config = store.read_config()?;
                let peer_id = nanoid::nanoid!(12);
                let peer_name = name.clone().unwrap_or_else(|| format!("peer-{}", config.peers.len() + 1));
                let name_display = peer_name.clone();
                config.peers.push(store::PeerConfig {
                    id: peer_id,
                    name: peer_name,
                    url: url.clone(),
                    access: access.clone(),
                    mount_path: None,
                });
                store.write_config(&config)?;
                println!("Added peer: {} ({}) [{}]", name_display, url, access);
            }
            PeerCommands::Remove { id, dir } => {
                let store = store::ContextStore::new(&dir);
                let mut config = store.read_config()?;
                config.peers.retain(|p| p.id != id && p.name != id);
                store.write_config(&config)?;
                println!("Removed peer: {}", id);
            }
            PeerCommands::Trust { public_key_file, dir } => {
                let store = store::ContextStore::new(&dir);
                let mut config = store.read_config()?;
                let pub_key = std::fs::read_to_string(&public_key_file)?.trim().to_string();
                let trusted = config.trusted_keys.get_or_insert_with(Vec::new);
                if trusted.contains(&pub_key) {
                    println!("Key already trusted.");
                    return Ok(());
                }
                trusted.push(pub_key);
                store.write_config(&config)?;
                println!("Key trusted. Messages signed with this key will show as [VERIFIED].");
            }
        },

        Commands::Key { dir } => {
            let store = store::ContextStore::new(&dir);
            let config = store.read_config()?;
            if let Some(pk) = config.public_key {
                println!("{}", pk);
            } else {
                eprintln!("No keys found. Run `openfuse init` first.");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
