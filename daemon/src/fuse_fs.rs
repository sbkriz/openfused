use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

const TTL: Duration = Duration::from_secs(5);

#[derive(Deserialize, Debug, Clone)]
struct RemoteEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

struct OpenFuseFS {
    client: Client,
    base_url: String,
    // inode -> (name, parent_inode, is_dir, size)
    inodes: HashMap<u64, (String, u64, bool, u64)>,
    // parent_inode -> children inodes
    children: HashMap<u64, Vec<u64>>,
    next_inode: u64,
}

impl OpenFuseFS {
    fn new(base_url: &str) -> Self {
        let mut fs = Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            inodes: HashMap::new(),
            children: HashMap::new(),
            next_inode: 2,
        };
        // Root inode
        fs.inodes.insert(1, ("/".to_string(), 0, true, 0));
        fs
    }

    fn make_attr(&self, ino: u64, is_dir: bool, size: u64) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino,
            size,
            blocks: (size + 511) / 512,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: if is_dir { FileType::Directory } else { FileType::RegularFile },
            perm: if is_dir { 0o755 } else { 0o644 },
            nlink: if is_dir { 2 } else { 1 },
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn fetch_listing_sync(&mut self, parent_ino: u64, path: &str) {
        let url = if path.is_empty() || path == "/" {
            format!("{}/ls", self.base_url)
        } else {
            format!("{}/ls/{}", self.base_url, path.trim_start_matches('/'))
        };

        // Blocking HTTP call (FUSE callbacks are synchronous)
        let rt = tokio::runtime::Handle::current();
        let client = self.client.clone();
        let entries: Vec<RemoteEntry> = match std::thread::spawn(move || {
            rt.block_on(async {
                client.get(&url).send().await?.json().await
            })
        }).join() {
            Ok(Ok(entries)) => entries,
            _ => return,
        };

        let mut child_inodes = Vec::new();
        for entry in entries {
            let ino = self.next_inode;
            self.next_inode += 1;
            self.inodes.insert(ino, (entry.name.clone(), parent_ino, entry.is_dir, entry.size));
            child_inodes.push(ino);
        }
        self.children.insert(parent_ino, child_inodes);
    }

    fn fetch_file_sync(&self, path: &str) -> Option<Vec<u8>> {
        let url = format!("{}/read/{}", self.base_url, path.trim_start_matches('/'));
        let client = self.client.clone();
        let rt = tokio::runtime::Handle::current();

        match std::thread::spawn(move || {
            rt.block_on(async {
                let resp = client.get(&url).send().await.ok()?;
                if resp.status().is_success() {
                    resp.bytes().await.ok().map(|b| b.to_vec())
                } else {
                    None
                }
            })
        }).join() {
            Ok(data) => data,
            _ => None,
        }
    }

    fn resolve_path(&self, ino: u64) -> String {
        let mut parts = Vec::new();
        let mut current = ino;
        while current > 1 {
            if let Some((name, parent, _, _)) = self.inodes.get(&current) {
                parts.push(name.clone());
                current = *parent;
            } else {
                break;
            }
        }
        parts.reverse();
        parts.join("/")
    }
}

impl Filesystem for OpenFuseFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_string_lossy().to_string();

        // Check if we have children cached
        if !self.children.contains_key(&parent) {
            let parent_path = self.resolve_path(parent);
            self.fetch_listing_sync(parent, &parent_path);
        }

        if let Some(child_inos) = self.children.get(&parent) {
            for &ino in child_inos {
                if let Some((n, _, is_dir, size)) = self.inodes.get(&ino) {
                    if *n == name_str {
                        reply.entry(&TTL, &self.make_attr(ino, *is_dir, *size), 0);
                        return;
                    }
                }
            }
        }

        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if let Some((_, _, is_dir, size)) = self.inodes.get(&ino) {
            reply.attr(&TTL, &self.make_attr(ino, *is_dir, *size));
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn read(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, size: u32, _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        let path = self.resolve_path(ino);
        if let Some(data) = self.fetch_file_sync(&path) {
            let start = offset as usize;
            let end = std::cmp::min(start + size as usize, data.len());
            if start < data.len() {
                reply.data(&data[start..end]);
            } else {
                reply.data(&[]);
            }
        } else {
            reply.error(libc::EIO);
        }
    }

    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        if offset > 0 {
            reply.ok();
            return;
        }

        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (ino, FileType::Directory, "..".to_string()),
        ];

        // Fetch if not cached
        if !self.children.contains_key(&ino) {
            let path = self.resolve_path(ino);
            self.fetch_listing_sync(ino, &path);
        }

        if let Some(child_inos) = self.children.get(&ino) {
            for &child_ino in child_inos {
                if let Some((name, _, is_dir, _)) = self.inodes.get(&child_ino) {
                    let ft = if *is_dir { FileType::Directory } else { FileType::RegularFile };
                    entries.push((child_ino, ft, name.clone()));
                }
            }
        }

        for (i, (ino, ft, name)) in entries.iter().enumerate() {
            if reply.add(*ino, (i + 1) as i64, *ft, name) {
                break;
            }
        }
        reply.ok();
    }
}

pub async fn mount_remote(url: &str, mountpoint: &Path) {
    let fs = OpenFuseFS::new(url);

    // Create mountpoint if it doesn't exist
    tokio::fs::create_dir_all(mountpoint).await.ok();

    let mountpoint = mountpoint.to_path_buf();
    tracing::info!("FUSE mounting {} at {:?}", url, mountpoint);

    // FUSE mount runs in a blocking thread
    let options = vec![
        MountOption::RO,
        MountOption::FSName("openfused".to_string()),
        MountOption::AutoUnmount,
        MountOption::AllowOther,
    ];

    // This blocks until unmounted
    tokio::task::spawn_blocking(move || {
        fuser::mount2(fs, &mountpoint, &options).unwrap();
    })
    .await
    .unwrap();
}
