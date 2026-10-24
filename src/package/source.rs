// SPDX-License-Identifier: GPL-3.0-or-later
//! Source sealing only. Content identities do not establish rights or build provenance.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::{
    PackageError,
    inventory::{DependencyInventory, collect_assets, verify_closure},
    records::{
        BuildInputs, ContentEntry, Digest, EnvironmentEntry, HostProfile, LockIdentity,
        RecipeIdentity, RelativePath, SourceIdentity, ToolIdentity, ToolInventory, canonical_bytes,
        decode_closed_json, parse_canonical, sha256,
    },
};

pub const SOURCE_EPOCH: u64 = 1_792_799_804;
const SOURCE_MANIFEST: &str = "osslscope-source.json";
pub(crate) const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn closed<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PackageError> {
    serde_json::from_value(decode_closed_json(bytes)?)
        .map_err(|e| PackageError::invalid(e.to_string()))
}
pub(crate) fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PackageError> {
    let mut bytes = serde_json::to_vec(
        &serde_json::to_value(value).map_err(|e| PackageError::invalid(e.to_string()))?,
    )
    .map_err(|e| PackageError::invalid(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn content(path: &str, bytes: &[u8]) -> Result<ContentEntry, PackageError> {
    if bytes.is_empty() {
        return Err(PackageError::invalid("empty required source asset"));
    }
    Ok(ContentEntry {
        path: RelativePath::new(path)?,
        sha256: sha256(bytes),
        bytes: bytes.len() as u64,
    })
}
fn io_error(error: std::io::Error, path: &str) -> PackageError {
    if error.kind() == std::io::ErrorKind::NotFound {
        PackageError::unavailable(format!("required input {path}"))
    } else {
        PackageError::unreadable(format!("{path}: {error}"))
    }
}
fn metadata_same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.len(),
        a.mode(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.len(),
        b.mode(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
pub(crate) fn read_regular(
    root: &Path,
    path: &RelativePath,
    limit: u64,
) -> Result<Vec<u8>, PackageError> {
    // Retain directory descriptors so a changed ancestor cannot redirect this open.
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|e| io_error(e, "input root"))?;
    let parts: Vec<_> = path.as_str().split('/').collect();
    use std::os::fd::{AsRawFd, FromRawFd};
    for part in &parts[..parts.len() - 1] {
        let name = std::ffi::CString::new(*part).map_err(|_| PackageError::invalid("NUL path"))?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io_error(std::io::Error::last_os_error(), path.as_str()));
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let name = std::ffi::CString::new(*parts.last().unwrap())
        .map_err(|_| PackageError::invalid("NUL path"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error(), path.as_str()));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|e| io_error(e, path.as_str()))?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(PackageError::invalid(
            "required input is not bounded single-link regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(e, path.as_str()))?;
    let after = file.metadata().map_err(|e| io_error(e, path.as_str()))?;
    if !metadata_same(&before, &after) || bytes.len() as u64 != before.len() {
        return Err(PackageError::Mutated {
            context: "source input changed while reading".into(),
        });
    }
    Ok(bytes)
}
pub(crate) fn verify_entry(root: &Path, entry: &ContentEntry) -> Result<Vec<u8>, PackageError> {
    check_input_path(&entry.path)?;
    if entry.bytes == 0 || entry.bytes > MAX_ASSET_BYTES {
        return Err(PackageError::invalid("empty or oversized required input"));
    }
    let bytes = read_regular(root, &entry.path, entry.bytes)?;
    if bytes.len() as u64 != entry.bytes || sha256(&bytes) != entry.sha256 {
        return Err(PackageError::invalid(format!(
            "changed input {}",
            entry.path.as_str()
        )));
    }
    Ok(bytes)
}
fn excluded(path: &str) -> bool {
    if path.split('/').any(|part| {
        matches!(
            part,
            ".git"
                | ".superpowers"
                | "target"
                | "evidence"
                | "incoming"
                | "vm-bases"
                | "vm-operational"
                | "preserved"
                | "__pycache__"
        ) || part == "attempts"
            || part.starts_with("attempt-")
    }) {
        return true;
    }
    // Checked-in public examples and fixtures are source even when they model
    // an output filename or a log format. Never filter them merely for that name.
    if path.starts_with("docs/")
        || ((path.starts_with("tests/")
            || path.starts_with("tools/")
            || path.starts_with("packaging/"))
            && path.contains("/fixtures/"))
    {
        return false;
    }
    matches!(
        path.rsplit('/').next().unwrap_or(path),
        SOURCE_MANIFEST
            | "build-inputs.json"
            | "bundle-contract.json"
            | "payload-manifest.json"
            | "release-index.json"
            | "offline-inventory.json"
            | "source.spdx.json"
            | "notices.json"
            | "license-index.json"
            | "source-availability.json"
    ) || path == "source.tar"
        || path.ends_with(".deb")
        || path.ends_with(".rpm")
        || path.ends_with(".log")
}
pub(crate) fn check_input_path(path: &RelativePath) -> Result<(), PackageError> {
    if excluded(path.as_str()) {
        Err(PackageError::invalid(
            "private/derived source-graph backedge",
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum SourceNodeKind {
    File,
    Symlink { target: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceNode {
    path: RelativePath,
    mode: u32,
    sha256: Digest,
    bytes: u64,
    node: SourceNodeKind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalInventory {
    schema: String,
    files: Vec<SourceNode>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    schema: String,
    source: SourceIdentity,
    inventory: OriginalInventory,
}

impl SourceManifest {
    fn validate(&self) -> Result<(), PackageError> {
        check_revision(&self.source.revision)?;
        if self.schema != "osslscope-source-manifest-v1"
            || self.inventory.schema != "osslscope-original-source-v1"
            || sha256(&json_bytes(&self.inventory)?) != self.source.inventory_sha256
        {
            return Err(PackageError::invalid("source identity/inventory mismatch"));
        }
        validate_nodes(&self.inventory.files)?;
        Ok(())
    }
}
impl SourceNode {
    fn read_bytes(&self, root: &Path) -> Result<Vec<u8>, PackageError> {
        if !matches!(&self.node, SourceNodeKind::File) {
            return Err(PackageError::invalid(
                "regular archive read requires a file node",
            ));
        }
        let bytes = read_regular(root, &self.path, MAX_ASSET_BYTES)?;
        if bytes.len() as u64 != self.bytes || sha256(&bytes) != self.sha256 {
            return Err(PackageError::Mutated {
                context: "archive read differs from admitted source node".into(),
            });
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct SourceTree {
    pub(crate) root: PathBuf,
    manifest: SourceManifest,
}

fn check_revision(revision: &str) -> Result<(), PackageError> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PackageError::invalid(
            "source revision must be full lowercase Git object ID",
        ));
    }
    Ok(())
}
fn link_destination(path: &str, target: &str) -> Result<String, PackageError> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\\')
        || target.chars().any(char::is_control)
    {
        return Err(PackageError::invalid("unsafe source symlink target"));
    }
    let mut result: Vec<_> = path.split('/').collect();
    result.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if result.pop().is_none() {
                    return Err(PackageError::invalid("source symlink escapes root"));
                }
            }
            _ => result.push(part),
        }
    }
    let destination = result.join("/");
    check_input_path(&RelativePath::new(&destination)?)?;
    Ok(destination)
}
fn validate_nodes(nodes: &[SourceNode]) -> Result<(), PackageError> {
    if nodes.is_empty() {
        return Err(PackageError::invalid("empty source inventory"));
    }
    let mut previous = "";
    let mut kinds = BTreeMap::new();
    for node in nodes {
        check_input_path(&node.path)?;
        let path = node.path.as_str();
        if path <= previous {
            return Err(PackageError::invalid(
                "source inventory must have unique lexical paths",
            ));
        }
        previous = path;
        match &node.node {
            SourceNodeKind::File if matches!(node.mode, 0o100644 | 0o100755) => {}
            SourceNodeKind::Symlink { target }
                if node.mode == 0o120000
                    && node.bytes == target.len() as u64
                    && node.sha256 == sha256(target.as_bytes()) =>
            {
                link_destination(path, target)?;
            }
            _ => {
                return Err(PackageError::invalid(
                    "source node mode/type/content mismatch",
                ));
            }
        }
        kinds.insert(path, &node.node);
    }
    for node in nodes {
        let path = node.path.as_str();
        let mut parent = Path::new(path).parent();
        while let Some(p) = parent {
            if let Some(s) = p.to_str() {
                if kinds.contains_key(s) {
                    return Err(PackageError::invalid(
                        "archive path crosses a non-directory node",
                    ));
                }
            }
            parent = p.parent();
        }
        if let SourceNodeKind::Symlink { target } = &node.node {
            let destination = link_destination(path, target)?;
            // Internal links may target a file or an implicit directory, but not another link.
            let exists = matches!(kinds.get(destination.as_str()), Some(SourceNodeKind::File))
                || nodes
                    .iter()
                    .any(|n| n.path.as_str().starts_with(&(destination.clone() + "/")));
            if !exists {
                return Err(PackageError::invalid(
                    "source symlink target absent or indirect",
                ));
            }
        }
    }
    Ok(())
}
impl SourceTree {
    /// Inventory an explicitly identified source snapshot. The revision is a claim,
    /// not authentication; production entry uses Git or the embedded manifest.
    pub fn snapshot(root: &Path, revision: &str) -> Result<Self, PackageError> {
        check_revision(revision)?;
        fn visit(
            root: &Path,
            directory: &Path,
            nodes: &mut Vec<SourceNode>,
        ) -> Result<(), PackageError> {
            let mut entries = fs::read_dir(directory)
                .map_err(|e| io_error(e, "source directory"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io_error(e, "source directory"))?;
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let full = entry.path();
                let text = full
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .ok_or_else(|| PackageError::invalid("non-UTF8 source path"))?
                    .to_owned();
                if excluded(&text) {
                    continue;
                }
                let path = RelativePath::new(&text)?;
                let metadata = fs::symlink_metadata(&full).map_err(|e| io_error(e, &text))?;
                if metadata.is_dir() {
                    visit(root, &full, nodes)?;
                } else if metadata.file_type().is_symlink() {
                    let target = fs::read_link(&full)
                        .map_err(|e| io_error(e, &text))?
                        .to_str()
                        .ok_or_else(|| PackageError::invalid("non-UTF8 symlink"))?
                        .to_owned();
                    nodes.push(SourceNode {
                        path,
                        mode: 0o120000,
                        bytes: target.len() as u64,
                        sha256: sha256(target.as_bytes()),
                        node: SourceNodeKind::Symlink { target },
                    });
                } else if metadata.is_file() {
                    let bytes = read_regular(root, &path, MAX_ASSET_BYTES)?;
                    nodes.push(SourceNode {
                        path,
                        mode: if metadata.mode() & 0o111 != 0 {
                            0o100755
                        } else {
                            0o100644
                        },
                        bytes: bytes.len() as u64,
                        sha256: sha256(&bytes),
                        node: SourceNodeKind::File,
                    });
                } else {
                    return Err(PackageError::invalid("special source node"));
                }
            }
            Ok(())
        }
        let mut files = Vec::new();
        visit(root, root, &mut files)?;
        files.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
        validate_nodes(&files)?;
        let inventory = OriginalInventory {
            schema: "osslscope-original-source-v1".into(),
            files,
        };
        let source = SourceIdentity {
            revision: revision.into(),
            inventory_sha256: sha256(&json_bytes(&inventory)?),
        };
        let tree = Self {
            root: root.to_owned(),
            manifest: SourceManifest {
                schema: "osslscope-source-manifest-v1".into(),
                source,
                inventory,
            },
        };
        if tree.manifest_bytes().len() > 1_048_576 {
            return Err(PackageError::invalid(
                "original source manifest exceeds 1 MiB",
            ));
        }
        Ok(tree)
    }
    pub fn open(root: &Path) -> Result<Self, PackageError> {
        if !root.join(".git").exists() {
            let bytes = read_regular(root, &RelativePath::new(SOURCE_MANIFEST)?, 1_048_576)?;
            return Self::from_manifest(root, &bytes);
        }
        // Read raw Git objects. A clean-filter/diff result is neither the source
        // bytes nor authority to execute repository filters during source admission.
        let command = || {
            let mut command = Command::new("git");
            command
                .args([
                    "--no-replace-objects",
                    "--no-optional-locks",
                    "--literal-pathspecs",
                    "-c",
                    "core.fsmonitor=false",
                    "-C",
                ])
                .arg(root)
                .env("GIT_OPTIONAL_LOCKS", "0");
            for key in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_CONFIG_COUNT",
            ] {
                command.env_remove(key);
            }
            command
        };
        let git = |args: &[&str]| -> Result<Vec<u8>, PackageError> {
            let output = command()
                .args(args)
                .output()
                .map_err(|e| io_error(e, "Git source identity"))?;
            if !output.status.success() {
                return Err(PackageError::unavailable(
                    "readable original Git source required",
                ));
            }
            Ok(output.stdout)
        };
        let revision = String::from_utf8(git(&["rev-parse", "--verify", "HEAD"])?)
            .map_err(|_| PackageError::invalid("non-UTF8 Git revision"))?;
        let revision = revision.trim();
        check_revision(revision)?;
        let listing = git(&["ls-tree", "-rz", "--full-tree", revision])?;
        let mut paths = BTreeMap::new();
        for entry in listing.split(|b| *b == 0).filter(|b| !b.is_empty()) {
            let text = std::str::from_utf8(entry)
                .map_err(|_| PackageError::invalid("non-UTF8 Git path"))?;
            let (info, path) = text
                .split_once('\t')
                .ok_or_else(|| PackageError::invalid("bad Git source row"))?;
            let fields = info.split(' ').collect::<Vec<_>>();
            if fields.len() != 3 || fields[1] != "blob" {
                return Err(PackageError::invalid(
                    "Git source contains unsupported node",
                ));
            }
            let mode = u32::from_str_radix(fields[0], 8)
                .map_err(|_| PackageError::invalid("bad Git node mode"))?;
            check_revision(fields[2])?;
            check_input_path(&RelativePath::new(path)?)?;
            if paths
                .insert(path.to_owned(), (mode, fields[2].to_owned()))
                .is_some()
            {
                return Err(PackageError::invalid("duplicate Git source path"));
            }
        }
        let tree = Self::snapshot(root, revision)?;
        if tree.manifest.inventory.files.len() != paths.len()
            || tree.manifest.inventory.files.iter().any(|n| {
                paths
                    .get(n.path.as_str())
                    .is_none_or(|(mode, _)| *mode != n.mode)
            })
        {
            return Err(PackageError::invalid(
                "Git node inventory differs from working source",
            ));
        }
        let mut input = Vec::new();
        for node in &tree.manifest.inventory.files {
            input.extend_from_slice(paths[node.path.as_str()].1.as_bytes());
            input.push(b'\n');
        }
        let limit = tree
            .manifest
            .inventory
            .files
            .iter()
            .map(|n| n.bytes)
            .sum::<u64>()
            .checked_add(paths.len() as u64 * 80)
            .filter(|n| *n <= MAX_ASSET_BYTES)
            .ok_or_else(|| PackageError::invalid("Git source bytes exceed bound"))?;
        use std::process::Stdio;
        let mut child = command()
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| io_error(e, "Git raw objects"))?;
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            stdin.write_all(&input)
        });
        let mut blobs = Vec::new();
        let read = child
            .stdout
            .take()
            .unwrap()
            .take(limit + 1)
            .read_to_end(&mut blobs);
        if read.is_err() || blobs.len() as u64 > limit {
            let _ = child.kill();
        }
        let status = child.wait().map_err(|e| io_error(e, "Git raw objects"))?;
        let wrote = writer.join().is_ok_and(|result| result.is_ok());
        if read.is_err() || !status.success() || !wrote || blobs.len() as u64 > limit {
            return Err(PackageError::invalid(
                "bounded original Git object read failed",
            ));
        }
        let mut offset = 0;
        for node in &tree.manifest.inventory.files {
            let end = blobs[offset..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| offset + n)
                .ok_or_else(|| PackageError::invalid("truncated original Git object header"))?;
            let expected = format!("{} blob {}", paths[node.path.as_str()].1, node.bytes);
            if blobs[offset..end] != *expected.as_bytes() {
                return Err(PackageError::invalid(
                    "original Git object identity/size mismatch",
                ));
            }
            let start = end + 1;
            let end = start
                .checked_add(node.bytes as usize)
                .filter(|n| *n < blobs.len())
                .ok_or_else(|| PackageError::invalid("truncated original Git object"))?;
            if blobs[end] != b'\n' || sha256(&blobs[start..end]) != node.sha256 {
                return Err(PackageError::invalid(
                    "original Git blob differs from working source",
                ));
            }
            offset = end + 1;
        }
        if offset != blobs.len() {
            return Err(PackageError::invalid("trailing original Git object stream"));
        }
        tree.verify()?;
        Ok(tree)
    }
    pub fn from_manifest(root: &Path, bytes: &[u8]) -> Result<Self, PackageError> {
        let manifest: SourceManifest = closed(bytes)?;
        if json_bytes(&manifest)? != bytes {
            return Err(PackageError::invalid("noncanonical source manifest"));
        }
        let tree = Self {
            root: root.to_owned(),
            manifest,
        };
        tree.verify()?;
        Ok(tree)
    }
    pub fn manifest_bytes(&self) -> Vec<u8> {
        json_bytes(&self.manifest).expect("serializable source manifest")
    }
    pub fn inventory_paths(&self) -> Vec<String> {
        self.manifest
            .inventory
            .files
            .iter()
            .map(|f| f.path.as_str().to_owned())
            .collect()
    }
    pub fn identity(&self) -> &SourceIdentity {
        &self.manifest.source
    }
    pub(crate) fn verify(&self) -> Result<(), PackageError> {
        self.manifest.validate()?;
        for node in &self.manifest.inventory.files {
            match &node.node {
                SourceNodeKind::File => {
                    let data = read_regular(&self.root, &node.path, MAX_ASSET_BYTES)?;
                    let meta = fs::symlink_metadata(self.root.join(node.path.as_str()))
                        .map_err(|e| io_error(e, node.path.as_str()))?;
                    let mode = if meta.mode() & 0o111 != 0 {
                        0o100755
                    } else {
                        0o100644
                    };
                    if data.len() as u64 != node.bytes
                        || sha256(&data) != node.sha256
                        || mode != node.mode
                    {
                        return Err(PackageError::invalid("source file changed"));
                    }
                }
                SourceNodeKind::Symlink { target } => {
                    let path = self.root.join(node.path.as_str());
                    let meta =
                        fs::symlink_metadata(&path).map_err(|e| io_error(e, node.path.as_str()))?;
                    if !meta.file_type().is_symlink()
                        || fs::read_link(path).map_err(|e| io_error(e, node.path.as_str()))?
                            != Path::new(target)
                    {
                        return Err(PackageError::invalid("source symlink changed"));
                    }
                }
            }
        }
        let current = Self::snapshot(&self.root, &self.manifest.source.revision)?;
        if current.manifest.inventory != self.manifest.inventory {
            return Err(PackageError::invalid(
                "unlisted or changed original source inventory",
            ));
        }
        Ok(())
    }
    pub(crate) fn contains(&self, path: &str) -> bool {
        self.manifest
            .inventory
            .files
            .iter()
            .any(|n| n.path.as_str() == path)
    }
    fn archive(&self) -> Result<Vec<u8>, PackageError> {
        self.verify()?;
        let mut rows = Vec::new();
        for node in &self.manifest.inventory.files {
            let (data, kind, link) = match &node.node {
                SourceNodeKind::File => (node.read_bytes(&self.root)?, b'0', ""),
                SourceNodeKind::Symlink { target } => (Vec::new(), b'2', target.as_str()),
            };
            rows.push((
                node.path.as_str().to_owned(),
                if kind == b'2' {
                    0o777
                } else {
                    node.mode & 0o777
                },
                kind,
                link.to_owned(),
                data,
            ));
        }
        rows.push((
            SOURCE_MANIFEST.into(),
            0o644,
            b'0',
            String::new(),
            self.manifest_bytes(),
        ));
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let mut output = Vec::new();
        for (path, mode, kind, link, data) in rows {
            tar_entry(&mut output, &path, mode, kind, &link, &data)?;
            if output.len() as u64 > MAX_ASSET_BYTES {
                return Err(PackageError::invalid("source archive exceeds bound"));
            }
        }
        output.extend_from_slice(&[0; 1024]);
        Ok(output)
    }
    pub(crate) fn verify_archive(&self, bytes: &[u8]) -> Result<(), PackageError> {
        let (_, manifest) = validate_tree_archive(bytes)?;
        if manifest != self.manifest {
            return Err(PackageError::invalid(
                "retained archive differs from admitted original inventory",
            ));
        }
        Ok(())
    }
    pub fn extract_archive(bytes: &[u8], destination: &Path) -> Result<Self, PackageError> {
        let (entries, parsed) = validate_tree_archive(bytes)?;
        let manifest_bytes = json_bytes(&parsed)?;
        if destination.exists() {
            return Err(PackageError::invalid(
                "extraction destination already exists",
            ));
        }
        fs::create_dir(destination).map_err(|e| io_error(e, "extraction destination"))?;
        let result = (|| {
            for entry in &entries {
                let full = destination.join(&entry.path);
                fs::create_dir_all(full.parent().unwrap()).map_err(|e| io_error(e, &entry.path))?;
                if entry.kind == b'2' {
                    std::os::unix::fs::symlink(&entry.link, &full)
                        .map_err(|e| io_error(e, &entry.path))?;
                } else {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(entry.mode)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&full)
                        .map_err(|e| io_error(e, &entry.path))?;
                    use std::io::Write;
                    file.write_all(&entry.data)
                        .map_err(|e| io_error(e, &entry.path))?;
                    file.set_permissions(fs::Permissions::from_mode(entry.mode))
                        .map_err(|e| io_error(e, &entry.path))?;
                }
            }
            Self::from_manifest(destination, &manifest_bytes)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        result
    }
}

fn validate_tree_archive(bytes: &[u8]) -> Result<(Vec<TarEntry>, SourceManifest), PackageError> {
    let entries = read_tar(bytes)?;
    let manifest = entries
        .iter()
        .find(|e| e.path == SOURCE_MANIFEST)
        .ok_or_else(|| PackageError::invalid("missing original source identity"))?;
    if manifest.kind != b'0' || manifest.mode != 0o644 {
        return Err(PackageError::invalid("source manifest is not regular"));
    }
    let parsed: SourceManifest = closed(&manifest.data)?;
    if json_bytes(&parsed)? != manifest.data {
        return Err(PackageError::invalid("noncanonical source manifest"));
    }
    parsed.validate()?;
    if entries.len() != parsed.inventory.files.len() + 1 {
        return Err(PackageError::invalid(
            "archive inventory has extra/missing nodes",
        ));
    }
    for node in &parsed.inventory.files {
        let entry = entries
            .iter()
            .find(|e| e.path == node.path.as_str())
            .ok_or_else(|| PackageError::invalid("missing archive source node"))?;
        let matches = match &node.node {
            SourceNodeKind::File => {
                entry.kind == b'0'
                    && entry.mode == node.mode & 0o777
                    && entry.data.len() as u64 == node.bytes
                    && sha256(&entry.data) == node.sha256
            }
            SourceNodeKind::Symlink { target } => {
                entry.kind == b'2' && entry.link == *target && entry.mode == 0o777
            }
        };
        if !matches {
            return Err(PackageError::invalid(
                "archive source node identity changed",
            ));
        }
    }
    Ok((entries, parsed))
}

struct TarEntry {
    path: String,
    mode: u32,
    kind: u8,
    link: String,
    data: Vec<u8>,
}
fn octal(bytes: &[u8]) -> Result<u64, PackageError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| PackageError::invalid("bad tar octal"))?
        .trim_matches(['\0', ' ']);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| PackageError::invalid("bad tar octal"))
}
fn tar_text(bytes: &[u8]) -> Result<String, PackageError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err(PackageError::invalid("tar text has nonzero padding"));
    }
    Ok(std::str::from_utf8(&bytes[..end])
        .map_err(|_| PackageError::invalid("non-UTF8 tar path"))?
        .to_owned())
}
fn tar_entry(
    out: &mut Vec<u8>,
    path: &str,
    mode: u32,
    kind: u8,
    link: &str,
    data: &[u8],
) -> Result<(), PackageError> {
    let mut h = [0; 512];
    let (prefix, name) = if path.len() <= 100 {
        ("", path)
    } else {
        path.rsplit_once('/')
            .filter(|(p, n)| p.len() <= 155 && n.len() <= 100)
            .ok_or_else(|| PackageError::invalid("source path exceeds ustar bound"))?
    };
    if link.len() > 100 {
        return Err(PackageError::invalid("symlink target exceeds ustar bound"));
    }
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    for (offset, width, value) in [
        (100, 8, mode as u64),
        (108, 8, 0),
        (116, 8, 0),
        (124, 12, data.len() as u64),
        (136, 12, SOURCE_EPOCH),
    ] {
        let text = format!("{:0width$o}\0", value, width = width - 1);
        if text.len() != width {
            return Err(PackageError::invalid("tar integer overflow"));
        }
        h[offset..offset + width].copy_from_slice(text.as_bytes());
    }
    h[148..156].fill(b' ');
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    Ok(())
}
fn read_tar(bytes: &[u8]) -> Result<Vec<TarEntry>, PackageError> {
    read_tar_bounded(bytes, MAX_ASSET_BYTES, 10_000)
}
fn read_tar_bounded(
    bytes: &[u8],
    member_bytes: u64,
    members: usize,
) -> Result<Vec<TarEntry>, PackageError> {
    if bytes.len() as u64 > MAX_ASSET_BYTES
        || bytes.len() < 1024
        || !bytes.len().is_multiple_of(512)
    {
        return Err(PackageError::invalid("truncated/oversized tar"));
    }
    let mut offset = 0;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    while offset + 512 <= bytes.len() {
        let h = &bytes[offset..offset + 512];
        if h.iter().all(|b| *b == 0) {
            if bytes.len() - offset < 1024 || bytes[offset..].iter().any(|b| *b != 0) {
                return Err(PackageError::invalid("truncated or trailing tar bytes"));
            }
            return Ok(entries);
        }
        let expected = octal(&h[148..156])?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as u64
                } else {
                    *b as u64
                }
            })
            .sum();
        if expected != sum || &h[257..263] != b"ustar\0" || &h[263..265] != b"00" {
            return Err(PackageError::invalid("tar checksum/format mismatch"));
        }
        let prefix = tar_text(&h[345..500])?;
        let name = tar_text(&h[..100])?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let relative = RelativePath::new(&path)?;
        if path != SOURCE_MANIFEST {
            check_input_path(&relative)?;
        }
        if entries.last().is_some_and(|e: &TarEntry| e.path >= path) {
            return Err(PackageError::invalid(
                "normalized tar paths are not in lexical order",
            ));
        }
        if !names.insert(path.clone()) {
            return Err(PackageError::invalid("duplicate archive path"));
        }
        let kind = h[156];
        if !matches!(kind, b'0' | b'2') {
            return Err(PackageError::invalid(
                "unsupported archive node: links/devices/special entries refuse",
            ));
        }
        let link = tar_text(&h[157..257])?;
        let length = usize::try_from(octal(&h[124..136])?)
            .map_err(|_| PackageError::invalid("tar length overflow"))?;
        if length as u64 > member_bytes || entries.len() >= members {
            return Err(PackageError::invalid(
                "normalized tar member-size/count limit",
            ));
        }
        let mode = octal(&h[100..108])? as u32;
        if !matches!(mode, 0o644 | 0o755 | 0o777)
            || (kind == b'2' && length != 0)
            || (kind == b'0' && !link.is_empty())
            || octal(&h[108..116])? != 0
            || octal(&h[116..124])? != 0
            || octal(&h[136..148])? != SOURCE_EPOCH
        {
            return Err(PackageError::invalid("non-normalized archive entry"));
        }
        if kind == b'2' {
            link_destination(&path, &link)?;
        }
        let start = offset + 512;
        let end = start
            .checked_add(length)
            .ok_or_else(|| PackageError::invalid("tar length overflow"))?;
        let next = end
            .checked_add(511)
            .map(|n| n / 512 * 512)
            .ok_or_else(|| PackageError::invalid("tar length overflow"))?;
        if next > bytes.len() || bytes[end..next].iter().any(|b| *b != 0) {
            return Err(PackageError::invalid("truncated tar content/padding"));
        }
        let mut normalized = Vec::new();
        tar_entry(
            &mut normalized,
            &path,
            mode,
            kind,
            &link,
            &bytes[start..end],
        )?;
        if normalized != bytes[offset..next] {
            return Err(PackageError::invalid("unrecorded normalized tar metadata"));
        }
        entries.push(TarEntry {
            path,
            mode,
            kind,
            link,
            data: bytes[start..end].to_vec(),
        });
        offset = next;
    }
    Err(PackageError::invalid("missing tar terminator"))
}
pub(crate) fn validate_source_archive(bytes: &[u8]) -> Result<(), PackageError> {
    let entries = read_tar(bytes)?;
    if entries.is_empty() {
        return Err(PackageError::invalid("empty source/dependency archive"));
    }
    let nodes: Vec<_> = entries
        .iter()
        .map(|e| SourceNode {
            path: RelativePath::new(&e.path).expect("checked tar path"),
            mode: if e.kind == b'2' {
                0o120000
            } else {
                0o100000 | e.mode
            },
            sha256: if e.kind == b'2' {
                sha256(e.link.as_bytes())
            } else {
                sha256(&e.data)
            },
            bytes: if e.kind == b'2' {
                e.link.len() as u64
            } else {
                e.data.len() as u64
            },
            node: if e.kind == b'2' {
                SourceNodeKind::Symlink {
                    target: e.link.clone(),
                }
            } else {
                SourceNodeKind::File
            },
        })
        .collect();
    let mut sorted = nodes;
    sorted.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    validate_nodes(&sorted)
}

/// Registry-domain limits. Callers may tighten, never raise, production ceilings.
#[derive(Clone, Copy, Debug)]
pub struct RegistryArchiveLimits {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub member_bytes: u64,
    pub members: usize,
}
impl RegistryArchiveLimits {
    pub const DEFAULT: Self = Self {
        compressed_bytes: 64 * 1024 * 1024,
        expanded_bytes: MAX_ASSET_BYTES,
        member_bytes: 64 * 1024 * 1024,
        members: 10_000,
    };
    fn validate(self) -> Result<(), PackageError> {
        let maximum = Self::DEFAULT;
        if self.compressed_bytes == 0
            || self.compressed_bytes > maximum.compressed_bytes
            || self.expanded_bytes == 0
            || self.expanded_bytes > maximum.expanded_bytes
            || self.member_bytes == 0
            || self.member_bytes > maximum.member_bytes
            || self.members == 0
            || self.members > maximum.members
        {
            return Err(PackageError::invalid(
                "unsupported registry source archive limits",
            ));
        }
        Ok(())
    }
}

// Only ordinary registry members in the supported GNU/POSIX layouts are
// accepted. GNU extension areas are never guessed to be POSIX fields.
fn registry_members<'a>(
    bytes: &'a [u8],
    root: &str,
    limits: RegistryArchiveLimits,
) -> Result<BTreeMap<String, (u32, &'a [u8])>, PackageError> {
    if bytes.len() < 1024
        || !bytes.len().is_multiple_of(512)
        || bytes.len() as u64 > limits.expanded_bytes
    {
        return Err(PackageError::invalid(
            "truncated/oversized original registry tar",
        ));
    }
    let mut members = BTreeMap::new();
    let mut offset: usize = 0;
    loop {
        let end = offset
            .checked_add(512)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| PackageError::invalid("missing original tar terminator"))?;
        let h = &bytes[offset..end];
        if h.iter().all(|b| *b == 0) {
            if bytes.len() - offset < 1024 || bytes[offset..].iter().any(|b| *b != 0) {
                return Err(PackageError::invalid(
                    "truncated original tar end markers or hidden payload",
                ));
            }
            break;
        }
        if members.len() >= limits.members {
            return Err(PackageError::invalid(
                "original registry member-count limit",
            ));
        }
        let expected = octal(&h[148..156])?;
        let sum: u64 = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as u64
                } else {
                    *b as u64
                }
            })
            .sum();
        if expected != sum {
            return Err(PackageError::invalid("original tar checksum mismatch"));
        }
        let magic = &h[257..265];
        let name = tar_text(&h[..100])?;
        let full = if magic == b"ustar  \0" {
            if h[345..512].iter().any(|b| *b != 0) {
                return Err(PackageError::invalid("unsupported GNU extension area"));
            }
            name
        } else if magic == b"ustar\x0000" {
            if h[500..512].iter().any(|b| *b != 0) {
                return Err(PackageError::invalid("unsupported POSIX header padding"));
            }
            let prefix = tar_text(&h[345..500])?;
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        } else {
            return Err(PackageError::invalid(
                "unsupported original GNU/POSIX tar format",
            ));
        };
        RelativePath::new(&full)?;
        let path = full
            .strip_prefix(root)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| PackageError::invalid("original tar member outside exact crate root"))?
            .to_owned();
        let relative = RelativePath::new(&path)?;
        check_input_path(&relative)?;
        if h[156] != b'0' || !tar_text(&h[157..257])?.is_empty() {
            return Err(PackageError::invalid(
                "original registry archive contains a link/special/extension node",
            ));
        }
        let mode = octal(&h[100..108])?;
        if !matches!(mode, 0o644 | 0o755) {
            return Err(PackageError::invalid("unsupported original source mode"));
        }
        for field in [&h[108..116], &h[116..124], &h[136..148]] {
            octal(field)?;
        }
        tar_text(&h[265..297])?;
        tar_text(&h[297..329])?;
        if octal(&h[329..337])? != 0 || octal(&h[337..345])? != 0 {
            return Err(PackageError::invalid(
                "original registry archive has device metadata",
            ));
        }
        let size = octal(&h[124..136])?;
        if size > limits.member_bytes {
            return Err(PackageError::invalid("original registry member-size limit"));
        }
        let size = usize::try_from(size)
            .map_err(|_| PackageError::invalid("original member size overflow"))?;
        let start = end;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| PackageError::invalid("truncated original member body"))?;
        let next = end
            .checked_add(511)
            .map(|n| n / 512 * 512)
            .filter(|next| *next <= bytes.len())
            .ok_or_else(|| PackageError::invalid("truncated original member padding"))?;
        if bytes[end..next].iter().any(|b| *b != 0)
            || members
                .insert(path, (mode as u32, &bytes[start..end]))
                .is_some()
        {
            return Err(PackageError::invalid(
                "duplicate original source path or nonzero member padding",
            ));
        }
        offset = next;
    }
    if members.is_empty() {
        return Err(PackageError::invalid("empty original source archive"));
    }
    for path in members.keys() {
        let mut parent = Path::new(path).parent();
        while let Some(p) = parent {
            if p.to_str().is_some_and(|p| members.contains_key(p)) {
                return Err(PackageError::invalid(
                    "original source file-ancestor collision",
                ));
            }
            parent = p.parent();
        }
    }
    Ok(members)
}

/// Compare every original gzip member's path, type, mode and bytes with the
/// complete normalized source set. The sealer invokes this predicate itself.
pub fn verify_registry_source(
    original: &[u8],
    normalized: &[u8],
    name: &str,
    version: &str,
    limits: RegistryArchiveLimits,
) -> Result<(), PackageError> {
    limits.validate()?;
    if original.is_empty()
        || original.len() as u64 > limits.compressed_bytes
        || normalized.len() as u64 > limits.expanded_bytes
    {
        return Err(PackageError::invalid(
            "compressed/normalized registry source limit",
        ));
    }
    if name.is_empty()
        || version.is_empty()
        || name.contains(['/', '\\'])
        || version.contains(['/', '\\'])
    {
        return Err(PackageError::invalid("invalid registry crate identity"));
    }
    let root = format!("{name}-{version}/");
    RelativePath::new(root.trim_end_matches('/'))?;
    let mut decoder = flate2::bufread::GzDecoder::new(original);
    let mut expanded = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        // A nonempty read at the exact bound still validates CRC/ISIZE and EOF.
        let count = decoder
            .read(&mut buffer)
            .map_err(|e| PackageError::invalid(format!("original gzip decode: {e}")))?;
        if count == 0 {
            break;
        }
        let next = expanded
            .len()
            .checked_add(count)
            .filter(|n| *n as u64 <= limits.expanded_bytes)
            .ok_or_else(|| PackageError::invalid("expanded registry source limit"))?;
        expanded
            .try_reserve_exact(next - expanded.len())
            .map_err(|_| PackageError::unavailable("bounded source decode allocation"))?;
        expanded.extend_from_slice(&buffer[..count]);
    }
    if !decoder.into_inner().is_empty() {
        return Err(PackageError::invalid(
            "multiple gzip members or trailing compressed bytes",
        ));
    }
    let original_members = registry_members(&expanded, &root, limits)?;
    let normalized_members = read_tar_bounded(normalized, limits.member_bytes, limits.members)?;
    if original_members.len() != normalized_members.len() {
        return Err(PackageError::invalid(
            "original/normalized source member set mismatch",
        ));
    }
    for member in &normalized_members {
        let (mode, data) = original_members
            .get(&member.path)
            .ok_or_else(|| PackageError::invalid("unexplained normalized source member"))?;
        if member.kind != b'0' || member.mode != *mode || member.data.as_slice() != *data {
            return Err(PackageError::invalid(
                "original/normalized source type/mode/content mismatch",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub id: String,
    pub target: String,
    pub abi_profile: String,
    pub builder: RelativePath,
    pub formats: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSettings {
    pub source_archive: RelativePath,
    pub offline_inventory: RelativePath,
    pub notices: RelativePath,
    pub license_index: RelativePath,
    pub sbom: RelativePath,
    pub source_availability: RelativePath,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseConfig {
    pub schema: String,
    pub product_version: String,
    pub cargo_toml_sha256: Digest,
    pub release_toml_sha256: Digest,
    pub package_epoch: u32,
    pub package_revision: u32,
    pub source_epoch: u64,
    pub jobs: u16,
    pub selected_profile: String,
    pub profiles: Vec<ProfileConfig>,
    pub artifacts: ArtifactSettings,
    #[serde(skip)]
    pub expected_source: Option<SourceIdentity>,
}
impl ReleaseConfig {
    pub fn parse_json(bytes: &[u8]) -> Result<Self, PackageError> {
        let config: Self = closed(bytes)?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<(), PackageError> {
        if self.schema != "osslscope-release-config-v1"
            || self.product_version.is_empty()
            || self.package_epoch != 1
            || self.package_revision != 1
            || self.source_epoch != SOURCE_EPOCH
            || self.jobs != 2
            || !matches!(self.selected_profile.as_str(), "gnu" | "musl")
            || self.profiles.len() != 2
        {
            return Err(PackageError::invalid(
                "unsupported candidate policy or missing explicit profile",
            ));
        }
        for (p, id, target, abi, formats) in [
            (
                &self.profiles[0],
                "gnu",
                "x86_64-unknown-linux-gnu",
                "linux-x86_64-gnu",
                vec!["deb", "rpm", "prefix"],
            ),
            (
                &self.profiles[1],
                "musl",
                "x86_64-unknown-linux-musl",
                "linux-x86_64-musl",
                vec!["prefix"],
            ),
        ] {
            if p.id != id
                || p.target != target
                || p.abi_profile != abi
                || p.builder.as_str() != format!("packaging/builders/{id}.json")
                || p.formats != formats
            {
                return Err(PackageError::invalid("profile policy mismatch"));
            }
        }
        let actual = json_bytes(&self.artifacts)?;
        let expected = json!({"source_archive":"source.tar","offline_inventory":"offline-inventory.json","notices":"notices.json","license_index":"license-index.json","sbom":"source.spdx.json","source_availability":"source-availability.json"});
        if actual != json_bytes(&expected)? {
            return Err(PackageError::invalid("unsupported artifact settings"));
        }
        Ok(())
    }
    pub(crate) fn verify(&self, tree: &SourceTree) -> Result<(), PackageError> {
        self.validate()?;
        let cargo = read_regular(&tree.root, &RelativePath::new("Cargo.toml")?, 1_048_576)?;
        let release = read_regular(
            &tree.root,
            &RelativePath::new("packaging/release.toml")?,
            1_048_576,
        )?;
        let package = package_fields(&cargo)?;
        if package.get("name") != Some(&"osslscope".to_owned())
            || package.get("version") != Some(&self.product_version)
            || sha256(&cargo) != self.cargo_toml_sha256
            || sha256(&release) != self.release_toml_sha256
        {
            return Err(PackageError::invalid(
                "actual root Cargo/source policy binding mismatch",
            ));
        }
        let profiles = self
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.id.clone(),
                    json!({
                        "target":profile.target,"abi_profile":profile.abi_profile,
                        "builder":profile.builder,"formats":profile.formats,
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        let expected = json!({
            "schema":"osslscope-release-policy-v1", "package_epoch":1,
            "package_revision":1, "source_epoch":SOURCE_EPOCH, "jobs":2,
            "profiles":profiles, "artifacts":self.artifacts,
        });
        if policy_fields(&release)? != expected {
            return Err(PackageError::invalid(
                "typed release policy differs from original TOML",
            ));
        }
        if self
            .expected_source
            .as_ref()
            .is_some_and(|s| s != tree.identity())
        {
            return Err(PackageError::invalid("claimed source identity mismatch"));
        }
        for path in [
            "Cargo.toml",
            "Cargo.lock",
            "crates/ebpf/Cargo.toml",
            "crates/ebpf/Cargo.lock",
            "crates/bpf-contract/Cargo.toml",
            "scripts/build-dev.sh",
            "scripts/install-dev.sh",
            "scripts/package-release.py",
            "packaging/release.toml",
            "NOTICE.md",
            "LICENSES/README.md",
            "LICENSE",
            "LICENSES/GPL-2.0-only.txt",
        ] {
            if !tree.contains(path) {
                return Err(PackageError::invalid(format!(
                    "required original source path absent: {path}"
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn selected(&self) -> &ProfileConfig {
        self.profiles
            .iter()
            .find(|p| p.id == self.selected_profile)
            .expect("validated explicit profile")
    }
}

// One owning byte envelope and structural TOML1.0 parser serves both Cargo
// and release policy. Parsing the complete document also rejects errors outside
// the fields we consume. Do not replace this with a recoverable/partial parser.
fn parse_toml(bytes: &[u8]) -> Result<toml::Table, PackageError> {
    if bytes.is_empty() || bytes.len() > 1_048_576 || bytes.starts_with(b"\xef\xbb\xbf") {
        return Err(PackageError::invalid(
            "empty/oversized/BOM-prefixed TOML input",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PackageError::invalid("non-UTF8 TOML"))?;
    text.parse::<toml::Table>()
        .map_err(|error| PackageError::invalid(format!("invalid TOML: {error}")))
}
fn policy_fields(bytes: &[u8]) -> Result<Value, PackageError> {
    fn policy_value(value: toml::Value) -> Result<Value, PackageError> {
        match value {
            toml::Value::String(value) => Ok(json!(value)),
            toml::Value::Integer(value) => Ok(json!(value)),
            toml::Value::Boolean(value) => Ok(json!(value)),
            toml::Value::Array(values) => values
                .into_iter()
                .map(policy_value)
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            toml::Value::Table(values) => values
                .into_iter()
                .map(|(key, value)| Ok((key, policy_value(value)?)))
                .collect::<Result<serde_json::Map<String, Value>, PackageError>>()
                .map(Value::Object),
            toml::Value::Float(_) | toml::Value::Datetime(_) => Err(PackageError::invalid(
                "unsupported release policy value type",
            )),
        }
    }
    policy_value(toml::Value::Table(parse_toml(bytes)?))
}
pub(crate) fn package_fields(bytes: &[u8]) -> Result<BTreeMap<String, String>, PackageError> {
    let document = parse_toml(bytes)?;
    let package = document
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| PackageError::invalid("missing actual Cargo package table"))?;
    let mut fields = BTreeMap::new();
    for key in ["name", "version", "license"] {
        if let Some(value) = package.get(key) {
            let value = value
                .as_str()
                .ok_or_else(|| PackageError::invalid("Cargo package identity must be string"))?;
            fields.insert(key.into(), value.to_owned());
        }
    }
    if !fields.contains_key("name") || !fields.contains_key("version") {
        return Err(PackageError::invalid(
            "missing actual Cargo package identity",
        ));
    }
    Ok(fields)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResource {
    pub role: String,
    pub identity: ToolIdentity,
    pub content: ContentEntry,
    pub acquisition: ContentEntry,
    pub source_component: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Determinism {
    pub locale: String,
    pub timezone: String,
    pub umask: u32,
    pub uid: u32,
    pub gid: u32,
    pub file_mode: u32,
    pub executable_mode: u32,
    pub symlink_mode: u32,
    pub mtime: u64,
    pub archive_order: String,
    pub compression: String,
    pub path_remap: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipe {
    pub schema: String,
    pub profile: String,
    pub host_profile: HostProfile,
    pub tools: ToolInventory,
    pub resources: Vec<ToolResource>,
    pub abi_evidence: ContentEntry,
    pub required_cells: Vec<String>,
    pub argv: Vec<String>,
    pub bpf_argv: Vec<String>,
    pub environment: Vec<EnvironmentEntry>,
    pub formats: Vec<String>,
    pub jobs: u16,
    pub determinism: Determinism,
}
impl BuildRecipe {
    pub fn parse_json(bytes: &[u8]) -> Result<Self, PackageError> {
        closed(bytes)
    }
    pub(crate) fn verify(
        &self,
        config: &ReleaseConfig,
        tools: &ToolInventory,
        deps: &DependencyInventory,
    ) -> Result<(), PackageError> {
        let selected = config.selected();
        if self.schema != "osslscope-build-recipe-v1"
            || self.profile != selected.id
            || self.host_profile.target != selected.target
            || self.host_profile.abi_profile != selected.abi_profile
            || self.host_profile.abi_floor.is_empty()
            || self.tools != *tools
            || self.formats != selected.formats
            || self.jobs != 2
        {
            return Err(PackageError::invalid(
                "selected profile/recipe/tool inventory mismatch",
            ));
        }
        if tools.host.version != "1.88.0"
            || tools.bpf.version != "nightly-2026-05-20"
            || tools.linker.version != "0.10.4"
        {
            return Err(PackageError::invalid("unreviewed tool version"));
        }
        let expected: Determinism = closed(&json_bytes(
            &json!({"locale":"C","timezone":"UTC","umask":18,"uid":0,"gid":0,"file_mode":420,"executable_mode":493,"symlink_mode":511,"mtime":SOURCE_EPOCH,"archive_order":"lexical","compression":"none","path_remap":"--remap-path-prefix=source=."}),
        )?)?;
        if self.determinism != expected {
            return Err(PackageError::invalid("unbound deterministic inputs"));
        }
        let expected_environment: Vec<EnvironmentEntry> = closed(&json_bytes(
            &json!([{"name":"LC_ALL","value":"C"},{"name":"TZ","value":"UTC"},{"name":"SOURCE_DATE_EPOCH","value":SOURCE_EPOCH.to_string()},{"name":"CARGO_NET_OFFLINE","value":"true"},{"name":"CARGO_BUILD_JOBS","value":"2"},{"name":"RUSTFLAGS","value":self.determinism.path_remap}]),
        )?)?;
        if self.environment != expected_environment {
            return Err(PackageError::invalid("unrecorded environment override"));
        }
        let expected_argv = vec![
            "cargo",
            "build",
            "--release",
            "--frozen",
            "--offline",
            "--target",
            selected.target.as_str(),
            "--jobs",
            "2",
        ];
        let expected_bpf = vec![
            "cargo",
            "build",
            "--release",
            "--frozen",
            "--offline",
            "-Z",
            "build-std=core",
            "--target",
            "bpfel-unknown-none",
            "--jobs",
            "2",
        ];
        if self.argv != expected_argv || self.bpf_argv != expected_bpf {
            return Err(PackageError::invalid("unrecorded compiler argv"));
        }
        let identities = std::iter::once(&tools.host)
            .chain([&tools.bpf, &tools.linker, &tools.llvm, &tools.builder])
            .chain(&tools.components)
            .collect::<Vec<_>>();
        if identities.len() != self.resources.len() {
            return Err(PackageError::invalid(
                "tool component/resource closure incomplete",
            ));
        }
        let mut roles = BTreeSet::new();
        let mut names = BTreeSet::new();
        for (resource, identity) in self.resources.iter().zip(identities) {
            if &resource.identity != identity
                || identity.sha256 != resource.content.sha256
                || identity.name.is_empty()
                || identity.version.is_empty()
                || identity.name.contains(['/', '\\'])
                || identity.version.starts_with(['/', '\\'])
                || identity.name.chars().any(char::is_control)
                || identity.version.chars().any(char::is_control)
                || matches!(identity.version.as_str(), "latest" | "main" | "master")
                || !names.insert(&identity.name)
                || !roles.insert(resource.role.as_str())
                || !deps.tool_sources.contains(&resource.source_component)
            {
                return Err(PackageError::invalid(
                    "tool binary/source/component identity mismatch",
                ));
            }
            verify_entry(&deps.root, &resource.content)?;
            verify_entry(&deps.root, &resource.acquisition)?;
        }
        for role in [
            "host",
            "bpf",
            "linker",
            "llvm",
            "builder",
            "rust-src",
            "sysroot",
            "native-compiler",
            "native-linker",
            "archive",
            "package",
            "host-cargo",
            "bpf-cargo",
            "llvm-library",
            "host-sysroot",
            "bpf-sysroot",
        ] {
            if !roles.contains(role) {
                return Err(PackageError::invalid(format!(
                    "missing mandatory tool role {role}"
                )));
            }
        }
        for (role, version) in [
            ("host-cargo", "1.88.0"),
            ("bpf-cargo", "nightly-2026-05-20"),
            ("host-sysroot", "1.88.0"),
            ("bpf-sysroot", "nightly-2026-05-20"),
            ("rust-src", "nightly-2026-05-20"),
        ] {
            if self
                .resources
                .iter()
                .find(|r| r.role == role)
                .is_none_or(|r| r.identity.version != version)
            {
                return Err(PackageError::invalid(
                    "tool component/toolchain pin mismatch",
                ));
            }
        }
        if self
            .resources
            .iter()
            .take(5)
            .map(|r| r.role.as_str())
            .collect::<Vec<_>>()
            != ["host", "bpf", "linker", "llvm", "builder"]
        {
            return Err(PackageError::invalid(
                "tool role/selected identity ordering mismatch",
            ));
        }
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
        enum Interpreter {
            Static,
            Dynamic { path: String },
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AbiCell {
            name: String,
            interpreter: Interpreter,
            needed: Vec<String>,
            symbol_versions: Vec<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AbiEvidence {
            schema: String,
            host_profile: HostProfile,
            cells: Vec<AbiCell>,
        }
        let abi: AbiEvidence = closed(&verify_entry(&deps.root, &self.abi_evidence)?)?;
        if abi.schema != "osslscope-abi-evidence-v1"
            || abi.host_profile != self.host_profile
            || self.required_cells.is_empty()
            || abi.cells.iter().map(|c| &c.name).collect::<Vec<_>>()
                != self.required_cells.iter().collect::<Vec<_>>()
            || self.required_cells.iter().collect::<BTreeSet<_>>().len()
                != self.required_cells.len()
            || abi.cells.iter().any(|c| {
                c.name.is_empty()
                    || match &c.interpreter {
                        Interpreter::Static => !c.needed.is_empty(),
                        Interpreter::Dynamic { path } => {
                            !path.starts_with('/')
                                || path.chars().any(char::is_control)
                                || path.split('/').any(|p| p == "..")
                        }
                    }
                    || c.needed.iter().any(String::is_empty)
                    || c.symbol_versions.iter().any(String::is_empty)
            })
        {
            return Err(PackageError::invalid(
                "missing/mismatched measured required-cell ABI evidence",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAssets {
    pub source_archive: ContentEntry,
    pub dependency_archives: Vec<ContentEntry>,
    pub tool_source_archives: Vec<ContentEntry>,
    pub tool_archives: Vec<ContentEntry>,
    pub offline_inventory: ContentEntry,
    pub notices: ContentEntry,
    pub license_index: ContentEntry,
    pub license_texts: Vec<ContentEntry>,
    pub sbom: ContentEntry,
    pub source_availability: ContentEntry,
}
#[derive(Clone, Debug)]
pub struct SealedSource {
    pub assets: SourceAssets,
    pub original_source: SourceIdentity,
    pub locks: LockIdentity,
    pub inputs: BuildInputs,
    pub input_bytes: Vec<u8>,
    pub(crate) tree: SourceTree,
    pub(crate) config: ReleaseConfig,
    pub(crate) dependencies: DependencyInventory,
    pub(crate) recipe: BuildRecipe,
    pub(crate) recipe_bytes: Vec<u8>,
    pub(crate) retained: BTreeMap<String, Arc<[u8]>>,
    pub(crate) required_inputs: Vec<ContentEntry>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealingRequest {
    pub config: ReleaseConfig,
    pub dependencies: DependencyInventory,
    pub tools: ToolInventory,
}
impl SealingRequest {
    pub fn parse_json(input_root: &Path, bytes: &[u8]) -> Result<Self, PackageError> {
        let mut request: Self = closed(bytes)?;
        request.config.validate()?;
        request.dependencies =
            DependencyInventory::parse_json(input_root, &json_bytes(&request.dependencies)?)?;
        Ok(request)
    }
}
impl SealedSource {
    pub fn asset_bytes(&self, entry: &ContentEntry) -> Result<&[u8], PackageError> {
        let bytes = self
            .retained
            .get(entry.path.as_str())
            .ok_or_else(|| PackageError::unavailable("retained source asset missing"))?;
        if entry.bytes != bytes.len() as u64 || entry.sha256 != sha256(bytes) {
            return Err(PackageError::invalid(
                "retained source asset identity mismatch",
            ));
        }
        Ok(bytes)
    }
    pub fn retained_assets(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.retained.iter().map(|(p, b)| (p.as_str(), b.as_ref()))
    }
}
pub fn seal_source(
    tree: &SourceTree,
    config: &ReleaseConfig,
    deps: &DependencyInventory,
    tools: &ToolInventory,
) -> Result<SealedSource, PackageError> {
    // Open the mandatory selected builder first: absent actual resources are prerequisites.
    config.validate()?;
    let recipe_bytes = read_regular(&tree.root, &config.selected().builder, 1_048_576)?;
    let recipe = BuildRecipe::parse_json(&recipe_bytes)?;
    tree.verify()?;
    config.verify(tree)?;
    if !tree.contains(config.selected().builder.as_str()) {
        return Err(PackageError::invalid(
            "builder recipe not in original inventory",
        ));
    }
    recipe.verify(config, tools, deps)?;
    deps.verify(tree, &recipe)?;
    let source_archive = tree.archive()?;
    let (assets, retained, required_inputs) =
        collect_assets(tree, config, deps, &recipe, &recipe_bytes, &source_archive)?;
    let inputs = BuildInputs {
        schema: "osslscope-build-inputs-v1".into(),
        source: tree.identity().clone(),
        product_version: config.product_version.clone(),
        package_epoch: config.package_epoch,
        package_revision: config.package_revision,
        source_epoch: config.source_epoch,
        host_profile: recipe.host_profile.clone(),
        locks: deps.locks.clone(),
        recipe: RecipeIdentity {
            recipe_sha256: sha256(&recipe_bytes),
            config_sha256: config.release_toml_sha256,
        },
        tools: tools.clone(),
        jobs: config.jobs,
        argv: recipe.argv.clone(),
        environment: recipe.environment.clone(),
        offline_inventory_sha256: assets.offline_inventory.sha256,
    };
    let input_bytes = canonical_bytes(&inputs);
    parse_canonical::<BuildInputs>(&input_bytes)?;
    let sealed = SealedSource {
        assets,
        original_source: tree.identity().clone(),
        locks: deps.locks.clone(),
        inputs,
        input_bytes,
        tree: tree.clone(),
        config: config.clone(),
        dependencies: deps.clone(),
        recipe,
        recipe_bytes,
        retained,
        required_inputs,
    };
    verify_closure(&sealed)?;
    Ok(sealed)
}

#[cfg(test)]
mod tests {
    use super::super::inventory::source_fixtures::Fixture;
    use super::*;

    #[test]
    fn exact_archive_read_must_match_the_admitted_node_despite_stable_individual_reads() {
        let fixture = Fixture::new();
        let tree = fixture.tree();
        let node = tree
            .manifest
            .inventory
            .files
            .iter()
            .find(|n| n.path.as_str() == "tests/fixtures/example.json")
            .unwrap();
        let original = &fixture.files[node.path.as_str()];
        assert_eq!(node.read_bytes(&tree.root).unwrap(), *original);
        for bytes in [
            b"another stable, independently readable source version\n".as_slice(),
            &vec![b'x'; original.len()],
        ] {
            std::fs::write(tree.root.join(node.path.as_str()), bytes).unwrap();
            assert_eq!(
                read_regular(&tree.root, &node.path, MAX_ASSET_BYTES).unwrap(),
                bytes
            );
            assert!(
                node.read_bytes(&tree.root).is_err(),
                "stable per-open mutation must not satisfy admitted node identity"
            );
            std::fs::write(tree.root.join(node.path.as_str()), original).unwrap();
            tree.verify().unwrap();
        }
    }
}
