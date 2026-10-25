// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure, fixed descriptors and retained resource admission. No launch authority.
use super::{
    PackageError,
    inventory::ComponentSource,
    records::{ContentEntry, Digest, EnvironmentEntry, RelativePath, sha256},
    source::{self, BuildRecipe, SOURCE_EPOCH, SealedSource},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
type R<T> = Result<T, PackageError>;
type Members = BTreeMap<String, Arc<[u8]>>;
type DecodedArchive = (ArchiveUsage, Members, ToolTree);
fn invalid(s: &str) -> PackageError {
    PackageError::invalid(s)
}

fn canonical_document<T: serde::de::DeserializeOwned + Serialize>(data: &[u8]) -> R<T> {
    if data.is_empty() || data.len() > 536870912 {
        return Err(invalid("document size bound"));
    }
    let value: T = serde_json::from_slice(data).map_err(|_| invalid("closed resource document"))?;
    if source::json_bytes(&value)? != data {
        return Err(invalid("noncanonical resource document"));
    }
    Ok(value)
}

#[derive(Clone, Debug)]
pub struct BuildPaths {
    pub work_root: PathBuf,
    pub host_target: PathBuf,
    pub bpf_target: PathBuf,
    pub cache_root: PathBuf,
    pub output_root: PathBuf,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Bootstrap,
    Native,
    Bpf,
    Host,
    Readback,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Native => "native",
            Self::Bpf => "bpf",
            Self::Host => "host",
            Self::Readback => "readback",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct CommandSpec {
    executable: PathBuf,
    argv: Vec<String>,
    environment: Vec<EnvironmentEntry>,
    cwd: PathBuf,
}
fn phase_spec(recipe: &BuildRecipe, phase: Phase) -> R<CommandSpec> {
    let target = &recipe.host_profile.target;
    if recipe.schema != "osslscope-build-recipe-v2"
        || recipe.jobs != 2
        || !["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"].contains(&target.as_str())
        || recipe.argv != source::recipe_v2_argv(target)
        || recipe.bpf_argv != source::recipe_v2_bpf_argv()
        || recipe.environment != source::recipe_v2_environment(SOURCE_EPOCH)
        || recipe.determinism.path_remap != "--remap-path-prefix=/build=."
    {
        return Err(invalid("fixed descriptor recipe mismatch"));
    }
    let mut environment = recipe.environment.clone();
    let mut add = |name: &str, value: String| {
        environment.push(EnvironmentEntry {
            name: name.into(),
            value,
        })
    };
    let mut argv;
    let executable;
    let cwd;
    if matches!(phase, Phase::Native | Phase::Readback) {
        add("HOME", "/build/home/bootstrap".into());
        add("TMPDIR", "/build/tmp/bootstrap".into());
        executable =
            "/build/target/bootstrap/x86_64-unknown-linux-gnu/release/osslscope-package".into();
        argv = if phase == Phase::Native {
            [
                "build-bundle",
                "--root",
                "/build/source",
                "--inputs",
                "/build/inputs",
                "--request",
                "/build/request.json",
                "--output",
                "/build/output",
            ]
            .to_vec()
        } else {
            ["verify-payload", "--root", "/build/output"].to_vec()
        }
        .into_iter()
        .map(str::to_owned)
        .collect();
        cwd = "/build/source".into();
    } else {
        let name = phase.name();
        let tc = if phase == Phase::Bpf { "bpf" } else { "host" };
        argv = if phase == Phase::Bpf {
            recipe.bpf_argv.clone()
        } else {
            source::recipe_v2_argv(if phase == Phase::Bootstrap {
                "x86_64-unknown-linux-gnu"
            } else {
                target
            })
        };
        if phase == Phase::Bootstrap {
            argv[10] = "osslscope-package".into();
        }
        argv.remove(0);
        for (key, val) in [
            ("CARGO_TARGET_DIR", format!("/build/target/{name}")),
            ("CARGO_HOME", format!("/build/cache/{name}/cargo")),
            ("HOME", format!("/build/home/{name}")),
            ("TMPDIR", format!("/build/tmp/{name}")),
            ("PATH", "/build/tools/build/bin".into()),
            ("RUSTC", format!("/build/tools/{tc}/bin/rustc")),
            ("CC", "/build/tools/build/bin/cc".into()),
            ("AR", "/build/tools/build/bin/ar".into()),
            (
                "LD_LIBRARY_PATH",
                "/build/tools/llvm/lib:/build/tools/native/lib".into(),
            ),
            (
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                "/build/tools/build/bin/cc".into(),
            ),
        ] {
            add(key, val);
        }
        if phase == Phase::Host && target == "x86_64-unknown-linux-musl" {
            for (key, value) in [
                (
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER",
                    "/build/tools/native/bin/cc",
                ),
                ("CC_x86_64_unknown_linux_musl", "/build/tools/native/bin/cc"),
                ("AR_x86_64_unknown_linux_musl", "/build/tools/native/bin/ar"),
            ] {
                add(key, value.into());
            }
        }
        if phase == Phase::Bpf {
            add(
                "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER",
                "/build/tools/bpf-linker/bin/bpf-linker".into(),
            );
        }
        if phase == Phase::Host {
            add("OSSL_PACKAGE_RECORD_DIR", "/build/records".into());
        }
        executable = format!("/build/tools/{tc}/bin/cargo").into();
        cwd = if phase == Phase::Bpf {
            "/build/source/crates/ebpf"
        } else {
            "/build/source"
        }
        .into();
    }
    Ok(CommandSpec {
        executable,
        argv,
        environment,
        cwd,
    })
}
fn descriptor_sha256(spec: &CommandSpec) -> Digest {
    sha256(&source::json_bytes(spec).expect("descriptor serialization"))
}

/// The nested targets/cache are fixed children; work/output must be new siblings
/// in an externally admitted domain. No paths enter a canonical identity.
pub fn validate_paths(paths: &BuildPaths) -> R<()> {
    if paths.host_target != paths.work_root.join("target/host")
        || paths.bpf_target != paths.work_root.join("target/bpf")
        || paths.cache_root != paths.work_root.join("cache")
    {
        return Err(invalid("noncanonical physical mapping"));
    }
    for path in [&paths.work_root, &paths.output_root] {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || path.symlink_metadata().is_ok()
        {
            return Err(invalid("new normalized absolute path required"));
        }
        for ancestor in path
            .parent()
            .ok_or_else(|| invalid("root path"))?
            .ancestors()
        {
            use std::os::unix::fs::MetadataExt;
            let meta =
                fs::symlink_metadata(ancestor).map_err(|_| invalid("missing physical ancestor"))?;
            if !meta.is_dir()
                || ![0, unsafe { libc::geteuid() }].contains(&meta.uid())
                || meta.mode() & 0o022 != 0
            {
                return Err(invalid("unprotected physical ancestry"));
            }
        }
    }
    if paths.work_root.starts_with(&paths.output_root)
        || paths.output_root.starts_with(&paths.work_root)
    {
        return Err(invalid("overlapping physical roots"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ToolNode {
    File {
        path: RelativePath,
        mode: u32,
        bytes: u64,
        sha256: Digest,
    },
    Directory {
        path: RelativePath,
        mode: u32,
    },
    Symlink {
        path: RelativePath,
        mode: u32,
        target: String,
    },
}
impl ToolNode {
    fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } | Self::Symlink { path, .. } => {
                path.as_str()
            }
        }
    }
    fn mode(&self) -> u32 {
        match self {
            Self::File { mode, .. } | Self::Directory { mode, .. } | Self::Symlink { mode, .. } => {
                *mode
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTree {
    schema: String,
    entries: Vec<ToolNode>,
}
impl ToolTree {
    fn parse(data: &[u8]) -> R<Self> {
        let tree: Self = canonical_document(data)?;
        tree.validate(false)?;
        Ok(tree)
    }
    fn validate(&self, implicit: bool) -> R<()> {
        if self.schema != "osslscope-tool-tree-v1" {
            return Err(invalid("tool tree schema"));
        }
        let mut last = "";
        let mut nodes = BTreeMap::new();
        for node in &self.entries {
            if node.path() <= last {
                return Err(invalid("unsorted/duplicate tree path"));
            }
            last = node.path();
            match node {
                ToolNode::File { mode, bytes, .. }
                    if matches!(mode, 0o644 | 0o755) && *bytes <= 536870912 => {}
                ToolNode::Directory { mode: 0o755, .. } => {}
                ToolNode::Symlink { mode: 0o777, .. } => {}
                _ => return Err(invalid("tool node mode/size")),
            }
            nodes.insert(node.path(), node);
        }
        for node in &self.entries {
            let mut parent = Path::new(node.path()).parent();
            while let Some(p) = parent {
                if let Some(s) = p.to_str().filter(|s| !s.is_empty()) {
                    if !(matches!(nodes.get(s), Some(ToolNode::Directory { .. }))
                        || implicit && !nodes.contains_key(s))
                    {
                        return Err(invalid("link/file/missing extraction ancestor"));
                    }
                }
                parent = p.parent();
            }
            if !implicit {
                self.resolve(node.path())?;
            }
        }
        Ok(())
    }
    fn resolve(&self, path: &str) -> R<&ToolNode> {
        let mut current = path.to_owned();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current.clone()) {
                return Err(invalid("tool link loop"));
            }
            let parts = current.split('/').collect::<Vec<_>>();
            let mut changed = false;
            for i in 1..=parts.len() {
                let prefix = parts[..i].join("/");
                let node = self
                    .entries
                    .iter()
                    .find(|n| n.path() == prefix)
                    .ok_or_else(|| invalid("unresolved tool link"))?;
                if let ToolNode::Symlink { target, .. } = node {
                    let mut p = link_destination(&prefix, target)?;
                    if i < parts.len() {
                        p.push('/');
                        p.push_str(&parts[i..].join("/"));
                    }
                    current = p;
                    changed = true;
                    break;
                }
            }
            if !changed {
                return self
                    .entries
                    .iter()
                    .find(|n| n.path() == current)
                    .ok_or_else(|| invalid("unresolved tool member"));
            }
        }
    }
    fn subtree(&self, member: &str) -> R<Self> {
        if member.is_empty() {
            return Ok(self.clone());
        }
        if !matches!(
            self.entries.iter().find(|n| n.path() == member),
            Some(ToolNode::Directory { .. })
        ) {
            return Err(invalid("tree binding root"));
        }
        let prefix = format!("{member}/");
        let mut value = serde_json::to_value(self).map_err(|_| invalid("tree encoding"))?;
        let entries = value["entries"]
            .as_array_mut()
            .ok_or_else(|| invalid("tree encoding"))?;
        entries.retain(|v| v["path"].as_str().is_some_and(|p| p.starts_with(&prefix)));
        for entry in entries {
            entry["path"] = entry["path"].as_str().unwrap()[prefix.len()..].into();
        }
        Self::parse(&source::json_bytes(&value)?)
    }
}
fn link_destination(path: &str, target: &str) -> R<String> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\\')
        || target.chars().any(char::is_control)
    {
        return Err(invalid("invalid tool link"));
    }
    let mut p = path.split('/').map(str::to_owned).collect::<Vec<_>>();
    p.pop();
    for c in target.split('/') {
        match c {
            "" | "." => return Err(invalid("unnormalized link")),
            ".." => {
                p.pop().ok_or_else(|| invalid("escaping link"))?;
            }
            _ => p.push(c.into()),
        }
    }
    let s = p.join("/");
    RelativePath::new(s.clone())?;
    Ok(s)
}
#[derive(Clone, Copy, Debug)]
pub struct ArchiveLimits {
    pub input_bytes: u64,
    pub member_bytes: u64,
    pub decoded_bytes: u64,
    pub entries: u64,
}
impl ArchiveLimits {
    pub const DEFAULT: Self = Self {
        input_bytes: source::ArchiveCaps::TOOL.input,
        member_bytes: source::ArchiveCaps::TOOL.member,
        decoded_bytes: source::ArchiveCaps::TOOL.decoded,
        entries: source::ArchiveCaps::TOOL.entries,
    };
    fn validate(self) -> R<()> {
        let d = Self::DEFAULT;
        if self.input_bytes == 0
            || self.input_bytes > d.input_bytes
            || self.member_bytes == 0
            || self.member_bytes > d.member_bytes
            || self.decoded_bytes == 0
            || self.decoded_bytes > d.decoded_bytes
            || self.entries == 0
            || self.entries > d.entries
        {
            return Err(invalid("archive limits"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ArchiveUsage {
    decoded_bytes: u64,
    entries: u64,
}
impl ArchiveUsage {
    fn charge(&mut self, other: Self, limits: ArchiveLimits) -> R<()> {
        let decoded = self
            .decoded_bytes
            .checked_add(other.decoded_bytes)
            .filter(|n| *n <= limits.decoded_bytes)
            .ok_or_else(|| invalid("cumulative decoded bound"))?;
        let entries = self
            .entries
            .checked_add(other.entries)
            .filter(|n| *n <= limits.entries)
            .ok_or_else(|| invalid("cumulative entry bound"))?;
        self.decoded_bytes = decoded;
        self.entries = entries;
        Ok(())
    }
}

fn decode_archive_in(
    bytes: &[u8],
    tree: Option<&ToolTree>,
    limits: ArchiveLimits,
    implicit: bool,
    owner: &mut source::ArchiveAdmission,
) -> R<DecodedArchive> {
    let result = (|| {
        limits.validate()?;
        if let Some(tree) = tree {
            tree.validate(implicit)?;
        }
        let data = owner.decode(
            bytes,
            source::ArchiveProfile::Tool,
            source::ArchiveCaps {
                input: limits.input_bytes,
                member: limits.member_bytes,
                decoded: limits.decoded_bytes,
                entries: limits.entries,
            },
        )?;
        let mut nodes = BTreeMap::new();
        let mut files = BTreeMap::new();
        for entry in &data.nodes {
            let mut path = entry.path.clone();
            if entry.kind == b'5' && path.ends_with('/') {
                path.pop();
            }
            let relative = RelativePath::new(path.clone())?;
            // Replay the tool parser's raw grammar even when another profile
            // already decoded these exact bytes. A parsed zero is not proof
            // of a nonempty octal field; only an entirely NUL device pair
            // has the historical empty-field exception.
            let fields = [
                &entry.header[148..156],
                &entry.header[329..337],
                &entry.header[337..345],
            ];
            let tool_numbers = fields
                .iter()
                .take(if entry.header[329..345].iter().all(|b| *b == 0) {
                    1
                } else {
                    3
                })
                .all(|field| {
                    let raw = std::str::from_utf8(field)
                        .unwrap_or("")
                        .trim_matches(['\0', ' ']);
                    !raw.is_empty() && raw.bytes().all(|b| (b'0'..=b'7').contains(&b))
                });
            if !entry.posix
                || !entry.strict_numbers
                || !tool_numbers
                || entry.uid != 0
                || entry.gid != 0
                || ![0, SOURCE_EPOCH].contains(&entry.mtime)
                || !entry.uname.is_empty()
                || !entry.gname.is_empty()
                || entry.major != 0
                || entry.minor != 0
            {
                return Err(invalid("tool archive header policy"));
            }
            let mode = u32::try_from(entry.mode).map_err(|_| invalid("mode overflow"))?;
            let node = match entry.kind {
                b'0' if entry.link.is_empty() && matches!(mode, 0o644 | 0o755) => {
                    files.insert(path.clone(), entry.data.clone());
                    ToolNode::File {
                        path: relative,
                        mode,
                        bytes: entry.data.len() as u64,
                        sha256: sha256(&entry.data),
                    }
                }
                b'5' if entry.data.is_empty() && entry.link.is_empty() && mode == 0o755 => {
                    ToolNode::Directory {
                        path: relative,
                        mode,
                    }
                }
                b'2' if entry.data.is_empty() && mode == 0o777 => ToolNode::Symlink {
                    path: relative,
                    mode,
                    target: entry.link.clone(),
                },
                _ => return Err(invalid("tool archive node policy")),
            };
            if nodes.insert(path, node).is_some() {
                return Err(invalid("duplicate normalized tool member"));
            }
        }
        let actual = ToolTree {
            schema: "osslscope-tool-tree-v1".into(),
            entries: nodes.into_values().collect(),
        };
        actual.validate(implicit)?;
        if tree.is_some_and(|t| t != &actual) {
            return Err(invalid("tool tree/member mismatch"));
        }
        Ok((
            ArchiveUsage {
                decoded_bytes: data.decoded,
                entries: data.nodes.len() as u64,
            },
            files,
            actual,
        ))
    })();
    owner.finish(result)
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Standalone pure validation entrypoint; attempts use its shared-owner body."
    )
)]
fn validate_tool_archive(bytes: &[u8], tree: &ToolTree, limits: ArchiveLimits) -> R<ArchiveUsage> {
    let mut owner = source::ArchiveAdmission::standalone();
    Ok(decode_archive_in(bytes, Some(tree), limits, false, &mut owner)?.0)
}
fn source_binding(sealed: &SealedSource) -> Vec<u8> {
    let mut binding = sealed.input_bytes.clone();
    binding.extend_from_slice(&sealed.recipe_bytes);
    binding
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveRow {
    acquisition: ContentEntry,
    tree: ContentEntry,
    root: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    role: String,
    archive_sha256: Digest,
    member: String,
    kind: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutDocument {
    schema: String,
    archives: Vec<ArchiveRow>,
    bindings: Vec<Binding>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostDocument {
    schema: String,
    files: Vec<HostFile>,
    links: Vec<HostLink>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    path: String,
    sha256: Digest,
    bytes: u64,
    mode: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostLink {
    path: String,
    target: String,
}
const ROOTS: [&str; 8] = [
    "rootfs", "host", "bpf", "linker", "llvm", "native", "build", "package",
];
fn fixed(role: &str) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match role {
        "host" => ("host", "bin/rustc", "file"),
        "host-cargo" => ("host", "bin/cargo", "file"),
        "bpf" => ("bpf", "bin/rustc", "file"),
        "bpf-cargo" => ("bpf", "bin/cargo", "file"),
        "linker" => ("linker", "bin/bpf-linker", "file"),
        "native-compiler" => ("native", "bin/cc", "file"),
        "native-linker" => ("native", "bin/ld", "file"),
        "archive" => ("native", "bin/ar", "file"),
        "build-compiler" => ("build", "bin/cc", "file"),
        "build-linker" => ("build", "bin/ld", "file"),
        "build-archive" => ("build", "bin/ar", "file"),
        "host-sysroot" => ("host", "lib/rustlib", "tree"),
        "bpf-sysroot" => ("bpf", "lib/rustlib", "tree"),
        "rust-src" => ("bpf", "lib/rustlib/src/rust", "tree"),
        "sysroot" => ("native", "sysroot", "tree"),
        "build-sysroot" => ("build", "sysroot", "tree"),
        "llvm" => ("llvm", "lib", "tree"),
        "package" => ("package", "", "tree"),
        "builder" => ("rootfs", "", "tree"),
        _ => return None,
    })
}
fn host_tree(bytes: &[u8]) -> R<ToolTree> {
    let host: HostDocument = canonical_document(bytes)?;
    if host.schema != "osslscope-executor-host-v1" {
        return Err(invalid("host schema"));
    }
    let mut nodes = BTreeMap::new();
    let public = |path: &str| -> R<RelativePath> {
        if !path.starts_with('/')
            || ["/build/", "/root/", "/home/", "/tmp/", "/work/"]
                .iter()
                .any(|p| path.starts_with(p))
        {
            return Err(invalid("host private/nonabsolute path"));
        }
        RelativePath::new(&path[1..])
    };
    let mut last = "";
    for f in &host.files {
        if f.path.as_str() <= last || f.bytes == 0 {
            return Err(invalid("host file order/size"));
        }
        last = &f.path;
        let path = public(&f.path)?;
        nodes.insert(
            path.as_str().to_owned(),
            ToolNode::File {
                path,
                mode: f.mode,
                bytes: f.bytes,
                sha256: f.sha256,
            },
        );
    }
    last = "";
    for link in &host.links {
        if link.path.as_str() <= last {
            return Err(invalid("host link order"));
        }
        last = &link.path;
        let path = public(&link.path)?;
        let target = if link.target.starts_with('/') {
            public(&link.target)?;
            let mut parent = path.as_str().split('/').collect::<Vec<_>>();
            parent.pop();
            let destination = link.target[1..].split('/').collect::<Vec<_>>();
            let common = parent
                .iter()
                .zip(&destination)
                .take_while(|(left, right)| left == right)
                .count();
            format!(
                "{}{}",
                "../".repeat(parent.len() - common),
                destination[common..].join("/")
            )
        } else {
            link.target.clone()
        };
        if nodes
            .insert(
                path.as_str().into(),
                ToolNode::Symlink {
                    path,
                    mode: 0o777,
                    target,
                },
            )
            .is_some()
        {
            return Err(invalid("host node collision"));
        }
    }
    let paths = nodes.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        for p in Path::new(&path).ancestors().skip(1) {
            let s = p.to_str().unwrap();
            if !s.is_empty() {
                nodes.entry(s.into()).or_insert(ToolNode::Directory {
                    path: RelativePath::new(s)?,
                    mode: 0o755,
                });
            }
        }
    }
    let tree = ToolTree {
        schema: "osslscope-tool-tree-v1".into(),
        entries: nodes.into_values().collect(),
    };
    tree.validate(false)?;
    for p in ["usr/bin/python3.11", "usr/bin/bwrap"] {
        if !matches!(tree.resolve(p)?, ToolNode::File { mode: 0o755, .. }) {
            return Err(invalid("host runtime executable missing"));
        }
    }
    Ok(tree)
}
/// Owned consistency result only. Initial worker/runtime and source rights are separate gates.
pub struct ExecutorLayout {
    archives: source::ArchiveAdmission,
    roots: BTreeMap<String, ToolTree>,
    files: BTreeMap<(String, String), Arc<[u8]>>,
    identities: Vec<Digest>,
    descriptors: Vec<Digest>,
    usage: ArchiveUsage,
    documents: BTreeMap<String, Arc<[u8]>>,
}
impl ExecutorLayout {
    pub fn retained_documents(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.documents
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_ref()))
    }
    pub fn archive_identity_count(&self) -> usize {
        self.identities.len()
    }
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }
    pub fn retained_file_count(&self) -> usize {
        self.files.len()
    }
    pub fn descriptor_digests(&self) -> &[Digest] {
        &self.descriptors
    }
    pub fn decoded_usage(&self) -> (u64, u64) {
        (self.usage.decoded_bytes, self.usage.entries)
    }
}
pub fn verify_executor_assets(sealed: &SealedSource) -> R<ExecutorLayout> {
    let mut archives = source::ArchiveAdmission::attempt(source_binding(sealed));
    super::inventory::verify_closure_in(sealed, &mut archives)?;
    sealed.tree.verify()?;
    source::verify_recipe_policy(&sealed.recipe, &sealed.inputs)?;
    let roles = sealed
        .recipe
        .resources
        .iter()
        .map(|r| (r.role.as_str(), r))
        .collect::<BTreeMap<_, _>>();
    let layout_resource = roles
        .get("executor-layout")
        .ok_or_else(|| invalid("missing layout resource"))?;
    let bytes = sealed.asset_bytes(&layout_resource.content)?;
    let doc: LayoutDocument = canonical_document(bytes)?;
    let source_layout = source::read_regular(
        &sealed.tree.root,
        &RelativePath::new(format!(
            "packaging/builders/{}.layout.json",
            sealed.recipe.profile
        ))?,
        1048576,
    )?;
    if doc.schema != "osslscope-executor-layout-v1" || source_layout != bytes {
        return Err(invalid("layout original source mismatch"));
    }
    let mut by_hash = BTreeMap::new();
    let mut roots: BTreeMap<String, BTreeMap<String, ToolNode>> = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut identities = Vec::new();
    let mut usage = ArchiveUsage::default();
    let mut documents = BTreeMap::from([(
        layout_resource.content.path.as_str().to_owned(),
        Arc::<[u8]>::from(bytes),
    )]);
    let mut last = None;
    let mut seen = BTreeSet::new();
    let expected = roles
        .iter()
        .filter(|(r, _)| !matches!(**r, "executor-host" | "executor-layout"))
        .map(|(_, r)| source::json_bytes(&r.acquisition))
        .collect::<R<BTreeSet<_>>>()?;
    for row in doc.archives {
        let key = (row.root.clone(), row.acquisition.path.as_str().to_owned());
        if !ROOTS.contains(&row.root.as_str()) || last.as_ref().is_some_and(|l| l >= &key) {
            return Err(invalid("archive root/order"));
        }
        last = Some(key);
        let id = source::json_bytes(&row.acquisition)?;
        if !expected.contains(&id)
            || !seen.insert(id)
            || !sealed.required_inputs.contains(&row.tree)
        {
            return Err(invalid("archive/tree retained closure"));
        }
        let tree = ToolTree::parse(sealed.asset_bytes(&row.tree)?)?;
        documents.insert(
            row.tree.path.as_str().to_owned(),
            Arc::from(sealed.asset_bytes(&row.tree)?),
        );
        let data = sealed.asset_bytes(&row.acquisition)?;
        let (used, contents, _) = decode_archive_in(
            data,
            Some(&tree),
            ArchiveLimits::DEFAULT,
            false,
            &mut archives,
        )?;
        let _ = used;
        if by_hash
            .insert(
                row.acquisition.sha256.to_string(),
                (row.root.clone(), tree.clone(), contents.clone()),
            )
            .is_some()
        {
            return Err(invalid("archive hash alias"));
        }
        let merged = roots.entry(row.root.clone()).or_default();
        for node in &tree.entries {
            if merged.get(node.path()).is_some_and(|n| n != node) {
                return Err(invalid("conflicting tool overlay"));
            }
            merged.insert(node.path().into(), node.clone());
        }
        for (path, data) in contents {
            let key = (row.root.clone(), path);
            if files
                .get(&key)
                .is_some_and(|old: &Arc<[u8]>| old.as_ref() != data.as_ref())
            {
                return Err(invalid("conflicting tool overlay bytes"));
            }
            files.entry(key).or_insert(data);
        }
        identities.push(row.acquisition.sha256);
    }
    if seen != expected
        || roots.keys().map(String::as_str).collect::<BTreeSet<_>>() != ROOTS.into_iter().collect()
    {
        return Err(invalid("incomplete eight-root acquisition map"));
    }
    let roots = roots
        .into_iter()
        .map(|(r, n)| {
            let tree = ToolTree {
                schema: "osslscope-tool-tree-v1".into(),
                entries: n.into_values().collect(),
            };
            tree.validate(false)?;
            Ok((r, tree))
        })
        .collect::<R<BTreeMap<_, _>>>()?;
    for anchor in ["build", "proc", "dev"] {
        let root = &roots["rootfs"];
        if !matches!(
            root.entries.iter().find(|n| n.path() == anchor),
            Some(ToolNode::Directory { mode: 0o755, .. })
        ) || root
            .entries
            .iter()
            .any(|n| n.path().starts_with(&format!("{anchor}/")))
        {
            return Err(invalid("rootfs anchor not empty real directory"));
        }
    }
    for tree in roots.values() {
        for node in &tree.entries {
            let p = node.path();
            if p.split('/').any(|p| p == ".cargo")
                && ["config", "config.toml"].contains(&p.rsplit('/').next().unwrap())
            {
                return Err(invalid("ambient tool Cargo config"));
            }
        }
    }
    let mut bound = BTreeSet::new();
    let mut last = "";
    for binding in &doc.bindings {
        let role = binding.role.as_str();
        if role <= last || matches!(role, "executor-host" | "executor-layout") {
            return Err(invalid("binding role/order"));
        }
        last = role;
        bound.insert(role);
        if !binding.member.is_empty() {
            RelativePath::new(&binding.member)?;
        } else if binding.kind != "tree" {
            return Err(invalid("empty file member"));
        }
        let (root, tree, contents) = by_hash
            .get(&binding.archive_sha256.to_string())
            .ok_or_else(|| invalid("binding archive missing"))?;
        if fixed(role).is_some_and(|f| {
            f != (
                root.as_str(),
                binding.member.as_str(),
                binding.kind.as_str(),
            )
        }) {
            return Err(invalid("fixed member destination mismatch"));
        }
        if role == "llvm-library"
            && (root != "llvm" || binding.kind != "file" || !binding.member.starts_with("lib/"))
        {
            return Err(invalid("LLVM exact member missing"));
        }
        let data = match binding.kind.as_str() {
            "tree" => source::json_bytes(&tree.subtree(&binding.member)?)?,
            "file" => {
                let node = tree.resolve(&binding.member)?;
                if !matches!(node, ToolNode::File { .. })
                    || (fixed(role).is_some() && node.mode() != 0o755)
                {
                    return Err(invalid("executable member binding"));
                }
                contents
                    .get(node.path())
                    .ok_or_else(|| invalid("member content missing"))?
                    .to_vec()
            }
            _ => return Err(invalid("binding kind")),
        };
        let resource = roles
            .get(role)
            .ok_or_else(|| invalid("unknown binding role"))?;
        if resource.acquisition.sha256 != binding.archive_sha256
            || data != sealed.asset_bytes(&resource.content)?
        {
            return Err(invalid("role content/member mismatch"));
        }
    }
    if bound
        != roles
            .keys()
            .copied()
            .filter(|r| !matches!(*r, "executor-host" | "executor-layout"))
            .collect()
    {
        return Err(invalid("missing runtime binding"));
    }
    let host = roles
        .get("executor-host")
        .ok_or_else(|| invalid("host resource missing"))?;
    let host_tree = host_tree(sealed.asset_bytes(&host.content)?)?;
    documents.insert(
        host.content.path.as_str().to_owned(),
        Arc::from(sealed.asset_bytes(&host.content)?),
    );
    usage.charge(
        decode_archive_in(
            sealed.asset_bytes(&host.acquisition)?,
            Some(&host_tree),
            ArchiveLimits::DEFAULT,
            false,
            &mut archives,
        )?
        .0,
        ArchiveLimits::DEFAULT,
    )?;
    identities.push(host.acquisition.sha256);
    let layout_tree = ToolTree {
        schema: "osslscope-tool-tree-v1".into(),
        entries: vec![ToolNode::File {
            path: RelativePath::new("layout.json")?,
            mode: 0o644,
            bytes: bytes.len() as u64,
            sha256: sha256(bytes),
        }],
    };
    usage.charge(
        decode_archive_in(
            sealed.asset_bytes(&layout_resource.acquisition)?,
            Some(&layout_tree),
            ArchiveLimits::DEFAULT,
            false,
            &mut archives,
        )?
        .0,
        ArchiveLimits::DEFAULT,
    )?;
    identities.push(layout_resource.acquisition.sha256);
    if sealed.recipe.host_profile.target == "x86_64-unknown-linux-gnu" {
        for (a, b) in [
            ("native-compiler", "build-compiler"),
            ("archive", "build-archive"),
            ("sysroot", "build-sysroot"),
        ] {
            if sealed.asset_bytes(&roles[a].content)? != sealed.asset_bytes(&roles[b].content)? {
                return Err(invalid("GNU tool content inequality"));
            }
        }
    }
    let descriptors = [
        Phase::Bootstrap,
        Phase::Native,
        Phase::Bpf,
        Phase::Host,
        Phase::Readback,
    ]
    .into_iter()
    .map(|p| phase_spec(&sealed.recipe, p).map(|s| descriptor_sha256(&s)))
    .collect::<R<Vec<_>>>()?;
    let (decoded_bytes, entries) = archives.usage();
    usage = ArchiveUsage {
        decoded_bytes,
        entries,
    };
    Ok(ExecutorLayout {
        archives,
        roots,
        files,
        identities,
        descriptors,
        usage,
        documents,
    })
}

/// Exact offline replacements and owned generated config/files, with no Cargo launch.
pub struct VendorFile {
    bytes: Arc<[u8]>,
    mode: u32,
}
pub struct VendorPlan {
    mappings: BTreeMap<String, String>,
    config: Vec<u8>,
    files: BTreeMap<String, VendorFile>,
}
impl VendorPlan {
    pub fn files(&self) -> impl Iterator<Item = (&str, u32, &[u8])> {
        self.files
            .iter()
            .map(|(p, n)| (p.as_str(), n.mode, n.bytes.as_ref()))
    }
    pub fn config_bytes(&self) -> &[u8] {
        &self.config
    }
    pub fn config_sha256(&self) -> Digest {
        sha256(&self.config)
    }
    pub fn mappings(&self) -> &BTreeMap<String, String> {
        &self.mappings
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}
fn reject_configs(root: &Path) -> R<()> {
    for p in root.ancestors() {
        for n in ["config", "config.toml"] {
            if p.join(".cargo").join(n).symlink_metadata().is_ok() {
                return Err(invalid("source/ancestor Cargo config"));
            }
        }
    }
    for key in ["HOME", "CARGO_HOME"] {
        if let Some(p) = std::env::var_os(key) {
            let p = PathBuf::from(p);
            let p = if key == "HOME" { p.join(".cargo") } else { p };
            for n in ["config", "config.toml"] {
                if p.join(n).symlink_metadata().is_ok() {
                    return Err(invalid("user Cargo config"));
                }
            }
        }
    }
    Ok(())
}
pub fn vendor_config(sealed: &SealedSource, layout: &mut ExecutorLayout) -> R<VendorPlan> {
    let result = (|| {
        layout.archives.check_binding(&source_binding(sealed))?;
        reject_configs(&sealed.tree.root)?;
        vendor_config_data(sealed, layout)
    })();
    layout.archives.finish(result)
}

type LockedSources = BTreeMap<(String, String, String), Option<String>>;
fn lock_sources(bytes: &[u8]) -> R<LockedSources> {
    if bytes.is_empty() || bytes.len() > 1048576 {
        return Err(invalid("bounded Cargo lock required"));
    }
    let table: toml::Table = std::str::from_utf8(bytes)
        .map_err(|_| invalid("lock encoding"))?
        .parse()
        .map_err(|_| invalid("lock TOML"))?;
    if table
        .keys()
        .any(|k| !matches!(k.as_str(), "version" | "package"))
        || !matches!(
            table.get("version").and_then(toml::Value::as_integer),
            Some(3 | 4)
        )
    {
        return Err(invalid("lock version/fields"));
    }
    let mut result = LockedSources::new();
    for row in table
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| invalid("lock package rows"))?
    {
        let name = row
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("lock name"))?;
        let version = row
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid("lock version"))?;
        if let Some(source) = row.get("source") {
            let source = source.as_str().ok_or_else(|| invalid("lock source type"))?;
            let checksum = match row.get("checksum") {
                None => None,
                Some(v) => Some(
                    v.as_str()
                        .ok_or_else(|| invalid("lock checksum type"))?
                        .to_owned(),
                ),
            };
            if result
                .insert((source.into(), name.into(), version.into()), checksum)
                .is_some()
            {
                return Err(invalid("ambiguous locked package"));
            }
        }
    }
    Ok(result)
}
fn corroborate_std_lock(
    data: &[u8],
    components: &[&super::inventory::SourceComponent],
    locked: &mut LockedSources,
) -> R<()> {
    let workspace = lock_sources(data)?;
    for c in components {
        let (source, checksum) = match &c.source {
            ComponentSource::Registry {
                location,
                checksum,
                archive,
                ..
            } => {
                if archive.sha256 != *checksum {
                    return Err(invalid("build-std original checksum"));
                }
                (location.clone(), Some(checksum.to_string()))
            }
            ComponentSource::Git {
                repository,
                revision,
                ..
            } => (format!("git+{repository}#{revision}"), None),
            _ => return Err(invalid("native/path is not a Cargo source ID")),
        };
        let key = (source, c.name.clone(), c.version.clone());
        if workspace.get(&key) != Some(&checksum)
            || locked.get(&key).is_some_and(|v| v != &checksum)
        {
            return Err(invalid("build-std declared lock closure mismatch"));
        }
        locked.insert(key, checksum);
    }
    Ok(())
}
fn vendor_config_data(sealed: &SealedSource, layout: &mut ExecutorLayout) -> R<VendorPlan> {
    super::inventory::verify_closure_in(sealed, &mut layout.archives)?;
    let mut locked = LockedSources::new();
    for path in ["Cargo.lock", "crates/ebpf/Cargo.lock"] {
        let bytes = source::read_regular(&sealed.tree.root, &RelativePath::new(path)?, 1048576)?;
        for (key, checksum) in lock_sources(&bytes)? {
            if locked
                .insert(key, checksum.clone())
                .is_some_and(|v| v != checksum)
            {
                return Err(invalid("mixed original locks"));
            }
        }
    }
    let std_components = sealed
        .dependencies
        .components
        .iter()
        .filter(|c| {
            sealed.dependencies.build_std.contains(&c.id)
                && matches!(
                    c.source,
                    ComponentSource::Registry { .. } | ComponentSource::Git { .. }
                )
        })
        .collect::<Vec<_>>();
    if !std_components.is_empty() {
        let path = "lib/rustlib/src/rust/library/Cargo.lock";
        let data = layout
            .files
            .get(&("bpf".into(), path.into()))
            .ok_or_else(|| invalid("missing retained rust-src library Cargo.lock"))?;
        let node = layout.roots["bpf"].resolve(path)?;
        if !matches!(node,ToolNode::File{bytes,sha256:hash,..} if *bytes==data.len() as u64&&*hash==sha256(data))
        {
            return Err(invalid("substituted rust-src lock member"));
        }
        corroborate_std_lock(data, &std_components, &mut locked)?;
    }
    let mut files = BTreeMap::new();
    let mut mappings = BTreeMap::new();
    let mut admitted = BTreeSet::new();
    let selected = sealed
        .dependencies
        .host
        .iter()
        .chain(&sealed.dependencies.bpf)
        .chain(&sealed.dependencies.build_std)
        .collect::<BTreeSet<_>>();
    for component in &sealed.dependencies.components {
        if !selected.contains(&component.id) {
            continue;
        }
        let (source_id, archive, package) = match &component.source {
            ComponentSource::Path { .. } => continue,
            ComponentSource::Native { .. }
                if sealed.dependencies.build_std.contains(&component.id) =>
            {
                continue;
            }
            ComponentSource::Registry {
                location,
                checksum,
                corresponding_source,
                ..
            } => (
                location.clone(),
                corresponding_source,
                Some(checksum.to_string()),
            ),
            ComponentSource::Git {
                repository,
                revision,
                archive,
            } => (format!("git+{repository}#{revision}"), archive, None),
            _ => return Err(invalid("build-std needs locked Cargo source identity")),
        };
        let key = (
            source_id.clone(),
            component.name.clone(),
            component.version.clone(),
        );
        if locked.get(&key) != Some(&package) || !admitted.insert(key) {
            return Err(invalid("missing/mixed/colliding locked source"));
        }
        let mut source_files = BTreeMap::new();
        for (path, mode, bytes) in
            source::vendor_source_in(sealed.asset_bytes(archive)?, &mut layout.archives)?
        {
            source_files.insert(path, VendorFile { bytes, mode });
        }
        if source_files.is_empty() || source_files.contains_key(".cargo-checksum.json") {
            return Err(invalid("empty/checksum-colliding vendor source"));
        }
        let checksum = serde_json::json!({"files":source_files.iter().map(|(p,n)|(p.clone(),sha256(&n.bytes).to_string())).collect::<BTreeMap<_,_>>(),"package":package});
        source_files.insert(
            ".cargo-checksum.json".into(),
            VendorFile {
                bytes: Arc::from(source::json_bytes(&checksum)?),
                mode: 0o644,
            },
        );
        let base = format!("/build/vendor/{}", sha256(source_id.as_bytes()));
        mappings.insert(source_id, base.clone());
        let package_dir = format!("{}-{}", component.name, component.version);
        RelativePath::new(&package_dir)?;
        for (path, data) in source_files {
            let destination = format!("{base}/{package_dir}/{path}");
            if files.insert(destination, data).is_some() {
                return Err(invalid("vendor destination collision"));
            }
        }
    }
    if admitted != locked.keys().cloned().collect() {
        return Err(invalid("incomplete locked vendor closure"));
    }
    let mut config = "[net]\noffline = true\n\n".to_owned();
    for (index, (source_id, directory)) in mappings.iter().enumerate() {
        let key = if source_id == "registry+https://github.com/rust-lang/crates.io-index" {
            "crates-io"
        } else {
            source_id
        };
        config.push_str(&format!(
            "[source.{}]\n",
            serde_json::to_string(key).map_err(|_| invalid("config key"))?
        ));
        if let Some(git) = source_id.strip_prefix("git+") {
            let (repository, revision) = git
                .rsplit_once('#')
                .ok_or_else(|| invalid("Git locked source"))?;
            config.push_str(&format!(
                "git = {}\nrev = {}\n",
                serde_json::to_string(repository).unwrap(),
                serde_json::to_string(revision).unwrap()
            ));
        }
        config.push_str(&format!(
            "replace-with = \"vendor-{index}\"\n[source.vendor-{index}]\ndirectory = {}\n\n",
            serde_json::to_string(directory).unwrap()
        ));
    }
    Ok(VendorPlan {
        mappings,
        config: config.into_bytes(),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::super::inventory::source_fixtures::Fixture;
    use super::*;
    use serde_json::json;
    #[test]
    fn descriptor_layout_fix1_i6_shared_owner_before_retention() {
        let nodes = vec![file("a", b"a")];
        let bytes = tar(&nodes);
        let mut owner =
            source::ArchiveAdmission::for_test(b"binding".to_vec(), (bytes.len() * 2) as u64, 2);
        let first = owner
            .decode(
                &bytes,
                source::ArchiveProfile::Tool,
                source::ArchiveCaps::TOOL,
            )
            .unwrap();
        let same = owner
            .decode(
                &bytes,
                source::ArchiveProfile::Tool,
                source::ArchiveCaps::TOOL,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(owner.decode_count(), 1);
        let other = tar(&[file("b", b"b")]);
        owner
            .decode(
                &other,
                source::ArchiveProfile::Tool,
                source::ArchiveCaps::TOOL,
            )
            .unwrap();
        assert_eq!(owner.usage(), ((bytes.len() * 2) as u64, 2));
        assert!(
            owner
                .decode(
                    &tar(&[file("c", b"c")]),
                    source::ArchiveProfile::Tool,
                    source::ArchiveCaps::TOOL
                )
                .is_err()
        );
        assert_eq!(owner.retained_rows(), 2);
        assert!(owner.check_binding(b"binding").is_err());
    }
    #[test]
    fn descriptor_layout_fix2_tool_numeric_grammar_fresh_and_cached() {
        let fixture = Fixture::new();
        let node = file("tool", b"tool-bytes");
        let tree = ToolTree {
            schema: "osslscope-tool-tree-v1".into(),
            entries: vec![node.0.clone()],
        };
        let raw = tar(&[node]);
        let mut mismatches = Vec::new();
        for (name, devices, lexical, accepted) in [
            ("all-NUL", [0; 16], "", true),
            ("encoded-zero", *b"0000000\x000000000\0", "", true),
            ("spaces", [b' '; 16], "", false),
            ("zero-blank", *b"0000000\0        ", "", false),
            ("blank-zero", *b"        0000000\0", "", false),
            ("zero-NUL", *b"0000000\0\0\0\0\0\0\0\0\0", "", false),
            ("NUL-zero", *b"\0\0\0\0\0\0\0\x000000000\0", "", false),
            ("leading-NUL-mode", [0; 16], "mode-NUL", true),
            ("leading-NUL-checksum", [0; 16], "checksum-NUL", true),
            ("plus-checksum", [0; 16], "checksum-plus", false),
            ("leading-space-checksum", [0; 16], "checksum-space", true),
        ] {
            let mut candidate = raw.clone();
            candidate[329..345].copy_from_slice(&devices);
            if lexical == "mode-NUL" {
                candidate[100] = 0;
            }
            candidate[148..156].fill(b' ');
            let sum: u64 = candidate[..512].iter().map(|b| u64::from(*b)).sum();
            let checksum = match lexical {
                "checksum-NUL" => format!("\0{sum:06o}\0"),
                "checksum-plus" => format!("+{sum:06o}\0"),
                "checksum-space" => format!(" {sum:06o}\0"),
                _ => format!("{sum:06o}\0 "),
            };
            candidate[148..156].copy_from_slice(checksum.as_bytes());
            assert_eq!(candidate.len(), raw.len());
            let acquisition =
                serde_json::from_value(fixture.input("numeric/tool.tar", &candidate)).unwrap();
            let acquired = source::verify_entry(&fixture.inputs, &acquisition).unwrap();
            for cached in [false, true] {
                let mut owner = source::ArchiveAdmission::attempt(Vec::new());
                if cached {
                    owner
                        .decode(
                            &acquired,
                            source::ArchiveProfile::Source,
                            source::ArchiveCaps::TOOL,
                        )
                        .unwrap();
                }
                let usage = owner.usage();
                let result = decode_archive_in(
                    &acquired,
                    Some(&tree),
                    ArchiveLimits::DEFAULT,
                    true,
                    &mut owner,
                );
                if result.is_ok() != accepted {
                    mismatches.push((name, cached));
                }
                if let Ok(decoded) = result {
                    assert_eq!(decoded.1["tool"].as_ref(), b"tool-bytes");
                }
                if !accepted && !mismatches.contains(&(name, cached)) {
                    assert!(owner.check_binding(&[]).is_err());
                }
                if cached {
                    assert_eq!(owner.usage(), usage);
                }
                assert_eq!(owner.decode_count(), 1);
                assert_eq!(sha256(&candidate), acquisition.sha256);
            }
        }
        assert!(
            mismatches.is_empty(),
            "numeric grammar mismatches: {mismatches:?}"
        );
    }
    #[test]
    fn descriptor_layout_fix2_real_parent_collision_refusals_poison() {
        use super::super::inventory::source_fixtures::fixture_tar;
        for paths in [["a", "a/b"], ["z/a", "z/a/b"]] {
            for reverse in [false, true] {
                let mut order = paths;
                if reverse {
                    order.reverse();
                }
                let mut raw = Vec::new();
                for path in order {
                    let member = fixture_tar(path, path.as_bytes(), b'0', "");
                    raw.extend_from_slice(&member[..member.len() - 1024]);
                }
                raw.extend([0; 1024]);
                let mut owner = source::ArchiveAdmission::attempt(Vec::new());
                owner
                    .decode(
                        &raw,
                        source::ArchiveProfile::Source,
                        source::ArchiveCaps::TOOL,
                    )
                    .unwrap();
                assert!(
                    source::validate_source_archive_in(&raw, &mut owner).is_err(),
                    "{paths:?} {reverse}"
                );
                assert!(owner.check_binding(&[]).is_err());
                assert_eq!(owner.decode_count(), 1);
            }
        }
    }
    const STD_LOCK_FIXTURE:&[u8]=b"version = 4\n[[package]]\nname = \"tiny\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/tiny#1111111111111111111111111111111111111111\"\n[[package]]\nname = \"optional\"\nversion = \"9.0.0\"\nsource = \"registry+https://example.invalid/index\"\nchecksum = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"\n";
    fn recipe(profile: &str) -> BuildRecipe {
        let f = Fixture::new();
        BuildRecipe::parse_json(&f.files[&format!("packaging/builders/{profile}.json")]).unwrap()
    }
    fn common() -> Vec<EnvironmentEntry> {
        [
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
            ("SOURCE_DATE_EPOCH", "1792799804"),
            ("CARGO_NET_OFFLINE", "true"),
            ("CARGO_BUILD_JOBS", "2"),
            ("RUSTFLAGS", "--remap-path-prefix=/build=."),
        ]
        .into_iter()
        .map(|(n, v)| EnvironmentEntry {
            name: n.into(),
            value: v.into(),
        })
        .collect()
    }
    fn tar(nodes: &[(ToolNode, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (node, bytes) in nodes {
            let mut h = [0u8; 512];
            let path = node.path();
            h[..path.len()].copy_from_slice(path.as_bytes());
            for (o, w, v) in [
                (100, 8, u64::from(node.mode())),
                (108, 8, 0),
                (116, 8, 0),
                (124, 12, bytes.len() as u64),
                (136, 12, 0),
            ] {
                h[o..o + w].copy_from_slice(format!("{v:0width$o}\0", width = w - 1).as_bytes());
            }
            h[148..156].fill(32);
            h[156] = match node {
                ToolNode::File { .. } => b'0',
                ToolNode::Directory { .. } => b'5',
                ToolNode::Symlink { target, .. } => {
                    h[157..157 + target.len()].copy_from_slice(target.as_bytes());
                    b'2'
                }
            };
            h[257..265].copy_from_slice(b"ustar\x0000");
            let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
            h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            out.extend(h);
            out.extend(bytes);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend([0; 1024]);
        out
    }
    fn file(path: &str, bytes: &[u8]) -> (ToolNode, Vec<u8>) {
        (
            ToolNode::File {
                path: RelativePath::new(path).unwrap(),
                mode: 0o755,
                bytes: bytes.len() as u64,
                sha256: sha256(bytes),
            },
            bytes.to_vec(),
        )
    }
    fn directory(path: &str) -> (ToolNode, Vec<u8>) {
        (
            ToolNode::Directory {
                path: RelativePath::new(path).unwrap(),
                mode: 0o755,
            },
            vec![],
        )
    }
    fn tree(nodes: &[(ToolNode, Vec<u8>)]) -> ToolTree {
        let mut entries = nodes.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        entries.sort_by(|a, b| a.path().cmp(b.path()));
        ToolTree {
            schema: "osslscope-tool-tree-v1".into(),
            entries,
        }
    }
    #[test]
    fn descriptor_layout_musl_bootstrap_exact_gnu_vector() {
        let r = recipe("musl");
        let s = phase_spec(&r, Phase::Bootstrap).unwrap();
        assert_eq!(s.executable, PathBuf::from("/build/tools/host/bin/cargo"));
        assert_eq!(
            s.argv,
            [
                "build",
                "--release",
                "--frozen",
                "--offline",
                "--target",
                "x86_64-unknown-linux-gnu",
                "--jobs",
                "2",
                "--bin",
                "osslscope-package",
                "--message-format=json-render-diagnostics"
            ]
        );
        assert!(
            !s.environment
                .iter()
                .any(|e| e.name == "OSSL_PACKAGE_RECORD_DIR")
        );
    }
    #[test]
    fn descriptor_layout_all_five_literal_descriptors() {
        for profile in ["gnu", "musl"] {
            let r = recipe(profile);
            for phase in [
                Phase::Bootstrap,
                Phase::Native,
                Phase::Bpf,
                Phase::Host,
                Phase::Readback,
            ] {
                let s = phase_spec(&r, phase).unwrap();
                let name = phase.name();
                let mut expected = common();
                if matches!(phase, Phase::Native | Phase::Readback) {
                    expected.extend([
                        EnvironmentEntry {
                            name: "HOME".into(),
                            value: "/build/home/bootstrap".into(),
                        },
                        EnvironmentEntry {
                            name: "TMPDIR".into(),
                            value: "/build/tmp/bootstrap".into(),
                        },
                    ]);
                    assert_eq!(
                        s.executable,
                        PathBuf::from(
                            "/build/target/bootstrap/x86_64-unknown-linux-gnu/release/osslscope-package"
                        )
                    );
                    assert_eq!(
                        s.argv,
                        if phase == Phase::Native {
                            vec![
                                "build-bundle",
                                "--root",
                                "/build/source",
                                "--inputs",
                                "/build/inputs",
                                "--request",
                                "/build/request.json",
                                "--output",
                                "/build/output",
                            ]
                        } else {
                            vec!["verify-payload", "--root", "/build/output"]
                        }
                    );
                } else {
                    let tc = if phase == Phase::Bpf { "bpf" } else { "host" };
                    let mut env = vec![
                        (
                            "CARGO_TARGET_DIR".to_owned(),
                            format!("/build/target/{name}"),
                        ),
                        ("CARGO_HOME".into(), format!("/build/cache/{name}/cargo")),
                        ("HOME".into(), format!("/build/home/{name}")),
                        ("TMPDIR".into(), format!("/build/tmp/{name}")),
                        ("PATH".into(), "/build/tools/build/bin".into()),
                        ("RUSTC".into(), format!("/build/tools/{tc}/bin/rustc")),
                        ("CC".into(), "/build/tools/build/bin/cc".into()),
                        ("AR".into(), "/build/tools/build/bin/ar".into()),
                        (
                            "LD_LIBRARY_PATH".into(),
                            "/build/tools/llvm/lib:/build/tools/native/lib".into(),
                        ),
                        (
                            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER".into(),
                            "/build/tools/build/bin/cc".into(),
                        ),
                    ];
                    if phase == Phase::Host && profile == "musl" {
                        env.extend([
                            (
                                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER".into(),
                                "/build/tools/native/bin/cc".into(),
                            ),
                            (
                                "CC_x86_64_unknown_linux_musl".into(),
                                "/build/tools/native/bin/cc".into(),
                            ),
                            (
                                "AR_x86_64_unknown_linux_musl".into(),
                                "/build/tools/native/bin/ar".into(),
                            ),
                        ]);
                    }
                    if phase == Phase::Bpf {
                        env.push((
                            "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER".into(),
                            "/build/tools/bpf-linker/bin/bpf-linker".into(),
                        ));
                    }
                    if phase == Phase::Host {
                        env.push(("OSSL_PACKAGE_RECORD_DIR".into(), "/build/records".into()));
                    }
                    expected.extend(
                        env.into_iter()
                            .map(|(name, value)| EnvironmentEntry { name, value }),
                    );
                    assert_eq!(
                        s.executable,
                        PathBuf::from(format!("/build/tools/{tc}/bin/cargo"))
                    );
                    let argv = if phase == Phase::Bpf {
                        vec![
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
                            "--bin",
                            "osslscope-harvest",
                            "--bin",
                            "osslscope-count",
                            "--bin",
                            "osslscope-members",
                            "--message-format=json-render-diagnostics",
                        ]
                    } else {
                        vec![
                            "build",
                            "--release",
                            "--frozen",
                            "--offline",
                            "--target",
                            if phase == Phase::Host && profile == "musl" {
                                "x86_64-unknown-linux-musl"
                            } else {
                                "x86_64-unknown-linux-gnu"
                            },
                            "--jobs",
                            "2",
                            "--bin",
                            if phase == Phase::Bootstrap {
                                "osslscope-package"
                            } else {
                                "osslscope"
                            },
                            "--message-format=json-render-diagnostics",
                        ]
                    };
                    assert_eq!(s.argv, argv);
                }
                assert_eq!(s.environment, expected);
                assert_eq!(
                    s.cwd,
                    PathBuf::from(if phase == Phase::Bpf {
                        "/build/source/crates/ebpf"
                    } else {
                        "/build/source"
                    })
                );
                let value = json!({"executable":s.executable,"argv":s.argv,"environment":s.environment,"cwd":s.cwd});
                assert_eq!(
                    descriptor_sha256(&s),
                    sha256(&source::json_bytes(&value).unwrap())
                );
            }
        }
    }
    #[test]
    fn descriptor_layout_descriptor_mutations_refuse() {
        for i in 0..6 {
            let mut r = recipe("gnu");
            match i {
                0 => r.argv.reverse(),
                1 => r.bpf_argv.push("--bin".into()),
                2 => r.environment.reverse(),
                3 => r.jobs = 3,
                4 => r.schema = "osslscope-build-recipe-v1".into(),
                _ => r.determinism.path_remap = "ambient".into(),
            }
            assert!(phase_spec(&r, Phase::Host).is_err());
        }
    }
    #[test]
    fn descriptor_layout_ustar_tree_exact_and_stream_bounded() {
        let n = vec![directory("bin"), file("bin/tool", b"abc")];
        let t = tree(&n);
        let data = tar(&n);
        let usage = validate_tool_archive(&data, &t, ArchiveLimits::DEFAULT).unwrap();
        assert_eq!(
            usage,
            ArchiveUsage {
                decoded_bytes: data.len() as u64,
                entries: 2
            }
        );
        for limit in [
            ArchiveLimits {
                decoded_bytes: data.len() as u64 - 1,
                ..ArchiveLimits::DEFAULT
            },
            ArchiveLimits {
                entries: 1,
                ..ArchiveLimits::DEFAULT
            },
            ArchiveLimits {
                member_bytes: 2,
                ..ArchiveLimits::DEFAULT
            },
            ArchiveLimits {
                input_bytes: 1,
                ..ArchiveLimits::DEFAULT
            },
        ] {
            assert!(validate_tool_archive(&data, &t, limit).is_err());
        }
        for offset in [0, 148, 257, 511, 1027] {
            let mut bad = data.clone();
            bad[offset] ^= 1;
            assert!(validate_tool_archive(&bad, &t, ArchiveLimits::DEFAULT).is_err());
        }
        assert!(
            validate_tool_archive(&data[..data.len() - 1], &t, ArchiveLimits::DEFAULT).is_err()
        );
    }
    #[test]
    fn descriptor_layout_archive_alias_link_overlap_refusal() {
        for n in [
            vec![file("a", b"a"), file("a", b"a")],
            vec![(
                ToolNode::Symlink {
                    path: RelativePath::new("a").unwrap(),
                    mode: 0o777,
                    target: "../escape".into(),
                },
                vec![],
            )],
            vec![file("a", b"x"), file("a/b", b"x")],
        ] {
            assert!(validate_tool_archive(&tar(&n), &tree(&n), ArchiveLimits::DEFAULT).is_err());
        }
    }
    #[test]
    fn descriptor_layout_cumulative_boundary_overflow() {
        let l = ArchiveLimits {
            decoded_bytes: 20,
            entries: 3,
            ..ArchiveLimits::DEFAULT
        };
        let mut u = ArchiveUsage::default();
        u.charge(
            ArchiveUsage {
                decoded_bytes: 10,
                entries: 1,
            },
            l,
        )
        .unwrap();
        u.charge(
            ArchiveUsage {
                decoded_bytes: 10,
                entries: 2,
            },
            l,
        )
        .unwrap();
        assert!(
            u.charge(
                ArchiveUsage {
                    decoded_bytes: 1,
                    entries: 0
                },
                l
            )
            .is_err()
        );
        let mut u = ArchiveUsage {
            decoded_bytes: u64::MAX,
            entries: u64::MAX,
        };
        assert!(
            u.charge(
                ArchiveUsage {
                    decoded_bytes: 1,
                    entries: 1
                },
                ArchiveLimits::DEFAULT
            )
            .is_err()
        );
    }
    #[test]
    fn descriptor_layout_literal_loader_inventory_including_count_extras() {
        let (wire, digest) = super::super::resolve::compiled_loader_identity().unwrap();
        assert_eq!(wire, 2);
        assert_eq!(
            digest.to_string(),
            "62d35545bf9b93389f9690c52c7fbfce5307acf832e0612ae126279aceb1e029"
        );
        let script = include_str!("../../scripts/package-executor.py");
        assert!(script.contains("'src/package/records.rs'"));
        assert!(script.contains("EXACT_LD_IMM64_SITE_AND_COUNT_MAP_MEMBER"));
    }
    #[test]
    fn descriptor_layout_host_runtime_manifest_closed() {
        let doc = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/usr/bin/bwrap","sha256":sha256(b"b"),"bytes":1,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"p"),"bytes":1,"mode":493}],"links":[]});
        assert!(host_tree(&source::json_bytes(&doc).unwrap()).is_ok());
        for field in ["commands", "mounts"] {
            let mut bad = doc.clone();
            bad[field] = json!([]);
            assert!(host_tree(&source::json_bytes(&bad).unwrap()).is_err());
        }
    }
    #[test]
    fn descriptor_layout_absolute_host_link_has_literal_relative_identity() {
        let document = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/usr/bin/bwrap","sha256":sha256(b"b"),"bytes":1,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"p"),"bytes":1,"mode":493}],"links":[{"path":"/usr/bin/python3","target":"/usr/bin/python3.11"}]});
        let tree = host_tree(&source::json_bytes(&document).unwrap()).unwrap();
        assert!(
            matches!(tree.entries.iter().find(|node|node.path()=="usr/bin/python3"),Some(ToolNode::Symlink{target,..}) if target=="python3.11")
        );
    }
    fn layout_fixture(profile: &str) -> (Fixture, SealedSource) {
        layout_fixture_overlay(profile, None)
    }
    fn layout_fixture_overlay(profile: &str, overlay: Option<bool>) -> (Fixture, SealedSource) {
        let mut f = Fixture::new();
        let structures = BTreeMap::from([
            (
                "rootfs",
                vec![directory("build"), directory("dev"), directory("proc")],
            ),
            (
                "host",
                vec![
                    directory("bin"),
                    file("bin/cargo", b"cargo"),
                    file("bin/rustc", b"rustc"),
                    directory("lib"),
                    directory("lib/rustlib"),
                    file("lib/rustlib/host", b"host"),
                ],
            ),
            (
                "bpf",
                vec![
                    directory("bin"),
                    file("bin/cargo", b"bpf-cargo"),
                    file("bin/rustc", b"bpf-rustc"),
                    directory("lib"),
                    directory("lib/rustlib"),
                    directory("lib/rustlib/src"),
                    directory("lib/rustlib/src/rust"),
                    directory("lib/rustlib/src/rust/library"),
                    file("lib/rustlib/src/rust/library/Cargo.lock", STD_LOCK_FIXTURE),
                    file("lib/rustlib/src/rust/source", b"rust-source"),
                ],
            ),
            (
                "linker",
                vec![directory("bin"), file("bin/bpf-linker", b"linker")],
            ),
            (
                "llvm",
                vec![directory("lib"), file("lib/libExact.so", b"llvm")],
            ),
            (
                "native",
                vec![
                    directory("bin"),
                    file("bin/ar", b"ar"),
                    file("bin/cc", b"cc"),
                    file("bin/ld", b"ld"),
                    directory("lib"),
                    directory("sysroot"),
                    file("sysroot/header", b"header"),
                ],
            ),
            (
                "build",
                vec![
                    directory("bin"),
                    file("bin/ar", b"ar"),
                    file("bin/cc", b"cc"),
                    file("bin/ld", b"ld"),
                    directory("sysroot"),
                    file("sysroot/header", b"header"),
                ],
            ),
            ("package", vec![file("format-tool", b"package")]),
        ]);
        let bindings = [
            ("host", "host", "bin/rustc", "file"),
            ("host-cargo", "host", "bin/cargo", "file"),
            ("bpf", "bpf", "bin/rustc", "file"),
            ("bpf-cargo", "bpf", "bin/cargo", "file"),
            ("linker", "linker", "bin/bpf-linker", "file"),
            ("llvm", "llvm", "lib", "tree"),
            ("llvm-library", "llvm", "lib/libExact.so", "file"),
            ("builder", "rootfs", "", "tree"),
            ("host-sysroot", "host", "lib/rustlib", "tree"),
            ("bpf-sysroot", "bpf", "lib/rustlib", "tree"),
            ("rust-src", "bpf", "lib/rustlib/src/rust", "tree"),
            ("sysroot", "native", "sysroot", "tree"),
            ("native-compiler", "native", "bin/cc", "file"),
            ("native-linker", "native", "bin/ld", "file"),
            ("archive", "native", "bin/ar", "file"),
            ("build-compiler", "build", "bin/cc", "file"),
            ("build-linker", "build", "bin/ld", "file"),
            ("build-archive", "build", "bin/ar", "file"),
            ("build-sysroot", "build", "sysroot", "tree"),
            ("package", "package", "", "tree"),
        ];
        let mut r: serde_json::Value =
            serde_json::from_slice(&f.files["packaging/builders/gnu.json"]).unwrap();
        let mut acquisitions = BTreeMap::new();
        let mut archives = Vec::new();
        let mut bound = Vec::new();
        for (root, nodes) in &structures {
            let acq = f.input(&format!("normalized/{root}.tar"), &tar(nodes));
            let content = f.input(
                &format!("normalized/{root}.tree.json"),
                &source::json_bytes(&tree(nodes)).unwrap(),
            );
            acquisitions.insert(*root, acq.clone());
            archives.push(json!({"acquisition":acq,"tree":content,"root":root}));
            let identity = json!({"name":format!("{root}-tree"),"version":"fixture","sha256":content["sha256"]});
            f.tools["components"]
                .as_array_mut()
                .unwrap()
                .push(identity.clone());
            r["resources"].as_array_mut().unwrap().push(json!({"role":format!("{root}-tree"),"identity":identity,"content":content,"acquisition":acquisitions[root],"source_component":"host-source"}));
            bound.push(json!({"role":format!("{root}-tree"),"archive_sha256":acquisitions[root]["sha256"],"member":"","kind":"tree"}));
        }
        if let Some(conflict) = overlay {
            let nodes = vec![
                file(
                    "format-tool",
                    if conflict { b"changed" } else { b"package" },
                ),
                file("marker", b"overlay"),
            ];
            let acq = f.input("normalized/package-overlay.tar", &tar(&nodes));
            let content = f.input(
                "normalized/package-overlay.tree.json",
                &source::json_bytes(&tree(&nodes)).unwrap(),
            );
            let identity = json!({"name":"package-overlay-data","version":"fixture","sha256":content["sha256"]});
            f.tools["components"]
                .as_array_mut()
                .unwrap()
                .push(identity.clone());
            r["resources"].as_array_mut().unwrap().push(json!({"role":"package-overlay","identity":identity,"content":content,"acquisition":acq,"source_component":"host-source"}));
            archives.push(json!({"root":"package","tree":content,"acquisition":acq}));
            bound.push(json!({"role":"package-overlay","archive_sha256":acq["sha256"],"member":"","kind":"tree"}));
            archives.sort_by(|a, b| {
                (a["root"].as_str(), a["acquisition"]["path"].as_str())
                    .cmp(&(b["root"].as_str(), b["acquisition"]["path"].as_str()))
            });
        }
        for (role, root, member, kind) in bindings {
            let nodes = &structures[root];
            let content = if kind == "file" {
                nodes
                    .iter()
                    .find(|(n, _)| n.path() == member)
                    .unwrap()
                    .1
                    .clone()
            } else {
                let prefix = format!("{member}/");
                let entries = nodes
                    .iter()
                    .filter(|(n, _)| member.is_empty() || n.path().starts_with(&prefix))
                    .map(|(n, _)| {
                        let mut value = serde_json::to_value(n).unwrap();
                        if !member.is_empty() {
                            value["path"] = value["path"].as_str().unwrap()[prefix.len()..].into();
                        }
                        value
                    })
                    .collect::<Vec<_>>();
                source::json_bytes(&json!({"schema":"osslscope-tool-tree-v1","entries":entries}))
                    .unwrap()
            };
            let entry = f.input(&format!("normalized/{role}.content"), &content);
            let resource = r["resources"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["role"] == role)
                .unwrap();
            resource["content"] = entry.clone();
            resource["identity"]["sha256"] = entry["sha256"].clone();
            resource["acquisition"] = acquisitions[root].clone();
            bound.push(json!({"role":role,"archive_sha256":acquisitions[root]["sha256"],"member":member,"kind":kind}));
        }
        let host_nodes = vec![
            directory("usr"),
            directory("usr/bin"),
            file("usr/bin/bwrap", b"bwrap"),
            file("usr/bin/python3.11", b"python"),
        ];
        let host = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/usr/bin/bwrap","sha256":sha256(b"bwrap"),"bytes":5,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"python"),"bytes":6,"mode":493}],"links":[]});
        bound.sort_by(|a, b| a["role"].as_str().cmp(&b["role"].as_str()));
        let layout =
            json!({"schema":"osslscope-executor-layout-v1","archives":archives,"bindings":bound});
        let layout_bytes = source::json_bytes(&layout).unwrap();
        let mut ln = file("layout.json", &layout_bytes);
        if let ToolNode::File { mode, .. } = &mut ln.0 {
            *mode = 0o644;
        }
        for (role, data, archive) in [
            (
                "executor-host",
                source::json_bytes(&host).unwrap(),
                tar(&host_nodes),
            ),
            ("executor-layout", layout_bytes.clone(), tar(&[ln])),
        ] {
            let content = f.input(&format!("normalized/{role}.json"), &data);
            let acq = f.input(&format!("normalized/{role}.tar"), &archive);
            let resource = r["resources"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["role"] == role)
                .unwrap();
            resource["content"] = content.clone();
            resource["identity"]["sha256"] = content["sha256"].clone();
            resource["acquisition"] = acq;
        }
        for (i, resource) in r["resources"].as_array().unwrap().iter().enumerate() {
            if i < 5 {
                let field = ["host", "bpf", "linker", "llvm", "builder"][i];
                f.tools[field] = resource["identity"].clone();
            } else {
                f.tools["components"][i - 5] = resource["identity"].clone();
            }
        }
        for p in ["gnu", "musl"] {
            let mut recipe: serde_json::Value =
                serde_json::from_slice(&f.files[&format!("packaging/builders/{p}.json")]).unwrap();
            recipe["resources"] = r["resources"].clone();
            recipe["tools"] = f.tools.clone();
            f.source(
                &format!("packaging/builders/{p}.json"),
                &source::json_bytes(&recipe).unwrap(),
            );
            f.source(
                &format!("packaging/builders/{p}.layout.json"),
                &layout_bytes,
            );
        }
        f.config["selected_profile"] = profile.into();
        let sealed = f.seal().unwrap();
        (f, sealed)
    }
    #[test]
    fn descriptor_layout_all_eight_roots_and_role_members() {
        for profile in ["gnu", "musl"] {
            let (_f, sealed) = layout_fixture(profile);
            let layout = verify_executor_assets(&sealed).unwrap();
            assert_eq!(layout.root_count(), 8);
            assert_eq!(layout.archive_identity_count(), 10);
            assert_eq!(layout.descriptor_digests().len(), 5);
            assert_eq!(layout.retained_documents().count(), 10);
            assert!(layout.retained_documents().any(|(_, bytes)| {
                bytes
                    == sealed
                        .asset_bytes(
                            &sealed
                                .recipe
                                .resources
                                .iter()
                                .find(|r| r.role == "executor-host")
                                .unwrap()
                                .content,
                        )
                        .unwrap()
            }));
            assert_eq!(
                layout.files[&("host".into(), "bin/cargo".into())].as_ref(),
                b"cargo"
            );
        }
    }

    #[test]
    fn descriptor_layout_physical_alias_reuse_and_two_root_identity() {
        let base = PathBuf::from(std::env::var_os("HOME").expect("test HOME"));
        let mk = |suffix: &str| {
            let work_root = base.join(format!("osslscope-pure-{}-{suffix}", std::process::id()));
            BuildPaths {
                host_target: work_root.join("target/host"),
                bpf_target: work_root.join("target/bpf"),
                cache_root: work_root.join("cache"),
                output_root: base.join(format!("osslscope-output-{}-{suffix}", std::process::id())),
                work_root,
            }
        };
        let a = mk("a");
        let b = mk("b");
        validate_paths(&a).unwrap();
        validate_paths(&b).unwrap();
        let mut alias = a.clone();
        alias.output_root = alias.work_root.clone();
        assert!(validate_paths(&alias).is_err());
        let mut overlap = a.clone();
        overlap.output_root = overlap.work_root.join("output");
        assert!(validate_paths(&overlap).is_err());
        let mut wrong = a;
        wrong.host_target = wrong.bpf_target.clone();
        assert!(validate_paths(&wrong).is_err());
        let (left, source_a) = layout_fixture("gnu");
        let (right, source_b) = layout_fixture("gnu");
        assert_ne!(left.root, right.root);
        assert_eq!(source_a.input_bytes, source_b.input_bytes);
        assert_eq!(
            verify_executor_assets(&source_a)
                .unwrap()
                .descriptor_digests(),
            verify_executor_assets(&source_b)
                .unwrap()
                .descriptor_digests()
        );
    }
    #[test]
    fn descriptor_layout_vendor_exact_locked_sources_and_checksums() {
        use super::super::inventory::source_fixtures::fixture_tar;
        use std::io::Write;
        let (mut f, _) = layout_fixture("gnu");
        let cargo = b"[package]\nname = \"tiny\"\nversion = \"1.0.0\"\n";
        let helper = b"#!/bin/sh\n";
        let executable = |path| {
            let mut data = fixture_tar(path, helper, b'0', "");
            data[100..108].copy_from_slice(b"0000755\0");
            data[148..156].fill(b' ');
            let sum: u64 = data[..512].iter().map(|b| u64::from(*b)).sum();
            data[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            data
        };
        let mut normalized = fixture_tar("Cargo.toml", cargo, b'0', "");
        normalized.truncate(normalized.len() - 1024);
        normalized.extend_from_slice(&fixture_tar("a", b"a", b'0', "")[..1024]);
        normalized.extend_from_slice(&executable("helper")[..1024]);
        normalized.extend(executable("z/a/b"));
        let mut original = fixture_tar("tiny-1.0.0/Cargo.toml", cargo, b'0', "");
        original.truncate(original.len() - 1024);
        original.extend_from_slice(&fixture_tar("tiny-1.0.0/a", b"a", b'0', "")[..1024]);
        original.extend_from_slice(&executable("tiny-1.0.0/helper")[..1024]);
        original.extend(executable("tiny-1.0.0/z/a/b"));
        let mut zip = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::default());
        zip.write_all(&original).unwrap();
        let compressed = zip.finish().unwrap();
        let sum = sha256(&compressed);
        let acquisition = f.input("registry/tiny.crate", &compressed);
        let source = f.input("registry/tiny.source.tar", &normalized);
        let mut host = f.files["Cargo.lock"].clone();
        host.extend_from_slice(format!("[[package]]\nname = \"tiny\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sum}\"\n").as_bytes());
        f.source("Cargo.lock", &host);
        f.inventory["locks"]["host_sha256"] = json!(sha256(&host));
        let terms = f.terms("tiny", "MIT");
        f.inventory["components"].as_array_mut().unwrap().push(json!({"id":"tiny","name":"tiny","version":"1.0.0","source":{"kind":"registry","location":"registry+https://github.com/rust-lang/crates.io-index","checksum":sum,"archive":acquisition,"corresponding_source":source},"terms":terms,"dependencies":[]}));
        f.inventory["host"]
            .as_array_mut()
            .unwrap()
            .push("tiny".into());
        let sealed = f.seal().unwrap();
        let mut layout = verify_executor_assets(&sealed).unwrap();
        let decodes = layout.archives.decode_count();
        let plan = vendor_config_data(&sealed, &mut layout).unwrap();
        assert_eq!(layout.archives.decode_count(), decodes);
        let base = "/build/vendor/c19b7c6f923b580ac259164a89f2577984ad5ab09ee9d583b888f934adbbe8d0";
        assert_eq!(plan.mappings.len(), 1);
        let actual = plan.mappings.values().next().unwrap();
        assert_eq!(actual, base);
        assert!(
            plan.config_bytes()
                .starts_with(b"[net]\noffline = true\n\n[source.\"crates-io\"]\n")
        );
        let checksum = &plan.files[&format!("{actual}/tiny-1.0.0/.cargo-checksum.json")];
        let usage = layout.archives.usage();
        let again = vendor_config_data(&sealed, &mut layout).unwrap();
        assert_eq!(layout.archives.usage(), usage);
        assert_eq!(layout.archives.decode_count(), decodes);
        for (path, bytes, mode) in [
            ("a", b"a".as_slice(), 0o644),
            ("z/a/b", helper.as_slice(), 0o755),
        ] {
            let key = format!("{actual}/tiny-1.0.0/{path}");
            assert_eq!(
                (plan.files[&key].bytes.as_ref(), plan.files[&key].mode),
                (bytes, mode)
            );
            assert!(Arc::ptr_eq(
                &plan.files[&key].bytes,
                &again.files[&key].bytes
            ));
        }

        let expected = json!({"files":{"Cargo.toml":sha256(cargo),"a":sha256(b"a"),"helper":sha256(helper),"z/a/b":sha256(helper)},"package":sum});
        assert_eq!(
            plan.files[&format!("{actual}/tiny-1.0.0/Cargo.toml")].mode,
            0o644
        );
        assert_eq!(
            plan.files[&format!("{actual}/tiny-1.0.0/helper")].mode,
            0o755
        );
        assert_eq!(checksum.mode, 0o644);
        assert_eq!(
            checksum.bytes.as_ref(),
            source::json_bytes(&expected).unwrap()
        );
    }
    #[test]
    fn descriptor_layout_build_std_fixed_retained_lock_and_declared_closure() {
        for profile in ["gnu", "musl"] {
            let (f, sealed) = layout_fixture(profile);
            let layout = verify_executor_assets(&sealed).unwrap();
            let path = "lib/rustlib/src/rust/library/Cargo.lock";
            let data = &layout.files[&("bpf".into(), path.into())];
            assert_eq!(data.as_ref(), STD_LOCK_FIXTURE);
            let source = f.input(
                "std/tiny.source.tar",
                &tar(&[file(
                    "Cargo.toml",
                    b"[package]\nname=\"tiny\"\nversion=\"1.0.0\"\n",
                )]),
            );
            let c:super::super::inventory::SourceComponent=serde_json::from_value(json!({"id":"tiny","name":"tiny","version":"1.0.0","source":{"kind":"git","repository":"https://example.invalid/tiny","revision":"1111111111111111111111111111111111111111","archive":source},"terms":f.terms("tiny","MIT"),"dependencies":[]})).unwrap();
            let mut locked = LockedSources::new();
            corroborate_std_lock(data, &[&c], &mut locked).unwrap();
            assert_eq!(locked.len(), 1);
            assert_eq!(
                locked.keys().next().unwrap(),
                &(
                    "git+https://example.invalid/tiny#1111111111111111111111111111111111111111"
                        .into(),
                    "tiny".into(),
                    "1.0.0".into()
                )
            );
            for bad in [
                STD_LOCK_FIXTURE
                    .to_vec()
                    .into_iter()
                    .map(|b| if b == b'1' { b'2' } else { b })
                    .collect::<Vec<_>>(),
                b"version=4\npackage=[]\n".to_vec(),
                [STD_LOCK_FIXTURE, STD_LOCK_FIXTURE].concat(),
            ] {
                assert!(corroborate_std_lock(&bad, &[&c], &mut LockedSources::new()).is_err());
            }
            let mut wrong = c.clone();
            wrong.version = "2.0.0".into();
            assert!(corroborate_std_lock(data, &[&wrong], &mut LockedSources::new()).is_err());
            let node = layout.roots["bpf"].resolve(path).unwrap();
            assert!(
                matches!(node,ToolNode::File{bytes,sha256:hash,..} if *bytes==data.len() as u64&&*hash==sha256(data))
            );
        }
    }
    #[test]
    fn descriptor_layout_fix1_i8_overlay_and_gzip_controls() {
        use std::io::Write;
        for profile in ["gnu", "musl"] {
            let (_f, sealed) = layout_fixture_overlay(profile, Some(false));
            let layout = verify_executor_assets(&sealed).unwrap();
            assert_eq!(
                layout.files[&("package".into(), "format-tool".into())].as_ref(),
                b"package"
            );
            assert_eq!(
                layout.files[&("package".into(), "marker".into())].as_ref(),
                b"overlay"
            );
            let (_f, bad) = layout_fixture_overlay(profile, Some(true));
            assert!(verify_executor_assets(&bad).is_err());
        }
        let nodes = vec![file("a", b"abc")];
        let plain = tar(&nodes);
        let manifest = tree(&nodes);
        let zip = |mtime, filename: Option<&str>| {
            let builder = flate2::GzBuilder::new().mtime(mtime);
            let builder = if let Some(n) = filename {
                builder.filename(n)
            } else {
                builder
            };
            let mut out = builder.write(Vec::new(), flate2::Compression::default());
            out.write_all(&plain).unwrap();
            out.finish().unwrap()
        };
        let good = zip(0, None);
        assert!(validate_tool_archive(&good, &manifest, ArchiveLimits::DEFAULT).is_ok());
        let mut crc = good.clone();
        let at = crc.len() - 8;
        crc[at] ^= 1;
        for bad in [
            zip(1, None),
            zip(0, Some("name")),
            [good.as_slice(), good.as_slice()].concat(),
            good[..good.len() - 1].to_vec(),
            crc,
        ] {
            assert!(validate_tool_archive(&bad, &manifest, ArchiveLimits::DEFAULT).is_err());
        }
    }
    #[test]
    fn descriptor_layout_fix1_i4_host_counterexamples() {
        for executable in ["/usr/bin/python3.11", "/usr/bin/bwrap"] {
            let mut doc = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/usr/bin/bwrap","sha256":sha256(b"b"),"bytes":1,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"p"),"bytes":1,"mode":493}],"links":[]});
            for row in doc["files"].as_array_mut().unwrap() {
                if row["path"] == executable {
                    row["path"] = format!("{executable}/child").into();
                }
            }
            assert!(host_tree(&source::json_bytes(&doc).unwrap()).is_err());
        }
        for target in [
            "/usr/bin/../bin/python3.11",
            "/usr//bin/python3.11",
            "/usr/bin/./python3.11",
        ] {
            let doc = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/usr/bin/bwrap","sha256":sha256(b"b"),"bytes":1,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"p"),"bytes":1,"mode":493}],"links":[{"path":"/usr/bin/python3","target":target}]});
            assert!(host_tree(&source::json_bytes(&doc).unwrap()).is_err());
        }
    }
    #[test]
    fn descriptor_layout_fix1_cache_binding_and_live_closure() {
        let (f, sealed) = layout_fixture("gnu");
        let mut layout = verify_executor_assets(&sealed).unwrap();
        let count = layout.archives.decode_count();
        let _ = vendor_config_data(&sealed, &mut layout).unwrap();
        assert_eq!(layout.archives.decode_count(), count);
        let term = &sealed.dependencies.components[0].terms.license_files[0];
        let path = f.inputs.join(term.path.as_str());
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"different terms").unwrap();
        assert!(vendor_config_data(&sealed, &mut layout).is_err());
        fs::write(path, original).unwrap();
        assert!(vendor_config_data(&sealed, &mut layout).is_err());
        let mut other = verify_executor_assets(&sealed).unwrap();
        let mut changed = sealed.clone();
        changed.input_bytes.push(b' ');
        assert!(vendor_config(&changed, &mut other).is_err());
        assert!(vendor_config(&sealed, &mut other).is_err());
        let mut owner = source::ArchiveAdmission::attempt(Vec::new());
        let raw = tar(&[file("a", b"abc")]);
        owner
            .decode(
                &raw,
                source::ArchiveProfile::Tool,
                source::ArchiveCaps::TOOL,
            )
            .unwrap();
        assert!(source::vendor_source_in(&raw, &mut owner).is_err());
        assert!(owner.check_binding(&[]).is_err());
    }
    #[test]
    fn descriptor_layout_fix1_source_policies_and_registry_cache() {
        use super::super::inventory::source_fixtures::fixture_tar;
        use super::super::source::{
            ArchiveAdmission, ArchiveCaps, ArchiveProfile, RegistryArchiveLimits,
            verify_registry_source_in,
        };
        use std::io::Write;
        let normalized = fixture_tar("Cargo.toml", b"manifest", b'0', "");
        let original = fixture_tar("tiny-1.0.0/Cargo.toml", b"manifest", b'0', "");
        let mut gzip = flate2::GzBuilder::new()
            .mtime(7)
            .filename("original.crate")
            .write(Vec::new(), flate2::Compression::default());
        gzip.write_all(&original).unwrap();
        let compressed = gzip.finish().unwrap();
        let mut owner =
            ArchiveAdmission::for_test(Vec::new(), (normalized.len() + original.len()) as u64, 2);
        verify_registry_source_in(
            &compressed,
            &normalized,
            "tiny",
            "1.0.0",
            RegistryArchiveLimits::DEFAULT,
            &mut owner,
        )
        .unwrap();
        let usage = owner.usage();
        assert_eq!(usage, ((normalized.len() + original.len()) as u64, 2));
        verify_registry_source_in(
            &compressed,
            &normalized,
            "tiny",
            "1.0.0",
            RegistryArchiveLimits::DEFAULT,
            &mut owner,
        )
        .unwrap();
        assert_eq!(owner.usage(), usage);
        assert_eq!(owner.decode_count(), 2);
        assert!(
            owner
                .decode(&compressed, ArchiveProfile::Tool, ArchiveCaps::TOOL)
                .is_err()
        );
        assert_eq!(owner.decode_count(), 2);
        let mut owner = ArchiveAdmission::attempt(Vec::new());
        verify_registry_source_in(
            &compressed,
            &normalized,
            "tiny",
            "1.0.0",
            RegistryArchiveLimits::DEFAULT,
            &mut owner,
        )
        .unwrap();
        assert!(
            verify_registry_source_in(
                &compressed,
                &normalized,
                "other",
                "1.0.0",
                RegistryArchiveLimits::DEFAULT,
                &mut owner
            )
            .is_err()
        );
        assert_eq!(owner.decode_count(), 2);
        let mut small = ArchiveAdmission::for_test(Vec::new(), u64::MAX, 1);
        let raw = tar(&[file("a", b"x"), file("b", b"y")]);
        assert!(
            small
                .decode(&raw, ArchiveProfile::Tool, ArchiveCaps::TOOL)
                .is_err()
        );
        assert_eq!(small.retained_rows(), 1);
        let mut small = ArchiveAdmission::for_test(Vec::new(), 512, 5);
        assert!(
            small
                .decode(
                    &tar(&[file("a", b"x")]),
                    ArchiveProfile::Tool,
                    ArchiveCaps::TOOL
                )
                .is_err()
        );
        assert_eq!(small.retained_rows(), 0);
        let mut overflow = ArchiveAdmission::for_test(Vec::new(), u64::MAX, u64::MAX);
        overflow.seed_test_usage(u64::MAX, 0);
        assert!(
            overflow
                .decode(&normalized, ArchiveProfile::Tool, ArchiveCaps::TOOL)
                .is_err()
        );
        assert_eq!(overflow.retained_rows(), 0);
    }
    #[test]
    fn descriptor_layout_fix1_build_std_uses_one_full_owner() {
        use super::super::inventory::source_fixtures::fixture_tar;
        for profile in ["gnu", "musl"] {
            let (mut f, _) = layout_fixture(profile);
            let source = f.input(
                "std/tiny.tar",
                &fixture_tar(
                    "Cargo.toml",
                    b"[package]\nname=\"tiny\"\nversion=\"1.0.0\"\nlicense=\"MIT\"\n",
                    b'0',
                    "",
                ),
            );
            let terms = f.terms("std-tiny", "MIT");
            f.inventory["components"].as_array_mut().unwrap().push(json!({"id":"std-tiny","name":"tiny","version":"1.0.0","source":{"kind":"git","repository":"https://example.invalid/tiny","revision":"1111111111111111111111111111111111111111","archive":source},"terms":terms,"dependencies":[]}));
            f.inventory["build_std"]
                .as_array_mut()
                .unwrap()
                .push("std-tiny".into());
            f.inventory["tool_sources"]
                .as_array_mut()
                .unwrap()
                .push("std-tiny".into());
            let sealed = f.seal().unwrap();
            let mut layout = verify_executor_assets(&sealed).unwrap();
            let count = layout.archives.decode_count();
            let usage = layout.archives.usage();
            let plan = vendor_config_data(&sealed, &mut layout).unwrap();
            assert_eq!(layout.archives.decode_count(), count);
            assert_eq!(layout.archives.usage(), usage);
            assert_eq!(plan.mappings.len(), 1);
            assert!(plan.mappings.contains_key(
                "git+https://example.invalid/tiny#1111111111111111111111111111111111111111"
            ));
            assert!(
                std::str::from_utf8(plan.config_bytes())
                    .unwrap()
                    .contains("git = \"https://example.invalid/tiny\"")
            );
        }
    }
}
