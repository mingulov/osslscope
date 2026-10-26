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

// Retained artifact buffers carry content identity, never an execution receipt.
// The only production constructor is the fd-anchored reader below.
#[derive(Clone, Debug)]
pub struct RetainedBinary {
    bytes: Arc<[u8]>,
    sha256: Digest,
    length: u64,
}
impl RetainedBinary {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> Digest {
        self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}
const ARTIFACT_LIMIT: u64 = 536_870_912;
const BUILD_RECORD_LIMIT: usize = 1_048_576;
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl ArtifactIdentity {
    fn of(m: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            links: m.nlink(),
            uid: m.uid(),
            gid: m.gid(),
            size: m.len(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
    fn regular(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
            && self.links == 1
            && self.size > 0
            && self.size <= ARTIFACT_LIMIT
    }
}
// Filled only by the owned broker after its actual child/reap/readonly barrier.
// No production constructor or caller-supplied freshness/success flag exists.
struct CurrentArtifactSet {
    tree: PathBuf,
    directory: fs::File,
    files: BTreeMap<String, ArtifactIdentity>,
    cargo_sha256: Digest,
    completion: std::process::ExitStatus,
}
struct ArtifactRequest {
    phase: Phase,
    package: String,
    version: String,
    bins: BTreeSet<String>,
    target: String,
    tree: PathBuf,
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Deferred owned package builder source-sealed selection; retained host regressions exercise this method"
    )
)]
impl ArtifactRequest {
    fn derive(sealed: &SealedSource, phase: Phase, paths: &BuildPaths) -> R<Self> {
        let (manifest, bins, target, tree) = match phase {
            Phase::Bootstrap => (
                "Cargo.toml",
                vec!["osslscope-package"],
                "x86_64-unknown-linux-gnu".to_owned(),
                paths.work_root.join("target/bootstrap"),
            ),
            Phase::Host => (
                "Cargo.toml",
                vec!["osslscope"],
                sealed.recipe.host_profile.target.clone(),
                paths.host_target.clone(),
            ),
            Phase::Bpf => (
                "crates/ebpf/Cargo.toml",
                vec!["osslscope-harvest", "osslscope-count", "osslscope-members"],
                "bpfel-unknown-none".to_owned(),
                paths.bpf_target.clone(),
            ),
            _ => return Err(invalid("not a Cargo artifact phase")),
        };
        let bytes = source::read_regular(
            &sealed.tree.root,
            &RelativePath::new(manifest)?,
            BUILD_RECORD_LIMIT as u64,
        )?;
        let doc: toml::Table = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("artifact manifest encoding"))?
            .parse()
            .map_err(|_| invalid("artifact manifest TOML"))?;
        let package = doc
            .get("package")
            .ok_or_else(|| invalid("artifact package"))?;
        let string = |key| {
            package
                .get(key)
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid("artifact package identity"))
        };
        let result = Self {
            phase,
            package: string("name")?,
            version: string("version")?,
            bins: bins.into_iter().map(str::to_owned).collect(),
            target,
            tree,
        };
        if (phase == Phase::Bpf && result.package != "osslscope-ebpf")
            || (phase != Phase::Bpf
                && (result.package != "osslscope"
                    || result.version != sealed.inputs.product_version))
        {
            return Err(invalid("artifact manifest selected identity"));
        }
        Ok(result)
    }
}
fn snapshot_artifact(
    file: &fs::File,
    expected: &ArtifactIdentity,
    reader: &mut impl std::io::Read,
) -> R<RetainedBinary> {
    use std::io::Read;
    let before = ArtifactIdentity::of(&file.metadata().map_err(|_| invalid("artifact metadata"))?);
    if &before != expected || !before.regular() {
        return Err(invalid("artifact identity/type/link/size"));
    }
    let mut bytes = Vec::new();
    reader
        .take(before.size + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("artifact read"))?;
    let after = ArtifactIdentity::of(&file.metadata().map_err(|_| invalid("artifact metadata"))?);
    if before != after || bytes.len() as u64 != before.size {
        return Err(invalid("artifact mutated during read"));
    }
    let bytes: Arc<[u8]> = Arc::from(bytes);
    let hash = sha256(&bytes);
    Ok(RetainedBinary {
        length: bytes.len() as u64,
        bytes,
        sha256: hash,
    })
}
fn artifact_open(root: &fs::File, path: &RelativePath) -> R<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut directory = root.try_clone().map_err(|_| invalid("artifact root fd"))?;
    let parts = path.as_str().split('/').collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        let name = std::ffi::CString::new(*part).map_err(|_| invalid("artifact path NUL"))?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if i + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(invalid("artifact no-follow open"));
        }
        directory = unsafe { fs::File::from_raw_fd(fd) };
    }
    Ok(directory)
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Deferred owned package builder Cargo output retention; retained host regressions exercise this item"
    )
)]
fn retain_artifacts(
    log: &[u8],
    request: &ArtifactRequest,
    current: &CurrentArtifactSet,
) -> R<BTreeMap<String, RetainedBinary>> {
    if log.is_empty()
        || log.len() > BUILD_RECORD_LIMIT
        || log.last() != Some(&b'\n')
        || !current.completion.success()
        || sha256(log) != current.cargo_sha256
        || request.tree != current.tree
        || !current
            .directory
            .metadata()
            .map_err(|_| invalid("artifact root"))?
            .is_dir()
    {
        return Err(invalid("Cargo invocation custody"));
    }
    let mut artifacts = BTreeMap::new();
    let mut finished = false;
    let mut total = 0u64;
    let source = if request.target == "bpfel-unknown-none" {
        "path+file:///build/source/crates/ebpf"
    } else {
        "path+file:///build/source"
    };
    let package_id = format!("{source}#{}@{}", request.package, request.version);
    for line in log[..log.len() - 1].split(|b| *b == b'\n') {
        // Parse each row with a duplicate-key rejecting visitor via a closed
        // canonical wrapper. Cargo itself need not emit canonical key order.
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| invalid("Cargo JSON row"))?;
        let compact = source::json_bytes(&value)?;
        // The existing record parser exposes no generic duplicate visitor; this
        // local visitor rejects duplicates recursively before typed inspection.
        let unique: CargoJson =
            serde_json::from_slice(line).map_err(|_| invalid("duplicate Cargo JSON field"))?;
        if source::json_bytes(&unique.0)? != compact || finished {
            return Err(invalid("Cargo framing/trailing row"));
        }
        let object = value
            .as_object()
            .ok_or_else(|| invalid("Cargo object row"))?;
        let reason = object
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("Cargo reason"))?;
        match reason {
            "build-finished" => {
                if value["success"] != true {
                    return Err(invalid("Cargo failed build"));
                }
                finished = true;
            }
            "compiler-message" | "build-script-executed" => {}
            "compiler-artifact" => {
                let name = value["target"]["name"]
                    .as_str()
                    .ok_or_else(|| invalid("Cargo target name"))?;
                let selected = request.bins.contains(name);
                let id = value["package_id"]
                    .as_str()
                    .ok_or_else(|| invalid("Cargo package ID"))?;
                if id != package_id {
                    if selected {
                        return Err(invalid("Cargo selected package/version/source"));
                    }
                    continue;
                }
                if value["target"]["kind"] != serde_json::json!(["bin"]) {
                    if selected {
                        return Err(invalid("Cargo selected target kind"));
                    }
                    continue;
                }
                if !selected
                    || value["target"]["crate_types"] != serde_json::json!(["bin"])
                    || value["profile"]["test"] != false
                    || value["fresh"] != false
                {
                    return Err(invalid("Cargo extra/noncurrent bin"));
                }
                let executable = value["executable"]
                    .as_str()
                    .ok_or_else(|| invalid("Cargo executable absent"))?;
                let relative = RelativePath::new(format!("{}/release/{name}", request.target))?;
                let expected_path = format!(
                    "/build/target/{}/{}",
                    request.phase.name(),
                    relative.as_str()
                );
                let (manifest, source_path) = match (request.phase, name) {
                    (Phase::Bootstrap, "osslscope-package") => (
                        "/build/source/Cargo.toml",
                        "/build/source/src/bin/osslscope-package.rs",
                    ),
                    (Phase::Host, "osslscope") => {
                        ("/build/source/Cargo.toml", "/build/source/src/main.rs")
                    }
                    (Phase::Bpf, "osslscope-harvest") => (
                        "/build/source/crates/ebpf/Cargo.toml",
                        "/build/source/crates/ebpf/src/bin/harvest.rs",
                    ),
                    (Phase::Bpf, "osslscope-count") => (
                        "/build/source/crates/ebpf/Cargo.toml",
                        "/build/source/crates/ebpf/src/bin/count.rs",
                    ),
                    (Phase::Bpf, "osslscope-members") => (
                        "/build/source/crates/ebpf/Cargo.toml",
                        "/build/source/crates/ebpf/src/bin/members.rs",
                    ),
                    _ => return Err(invalid("Cargo selected phase/bin identity")),
                };
                if executable != expected_path
                    || value["manifest_path"] != manifest
                    || value["target"]["src_path"] != source_path
                    || value["filenames"] != serde_json::json!([expected_path])
                    || artifacts.contains_key(name)
                {
                    return Err(invalid("Cargo artifact path/duplicate"));
                }
                let identity = current
                    .files
                    .get(relative.as_str())
                    .ok_or_else(|| invalid("artifact not current invocation output"))?;
                total = total
                    .checked_add(identity.size)
                    .ok_or_else(|| invalid("artifact total overflow"))?;
                if total > ARTIFACT_LIMIT {
                    return Err(invalid("artifact total bound"));
                }
                let file = artifact_open(&current.directory, &relative)?;
                let binary = snapshot_artifact(&file, identity, &mut &file)?;
                artifacts.insert(name.to_owned(), binary);
            }
            _ => return Err(invalid("unexpected Cargo row")),
        }
    }
    if !finished || artifacts.keys().collect::<BTreeSet<_>>() != request.bins.iter().collect() {
        return Err(invalid("missing Cargo artifacts/completion"));
    }
    Ok(artifacts)
}
struct CargoJson(serde_json::Value);
impl<'de> Deserialize<'de> for CargoJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = serde_json::Value;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate fields")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, CargoJson>()? {
                    if result.insert(k, v.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate field"));
                    }
                }
                Ok(result.into())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut v = vec![];
                while let Some(n) = a.next_element::<CargoJson>()? {
                    v.push(n.0);
                }
                Ok(v.into())
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(Into::into)
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
        }
        d.deserialize_any(Visitor).map(Self)
    }
}
fn validate_triple(roles: &BTreeMap<super::records::Role, RetainedBinary>) -> R<()> {
    use super::records::Role;
    if roles.len() != 3 {
        return Err(invalid("complete artifact triple required"));
    }
    let mut total = 0u64;
    for role in [Role::Harvest, Role::Count, Role::Members] {
        let binary = roles
            .get(&role)
            .ok_or_else(|| invalid("missing retained role"))?;
        total = total
            .checked_add(binary.length)
            .ok_or_else(|| invalid("retained triple total overflow"))?;
        if binary.length == 0
            || binary.length > ARTIFACT_LIMIT
            || binary.length != binary.bytes.len() as u64
            || total > ARTIFACT_LIMIT
            || binary.sha256 != sha256(binary.bytes())
        {
            return Err(invalid("retained triple identity/bound"));
        }
        // Count goes through object -> real prepare -> installed prepared ->
        // count prepared policy, exactly as its owner. No BPF syscall occurs.
        crate::discovery::onboard::check_installed_role_compatible(role, binary.bytes())?;
    }
    Ok(())
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Deferred owned package builder v1 contract construction; retained host regressions exercise this item"
    )
)]
fn make_contract(
    inputs: &super::records::BuildInputs,
    roles: &BTreeMap<super::records::Role, RetainedBinary>,
) -> R<super::records::BundleContract> {
    use super::records::{BundleContract, PackageRecord, Role, RoleEntry, canonical_bytes};
    inputs.validate()?;
    validate_triple(roles)?;
    let (wire_abi, loader_contract_sha256) =
        super::resolve::compiled_loader_identity(crate::package::records::RecordVersion::V1)?;
    let result = BundleContract {
        schema: "osslscope-bundle-contract-v1".into(),
        input_id: sha256(&canonical_bytes(inputs)),
        source: inputs.source.clone(),
        product_version: inputs.product_version.clone(),
        host_profile: inputs.host_profile.clone(),
        wire_abi,
        loader_contract_sha256,
        roles: [Role::Harvest, Role::Count, Role::Members]
            .into_iter()
            .map(|role| RoleEntry {
                role,
                file: RelativePath::new(role.file_name()).expect("fixed role path"),
                sha256: roles[&role].sha256(),
                bytes: roles[&role].length(),
            })
            .collect(),
    };
    result.validate()?;
    Ok(result)
}

fn elf_range(bytes: &[u8], offset: u64, length: u64) -> R<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("ELF range overflow"))?;
    let start = usize::try_from(offset).map_err(|_| invalid("ELF offset"))?;
    let end = usize::try_from(end).map_err(|_| invalid("ELF end"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| invalid("ELF range outside retained buffer"))
}
fn elf_u16(bytes: &[u8], at: usize) -> R<u16> {
    Ok(u16::from_le_bytes(
        elf_range(bytes, at as u64, 2)?.try_into().unwrap(),
    ))
}
fn elf_u32(bytes: &[u8], at: usize) -> R<u32> {
    Ok(u32::from_le_bytes(
        elf_range(bytes, at as u64, 4)?.try_into().unwrap(),
    ))
}
fn elf_u64(bytes: &[u8], at: usize) -> R<u64> {
    Ok(u64::from_le_bytes(
        elf_range(bytes, at as u64, 8)?.try_into().unwrap(),
    ))
}
// Long NUL-delimited regions are scanned and UTF-8 checked once, including
// when consumers reference overlapping suffixes. Short regions cost at most
// 64 bytes per reference and do not create a cache node for every short string.
const SHORT_ELF_STRING: usize = 64;
#[derive(Clone, Copy)]
struct ElfString<'a> {
    value: &'a str,
    is_atom: bool,
}
#[derive(Clone, Copy)]
struct ElfAtom<'a> {
    value: &'a str,
    key: usize,
}
struct StringRegion<'a> {
    end: usize,
    valid_start: usize,
    valid_suffix: &'a str,
    last_forbidden: Option<usize>,
}
impl<'a> StringRegion<'a> {
    fn at(&self, offset: usize) -> R<ElfString<'a>> {
        let relative = offset
            .checked_sub(self.valid_start)
            .ok_or_else(|| invalid("ELF string encoding"))?;
        let value = self
            .valid_suffix
            .get(relative..)
            .ok_or_else(|| invalid("ELF string UTF-8 boundary"))?;
        Ok(ElfString {
            value,
            is_atom: !value.is_empty() && self.last_forbidden.is_none_or(|bad| bad < offset),
        })
    }
}
struct ElfStrings<'a> {
    bytes: &'a [u8],
    regions: BTreeMap<usize, StringRegion<'a>>,
    // Length precedes text so distinct overlapping suffixes never cause long
    // shared-text comparisons. Repeated long offsets use numeric keys only.
    interns: BTreeMap<(usize, &'a str), usize>,
    long_ids: BTreeMap<usize, usize>,
    #[cfg(test)]
    scanned_bytes: usize,
}
impl<'a> ElfStrings<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            regions: BTreeMap::new(),
            interns: BTreeMap::new(),
            long_ids: BTreeMap::new(),
            #[cfg(test)]
            scanned_bytes: 0,
        }
    }
    fn lookup(&mut self, offset: u64) -> R<ElfString<'a>> {
        let offset = usize::try_from(offset).map_err(|_| invalid("ELF string offset"))?;
        let byte = *self
            .bytes
            .get(offset)
            .ok_or_else(|| invalid("ELF string range"))?;
        if byte == 0 {
            return Ok(ElfString {
                value: "",
                is_atom: false,
            });
        }
        if let Some((_, region)) = self.regions.range(..=offset).next_back() {
            if offset < region.end {
                return region.at(offset);
            }
        }
        let start = self.bytes[..offset]
            .iter()
            .rposition(|b| *b == 0)
            .map_or(0, |p| p + 1);
        let end = offset
            + self.bytes[offset..]
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| invalid("ELF string terminator"))?;
        #[cfg(test)]
        {
            self.scanned_bytes += end - start + 1;
        }
        let mut valid_start = start;
        let valid_suffix = loop {
            match std::str::from_utf8(&self.bytes[valid_start..end]) {
                Ok(value) => {
                    #[cfg(test)]
                    {
                        self.scanned_bytes += end - valid_start;
                    }
                    break value;
                }
                Err(error) => {
                    let advance = error.valid_up_to()
                        + error
                            .error_len()
                            .unwrap_or(end - valid_start - error.valid_up_to());
                    #[cfg(test)]
                    {
                        self.scanned_bytes += advance;
                    }
                    valid_start += advance;
                }
            }
        };
        #[cfg(test)]
        {
            self.scanned_bytes += valid_suffix.len();
        }
        let last_forbidden = valid_suffix
            .char_indices()
            .rev()
            .find(|(_, c)| matches!(c, '@' | '/' | '\\') || c.is_control())
            .map(|(i, _)| valid_start + i);
        let region = StringRegion {
            end,
            valid_start,
            valid_suffix,
            last_forbidden,
        };
        let result = region.at(offset);
        if end - start > SHORT_ELF_STRING {
            self.regions.insert(start, region);
        }
        result
    }
    fn atom(&mut self, offset: u64) -> R<ElfAtom<'a>> {
        let value = self.lookup(offset)?;
        if !value.is_atom {
            return Err(invalid("ELF invalid provider/version atom"));
        }
        let offset = usize::try_from(offset).map_err(|_| invalid("ELF string offset"))?;
        if value.value.len() > SHORT_ELF_STRING {
            if let Some(key) = self.long_ids.get(&offset) {
                return Ok(ElfAtom {
                    value: value.value,
                    key: *key,
                });
            }
        }
        let next = self.interns.len();
        let key = *self
            .interns
            .entry((value.value.len(), value.value))
            .or_insert(next);
        if value.value.len() > SHORT_ELF_STRING {
            self.long_ids.insert(offset, key);
        }
        Ok(ElfAtom {
            value: value.value,
            key,
        })
    }
}
#[derive(Clone)]
struct HostSection<'a> {
    name: &'a str,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entry: u64,
    alignment: u64,
}
#[derive(Clone)]
struct HostSegment {
    kind: u32,
    offset: u64,
    address: u64,
    files: u64,
    memory: u64,
}
struct HostElf<'a> {
    contract: Option<&'a [u8]>,
    interpreter: Option<&'a str>,
    needed: Vec<&'a str>,
    versions: Vec<(&'a str, &'a str)>,
    build_id: Option<Vec<u8>>,
}
// One interval per structural record/header, never one tree node per byte.
fn disjoint_ranges(ranges: &mut Vec<(u64, u64)>) -> R<()> {
    if ranges.iter().any(|(start, end)| start > end) {
        return Err(invalid("ELF reversed interval"));
    }
    ranges.retain(|(start, end)| start != end);
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("ELF overlapping intervals"));
    }
    Ok(())
}
struct NoteGroup {
    start: u64,
    end: u64,
    boundaries: Vec<u64>,
}
fn note_groups(mut views: Vec<(u64, u64)>) -> R<Vec<NoteGroup>> {
    if views.iter().any(|(start, end)| start > end) {
        return Err(invalid("ELF reversed note view"));
    }
    views.retain(|(start, end)| start != end);
    views.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    views.dedup();
    let mut groups: Vec<NoteGroup> = vec![];
    let mut stack = vec![];
    for (start, end) in views {
        while stack.last().is_some_and(|prior| *prior <= start) {
            stack.pop();
        }
        if let Some(parent) = stack.last() {
            if end > *parent {
                return Err(invalid("ELF partially overlapping note views"));
            }
        } else {
            groups.push(NoteGroup {
                start,
                end,
                boundaries: vec![],
            });
        }
        stack.push(end);
        let group = groups.last_mut().expect("nonempty note group");
        group.boundaries.extend([start, end]);
    }
    for group in &mut groups {
        group.boundaries.sort_unstable();
        group.boundaries.dedup();
    }
    Ok(groups)
}
// Exactly one bit per table byte, with at most ceil(table_bytes/64) words.
// Version record sizes are constant, so overlap checks have constant work per
// record and the gap scan is linear in the already bounded retained table.
struct TableCoverage {
    length: usize,
    words: Vec<u64>,
}
impl TableCoverage {
    fn new(length: usize) -> Self {
        Self {
            length,
            words: vec![0; length / 64 + usize::from(length % 64 != 0)],
        }
    }
    fn claim(&mut self, start: usize, length: usize) -> R<()> {
        let end = start
            .checked_add(length)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| invalid("ELF table coverage range"))?;
        for i in start..end {
            let bit = 1u64 << (i % 64);
            let word = &mut self.words[i / 64];
            if *word & bit != 0 {
                return Err(invalid("ELF overlapping version records"));
            }
            *word |= bit;
        }
        Ok(())
    }
    fn zero_gaps(&self, data: &[u8]) -> R<()> {
        if data.len() != self.length
            || data
                .iter()
                .enumerate()
                .any(|(i, byte)| *byte != 0 && self.words[i / 64] & (1u64 << (i % 64)) == 0)
        {
            return Err(invalid("ELF unclaimed version table data"));
        }
        Ok(())
    }
}
fn validate_sysv_hash(data: &[u8], symbol_count: u64) -> R<()> {
    let buckets = elf_u32(data, 0)? as u64;
    let chains = elf_u32(data, 4)? as u64;
    let length = 8u64
        .checked_add(
            buckets
                .checked_add(chains)
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(|| invalid("ELF SysV hash array overflow"))?,
        )
        .ok_or_else(|| invalid("ELF SysV hash size overflow"))?;
    if buckets == 0 || chains == 0 || chains != symbol_count || length != data.len() as u64 {
        return Err(invalid("ELF SysV hash count/size"));
    }
    let bucket_data = elf_range(data, 8, buckets * 4)?;
    let chain_data = elf_range(data, 8 + buckets * 4, chains * 4)?;
    for entry in bucket_data
        .chunks_exact(4)
        .chain(chain_data.chunks_exact(4))
    {
        if elf_u32(entry, 0)? as u64 >= chains {
            return Err(invalid("ELF SysV hash symbol index"));
        }
    }
    if elf_u32(chain_data, 0)? != 0 {
        return Err(invalid("ELF SysV null symbol chain"));
    }
    let mut states = vec![0u8; chains as usize];
    states[0] = 2;
    for start in 1..chains as usize {
        let mut i = start;
        while states[i] == 0 {
            states[i] = 1;
            i = elf_u32(chain_data, i * 4)? as usize;
        }
        if states[i] == 1 {
            return Err(invalid("ELF cyclic SysV hash chain"));
        }
        i = start;
        while states[i] == 1 {
            states[i] = 2;
            i = elf_u32(chain_data, i * 4)? as usize;
        }
    }
    Ok(())
}
fn validate_gnu_hash(data: &[u8], symbol_count: u64) -> R<()> {
    let buckets = elf_u32(data, 0)? as u64;
    let first = elf_u32(data, 4)? as u64;
    let bloom = elf_u32(data, 8)? as u64;
    let shift = elf_u32(data, 12)?;
    if buckets == 0 || !bloom.is_power_of_two() || shift >= u32::BITS || first > symbol_count {
        return Err(invalid("ELF GNU hash header/symbol offset"));
    }
    let bucket_offset = 16u64
        .checked_add(
            bloom
                .checked_mul(8)
                .ok_or_else(|| invalid("ELF GNU bloom overflow"))?,
        )
        .ok_or_else(|| invalid("ELF GNU hash header overflow"))?;
    let chain_offset = bucket_offset
        .checked_add(
            buckets
                .checked_mul(4)
                .ok_or_else(|| invalid("ELF GNU bucket overflow"))?,
        )
        .ok_or_else(|| invalid("ELF GNU hash arrays overflow"))?;
    let end = chain_offset
        .checked_add(
            (symbol_count - first)
                .checked_mul(4)
                .ok_or_else(|| invalid("ELF GNU chain overflow"))?,
        )
        .ok_or_else(|| invalid("ELF GNU hash size overflow"))?;
    if end != data.len() as u64 {
        return Err(invalid("ELF GNU hash full array bound"));
    }
    elf_range(data, 16, bloom * 8)?;
    let mut starts = vec![];
    for row in elf_range(data, bucket_offset, buckets * 4)?.chunks_exact(4) {
        let symbol = elf_u32(row, 0)? as u64;
        if symbol != 0 {
            if symbol < first || symbol >= symbol_count {
                return Err(invalid("ELF GNU bucket symbol index"));
            }
            // There cannot be more nonempty bucket roots than hashed symbols.
            // Refuse repeated roots before retaining an attacker-sized vector.
            if starts.len() as u64 >= symbol_count - first {
                return Err(invalid("ELF GNU excessive bucket roots"));
            }
            starts.push(symbol);
        }
    }
    starts.sort_unstable();
    if starts.windows(2).any(|p| p[0] == p[1])
        || first < symbol_count && starts.first() != Some(&first)
        || first == symbol_count && !starts.is_empty()
    {
        return Err(invalid("ELF GNU hash symbol coverage"));
    }
    for (i, start) in starts.iter().copied().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(symbol_count);
        for symbol in start..end {
            let value = elf_u32(data, (chain_offset + (symbol - first) * 4) as usize)?;
            if (value & 1 != 0) != (symbol + 1 == end) {
                return Err(invalid("ELF GNU hash chain termination"));
            }
        }
    }
    Ok(())
}
fn host_elf(bytes: &[u8]) -> R<HostElf<'_>> {
    if bytes.is_empty()
        || bytes.len() as u64 > ARTIFACT_LIMIT
        || elf_range(bytes, 0, 7)? != b"\x7fELF\x02\x01\x01"
        || !matches!(elf_u16(bytes, 16)?, 2 | 3)
        || elf_u16(bytes, 18)? != 62
        || elf_u32(bytes, 20)? != 1
        || elf_u16(bytes, 52)? != 64
    {
        return Err(invalid(
            "ELF64 little-endian x86_64 executable/PIE required",
        ));
    }
    let phoff = elf_u64(bytes, 32)?;
    let phnum = elf_u16(bytes, 56)? as u64;
    let shoff = elf_u64(bytes, 40)?;
    let shnum = elf_u16(bytes, 60)? as u64;
    let names_index = elf_u16(bytes, 62)? as u64;
    if phnum == 0
        || phnum == 0xffff
        || shnum < 2
        || names_index == 0
        || names_index >= shnum
        || elf_u16(bytes, 54)? != 56
        || elf_u16(bytes, 58)? != 64
        || phoff < 64
        || shoff < 64
    {
        return Err(invalid("ELF full header tables required"));
    }
    let phbytes = elf_range(bytes, phoff, phnum * 56)?;
    let shbytes = elf_range(bytes, shoff, shnum * 64)?;
    let overlaps = |a: u64, n: u64, b: u64, m: u64| n != 0 && m != 0 && a < b + m && b < a + n;
    if overlaps(phoff, phnum * 56, shoff, shnum * 64) || shbytes[..64].iter().any(|b| *b != 0) {
        return Err(invalid("ELF table overlap/null section"));
    }
    let names_header = &shbytes[names_index as usize * 64..(names_index as usize + 1) * 64];
    if elf_u32(names_header, 4)? != 3 {
        return Err(invalid("ELF section-name table type"));
    }
    let names = elf_range(
        bytes,
        elf_u64(names_header, 24)?,
        elf_u64(names_header, 32)?,
    )?;
    if names.first() != Some(&0) || names.last() != Some(&0) {
        return Err(invalid("ELF section-name framing"));
    }
    let mut names = ElfStrings::new(names);
    let mut section_ranges = vec![
        (0, 64),
        (phoff, phoff + phnum * 56),
        (shoff, shoff + shnum * 64),
    ];
    let mut sections: Vec<HostSection<'_>> = vec![];
    let mut seen = BTreeSet::new();
    for row in shbytes[64..].chunks_exact(64) {
        let name = names.lookup(elf_u32(row, 0)? as u64)?.value;
        if name.is_empty() || !seen.insert((name.len(), name)) {
            return Err(invalid("ELF duplicate/empty section name"));
        }
        let section = HostSection {
            name,
            kind: elf_u32(row, 4)?,
            flags: elf_u64(row, 8)?,
            address: elf_u64(row, 16)?,
            offset: elf_u64(row, 24)?,
            size: elf_u64(row, 32)?,
            link: elf_u32(row, 40)?,
            info: elf_u32(row, 44)?,
            alignment: elf_u64(row, 48)?,
            entry: elf_u64(row, 56)?,
        };
        if section.link as u64 >= shnum
            || section.alignment > 1 && !section.alignment.is_power_of_two()
            || section.entry != 0 && section.size % section.entry != 0
        {
            return Err(invalid("ELF section link/alignment/entry"));
        }
        if section.kind != 8 {
            elf_range(bytes, section.offset, section.size)?;
            section_ranges.push((section.offset, section.offset + section.size));
        }
        section
            .address
            .checked_add(section.size)
            .ok_or_else(|| invalid("ELF section address overflow"))?;
        sections.push(section);
    }
    disjoint_ranges(&mut section_ranges)?;
    let section_data = |s: &HostSection<'_>| elf_range(bytes, s.offset, s.size);
    let mut segments: Vec<HostSegment> = vec![];
    let mut unique_segments = BTreeSet::new();
    for row in phbytes.chunks_exact(56) {
        let segment = HostSegment {
            kind: elf_u32(row, 0)?,
            offset: elf_u64(row, 8)?,
            address: elf_u64(row, 16)?,
            files: elf_u64(row, 32)?,
            memory: elf_u64(row, 40)?,
        };
        let align = elf_u64(row, 48)?;
        elf_range(bytes, segment.offset, segment.files)?;
        segment
            .address
            .checked_add(segment.memory)
            .ok_or_else(|| invalid("ELF segment address overflow"))?;
        if segment.files > segment.memory
            || align > 1 && !align.is_power_of_two()
            || segment.kind == 1 && align > 1 && segment.address % align != segment.offset % align
        {
            return Err(invalid("ELF segment sizes/alignment"));
        }
        if matches!(segment.kind, 2 | 3) && !unique_segments.insert(segment.kind) {
            return Err(invalid("ELF duplicate dynamic/interpreter segment"));
        }
        segments.push(segment);
    }
    let mut loads = segments
        .iter()
        .filter(|s| s.kind == 1 && s.memory != 0)
        .collect::<Vec<_>>();
    loads.sort_unstable_by_key(|p| p.address);
    let mut load_ranges = loads
        .iter()
        .map(|p| (p.address, p.address + p.memory))
        .collect::<Vec<_>>();
    disjoint_ranges(&mut load_ranges)?;
    if loads.is_empty() {
        return Err(invalid("ELF load segment absent"));
    }
    for s in &sections {
        if s.flags & 2 != 0 && s.size > 0 {
            let owner = loads
                .partition_point(|p| p.address <= s.address)
                .checked_sub(1)
                .and_then(|i| loads.get(i))
                .ok_or_else(|| invalid("ELF allocated section outside unique load"))?;
            if s.address + s.size > owner.address + owner.memory
                || s.kind != 8
                    && (s.offset < owner.offset
                        || s.address - owner.address != s.offset - owner.offset
                        || s.offset + s.size > owner.offset + owner.files)
            {
                return Err(invalid("ELF allocated section outside unique load"));
            }
        }
    }
    let mapped = |address: u64, length: u64| -> R<&[u8]> {
        let end = address
            .checked_add(length)
            .ok_or_else(|| invalid("ELF mapped range overflow"))?;
        let p = loads
            .partition_point(|p| p.address <= address)
            .checked_sub(1)
            .and_then(|i| loads.get(i))
            .ok_or_else(|| invalid("ELF unmapped virtual range"))?;
        if end > p.address + p.files {
            return Err(invalid("ELF unmapped virtual range"));
        }
        elf_range(bytes, p.offset + (address - p.address), length)
    };
    let mut string_tables: BTreeMap<u32, ElfStrings<'_>> = BTreeMap::new();
    for s in &sections {
        match s.kind {
            2 | 11 => {
                if s.entry != 24 || s.link == 0 || sections[(s.link - 1) as usize].kind != 3 {
                    return Err(invalid("ELF symbol table framing/link"));
                }
                let bytes = section_data(&sections[(s.link - 1) as usize])?;
                let strings = string_tables
                    .entry(s.link)
                    .or_insert_with(|| ElfStrings::new(bytes));
                for sym in section_data(s)?.chunks_exact(24) {
                    strings.lookup(elf_u32(sym, 0)? as u64)?;
                    let index = elf_u16(sym, 6)?;
                    if index < 0xff00 && index as u64 >= shnum {
                        return Err(invalid("ELF symbol section index"));
                    }
                }
            }
            4 | 9 => {
                let width = if s.kind == 4 { 24 } else { 16 };
                if s.entry != width
                    || s.link == 0
                    || !matches!(sections[(s.link - 1) as usize].kind, 2 | 11)
                    || s.info as u64 >= shnum
                {
                    return Err(invalid("ELF relocation framing/link"));
                }
                let count = sections[(s.link - 1) as usize].size / 24;
                for rel in section_data(s)?.chunks_exact(width as usize) {
                    if elf_u64(rel, 8)? >> 32 >= count {
                        return Err(invalid("ELF relocation symbol index"));
                    }
                }
            }
            0x6fffffff => {
                if s.entry != 2
                    || s.link == 0
                    || sections[(s.link - 1) as usize].kind != 11
                    || s.size / 2 != sections[(s.link - 1) as usize].size / 24
                {
                    return Err(invalid("ELF version-symbol bounds/link"));
                }
            }
            _ => {}
        }
    }
    for kind in [0x6ffffffe, 0x6ffffffd, 0x6fffffff] {
        if sections.iter().filter(|s| s.kind == kind).count() > 1 {
            return Err(invalid("ELF ambiguous version tables"));
        }
    }
    let mut result = HostElf {
        contract: None,
        interpreter: None,
        needed: vec![],
        versions: vec![],
        build_id: None,
    };
    if let Some(s) = sections
        .iter()
        .find(|s| s.name == ".osslscope.bundle_contract")
    {
        if s.kind != 1 || s.flags != 2 || s.size == 0 || s.size > BUILD_RECORD_LIMIT as u64 {
            return Err(invalid("ELF contract section shape/bound"));
        }
        let data = section_data(s)?;
        super::records::parse_canonical::<super::records::AdmittedContract>(data)?;
        result.contract = Some(data);
    }
    let interp_section = sections.iter().find(|s| s.name == ".interp");
    if let Some(p) = segments.iter().find(|s| s.kind == 3) {
        let data = elf_range(bytes, p.offset, p.files)?;
        let name = ElfStrings::new(data).lookup(0)?.value;
        let s = interp_section.ok_or_else(|| invalid("ELF interpreter section absent"))?;
        if data.len() != name.len() + 1
            || name.is_empty()
            || !name.starts_with('/')
            || name[1..].split('/').any(|p| matches!(p, "" | "." | ".."))
            || name.chars().any(char::is_control)
            || name.contains('\\')
            || s.kind != 1
            || s.flags & 2 == 0
            || s.offset != p.offset
            || s.size != p.files
            || mapped(p.address, p.files)? != data
        {
            return Err(invalid("ELF interpreter shape/mapping"));
        }
        result.interpreter = Some(name);
    } else if interp_section.is_some() {
        return Err(invalid("ELF orphan interpreter section"));
    }
    let dyn_sections = sections.iter().filter(|s| s.kind == 6).collect::<Vec<_>>();
    if dyn_sections.len() > 1 {
        return Err(invalid("ELF ambiguous dynamic sections"));
    }
    let mut tags = BTreeMap::<u64, u64>::new();
    let mut needed_offsets = vec![];
    if let Some(p) = segments.iter().find(|s| s.kind == 2) {
        let s = dyn_sections
            .first()
            .ok_or_else(|| invalid("ELF dynamic section absent"))?;
        if s.offset != p.offset
            || s.size != p.files
            || s.entry != 16
            || s.size == 0
            || s.size % 16 != 0
            || s.link == 0
            || sections[(s.link - 1) as usize].kind != 3
            || mapped(p.address, p.files)? != section_data(s)?
        {
            return Err(invalid("ELF dynamic framing/mapping"));
        }
        let mut terminated = false;
        for row in section_data(s)?.chunks_exact(16) {
            let tag = elf_u64(row, 0)?;
            let value = elf_u64(row, 8)?;
            if terminated {
                if tag != 0 || value != 0 {
                    return Err(invalid("ELF dynamic data after null"));
                }
                continue;
            }
            if tag == 0 {
                if value != 0 {
                    return Err(invalid("ELF dynamic null value"));
                }
                terminated = true;
                continue;
            }
            if matches!(tag, 15 | 29 | 0x7ffffffd | 0x7fffffff) {
                return Err(invalid("ELF unsupported dynamic lookup mechanism"));
            }
            if tag == 1 {
                needed_offsets.push(value);
            } else if tags.insert(tag, value).is_some() {
                return Err(invalid("ELF duplicate dynamic tag"));
            }
        }
        if !terminated {
            return Err(invalid("ELF unterminated dynamic table"));
        }
        let strings = &sections[(s.link - 1) as usize];
        if tags.get(&5) != Some(&strings.address) || tags.get(&10) != Some(&strings.size) {
            return Err(invalid("ELF dynamic string table disagreement"));
        }
        let string_bytes = mapped(strings.address, strings.size)?;
        if !std::ptr::eq(section_data(strings)?, string_bytes) {
            return Err(invalid("ELF dynamic string section/mapping identity"));
        }
        if string_bytes.first() != Some(&0) || string_bytes.last() != Some(&0) {
            return Err(invalid("ELF dynamic strings framing"));
        }
        let strings = string_tables
            .entry(s.link)
            .or_insert_with(|| ElfStrings::new(string_bytes));
        if !std::ptr::eq(strings.bytes, string_bytes) {
            return Err(invalid("ELF dynamic string cache identity"));
        }
        let mut needed_ids = BTreeSet::new();
        for offset in needed_offsets {
            let name = strings.atom(offset)?;
            if !needed_ids.insert(name.key) {
                return Err(invalid("ELF duplicate/invalid needed provider"));
            }
            result.needed.push(name.value);
        }
        let associated = |address: u64,
                          length: u64,
                          kind: u32,
                          entry: Option<u64>,
                          link: Option<u32>|
         -> R<&HostSection<'_>> {
            if address == 0 {
                return Err(invalid("ELF zero dynamic table address"));
            }
            let mut matches = sections.iter().filter(|section| {
                section.kind == kind
                    && section.address == address
                    && section.size == length
                    && section.flags & 2 != 0
                    && entry.is_none_or(|width| section.entry == width)
                    && link.is_none_or(|index| section.link == index)
            });
            let section = matches
                .next()
                .ok_or_else(|| invalid("ELF dynamic table section association"))?;
            if matches.next().is_some() || mapped(address, length)? != section_data(section)? {
                return Err(invalid("ELF ambiguous dynamic table association"));
            }
            Ok(section)
        };
        let dynamic_symbols = match (tags.get(&6), tags.get(&11)) {
            (Some(address), Some(24)) => {
                let mut candidates = sections
                    .iter()
                    .enumerate()
                    .filter(|(_, section)| section.kind == 11 && section.address == *address);
                let (index, section) = candidates
                    .next()
                    .ok_or_else(|| invalid("ELF dynamic symbols absent"))?;
                if candidates.next().is_some() {
                    return Err(invalid("ELF ambiguous dynamic symbols"));
                }
                associated(*address, section.size, 11, Some(24), Some(s.link))?;
                Some((index as u32 + 1, section.size / 24))
            }
            (None, None) => None,
            _ => return Err(invalid("ELF partial dynamic symbol table")),
        };
        for (tag, kind) in [(4, 5), (0x6ffffef5, 0x6ffffff6)] {
            let mut candidates = sections.iter().filter(|section| section.kind == kind);
            let hash = candidates.next();
            if candidates.next().is_some() {
                return Err(invalid("ELF ambiguous dynamic hash sections"));
            }
            match (tags.get(&tag), hash) {
                (Some(address), Some(section)) => {
                    let (index, count) = dynamic_symbols
                        .ok_or_else(|| invalid("ELF hash without dynamic symbols"))?;
                    associated(
                        *address,
                        section.size,
                        kind,
                        if tag == 4 { Some(4) } else { None },
                        Some(index),
                    )?;
                    let data = mapped(*address, section.size)?;
                    if tag == 4 {
                        validate_sysv_hash(data, count)?;
                    } else {
                        validate_gnu_hash(data, count)?;
                    }
                }
                (None, None) => {}
                _ => return Err(invalid("ELF partial/orphan dynamic hash table")),
            }
        }
        for (pointer, size, entry, kind, width) in [(7, 8, 9, 4, 24), (17, 18, 19, 9, 16)] {
            match (tags.get(&pointer), tags.get(&size)) {
                (Some(address), Some(length)) => {
                    if tags.get(&entry) != Some(&width) || length % width != 0 {
                        return Err(invalid("ELF dynamic relocation entry size"));
                    }
                    let (index, _) = dynamic_symbols
                        .ok_or_else(|| invalid("ELF relocations without dynamic symbols"))?;
                    associated(*address, *length, kind, Some(width), Some(index))?;
                }
                (None, None) => {}
                _ => return Err(invalid("ELF partial dynamic relocation table")),
            }
        }
        match (tags.get(&23), tags.get(&2), tags.get(&20)) {
            (Some(address), Some(length), Some(discriminator)) => {
                let (kind, width) = match discriminator {
                    7 => (4, 24),
                    17 => (9, 16),
                    _ => return Err(invalid("ELF invalid PLT relocation discriminator")),
                };
                if length % width != 0 {
                    return Err(invalid("ELF PLT relocation width"));
                }
                let (index, _) =
                    dynamic_symbols.ok_or_else(|| invalid("ELF PLT without dynamic symbols"))?;
                associated(*address, *length, kind, Some(width), Some(index))?;
            }
            (None, None, None) => {}
            _ => return Err(invalid("ELF partial PLT relocation table")),
        }
        for (pointer, size, kind) in [(25, 27, 14), (26, 28, 15), (32, 33, 16)] {
            match (tags.get(&pointer), tags.get(&size)) {
                (Some(address), Some(length)) => {
                    if length % 8 != 0 {
                        return Err(invalid("ELF dynamic pointer-array width"));
                    }
                    associated(*address, *length, kind, Some(8), None)?;
                }
                (None, None) => {}
                _ => return Err(invalid("ELF partial dynamic pointer array")),
            }
        }
        for pointer in [12, 13, 0x6ffffff0] {
            if let Some(address) = tags.get(&pointer) {
                if *address != 0 {
                    mapped(*address, 1)?;
                }
            }
        }
        let mut version_indices = BTreeSet::new();
        let mut version_pairs = BTreeSet::new();
        let verneed = sections.iter().find(|s| s.kind == 0x6ffffffe);
        match (tags.get(&0x6ffffffe), tags.get(&0x6fffffff), verneed) {
            (Some(address), Some(count), Some(v)) => {
                if *address != v.address
                    || *count == 0
                    || *count != v.info as u64
                    || v.link != s.link
                {
                    return Err(invalid("ELF version need identity/count/link"));
                }
                let data = mapped(*address, v.size)?;
                let mut at = 0usize;
                let mut occupied = TableCoverage::new(data.len());
                let mut providers = BTreeSet::new();
                for i in 0..*count {
                    let row = elf_range(data, at as u64, 16)?;
                    occupied.claim(at, 16)?;
                    if elf_u16(row, 0)? != 1 {
                        return Err(invalid("ELF version need format"));
                    }
                    let provider = strings.atom(elf_u32(row, 4)? as u64)?;
                    if !needed_ids.contains(&provider.key) || !providers.insert(provider.key) {
                        return Err(invalid("ELF version need provider"));
                    }
                    let aux_count = elf_u16(row, 2)? as usize;
                    let aux = elf_u32(row, 8)? as usize;
                    if aux_count == 0 || aux < 16 {
                        return Err(invalid("ELF version auxiliaries absent"));
                    }
                    let mut pos = at
                        .checked_add(aux)
                        .ok_or_else(|| invalid("ELF version aux overflow"))?;
                    for j in 0..aux_count {
                        let aux = elf_range(data, pos as u64, 16)?;
                        occupied.claim(pos, 16)?;
                        let index = elf_u16(aux, 6)? & 0x7fff;
                        if index < 2 || !version_indices.insert(index) {
                            return Err(invalid("ELF reserved/duplicate external version index"));
                        }
                        let version = strings.atom(elf_u32(aux, 8)? as u64)?;
                        if !version_pairs.insert((provider.key, version.key)) {
                            return Err(invalid("ELF duplicate/invalid version requirement"));
                        }
                        result.versions.push((provider.value, version.value));
                        let next = elf_u32(aux, 12)? as usize;
                        if (j + 1 == aux_count) != (next == 0) || next != 0 && next < 16 {
                            return Err(invalid("ELF version aux chain"));
                        }
                        pos = pos
                            .checked_add(next)
                            .ok_or_else(|| invalid("ELF version aux overflow"))?;
                    }
                    let next = elf_u32(row, 12)? as usize;
                    if (i + 1 == *count) != (next == 0) || next != 0 && next < 16 {
                        return Err(invalid("ELF version need chain"));
                    }
                    at = at
                        .checked_add(next)
                        .ok_or_else(|| invalid("ELF version need overflow"))?;
                }
                occupied.zero_gaps(data)?;
            }
            (None, None, None) => {}
            _ => return Err(invalid("ELF partial/orphan version need")),
        }
        // Executables with exported version definitions remain supported, with
        // every forward/aux range validated rather than delegated to strings.
        let verdef = sections.iter().find(|s| s.kind == 0x6ffffffd);
        match (tags.get(&0x6ffffffc), tags.get(&0x6ffffffd), verdef) {
            (Some(address), Some(count), Some(v)) => {
                if *address != v.address
                    || *count == 0
                    || *count != v.info as u64
                    || v.link != s.link
                {
                    return Err(invalid("ELF version definition identity/count"));
                }
                let data = mapped(*address, v.size)?;
                let mut at = 0usize;
                let mut occupied = TableCoverage::new(data.len());
                for i in 0..*count {
                    let row = elf_range(data, at as u64, 20)?;
                    occupied.claim(at, 20)?;
                    if elf_u16(row, 0)? != 1 {
                        return Err(invalid("ELF version definition format"));
                    }
                    let index = elf_u16(row, 4)? & 0x7fff;
                    if index == 0 || !version_indices.insert(index) {
                        return Err(invalid("ELF reserved/duplicate version definition index"));
                    }
                    let n = elf_u16(row, 6)? as usize;
                    let aux = elf_u32(row, 12)? as usize;
                    if n == 0 || aux < 20 {
                        return Err(invalid("ELF version definition auxiliaries"));
                    }
                    let mut pos = at
                        .checked_add(aux)
                        .ok_or_else(|| invalid("ELF version overflow"))?;
                    for j in 0..n {
                        let a = elf_range(data, pos as u64, 8)?;
                        occupied.claim(pos, 8)?;
                        strings.atom(elf_u32(a, 0)? as u64)?;
                        let next = elf_u32(a, 4)? as usize;
                        if (j + 1 == n) != (next == 0) || next != 0 && next < 8 {
                            return Err(invalid("ELF definition aux chain"));
                        }
                        pos = pos
                            .checked_add(next)
                            .ok_or_else(|| invalid("ELF definition overflow"))?;
                    }
                    let next = elf_u32(row, 16)? as usize;
                    if (i + 1 == *count) != (next == 0) || next != 0 && next < 20 {
                        return Err(invalid("ELF definition chain"));
                    }
                    at = at
                        .checked_add(next)
                        .ok_or_else(|| invalid("ELF definition overflow"))?;
                }
                occupied.zero_gaps(data)?;
            }
            (None, None, None) => {}
            _ => return Err(invalid("ELF partial/orphan version definitions")),
        }
        let versym = sections.iter().find(|s| s.kind == 0x6fffffff);
        match (tags.get(&0x6ffffff0), versym) {
            (Some(address), Some(section)) => {
                if *address != section.address {
                    return Err(invalid("ELF version-symbol address mismatch"));
                }
                for index in mapped(*address, section.size)?.chunks_exact(2) {
                    let index = elf_u16(index, 0)? & 0x7fff;
                    if index > 1 && !version_indices.contains(&index) {
                        return Err(invalid("ELF unknown symbol version index"));
                    }
                }
            }
            (None, None) => {}
            _ => return Err(invalid("ELF partial version-symbol table")),
        }
    } else if !dyn_sections.is_empty()
        || sections
            .iter()
            .any(|s| matches!(s.kind, 0x6ffffffd..=0x6fffffff))
    {
        return Err(invalid("ELF orphan dynamic/version sections"));
    }
    let views = sections
        .iter()
        .filter(|s| s.kind == 7)
        .map(|s| (s.offset, s.offset + s.size))
        .chain(
            segments
                .iter()
                .filter(|s| s.kind == 4)
                .map(|s| (s.offset, s.offset + s.files)),
        )
        .collect();
    for group in note_groups(views)? {
        let offset = group.start;
        let size = group.end - group.start;
        let data = elf_range(bytes, offset, size)?;
        let mut at = 0usize;
        let mut boundary_index = 1;
        while at < data.len() {
            let row = elf_range(data, at as u64, 12)?;
            let ns = elf_u32(row, 0)? as usize;
            let ds = elf_u32(row, 4)? as usize;
            let typ = elf_u32(row, 8)?;
            let no = at + 12;
            let name = elf_range(data, no as u64, ns as u64)?;
            if !name.is_empty() && name.last() != Some(&0) {
                return Err(invalid("ELF unterminated note owner"));
            }
            let desc_at = no
                .checked_add(ns)
                .and_then(|n| n.checked_add(3))
                .ok_or_else(|| invalid("ELF note overflow"))?
                & !3;
            let desc = elf_range(data, desc_at as u64, ds as u64)?;
            let end = desc_at
                .checked_add(ds)
                .and_then(|n| n.checked_add(3))
                .ok_or_else(|| invalid("ELF note overflow"))?
                & !3;
            if data
                .get(no + ns..desc_at)
                .ok_or_else(|| invalid("ELF note padding"))?
                .iter()
                .chain(
                    data.get(desc_at + ds..end)
                        .ok_or_else(|| invalid("ELF note padding"))?,
                )
                .any(|b| *b != 0)
            {
                return Err(invalid("ELF nonzero note padding"));
            }
            if typ == 3 && name == b"GNU\0" {
                if ds == 0 || ds > 64 || result.build_id.is_some() {
                    return Err(invalid("ELF absent/duplicate/oversized build ID"));
                }
                result.build_id = Some(desc.to_vec());
            }
            at = end;
            let boundary = offset + at as u64;
            while group
                .boundaries
                .get(boundary_index)
                .is_some_and(|wanted| *wanted <= boundary)
            {
                if group.boundaries[boundary_index] != boundary {
                    return Err(invalid("ELF note view cuts a record"));
                }
                boundary_index += 1;
            }
        }
        if boundary_index != group.boundaries.len() {
            return Err(invalid("ELF note boundary range"));
        }
    }
    Ok(result)
}
fn host_contract_bytes(bytes: &[u8]) -> R<&[u8]> {
    host_elf(bytes)?
        .contract
        .ok_or_else(|| invalid("unique canonical host contract absent"))
}
/// Extract a structurally valid canonical contract from one retained host ELF.
/// This alone does not admit provenance, source identity, ABI cells or a payload.
pub fn extract_host_contract(bytes: &[u8]) -> R<super::records::AdmittedContract> {
    super::records::parse_canonical(host_contract_bytes(bytes)?)
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Deferred owned package builder measured host ABI admission; retained host regressions exercise this item"
    )
)]
fn validate_host_abi(bytes: &[u8], evidence: &source::AbiEvidence) -> R<()> {
    let elf = host_elf(bytes)?;
    if evidence.schema != "osslscope-abi-evidence-v1" || evidence.cells.is_empty() {
        return Err(invalid("ABI evidence cells absent"));
    }
    for cell in &evidence.cells {
        match &cell.interpreter {
            source::AbiInterpreter::Static => {
                if elf.interpreter.is_some()
                    || !elf.needed.is_empty()
                    || !elf.versions.is_empty()
                    || !cell.needed.is_empty()
                    || !cell.symbol_versions.is_empty()
                {
                    return Err(invalid("static ABI contains dynamic requirements"));
                }
            }
            source::AbiInterpreter::Dynamic { path } => {
                let needed = cell
                    .needed
                    .iter()
                    .map(|value| (value.len(), value.as_str()))
                    .collect::<BTreeSet<_>>();
                let versions = cell
                    .symbol_versions
                    .iter()
                    .map(|value| {
                        let (provider, version) = value
                            .split_once('@')
                            .ok_or_else(|| invalid("ABI provider/version pair"))?;
                        Ok((provider.len(), version.len(), provider, version))
                    })
                    .collect::<R<BTreeSet<_>>>()?;
                if elf.interpreter != Some(path.as_str())
                    || elf
                        .needed
                        .iter()
                        .any(|name| !needed.contains(&(name.len(), *name)))
                    || elf.versions.iter().any(|(provider, version)| {
                        !versions.contains(&(provider.len(), version.len(), *provider, *version))
                    })
                {
                    return Err(invalid("host ABI unsupported by required measured cell"));
                }
            }
        }
    }
    Ok(())
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Deferred owned package builder bootstrap admission; retained host regressions exercise this item"
    )
)]
fn inspect_bootstrap(bytes: &[u8], layout: &ExecutorLayout) -> R<()> {
    let elf = host_elf(bytes)?;
    if elf.contract.is_some() || elf.interpreter != Some("/lib64/ld-linux-x86-64.so.2") {
        return Err(invalid("bootstrap must be GNU and descriptor-free"));
    }
    let mut tree = None;
    for bytes in layout.documents.values() {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("retained layout document"))?;
        if value["schema"] == "osslscope-executor-host-v1" {
            if tree.is_some() {
                return Err(invalid("duplicate retained host manifest"));
            }
            tree = Some(host_tree(bytes)?);
        }
    }
    let tree = tree.ok_or_else(|| invalid("retained bootstrap host tree absent"))?;
    if !matches!(
        tree.resolve("lib64/ld-linux-x86-64.so.2")?,
        ToolNode::File { mode: 0o755, .. }
    ) {
        return Err(invalid("bootstrap GNU interpreter unavailable"));
    }
    for name in elf.needed {
        let mut identities = BTreeSet::new();
        for prefix in [
            "lib/x86_64-linux-gnu",
            "usr/lib/x86_64-linux-gnu",
            "lib64",
            "usr/lib64",
            "lib",
            "usr/lib",
        ] {
            if let Ok(ToolNode::File { sha256, bytes, .. }) =
                tree.resolve(&format!("{prefix}/{name}"))
            {
                identities.insert((sha256.0, *bytes));
            }
        }
        if identities.len() != 1 {
            return Err(invalid(
                "bootstrap dependency missing/ambiguous in retained GNU rootfs",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::inventory::source_fixtures::Fixture;
    use super::*;
    use serde_json::json;
    mod retained {
        use super::*;
        use crate::package::records::{BundleContract, Role, parse_canonical};
        use crate::package::source::{AbiCell, AbiEvidence, AbiInterpreter};
        use std::os::unix::{fs::symlink, process::ExitStatusExt};
        fn w16(b: &mut [u8], at: usize, n: u16) {
            b[at..at + 2].copy_from_slice(&n.to_le_bytes());
        }
        fn w32(b: &mut [u8], at: usize, n: u32) {
            b[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        fn w64(b: &mut [u8], at: usize, n: u64) {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        // Independent section/symbol assembler: no production policy table is read.
        type Section = (&'static str, u32, u64, Vec<u8>, u32, u32, u64);
        fn image(
            machine: u16,
            kind: u16,
            mut sections: Vec<Section>,
            phnum: usize,
        ) -> (Vec<u8>, BTreeMap<String, (usize, usize)>, usize) {
            let mut names = vec![0];
            let mut no = vec![0];
            for s in &sections {
                no.push(names.len());
                names.extend(s.0.as_bytes());
                names.push(0);
            }
            no.push(names.len());
            names.extend(b".shstrtab\0");
            sections.push((".shstrtab", 3, 0, names, 0, 0, 0));
            let mut b = vec![0; 64 + phnum * 56];
            b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            w16(&mut b, 16, kind);
            w16(&mut b, 18, machine);
            w32(&mut b, 20, 1);
            w16(&mut b, 52, 64);
            if phnum > 0 {
                w64(&mut b, 32, 64);
                w16(&mut b, 54, 56);
                w16(&mut b, 56, phnum as u16);
            }
            w16(&mut b, 58, 64);
            w16(&mut b, 60, (sections.len() + 1) as u16);
            w16(&mut b, 62, sections.len() as u16);
            let mut spans = BTreeMap::new();
            for s in &sections {
                while b.len() % 8 != 0 {
                    b.push(0);
                }
                spans.insert(s.0.to_string(), (b.len(), s.3.len()));
                b.extend(&s.3);
            }
            while b.len() % 8 != 0 {
                b.push(0);
            }
            let sh = b.len();
            w64(&mut b, 40, sh as u64);
            b.resize(sh + 64 * (sections.len() + 1), 0);
            for (i, s) in sections.iter().enumerate() {
                let at = sh + (i + 1) * 64;
                let (off, len) = spans[s.0];
                w32(&mut b, at, no[i + 1] as u32);
                w32(&mut b, at + 4, s.1);
                w64(&mut b, at + 8, s.2);
                if s.2 & 2 != 0 {
                    w64(&mut b, at + 16, 0x400000 + off as u64);
                }
                w64(&mut b, at + 24, off as u64);
                w64(&mut b, at + 32, len as u64);
                w32(&mut b, at + 40, s.4);
                w32(&mut b, at + 44, s.5);
                w64(&mut b, at + 48, 8);
                w64(&mut b, at + 56, s.6);
            }
            (b, spans, sh)
        }
        fn contract() -> Vec<u8> {
            source::json_bytes(&json!({"schema":"osslscope-bundle-contract-v1","input_id":"11".repeat(32),"source":{"revision":"a".repeat(40),"inventory_sha256":"22".repeat(32)},"product_version":"0.1.0","host_profile":{"target":"x86_64-unknown-linux-gnu","abi_profile":"linux-x86_64-gnu","abi_floor":"fixture"},"wire_abi":2,"loader_contract_sha256":"33".repeat(32),"roles":[{"role":"harvest","file":"osslscope-harvest","bytes":1,"sha256":"44".repeat(32)},{"role":"count","file":"osslscope-count","bytes":2,"sha256":"55".repeat(32)},{"role":"members","file":"osslscope-members","bytes":3,"sha256":"66".repeat(32)}]})).unwrap()
        }
        fn host(
            dynamic: bool,
            descriptor: bool,
        ) -> (Vec<u8>, BTreeMap<String, (usize, usize)>, usize) {
            host_needed(dynamic, descriptor, &[1])
        }
        fn host_needed(
            dynamic: bool,
            descriptor: bool,
            needed: &[u64],
        ) -> (Vec<u8>, BTreeMap<String, (usize, usize)>, usize) {
            let mut sections = vec![];
            if descriptor {
                sections.push((".osslscope.bundle_contract", 1, 2, contract(), 0, 0, 0));
            }
            if dynamic {
                sections.push((
                    ".interp",
                    1,
                    2,
                    b"/lib64/ld-linux-x86-64.so.2\0".to_vec(),
                    0,
                    0,
                    0,
                ));
                sections.push((
                    ".dynstr",
                    3,
                    2,
                    b"\0libc.so.6\0GLIBC_2.17\0".to_vec(),
                    0,
                    0,
                    0,
                ));
                let mut ver = vec![0; 32];
                w16(&mut ver, 0, 1);
                w16(&mut ver, 2, 1);
                w32(&mut ver, 4, 1);
                w32(&mut ver, 8, 16);
                w16(&mut ver, 22, 2);
                w32(&mut ver, 24, 11);
                let stridx = sections.len() as u32;
                sections.push((".gnu.version_r", 0x6ffffffe, 2, ver, stridx, 1, 0));
                sections.push((
                    ".dynamic",
                    6,
                    3,
                    vec![0; (5 + needed.len()) * 16],
                    stridx,
                    0,
                    16,
                ));
            }
            let (mut b, spans, sh) = image(62, 3, sections, if dynamic { 3 } else { 1 });
            let len = b.len() as u64;
            w32(&mut b, 64, 1);
            w32(&mut b, 68, 5);
            w64(&mut b, 80, 0x400000);
            w64(&mut b, 88, 0x400000);
            w64(&mut b, 96, len);
            w64(&mut b, 104, len);
            w64(&mut b, 112, 0x1000);
            if dynamic {
                for (i, (typ, name)) in [(3, ".interp"), (2, ".dynamic")].iter().enumerate() {
                    let at = 120 + i * 56;
                    let (off, len) = spans[*name];
                    w32(&mut b, at, *typ);
                    w32(&mut b, at + 4, 4);
                    w64(&mut b, at + 8, off as u64);
                    w64(&mut b, at + 16, 0x400000 + off as u64);
                    w64(&mut b, at + 32, len as u64);
                    w64(&mut b, at + 40, len as u64);
                    w64(&mut b, at + 48, 8);
                }
                let d = spans[".dynamic"].0;
                let mut entries = vec![
                    (5, 0x400000 + spans[".dynstr"].0 as u64),
                    (10, spans[".dynstr"].1 as u64),
                ];
                entries.extend(needed.iter().map(|offset| (1, *offset)));
                entries.extend([
                    (0x6ffffffe, 0x400000 + spans[".gnu.version_r"].0 as u64),
                    (0x6fffffff, 1),
                    (0, 0),
                ]);
                for (i, (tag, val)) in entries.into_iter().enumerate() {
                    w64(&mut b, d + i * 16, tag);
                    w64(&mut b, d + i * 16 + 8, val);
                }
            }
            (b, spans, sh)
        }
        fn abi(dynamic: bool) -> AbiEvidence {
            serde_json::from_value(json!({"schema":"osslscope-abi-evidence-v1","host_profile":{"target":if dynamic {"x86_64-unknown-linux-gnu"}else{"x86_64-unknown-linux-musl"},"abi_profile":if dynamic {"linux-x86_64-gnu"}else{"linux-x86_64-musl"},"abi_floor":"fixture"},"cells":[{"name":"one","interpreter":if dynamic {json!({"kind":"dynamic","path":"/lib64/ld-linux-x86-64.so.2"})}else{json!({"kind":"static"})},"needed":if dynamic {vec!["libc.so.6"]}else{vec![]},"symbol_versions":if dynamic {vec!["libc.so.6@GLIBC_2.17"]}else{vec![]}}]})).unwrap()
        }
        fn retained_bytes(bytes: Vec<u8>) -> RetainedBinary {
            let length = bytes.len() as u64;
            let hash = sha256(&bytes);
            RetainedBinary {
                bytes: Arc::from(bytes),
                sha256: hash,
                length,
            }
        }
        // Literal independent maps: (name,type,key,value,maximum,flags).
        fn maps(role: Role) -> Vec<(&'static str, [u32; 5])> {
            match role {
                Role::Identity => panic!("v1 fixture excludes identity"),
                Role::Count => vec![
                    ("COUNTS", [5, 8, 24, 8192, 0]),
                    ("ADMITTED", [6, 4, 8, 1, 0]),
                    ("LATC", [6, 4, 8, 16, 0]),
                    ("GEN", [2, 4, 4, 1, 0]),
                    ("TARGET", [2, 4, 8, 1, 0]),
                    ("WINDOW", [2, 4, 8, 2, 0]),
                    ("DROPFAIL", [6, 4, 8, 1, 0]),
                ],
                Role::Harvest => vec![
                    ("EVENTS", [27, 0, 0, 2097152, 0]),
                    ("PENDING_INIT", [1, 8, 8, 1024, 0]),
                    ("PENDING_QUERY", [1, 8, 16, 1024, 0]),
                    ("TERMD", [1, 8, 8, 1024, 0]),
                    ("GEN", [1, 8, 8, 1024, 0]),
                    ("LOSS", [5, 4, 8, 32, 0]),
                    ("QUERY_NEXT", [1, 16, 8, 4096, 0]),
                    ("TRUNC", [5, 4, 8, 64, 0]),
                    ("CALLS", [5, 4, 8, 64, 0]),
                    ("TRIP", [5, 8, 8, 128, 0]),
                    ("LGCALLS", [5, 4, 8, 64, 0]),
                    ("ALG_CLASS", [1, 8, 42, 1024, 0]),
                    ("TRIP_CLASS", [1, 8, 22, 64, 0]),
                    ("JUMPS", [3, 4, 4, 8, 0]),
                ],
                Role::Members => vec![
                    ("EVENTS", [27, 0, 0, 16777216, 0]),
                    ("BUCKET", [1, 4, 8, 4096, 0]),
                    ("GEN", [1, 8, 8, 1024, 0]),
                    ("LOSS", [5, 4, 8, 32, 0]),
                    ("TRUNC", [5, 4, 8, 64, 0]),
                    ("CALLS", [5, 4, 8, 64, 0]),
                    ("ALG_CLASS", [1, 8, 42, 1024, 0]),
                    ("SCAN", [9, 4, 40, 1024, 0]),
                    ("SEQ", [1, 4, 8, 4096, 0]),
                    ("BIRTH", [1, 4, 2, 4096, 0]),
                    ("RCOUNT", [1, 4, 8, 4096, 0]),
                    ("T_CACHE", [1, 8, 16, 1024, 0]),
                    ("CTRL", [2, 4, 24, 1, 0]),
                    ("ATTEMPT", [6, 4, 8, 1, 0]),
                    ("TRUNC_SEQ", [5, 4, 8, 64, 0]),
                ],
            }
        }
        fn bpf(role: Role) -> Vec<u8> {
            bpf_variant(role, None, false)
        }
        fn bpf_variant(role: Role, extra: Option<Section>, callback: bool) -> Vec<u8> {
            let maps = maps(role);
            let mut roots: Vec<(String, bool)> = match role {
                Role::Identity => panic!("v1 fixture excludes identity"),
                Role::Count => vec![("count_entry".into(), false)],
                Role::Harvest => vec![
                    ("init_entry".into(), false),
                    ("init_return".into(), true),
                    ("query_entry".into(), false),
                    ("query_return".into(), true),
                    ("trip_count".into(), false),
                    ("trip_str0".into(), false),
                    ("trip_str1".into(), false),
                ],
                Role::Members => vec![("member_entry".into(), false)],
            };
            if role == Role::Harvest {
                for i in 0..8 {
                    roots.push((format!("c{i}"), true));
                }
            }
            if role == Role::Members {
                for i in 0..512 {
                    roots.push((format!("member_{i:03}"), true));
                }
            }
            let mut strings = vec![0];
            let mut symbols = vec![0; 24];
            let mut defs = vec![];
            let mut up = vec![];
            let mut ret = vec![];
            let mut rel = vec![];
            for (name, dims) in &maps {
                let nameoff = strings.len();
                strings.extend(name.as_bytes());
                strings.push(0);
                let at = symbols.len();
                symbols.resize(at + 24, 0);
                w32(&mut symbols, at, nameoff as u32);
                symbols[at + 4] = 0x11;
                w16(&mut symbols, at + 6, 3);
                w64(&mut symbols, at + 8, defs.len() as u64);
                w64(&mut symbols, at + 16, 28);
                for d in dims.iter().copied().chain([0, 0]) {
                    defs.extend(d.to_le_bytes());
                }
            }
            for (name, is_return) in roots {
                let code = if is_return { &mut ret } else { &mut up };
                let offset = code.len();
                if role == Role::Count {
                    for i in 0..7 {
                        let pos = code.len();
                        code.extend([0x18, 1, 0, 0, 0, 0, 0, 0]);
                        code.extend([0; 8]);
                        rel.extend((pos as u64).to_le_bytes());
                        rel.extend((((i + 1) as u64) << 32 | 1).to_le_bytes());
                    }
                }
                if callback {
                    code.extend([0x18, 1, 0, 0, 0, 0, 0, 0]);
                    code.extend([0; 8]);
                    rel.extend((112u64).to_le_bytes());
                    rel.extend(((9u64 << 32) | 1).to_le_bytes());
                }
                code.extend([0x95, 0, 0, 0, 0, 0, 0, 0]);
                let nameoff = strings.len();
                strings.extend(name.as_bytes());
                strings.push(0);
                let at = symbols.len();
                symbols.resize(at + 24, 0);
                w32(&mut symbols, at, nameoff as u32);
                symbols[at + 4] = 0x12;
                w16(&mut symbols, at + 6, if is_return { 5 } else { 4 });
                w64(&mut symbols, at + 8, offset as u64);
                w64(&mut symbols, at + 16, (code.len() - offset) as u64);
            }
            if callback {
                let off = strings.len();
                strings.extend(b"callback\0");
                let at = symbols.len();
                symbols.resize(at + 24, 0);
                w32(&mut symbols, at, off as u32);
                symbols[at + 4] = 0x12;
                w16(&mut symbols, at + 6, 7);
                w64(&mut symbols, at + 16, 8);
            }
            let mut sections = vec![
                (".strtab", 3, 0, strings, 0, 0, 0),
                (".symtab", 2, 0, symbols, 1, 1, 24),
                ("maps", 1, 0, defs, 0, 0, 0),
                ("uprobe", 1, 6, up, 0, 0, 0),
                (
                    "uretprobe",
                    1,
                    if role == Role::Count { 0 } else { 6 },
                    ret,
                    0,
                    0,
                    0,
                ),
                (".reluprobe", 9, 0, rel, 2, 4, 16),
            ];
            if callback {
                sections.push((".text", 1, 6, vec![0x95, 0, 0, 0, 0, 0, 0, 0], 0, 0, 0));
            }
            if let Some(extra) = extra {
                sections.push(extra);
            }
            image(247, 1, sections, 0).0
        }
        fn triple() -> BTreeMap<Role, RetainedBinary> {
            [Role::Harvest, Role::Count, Role::Members]
                .into_iter()
                .map(|r| (r, retained_bytes(bpf(r))))
                .collect()
        }
        #[test]
        fn triple_real_prepare_positive() {
            let roles = triple();
            validate_triple(&roles).unwrap();
            let (_f, sealed) = super::layout_fixture("gnu");
            let c = make_contract(&sealed.inputs, &roles).unwrap();
            assert_eq!(c.roles.len(), 3);
            assert_eq!(c.roles[2].bytes, roles[&Role::Members].length());
            assert_eq!(
                (c.wire_abi, c.loader_contract_sha256),
                crate::package::resolve::compiled_loader_identity(
                    crate::package::records::RecordVersion::V1
                )
                .unwrap()
            );
            for role in [Role::Harvest, Role::Count, Role::Members] {
                let mut pair = triple();
                pair.remove(&role);
                assert!(validate_triple(&pair).is_err());
            }
        }
        #[test]
        fn count_full_chain_negatives() {
            let valid = bpf(Role::Count);
            crate::discovery::onboard::check_installed_role_compatible(Role::Count, &valid)
                .unwrap();
            let parsed = goblin::elf::Elf::parse(&valid).unwrap();
            let up = parsed
                .section_headers
                .iter()
                .find(|s| parsed.shdr_strtab.get_at(s.sh_name) == Some("uprobe"))
                .unwrap()
                .sh_offset as usize;
            let mut tail = valid.clone();
            tail[up + 112] = 0x85;
            w32(&mut tail, up + 116, 12);
            assert!(
                crate::loader::prepare(
                    &tail,
                    &crate::loader::COUNT_MAPS,
                    &crate::loader::COUNT_PROGS
                )
                .is_ok()
            );
            let mut roles = triple();
            roles.insert(Role::Count, retained_bytes(tail));
            assert!(validate_triple(&roles).is_err());
            for mutation in 0..5 {
                let mut p = crate::loader::prepare(
                    &valid,
                    &crate::loader::COUNT_MAPS,
                    &crate::loader::COUNT_PROGS,
                )
                .unwrap();
                match mutation {
                    0 => p.progs[0].subprogs[0].is_callback = true,
                    1 => p.progs[0].subprogs[0].insn_off = 1,
                    2 => p.progs[0].map_fixups[0].map = "UNREVIEWED".into(),
                    3 => p.progs[0].map_fixups[0].insn_off = 1,
                    _ => {
                        p.progs[0].insns[1] = 0x40;
                    }
                }
                assert!(crate::discovery::onboard::validate_installed_count_prepared(&p).is_err());
            }
            let mut renamed = valid.clone();
            let at = renamed
                .windows(12)
                .position(|b| b == b"count_entry\0")
                .unwrap();
            renamed[at] = b'x';
            let mut roles = triple();
            roles.insert(Role::Count, retained_bytes(renamed));
            assert!(validate_triple(&roles).is_err());
        }
        #[test]
        fn host_section_unique_canonical_ranges() {
            let (b, spans, sh) = host(true, true);
            assert_eq!(host_contract_bytes(&b).unwrap(), contract());
            assert_eq!(
                extract_host_contract(&b).unwrap(),
                crate::package::records::AdmittedContract::V1(
                    parse_canonical::<BundleContract>(&contract()).unwrap()
                )
            );
            let mut bad = b.clone();
            w64(&mut bad, sh + 64 + 24, u64::MAX);
            assert!(extract_host_contract(&bad).is_err());
            let mut bad = b.clone();
            bad[spans[".osslscope.bundle_contract"].0] = b' ';
            assert!(extract_host_contract(&bad).is_err());
            let mut bad = b.clone();
            w32(&mut bad, sh + 128, 1);
            assert!(extract_host_contract(&bad).is_err());
            let mut bad = b.clone();
            w64(
                &mut bad,
                sh + 128 + 24,
                spans[".osslscope.bundle_contract"].0 as u64,
            );
            assert!(extract_host_contract(&bad).is_err());
            assert!(extract_host_contract(&b[..b.len() - 1]).is_err());
            assert!(extract_host_contract(&host(false, false).0).is_err());
            for off in [4, 5, 18, 16] {
                let mut bad = b.clone();
                bad[off] = 0;
                assert!(extract_host_contract(&bad).is_err());
            }
        }
        #[test]
        fn abi_every_cell_and_provider() {
            let (b, spans, sh) = host(true, true);
            validate_host_abi(&b, &abi(true)).unwrap();
            validate_host_abi(&host(false, true).0, &abi(false)).unwrap();
            let mut a = abi(true);
            a.cells.push(AbiCell {
                name: "second".into(),
                interpreter: AbiInterpreter::Dynamic {
                    path: "/wrong/loader".into(),
                },
                needed: vec!["libc.so.6".into()],
                symbol_versions: vec!["libc.so.6@GLIBC_2.17".into()],
            });
            assert!(validate_host_abi(&b, &a).is_err());
            for mutation in 0..4 {
                let mut a = abi(true);
                match mutation {
                    0 => a.cells[0].needed.clear(),
                    1 => a.cells[0].symbol_versions = vec!["libother.so@GLIBC_2.17".into()],
                    2 => a.cells[0].symbol_versions = vec!["libc.so.6@GLIBC_2.9".into()],
                    _ => a.cells[0].interpreter = AbiInterpreter::Static,
                };
                assert!(validate_host_abi(&b, &a).is_err());
            }
            for tag in [15u64, 29, 0x7ffffffd, 0x7fffffff] {
                let mut bad = b.clone();
                w64(&mut bad, spans[".dynamic"].0 + 32, tag);
                assert!(validate_host_abi(&bad, &abi(true)).is_err());
            }
            let mut bad = b.clone();
            w32(&mut bad, spans[".gnu.version_r"].0 + 8, u32::MAX);
            assert!(validate_host_abi(&bad, &abi(true)).is_err());
            let mut bad = b.clone();
            w64(&mut bad, sh + 4 * 64 + 24, 0);
            assert!(validate_host_abi(&bad, &abi(true)).is_err());
            assert!(validate_host_abi(&b, &abi(false)).is_err());
            assert!(validate_host_abi(&host(false, true).0, &abi(true)).is_err());
        }
        #[test]
        fn genuine_callback_and_generic_policy_refusals() {
            let extra = bpf_variant(
                Role::Count,
                Some(("extra_exec", 1, 6, vec![0x95, 0, 0, 0, 0, 0, 0, 0], 0, 0, 0)),
                false,
            );
            assert!(
                crate::loader::prepare(
                    &extra,
                    &crate::loader::COUNT_MAPS,
                    &crate::loader::COUNT_PROGS
                )
                .is_ok()
            );
            let mut roles = triple();
            roles.insert(Role::Count, retained_bytes(extra));
            assert!(validate_triple(&roles).is_err());
            let callback = bpf_variant(Role::Count, None, true);
            let p = crate::loader::prepare(
                &callback,
                &crate::loader::COUNT_MAPS,
                &crate::loader::COUNT_PROGS,
            )
            .unwrap();
            assert!(p.progs[0].subprogs.iter().any(|s| s.is_callback));
            assert!(
                p.progs[0]
                    .insns
                    .chunks_exact(8)
                    .any(|i| i[0] == 0x18 && i[1] >> 4 == 4)
            );
            let mut roles = triple();
            roles.insert(Role::Count, retained_bytes(callback));
            assert!(validate_triple(&roles).is_err());
            for role in [Role::Harvest, Role::Count, Role::Members] {
                for license in [b"GPL\0".as_slice(), b"Dual BSD/GPL\0".as_slice()] {
                    let mut roles = triple();
                    roles.insert(
                        role,
                        retained_bytes(bpf_variant(
                            role,
                            Some((".license", 1, 0, license.to_vec(), 0, 0, 0)),
                            false,
                        )),
                    );
                    validate_triple(&roles).unwrap();
                }
                for extra in [
                    (".license", 1, 0, b"MIT\0".to_vec(), 0, 0, 0),
                    (".BTF", 1, 0, vec![0; 8], 0, 0, 0),
                    (".BTF.ext", 1, 0, vec![0; 8], 0, 0, 0),
                ] {
                    let mut roles = triple();
                    roles.insert(role, retained_bytes(bpf_variant(role, Some(extra), false)));
                    assert!(validate_triple(&roles).is_err());
                }
                let mut bytes = bpf(role);
                let elf = goblin::elf::Elf::parse(&bytes).unwrap();
                let map = elf
                    .section_headers
                    .iter()
                    .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some("maps"))
                    .unwrap()
                    .sh_offset as usize;
                w32(&mut bytes, map + 12, 1);
                let mut roles = triple();
                roles.insert(role, retained_bytes(bytes));
                assert!(validate_triple(&roles).is_err());
            }
        }
        #[test]
        fn artifact_requests_derive_source_version_and_fixed_roles() {
            for profile in ["gnu", "musl"] {
                let (_f, sealed) = super::layout_fixture(profile);
                let paths = BuildPaths {
                    work_root: "/build".into(),
                    host_target: "/build/target/host".into(),
                    bpf_target: "/build/target/bpf".into(),
                    cache_root: "/build/cache".into(),
                    output_root: "/output".into(),
                };
                let b = ArtifactRequest::derive(&sealed, Phase::Bpf, &paths).unwrap();
                assert_eq!(
                    (
                        b.package.as_str(),
                        b.version.as_str(),
                        b.target.as_str(),
                        b.bins.len()
                    ),
                    ("osslscope-ebpf", "0.0.0", "bpfel-unknown-none", 3)
                );
                let b = ArtifactRequest::derive(&sealed, Phase::Bootstrap, &paths).unwrap();
                assert_eq!(
                    (b.target.as_str(), b.tree, b.bins),
                    (
                        "x86_64-unknown-linux-gnu",
                        PathBuf::from("/build/target/bootstrap"),
                        BTreeSet::from(["osslscope-package".into()])
                    )
                );
                let h = ArtifactRequest::derive(&sealed, Phase::Host, &paths).unwrap();
                assert_eq!(h.version, sealed.inputs.product_version);
                assert_eq!(
                    h.target,
                    if profile == "gnu" {
                        "x86_64-unknown-linux-gnu"
                    } else {
                        "x86_64-unknown-linux-musl"
                    }
                );
                assert!(ArtifactRequest::derive(&sealed, Phase::Native, &paths).is_err());
            }
        }
        fn note(name: &[u8; 4], kind: u32) -> Vec<u8> {
            let mut b = vec![0; 24];
            w32(&mut b, 0, 4);
            w32(&mut b, 4, 8);
            w32(&mut b, 8, kind);
            b[12..16].copy_from_slice(name);
            b[16..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            b
        }
        fn noted_host(duplicate: bool) -> Vec<u8> {
            let (mut b, spans, _) = image(
                62,
                3,
                vec![
                    (".osslscope.bundle_contract", 1, 2, contract(), 0, 0, 0),
                    (".note.gnu.build-id", 7, 2, note(b"GNU\0", 3), 0, 0, 0),
                    (
                        ".note.other",
                        7,
                        2,
                        if duplicate {
                            note(b"GNU\0", 3)
                        } else {
                            note(b"XYZ\0", 1)
                        },
                        0,
                        0,
                        0,
                    ),
                ],
                2,
            );
            let len = b.len() as u64;
            w32(&mut b, 64, 1);
            w64(&mut b, 80, 0x400000);
            w64(&mut b, 96, len);
            w64(&mut b, 104, len);
            w64(&mut b, 112, 0x1000);
            w32(&mut b, 120, 4);
            let off = spans[".note.gnu.build-id"].0 as u64;
            w64(&mut b, 128, off);
            w64(&mut b, 136, 0x400000 + off);
            w64(&mut b, 152, 48);
            w64(&mut b, 160, 48);
            w64(&mut b, 168, 4);
            b
        }
        #[test]
        fn malformed_note_owner() {
            let mut b = noted_host(false);
            let off = u64::from_le_bytes(b[128..136].try_into().unwrap()) as usize;
            b[off + 15] = b'x';
            assert!(extract_host_contract(&b).is_err());
        }
        #[test]
        fn reserved_external_version_index() {
            let (mut b, spans, _) = host(true, true);
            w16(&mut b, spans[".gnu.version_r"].0 + 22, 0);
            assert!(validate_host_abi(&b, &abi(true)).is_err());
        }
        #[test]
        fn host_notes_exact_identity_and_shared_views() {
            let b = noted_host(false);
            assert_eq!(
                host_elf(&b).unwrap().build_id,
                Some(vec![1, 2, 3, 4, 5, 6, 7, 8])
            );
            assert_eq!(host_elf(&host(false, true).0).unwrap().build_id, None);
            assert!(extract_host_contract(&noted_host(true)).is_err());
            let mut truncated = b.clone();
            let off = u64::from_le_bytes(b[128..136].try_into().unwrap()) as usize;
            w32(&mut truncated, off + 4, u32::MAX);
            assert!(extract_host_contract(&truncated).is_err());
            let mut partial = b;
            w64(&mut partial, 128, (off + 4) as u64);
            assert!(extract_host_contract(&partial).is_err());
        }
        #[test]
        fn fixed_logical_cargo_paths_use_distinct_physical_custody() {
            let physical = root();
            let paths = BuildPaths {
                work_root: physical.clone(),
                host_target: physical.join("target/host"),
                bpf_target: physical.join("target/bpf"),
                cache_root: physical.join("cache"),
                output_root: physical.join("output"),
            };
            for profile in ["gnu", "musl"] {
                let (_f, sealed) = super::layout_fixture(profile);
                for (phase, logical, manifest, sources) in [
                    (
                        Phase::Bootstrap,
                        "/build/target/bootstrap",
                        "/build/source/Cargo.toml",
                        vec![(
                            "osslscope-package",
                            "/build/source/src/bin/osslscope-package.rs",
                        )],
                    ),
                    (
                        Phase::Bpf,
                        "/build/target/bpf",
                        "/build/source/crates/ebpf/Cargo.toml",
                        vec![
                            (
                                "osslscope-harvest",
                                "/build/source/crates/ebpf/src/bin/harvest.rs",
                            ),
                            (
                                "osslscope-count",
                                "/build/source/crates/ebpf/src/bin/count.rs",
                            ),
                            (
                                "osslscope-members",
                                "/build/source/crates/ebpf/src/bin/members.rs",
                            ),
                        ],
                    ),
                    (
                        Phase::Host,
                        "/build/target/host",
                        "/build/source/Cargo.toml",
                        vec![("osslscope", "/build/source/src/main.rs")],
                    ),
                ] {
                    let req = ArtifactRequest::derive(&sealed, phase, &paths).unwrap();
                    let mut files = BTreeMap::new();
                    let mut rows = vec![];
                    for (name, source) in sources {
                        let rel = format!("{}/release/{name}", req.target);
                        let path = req.tree.join(&rel);
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        fs::write(&path, name).unwrap();
                        files.insert(
                            rel.clone(),
                            ArtifactIdentity::of(&fs::metadata(path).unwrap()),
                        );
                        let source_id = if phase == Phase::Bpf {
                            "path+file:///build/source/crates/ebpf"
                        } else {
                            "path+file:///build/source"
                        };
                        rows.push(json!({"reason":"compiler-artifact","package_id":format!("{source_id}#{}@{}",req.package,req.version),"manifest_path":manifest,"target":{"name":name,"src_path":source,"kind":["bin"],"crate_types":["bin"]},"profile":{"test":false},"fresh":false,"executable":format!("{logical}/{rel}"),"filenames":[format!("{logical}/{rel}")]}));
                    }
                    rows.push(json!({"reason":"build-finished","success":true}));
                    let log_of = |rows: &[serde_json::Value]| {
                        rows.iter()
                            .flat_map(|row| {
                                let mut b = serde_json::to_vec(row).unwrap();
                                b.push(b'\n');
                                b
                            })
                            .collect::<Vec<_>>()
                    };
                    let log = log_of(&rows);
                    let mut ctx = CurrentArtifactSet {
                        tree: req.tree.clone(),
                        directory: fs::File::open(&req.tree).unwrap(),
                        files,
                        cargo_sha256: sha256(&log),
                        completion: std::process::ExitStatus::from_raw(0),
                    };
                    assert_eq!(
                        retain_artifacts(&log, &req, &ctx).unwrap().len(),
                        req.bins.len(),
                        "{phase:?}"
                    );
                    for mutation in 0..5 {
                        let mut wrong = rows.clone();
                        let name = wrong[0]["target"]["name"].as_str().unwrap().to_owned();
                        match mutation {
                            0 => {
                                let p = req.tree.join(format!("{}/release/{name}", req.target));
                                wrong[0]["executable"] = json!(p);
                                wrong[0]["filenames"] = json!([p]);
                            }
                            1 => {
                                let p =
                                    format!("/build/target/foreign/{}/release/{name}", req.target);
                                wrong[0]["executable"] = json!(p);
                                wrong[0]["filenames"] = json!([p]);
                            }
                            2 => wrong[0]["manifest_path"] = json!(physical.join("Cargo.toml")),
                            3 => {
                                wrong[0]["target"]["src_path"] = json!(physical.join("src/main.rs"))
                            }
                            _ => {
                                let p = format!("{logical}//{}/release/{name}", req.target);
                                wrong[0]["executable"] = json!(p);
                                wrong[0]["filenames"] = json!([p]);
                            }
                        }
                        let wrong = log_of(&wrong);
                        ctx.cargo_sha256 = sha256(&wrong);
                        assert!(
                            retain_artifacts(&wrong, &req, &ctx).is_err(),
                            "{phase:?} mutation {mutation}"
                        );
                    }
                }
            }
            fs::remove_dir_all(physical).unwrap();
        }
        fn dynamic_tables(
            hash_mode: u8,
            plt_rela: bool,
        ) -> (Vec<u8>, BTreeMap<String, (usize, usize)>, usize) {
            let mut symbols = vec![0; 48];
            w32(&mut symbols, 24, 1);
            symbols[28] = 0x12;
            let mut sections = vec![
                (".osslscope.bundle_contract", 1, 2, contract(), 0, 0, 0),
                (
                    ".interp",
                    1,
                    2,
                    b"/lib64/ld-linux-x86-64.so.2\0".to_vec(),
                    0,
                    0,
                    0,
                ),
                (".dynstr", 3, 2, b"\0foo\0".to_vec(), 0, 0, 0),
                (".dynsym", 11, 2, symbols, 3, 1, 24),
            ];
            if hash_mode != 1 {
                let mut b = vec![0; 20];
                for (i, v) in [1, 2, 1, 0, 0].into_iter().enumerate() {
                    w32(&mut b, i * 4, v);
                }
                sections.push((".hash", 5, 2, b, 4, 0, 4));
            }
            if hash_mode != 0 {
                let mut b = vec![0; 32];
                for (i, v) in [1, 1, 1, 5].into_iter().enumerate() {
                    w32(&mut b, i * 4, v);
                }
                w64(&mut b, 16, 0x10000200);
                w32(&mut b, 24, 1);
                w32(&mut b, 28, 0x0b887389);
                sections.push((".gnu.hash", 0x6ffffff6, 2, b, 4, 0, 0));
            }
            for (name, kind, width) in [
                (".rela.dyn", 4, 24),
                (".rel.dyn", 9, 16),
                (".rela.plt", 4, 24),
                (".rel.plt", 9, 16),
            ] {
                let mut b = vec![0; width];
                w64(&mut b, 8, (1u64 << 32) | 7);
                sections.push((name, kind, 2, b, 4, 0, width as u64));
            }
            for (name, kind) in [
                (".init_array", 14),
                (".fini_array", 15),
                (".preinit_array", 16),
            ] {
                sections.push((name, kind, 3, vec![0; 8], 0, 0, 8));
            }
            let tag_count = if hash_mode == 2 { 22 } else { 21 };
            sections.push((".dynamic", 6, 3, vec![0; tag_count * 16], 3, 0, 16));
            let (mut b, spans, sh) = image(62, 3, sections, 3);
            let len = b.len() as u64;
            w32(&mut b, 64, 1);
            w32(&mut b, 68, 5);
            w64(&mut b, 80, 0x400000);
            w64(&mut b, 96, len);
            w64(&mut b, 104, len);
            w64(&mut b, 112, 0x1000);
            for (i, (kind, name)) in [(3, ".interp"), (2, ".dynamic")].iter().enumerate() {
                let at = 120 + i * 56;
                let (off, len) = spans[*name];
                w32(&mut b, at, *kind);
                w64(&mut b, at + 8, off as u64);
                w64(&mut b, at + 16, 0x400000 + off as u64);
                w64(&mut b, at + 32, len as u64);
                w64(&mut b, at + 40, len as u64);
                w64(&mut b, at + 48, 8);
            }
            let mut tags = vec![
                (5, 0x400000 + spans[".dynstr"].0 as u64),
                (10, 5),
                (6, 0x400000 + spans[".dynsym"].0 as u64),
                (11, 24),
            ];
            for (tag, name) in [(4, ".hash"), (0x6ffffef5, ".gnu.hash")] {
                if let Some((off, _)) = spans.get(name) {
                    tags.push((tag, 0x400000 + *off as u64));
                }
            }
            for (tag, size, entry, name, width) in
                [(7, 8, 9, ".rela.dyn", 24), (17, 18, 19, ".rel.dyn", 16)]
            {
                tags.extend([
                    (tag, 0x400000 + spans[name].0 as u64),
                    (size, width),
                    (entry, width),
                ]);
            }
            let plt = if plt_rela { ".rela.plt" } else { ".rel.plt" };
            tags.extend([
                (23, 0x400000 + spans[plt].0 as u64),
                (2, spans[plt].1 as u64),
                (20, if plt_rela { 7 } else { 17 }),
            ]);
            for (tag, size, name) in [
                (25, 27, ".init_array"),
                (26, 28, ".fini_array"),
                (32, 33, ".preinit_array"),
            ] {
                tags.extend([(tag, 0x400000 + spans[name].0 as u64), (size, 8)]);
            }
            tags.push((0, 0));
            assert_eq!(tags.len(), tag_count);
            let d = spans[".dynamic"].0;
            for (i, (tag, value)) in tags.into_iter().enumerate() {
                w64(&mut b, d + i * 16, tag);
                w64(&mut b, d + i * 16 + 8, value);
            }
            (b, spans, sh)
        }
        fn tag_value(b: &[u8], spans: &BTreeMap<String, (usize, usize)>, tag: u64) -> usize {
            let (at, n) = spans[".dynamic"];
            (at..at + n)
                .step_by(16)
                .find(|i| u64::from_le_bytes(b[*i..*i + 8].try_into().unwrap()) == tag)
                .unwrap()
                + 8
        }
        #[test]
        fn complete_dynamic_hash_and_pointer_tables() {
            let mut accepted = vec![];
            for hash_mode in 0..3 {
                for rela in [false, true] {
                    let (b, spans, sh) = dynamic_tables(hash_mode, rela);
                    extract_host_contract(&b).unwrap();
                    for (tag, name) in [(4, ".hash"), (0x6ffffef5, ".gnu.hash")] {
                        if let Some((off, _)) = spans.get(name) {
                            for mutation in 0..9 {
                                let mut bad = b.clone();
                                match mutation {
                                    0 => {
                                        let at = tag_value(&bad, &spans, tag);
                                        w64(&mut bad, at, 0);
                                    }
                                    1 => {
                                        let at = tag_value(&bad, &spans, tag);
                                        w64(&mut bad, at, 0x400000 + b.len() as u64 - 1);
                                    }
                                    2 => w32(&mut bad, *off, u32::MAX),
                                    3 => {
                                        let bucket = if tag == 4 { *off + 8 } else { *off + 24 };
                                        w32(&mut bad, bucket, 2);
                                    }
                                    5 => w32(&mut bad, *off + 4, 3),
                                    6 => {
                                        if tag == 4 {
                                            w32(&mut bad, *off + 16, 1);
                                        } else {
                                            w32(&mut bad, *off + 28, 0x0b887388);
                                        }
                                    }
                                    7 => {
                                        if tag == 4 {
                                            w32(&mut bad, *off, 0);
                                        } else {
                                            w32(&mut bad, *off + 8, 0);
                                        }
                                    }
                                    8 => {
                                        if tag == 4 {
                                            w32(&mut bad, *off + 4, u32::MAX);
                                        } else {
                                            w32(&mut bad, *off + 8, u32::MAX);
                                        }
                                    }
                                    _ => {
                                        let sec =
                                            (1..u16::from_le_bytes(b[60..62].try_into().unwrap())
                                                as usize)
                                                .find(|i| {
                                                    u64::from_le_bytes(
                                                        b[sh + i * 64 + 24..sh + i * 64 + 32]
                                                            .try_into()
                                                            .unwrap(),
                                                    ) == *off as u64
                                                })
                                                .unwrap();
                                        w32(&mut bad, sh + sec * 64 + 40, 3);
                                    }
                                }
                                if extract_host_contract(&bad).is_ok() {
                                    accepted.push(format!(
                                        "hash{tag:x} mode{hash_mode} rela{rela} mutation{mutation}"
                                    ));
                                }
                            }
                        }
                    }
                    for mutation in 0..8 {
                        let mut bad = b.clone();
                        let (tag, value) = match mutation {
                            0 => (20, 8),
                            1 => (2, 1),
                            2 => (23, 0x400000 + spans[".dynstr"].0 as u64),
                            3 => (27, 7),
                            4 => (28, 7),
                            5 => (33, 7),
                            6 => (25, 0x400000 + spans[".dynstr"].0 as u64),
                            _ => (7, 0x400000 + spans[".init_array"].0 as u64),
                        };
                        let at = tag_value(&bad, &spans, tag);
                        w64(&mut bad, at, value);
                        if extract_host_contract(&bad).is_ok() {
                            accepted.push(format!(
                                "pointer mode{hash_mode} rela{rela} mutation{mutation}"
                            ));
                        }
                    }
                }
            }
            assert!(
                accepted.is_empty(),
                "accepted malformed metadata: {accepted:?}"
            );
        }
        #[test]
        fn symbol_seeded_dynamic_strings_require_exact_mapped_view() {
            fn fixture(other_view: bool, other: &[u8]) -> Vec<u8> {
                let (mut bytes, spans, sh) = image(
                    62,
                    3,
                    vec![
                        (".osslscope.bundle_contract", 1, 2, contract(), 0, 0, 0),
                        (
                            ".interp",
                            1,
                            2,
                            b"/lib64/ld-linux-x86-64.so.2\0".to_vec(),
                            0,
                            0,
                            0,
                        ),
                        (".dynstr", 3, 0, b"\0liba.so\0".to_vec(), 0, 0, 0),
                        (".runtime_strings", 1, 2, other.to_vec(), 0, 0, 0),
                        // The real symbol pass creates the linked string cache,
                        // including when the only symbol references empty offset0.
                        (".symtab", 2, 0, vec![0; 24], 3, 1, 24),
                        (".dynamic", 6, 3, vec![0; 64], 3, 0, 16),
                    ],
                    3,
                );
                let len = bytes.len() as u64;
                w32(&mut bytes, 64, 1);
                w32(&mut bytes, 68, 5);
                w64(&mut bytes, 80, 0x400000);
                w64(&mut bytes, 96, len);
                w64(&mut bytes, 104, len);
                w64(&mut bytes, 112, 0x1000);
                for (i, (kind, name)) in [(3, ".interp"), (2, ".dynamic")].iter().enumerate() {
                    let at = 120 + i * 56;
                    let (off, len) = spans[*name];
                    w32(&mut bytes, at, *kind);
                    w64(&mut bytes, at + 8, off as u64);
                    w64(&mut bytes, at + 16, 0x400000 + off as u64);
                    w64(&mut bytes, at + 32, len as u64);
                    w64(&mut bytes, at + 40, len as u64);
                    w64(&mut bytes, at + 48, 8);
                }
                let address = 0x400000
                    + spans[if other_view {
                        ".runtime_strings"
                    } else {
                        ".dynstr"
                    }]
                    .0 as u64;
                w64(&mut bytes, sh + 3 * 64 + 16, address);
                let d = spans[".dynamic"].0;
                for (i, (tag, value)) in [(5, address), (10, 9), (1, 1), (0, 0)]
                    .into_iter()
                    .enumerate()
                {
                    w64(&mut bytes, d + i * 16, tag);
                    w64(&mut bytes, d + i * 16 + 8, value);
                }
                bytes
            }
            let mut a = abi(true);
            a.cells[0].needed = vec!["liba.so".into()];
            a.cells[0].symbol_versions.clear();
            let mut b = abi(true);
            b.cells[0].needed = vec!["libb.so".into()];
            b.cells[0].symbol_versions.clear();
            let matching = fixture(false, b"\0libb.so\0");
            assert_eq!(host_elf(&matching).unwrap().needed, vec!["liba.so"]);
            validate_host_abi(&matching, &a).unwrap();
            assert!(validate_host_abi(&matching, &b).is_err());
            for other in [b"\0libb.so\0".as_slice(), b"\0liba.so\0".as_slice()] {
                let contradictory = fixture(true, other);
                assert_eq!(
                    [
                        host_elf(&contradictory).is_ok(),
                        validate_host_abi(&contradictory, &a).is_ok(),
                        validate_host_abi(&contradictory, &b).is_ok()
                    ],
                    [false; 3],
                    "section/mapped correspondence must precede cache reuse"
                );
            }
        }
        #[test]
        fn bounded_string_regions_repeated_offsets_and_overlapping_suffixes() {
            let mut bytes = vec![b'a'; 129];
            bytes.push(0);
            let mut strings = ElfStrings::new(&bytes);
            assert_eq!(strings.lookup(0).unwrap().value.len(), 129);
            let first_work = strings.scanned_bytes;
            for _ in 0..4 {
                for offset in 0..129 {
                    assert_eq!(
                        strings.lookup(offset).unwrap().value.len(),
                        129 - offset as usize
                    );
                }
            }
            assert_eq!(strings.scanned_bytes, first_work);
            assert!(first_work <= bytes.len() * 3);
            assert_eq!(strings.regions.len(), 1);
            let mut short = vec![b'b'; 64];
            short.push(0);
            let mut strings = ElfStrings::new(&short);
            strings.lookup(0).unwrap();
            strings.lookup(0).unwrap();
            assert!(strings.regions.is_empty());
            assert!(strings.scanned_bytes <= 2 * (3 * 64 + 1));
            let mut long = vec![b'c'; 65];
            long.push(0);
            let mut strings = ElfStrings::new(&long);
            let name = strings.atom(0).unwrap();
            let work = strings.scanned_bytes;
            for _ in 0..32 {
                assert_eq!(strings.atom(0).unwrap().key, name.key);
            }
            assert_eq!(strings.scanned_bytes, work);
            assert_eq!(strings.long_ids.len(), 1);
            assert_eq!(strings.interns.len(), 1);
            assert!(strings.lookup(long.len() as u64).is_err());
            assert!(strings.lookup(u64::MAX).is_err());
            assert!(ElfStrings::new(b"unterminated").lookup(0).is_err());
        }
        #[test]
        fn string_suffix_utf8_atom_and_content_identity_semantics() {
            let mut strings = ElfStrings::new(b"\0\xff\xc3\xa9ok\0");
            assert_eq!(strings.lookup(2).unwrap().value, "éok");
            assert_eq!(strings.lookup(4).unwrap().value, "ok");
            assert!(strings.lookup(1).is_err());
            assert!(strings.lookup(3).is_err());
            assert_eq!(strings.lookup(0).unwrap().value, "");
            assert!(strings.atom(0).is_err());
            let mut bytes = vec![0];
            let a = bytes.len();
            bytes.extend(b"liba.so\0");
            let prefix = bytes.len();
            bytes.extend(b"prefixliba.so\0");
            let duplicate = bytes.len();
            bytes.extend(b"liba.so\0");
            let mut strings = ElfStrings::new(&bytes);
            let a = strings.atom(a as u64).unwrap();
            let suffix = strings.atom((prefix + 6) as u64).unwrap();
            let duplicate = strings.atom(duplicate as u64).unwrap();
            assert_eq!(a.key, suffix.key);
            assert_eq!(a.key, duplicate.key);
            assert_ne!(strings.atom(prefix as u64).unwrap().key, a.key);
            let mut bytes = vec![0xff];
            bytes.extend([b'a'; 70]);
            bytes.extend(b"/valid\0");
            let mut strings = ElfStrings::new(&bytes);
            assert!(strings.atom(1).is_err());
            assert_eq!(strings.atom(72).unwrap().value, "valid");
            assert!(strings.lookup(0).is_err());
        }
        #[test]
        fn symbol_names_share_referenced_valid_suffixes() {
            let mut strings = vec![0, 0xff];
            strings.extend([b'x'; 129]);
            strings.push(0);
            let mut symbols = vec![0; 33 * 24];
            for i in 1..33 {
                w32(
                    &mut symbols,
                    i * 24,
                    if i % 2 == 0 { 2 } else { 2 + i as u32 },
                );
                symbols[i * 24 + 4] = 0x12;
            }
            let (mut bytes, _, _) = image(
                62,
                3,
                vec![
                    (".osslscope.bundle_contract", 1, 2, contract(), 0, 0, 0),
                    (".strtab", 3, 0, strings, 0, 0, 0),
                    (".symtab", 2, 0, symbols, 2, 1, 24),
                ],
                1,
            );
            let len = bytes.len() as u64;
            w32(&mut bytes, 64, 1);
            w32(&mut bytes, 68, 5);
            w64(&mut bytes, 80, 0x400000);
            w64(&mut bytes, 96, len);
            w64(&mut bytes, 104, len);
            w64(&mut bytes, 112, 0x1000);
            extract_host_contract(&bytes).unwrap();
        }
        #[test]
        fn needed_order_and_exact_duplicate_names_survive_indexing() {
            let bytes = host_needed(true, true, &[11, 1]).0;
            let elf = host_elf(&bytes).unwrap();
            assert_eq!(elf.needed, vec!["GLIBC_2.17", "libc.so.6"]);
            assert_eq!(elf.versions, vec![("libc.so.6", "GLIBC_2.17")]);
            assert!(host_elf(&host_needed(true, true, &[1, 1]).0).is_err());
            let bytes = host_needed(true, true, &[1, 11]).0;
            let elf = host_elf(&bytes).unwrap();
            assert_eq!(elf.needed, vec!["libc.so.6", "GLIBC_2.17"]);
        }
        fn bloom_table(words: u32, shift: u32) -> Vec<u8> {
            let mut bytes = vec![0; 16 + words as usize * 8 + 8];
            for (i, value) in [1, 1, words, shift].into_iter().enumerate() {
                w32(&mut bytes, i * 4, value);
            }
            w32(&mut bytes, 16 + words as usize * 8, 1);
            w32(&mut bytes, 20 + words as usize * 8, 0x0b887389);
            bytes
        }
        #[test]
        fn gnu_bloom_geometry_and_hash_shift_width() {
            for words in [1, 2, 4] {
                for shift in [0, 5, 31] {
                    validate_gnu_hash(&bloom_table(words, shift), 2).unwrap();
                }
            }
            for (words, shift) in [(3, 5), (2, 32), (2, u32::MAX)] {
                assert!(
                    validate_gnu_hash(&bloom_table(words, shift), 2).is_err(),
                    "words={words} shift={shift}"
                );
            }
        }
        #[test]
        fn admitted_musl_static_evidence_uses_supported_profile_literal() {
            let fixture = abi(false);
            assert_eq!(fixture.host_profile.abi_profile, "linux-x86_64-musl");
            let mut recipe = super::recipe("musl");
            assert_eq!(
                recipe.host_profile.abi_profile,
                fixture.host_profile.abi_profile
            );
            recipe.required_cells = vec!["one".into()];
            let bytes=source::json_bytes(&json!({"schema":"osslscope-abi-evidence-v1","host_profile":recipe.host_profile,"cells":[{"name":"one","interpreter":{"kind":"static"},"needed":[],"symbol_versions":[]}]})).unwrap();
            recipe.abi_evidence.bytes = bytes.len() as u64;
            recipe.abi_evidence.sha256 = sha256(&bytes);
            let admitted = source::verify_abi_evidence(&recipe, &bytes).unwrap();
            validate_host_abi(&host(false, true).0, &admitted).unwrap();
        }
        #[test]
        fn structural_work_and_compact_coverage_boundaries() {
            let mut spans = (0..256)
                .rev()
                .map(|i| (i * 8, i * 8 + 4))
                .collect::<Vec<_>>();
            disjoint_ranges(&mut spans).unwrap();
            assert_eq!(spans.len(), 256);
            let mut overlap = vec![(0, 4), (3, 8)];
            assert!(disjoint_ranges(&mut overlap).is_err());
            let groups =
                note_groups(vec![(0, 100), (0, 20), (20, 40), (40, 100), (100, 124)]).unwrap();
            assert_eq!(groups.len(), 2);
            assert_eq!(groups[0].boundaries, vec![0, 20, 40, 100]);
            assert!(note_groups(vec![(0, 100), (10, 60), (20, 70)]).is_err());
            let mut coverage = TableCoverage::new(129);
            assert_eq!(coverage.words.len(), 3);
            coverage.claim(0, 64).unwrap();
            coverage.claim(64, 64).unwrap();
            coverage.claim(128, 1).unwrap();
            assert!(coverage.claim(129, 1).is_err());
            assert!(coverage.claim(63, 2).is_err());
            coverage.zero_gaps(&[0; 129]).unwrap();
            let mut gaps = TableCoverage::new(129);
            gaps.claim(0, 16).unwrap();
            gaps.claim(64, 16).unwrap();
            let mut data = [0; 129];
            data[80] = 1;
            assert!(gaps.zero_gaps(&data).is_err());
            data[80] = 0;
            gaps.zero_gaps(&data).unwrap();
        }
        fn request(root: &Path) -> ArtifactRequest {
            ArtifactRequest {
                phase: Phase::Bpf,
                package: "osslscope-ebpf".into(),
                version: "0.0.0".into(),
                bins: ["osslscope-harvest", "osslscope-count", "osslscope-members"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                target: "bpfel-unknown-none".into(),
                tree: root.to_path_buf(),
            }
        }
        fn logs(_root: &Path) -> Vec<u8> {
            let mut data = vec![];
            for name in ["osslscope-harvest", "osslscope-count", "osslscope-members"] {
                let v = json!({"reason":"compiler-artifact","package_id":"path+file:///build/source/crates/ebpf#osslscope-ebpf@0.0.0","manifest_path":"/build/source/crates/ebpf/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":name,"src_path":format!("/build/source/crates/ebpf/src/bin/{}.rs",name.strip_prefix("osslscope-").unwrap()),"edition":"2021","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":[format!("/build/target/bpf/bpfel-unknown-none/release/{name}")],"executable":format!("/build/target/bpf/bpfel-unknown-none/release/{name}"),"fresh":false});
                data.extend(serde_json::to_vec(&v).unwrap());
                data.push(b'\n');
            }
            data.extend(b"{\"reason\":\"build-finished\",\"success\":true}\n");
            data
        }
        fn custody(root: &Path, log: &[u8]) -> CurrentArtifactSet {
            let dir = fs::File::open(root).unwrap();
            let mut files = BTreeMap::new();
            for name in ["osslscope-harvest", "osslscope-count", "osslscope-members"] {
                let rel = RelativePath::new(format!("bpfel-unknown-none/release/{name}")).unwrap();
                files.insert(
                    rel.as_str().to_owned(),
                    ArtifactIdentity::of(
                        &fs::metadata(root.join("bpfel-unknown-none/release").join(name)).unwrap(),
                    ),
                );
            }
            CurrentArtifactSet {
                tree: root.to_path_buf(),
                directory: dir,
                files,
                cargo_sha256: sha256(log),
                completion: std::process::ExitStatus::from_raw(0),
            }
        }
        fn root() -> PathBuf {
            let base = std::env::var_os("OSSL_PACKAGE_TEST_PRIVATE_DIR").unwrap();
            let root = PathBuf::from(base).join(format!(
                "retained-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join("bpfel-unknown-none/release")).unwrap();
            for name in ["osslscope-harvest", "osslscope-count", "osslscope-members"] {
                fs::write(
                    root.join("bpfel-unknown-none/release").join(name),
                    name.as_bytes(),
                )
                .unwrap();
            }
            root
        }
        #[test]
        fn unique_current_cargo_artifacts() {
            let root = root();
            let log = logs(&root);
            let current = custody(&root, &log);
            let req = request(&root);
            let r = retain_artifacts(&log, &req, &current).unwrap();
            assert_eq!(r.len(), 3);
            assert_eq!(r["osslscope-count"].bytes(), b"osslscope-count");
            let rows: Vec<serde_json::Value> = log
                .split(|b| *b == b'\n')
                .filter(|b| !b.is_empty())
                .map(|b| serde_json::from_slice(b).unwrap())
                .collect();
            for mutation in 0..13 {
                let mut rows = rows.clone();
                match mutation {
                    0 => {
                        rows.remove(0);
                    }
                    1 => {
                        rows.truncate(1);
                    }
                    2 => {
                        let row = rows[0].clone();
                        rows.insert(0, row);
                    }
                    3 => rows[0]["target"]["name"] = "fourth-bin".into(),
                    4 => {
                        rows[0]["package_id"] =
                            "path+file:///build/source/crates/ebpf#other@0.0.0".into()
                    }
                    5 => {
                        rows[0]["package_id"] =
                            "path+file:///build/source/crates/ebpf#osslscope-ebpf@9.0.0".into()
                    }
                    6 => rows[0]["target"]["kind"] = json!(["lib"]),
                    7 => rows[0]["executable"] = serde_json::Value::Null,
                    8 => rows[0]["fresh"] = true.into(),
                    9 => {
                        rows[0]["executable"] = root
                            .join("x86_64-unknown-linux-gnu/release/osslscope-harvest")
                            .to_string_lossy()
                            .as_ref()
                            .into()
                    }
                    10 => rows[0]["executable"] = "/outside/osslscope-harvest".into(),
                    11 => rows.last_mut().unwrap()["success"] = false.into(),
                    _ => rows[0]["target"]["crate_types"] = json!(["lib"]),
                }
                let log = rows
                    .iter()
                    .flat_map(|v| {
                        let mut b = serde_json::to_vec(v).unwrap();
                        b.push(b'\n');
                        b
                    })
                    .collect::<Vec<_>>();
                let mut current = custody(&root, &log);
                if mutation == 8 {
                    current.files.clear();
                }
                assert!(
                    retain_artifacts(&log, &req, &current).is_err(),
                    "mutation {mutation}"
                );
            }
            let mut failed = custody(&root, &log);
            failed.completion = std::process::ExitStatus::from_raw(256);
            assert!(retain_artifacts(&log, &req, &failed).is_err());
            let malformed = b"{bad}\n";
            let malformed_current = custody(&root, malformed);
            assert!(retain_artifacts(malformed, &req, &malformed_current).is_err());
            assert!(retain_artifacts(&vec![b' '; 1048577], &req, &current).is_err());
            let duplicate = log
                .windows(1)
                .enumerate()
                .find(|(_, b)| *b == b"{")
                .unwrap()
                .0;
            let mut dup = log.clone();
            dup.splice(
                duplicate + 1..duplicate + 1,
                b"\"reason\":\"compiler-artifact\",".iter().copied(),
            );
            let dup_current = custody(&root, &dup);
            assert!(retain_artifacts(&dup, &req, &dup_current).is_err());
            let mut preexisting = custody(&root, &log);
            preexisting.files.clear();
            assert!(retain_artifacts(&log, &req, &preexisting).is_err());
            let path = root.join("bpfel-unknown-none/release/osslscope-count");
            let alternate = root.join("alternate");
            fs::rename(&path, &alternate).unwrap();
            symlink(&alternate, &path).unwrap();
            assert!(retain_artifacts(&log, &req, &current).is_err());
            fs::remove_file(&path).unwrap();
            fs::hard_link(&alternate, &path).unwrap();
            assert!(retain_artifacts(&log, &req, &current).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn retained_bytes_survive_path_replacement() {
            let root = root();
            let log = logs(&root);
            let current = custody(&root, &log);
            let retained = retain_artifacts(&log, &request(&root), &current).unwrap();
            let old = &retained["osslscope-count"];
            let path = root.join("bpfel-unknown-none/release/osslscope-count");
            fs::rename(&path, root.join("old")).unwrap();
            fs::write(&path, b"replacement").unwrap();
            assert_eq!(old.bytes(), b"osslscope-count");
            assert_eq!(old.sha256(), sha256(b"osslscope-count"));
            assert_eq!(old.length(), 15);
            assert!(retain_artifacts(&log, &request(&root), &current).is_err());
            // Deterministic interleaving exercises the same snapshot reader, no race timing.
            let fd = fs::File::open(&path).unwrap();
            let identity = ArtifactIdentity::of(&fd.metadata().unwrap());
            struct MutatingReader<'a> {
                fd: &'a fs::File,
                path: &'a Path,
            }
            impl std::io::Read for MutatingReader<'_> {
                fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                    let n = std::io::Read::read(&mut self.fd, b)?;
                    fs::write(self.path, b"mutation!!!")?;
                    Ok(n)
                }
            }
            let result = snapshot_artifact(
                &fd,
                &identity,
                &mut MutatingReader {
                    fd: &fd,
                    path: &path,
                },
            );
            assert!(result.is_err());
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn bootstrap_gnu_without_descriptor() {
            let (_f, sealed) = super::layout_fixture("musl");
            let mut layout = verify_executor_assets(&sealed).unwrap();
            let hostdoc = json!({"schema":"osslscope-executor-host-v1","files":[{"path":"/lib/x86_64-linux-gnu/libc.so.6","sha256":sha256(b"libc"),"bytes":4,"mode":493},{"path":"/lib64/ld-linux-x86-64.so.2","sha256":sha256(b"ld"),"bytes":2,"mode":493},{"path":"/usr/bin/bwrap","sha256":sha256(b"bwrap"),"bytes":5,"mode":493},{"path":"/usr/bin/python3.11","sha256":sha256(b"python"),"bytes":6,"mode":493}],"links":[]});
            let key = layout
                .documents
                .iter()
                .find(|(_, v)| {
                    serde_json::from_slice::<serde_json::Value>(v).unwrap()["schema"]
                        == "osslscope-executor-host-v1"
                })
                .unwrap()
                .0
                .clone();
            layout
                .documents
                .insert(key, Arc::from(source::json_bytes(&hostdoc).unwrap()));
            inspect_bootstrap(&host(true, false).0, &layout).unwrap();
            assert!(inspect_bootstrap(&host(true, true).0, &layout).is_err());
            assert!(inspect_bootstrap(&host(false, false).0, &layout).is_err());
            let mut b = host(true, false).0;
            let at = b
                .windows(b"/lib64/ld-linux-x86-64.so.2\0".len())
                .position(|x| x == b"/lib64/ld-linux-x86-64.so.2\0")
                .unwrap();
            b[at + 7] = b'x';
            assert!(inspect_bootstrap(&b, &layout).is_err());
        }
    }
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
        let (wire, digest) = super::super::resolve::compiled_loader_identity(
            crate::package::records::RecordVersion::V1,
        )
        .unwrap();
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
