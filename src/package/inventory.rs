// SPDX-License-Identifier: GPL-3.0-or-later
//! Closed offline source, tool and legal inventories. Declared terms are not a grant of rights.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    PackageError,
    records::{
        BuildInputs, ContentEntry, Digest, LockIdentity, RelativePath, parse_canonical, sha256,
    },
    source::{
        BuildRecipe, MAX_ASSET_BYTES, RegistryArchiveLimits, ReleaseConfig, SealedSource,
        SourceAssets, SourceTree, check_input_path, closed, content, json_bytes, package_fields,
        read_regular, validate_source_archive, verify_entry, verify_registry_source,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ComponentSource {
    Path {
        manifest: RelativePath,
    },
    Registry {
        location: String,
        checksum: Digest,
        archive: ContentEntry,
        corresponding_source: ContentEntry,
    },
    Git {
        repository: String,
        revision: String,
        archive: ContentEntry,
    },
    Native {
        location: String,
        archive: ContentEntry,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentTerms {
    pub spdx: String,
    pub license_files: Vec<ContentEntry>,
    pub notice_files: Vec<ContentEntry>,
    pub source_availability: ContentEntry,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceComponent {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: ComponentSource,
    pub terms: ComponentTerms,
    pub dependencies: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyInventory {
    pub schema: String,
    pub locks: LockIdentity,
    pub components: Vec<SourceComponent>,
    pub host: Vec<String>,
    pub bpf: Vec<String>,
    pub tool_sources: Vec<String>,
    pub build_std: Vec<String>,
    pub linker_build: Vec<String>,
    pub runtime: Vec<String>,
    #[serde(skip)]
    pub(crate) root: PathBuf,
}

#[derive(Clone, Debug)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<Digest>,
    dependencies: Vec<String>,
}
// Cargo-generated lockfiles use this deliberately bounded TOML subset. Unsupported
// syntax refuses; it is never silently omitted from a closure.
fn lock_packages(bytes: &[u8]) -> Result<Vec<LockPackage>, PackageError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PackageError::invalid("non-UTF8 original Cargo lock"))?;
    let mut rows = Vec::new();
    let mut current = BTreeMap::<String, Value>::new();
    let mut active = false;
    let mut root_version = false;
    let mut lines = text.lines();
    fn finish(
        row: &mut BTreeMap<String, Value>,
        rows: &mut Vec<LockPackage>,
    ) -> Result<(), PackageError> {
        if row.is_empty() {
            return Err(PackageError::invalid("empty lock package row"));
        }
        let string = |name: &str| -> Result<String, PackageError> {
            row.get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| PackageError::invalid("missing lock package identity"))
        };
        let name = string("name")?;
        let version = string("version")?;
        let source = row
            .get("source")
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| PackageError::invalid("bad lock source"))
            })
            .transpose()?;
        let checksum = row
            .get("checksum")
            .map(|v| {
                serde_json::from_value::<Digest>(v.clone())
                    .map_err(|_| PackageError::invalid("bad lock checksum"))
            })
            .transpose()?;
        let dependencies = row
            .get("dependencies")
            .map(|v| {
                v.as_array()
                    .ok_or_else(|| PackageError::invalid("bad lock dependency array"))?
                    .iter()
                    .map(|d| {
                        d.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| PackageError::invalid("bad lock dependency"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        if row.keys().any(|k| {
            !matches!(
                k.as_str(),
                "name" | "version" | "source" | "checksum" | "dependencies"
            )
        }) {
            return Err(PackageError::invalid("unknown Cargo lock package field"));
        }
        if source.as_ref().is_some_and(|s| s.starts_with("registry+")) != checksum.is_some() {
            return Err(PackageError::invalid("registry source/checksum incomplete"));
        }
        rows.push(LockPackage {
            name,
            version,
            source,
            checksum,
            dependencies,
        });
        row.clear();
        Ok(())
    }
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            if active {
                finish(&mut current, &mut rows)?;
            }
            active = true;
            continue;
        }
        if line.starts_with('[') {
            return Err(PackageError::invalid("unsupported lock table/metadata"));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| PackageError::invalid("malformed lock TOML"))?;
        let key = key.trim();
        let mut value = value.trim().to_owned();
        if !active {
            if key != "version" || root_version || value != "4" {
                return Err(PackageError::invalid(
                    "unsupported original Cargo lock format",
                ));
            }
            root_version = true;
            continue;
        }
        if value.starts_with('[') && !value.ends_with(']') {
            loop {
                let next = lines
                    .next()
                    .ok_or_else(|| PackageError::invalid("truncated lock dependencies"))?
                    .trim();
                value.push_str(next);
                if next.ends_with(']') {
                    break;
                }
            }
        }
        // Cargo uses a trailing comma in multiline dependency arrays.
        let value = value.replace(",]", "]");
        let parsed: Value = serde_json::from_str(&value)
            .map_err(|_| PackageError::invalid("unsupported Cargo lock value"))?;
        if current.insert(key.into(), parsed).is_some() {
            return Err(PackageError::invalid("duplicate Cargo lock field"));
        }
    }
    if active {
        finish(&mut current, &mut rows)?;
    }
    if !root_version || rows.is_empty() {
        return Err(PackageError::invalid("empty original Cargo lock closure"));
    }
    let mut identities = BTreeSet::new();
    for row in &rows {
        if !identities.insert((&row.name, &row.version, &row.source)) {
            return Err(PackageError::invalid("duplicate original lock identity"));
        }
    }
    Ok(rows)
}
impl DependencyInventory {
    pub fn parse_json(root: &Path, bytes: &[u8]) -> Result<Self, PackageError> {
        let mut inventory: Self = closed(bytes)?;
        inventory.root = root.to_owned();
        inventory.validate_shape()?;
        Ok(inventory)
    }
    fn validate_shape(&self) -> Result<(), PackageError> {
        if self.schema != "osslscope-dependency-inventory-v1"
            || self.components.is_empty()
            || self.host.is_empty()
            || self.bpf.is_empty()
            || self.tool_sources.is_empty()
            || self.build_std.is_empty()
            || self.linker_build.is_empty()
            || self.runtime.is_empty()
        {
            return Err(PackageError::invalid(
                "incomplete offline dependency inventory",
            ));
        }
        let mut ids = BTreeSet::new();
        for component in &self.components {
            if component.id.is_empty()
                || !component
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || component.name.is_empty()
                || component.version.is_empty()
                || !ids.insert(&component.id)
            {
                return Err(PackageError::invalid(
                    "invalid/duplicate source component identity",
                ));
            }
            if component.terms.spdx.is_empty()
                || component.terms.license_files.is_empty()
                || matches!(component.terms.spdx.as_str(), "NOASSERTION" | "NONE")
            {
                return Err(PackageError::invalid(
                    "complete applicable source terms required",
                ));
            }
            for entry in component
                .terms
                .license_files
                .iter()
                .chain(&component.terms.notice_files)
                .chain(std::iter::once(&component.terms.source_availability))
            {
                check_input_path(&entry.path)?;
                if entry.bytes == 0 {
                    return Err(PackageError::invalid("missing source terms content"));
                }
            }
        }
        for group in [
            &self.host,
            &self.bpf,
            &self.tool_sources,
            &self.build_std,
            &self.linker_build,
            &self.runtime,
        ] {
            let mut seen = BTreeSet::new();
            for id in group {
                if !ids.contains(id) || !seen.insert(id) {
                    return Err(PackageError::invalid(
                        "missing/duplicate closure component reference",
                    ));
                }
            }
        }
        if self
            .build_std
            .iter()
            .chain(&self.linker_build)
            .any(|id| !self.tool_sources.contains(id))
        {
            return Err(PackageError::invalid(
                "build-std/linker closure absent from tool-source inventory",
            ));
        }
        for component in &self.components {
            let mut seen = BTreeSet::new();
            for id in &component.dependencies {
                if !ids.contains(id) || !seen.insert(id) {
                    return Err(PackageError::invalid(
                        "unresolved/duplicate dependency relationship",
                    ));
                }
            }
        }
        Ok(())
    }
    fn component(&self, id: &str) -> Result<&SourceComponent, PackageError> {
        self.components
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| PackageError::invalid("unresolved source component"))
    }
    pub fn bpf_dependency_names(&self) -> Result<Vec<String>, PackageError> {
        self.validate_shape()?;
        let mut pending = self.bpf.clone();
        let mut visited = BTreeSet::new();
        let mut names = Vec::new();
        while let Some(id) = pending.pop() {
            if visited.insert(id.clone()) {
                let component = self.component(&id)?;
                names.push(component.name.clone());
                pending.extend(component.dependencies.clone());
            }
        }
        Ok(names)
    }
    pub(crate) fn verify(
        &self,
        tree: &SourceTree,
        recipe: &BuildRecipe,
    ) -> Result<(), PackageError> {
        self.validate_shape()?;
        let host = read_regular(&tree.root, &RelativePath::new("Cargo.lock")?, 1_048_576)?;
        let bpf = read_regular(
            &tree.root,
            &RelativePath::new("crates/ebpf/Cargo.lock")?,
            1_048_576,
        )?;
        if sha256(&host) != self.locks.host_sha256 || sha256(&bpf) != self.locks.bpf_sha256 {
            return Err(PackageError::invalid("original host/BPF lock changed"));
        }
        for (bytes, group) in [(&host, &self.host), (&bpf, &self.bpf)] {
            let rows = lock_packages(bytes)?;
            if rows.len() != group.len() {
                return Err(PackageError::invalid(
                    "lock/path/registry/git closure incomplete",
                ));
            }
            for (row, id) in rows.iter().zip(group) {
                let component = self.component(id)?;
                if component.name != row.name || component.version != row.version {
                    return Err(PackageError::invalid(
                        "lock package/source component mismatch",
                    ));
                }
                match (&component.source, &row.source, &row.checksum) {
                    (ComponentSource::Path { .. }, None, None) => {}
                    (
                        ComponentSource::Registry {
                            location,
                            checksum,
                            archive,
                            ..
                        },
                        Some(source),
                        Some(sum),
                    ) if source == location && checksum == sum && archive.sha256 == *sum => {}
                    (
                        ComponentSource::Git {
                            repository,
                            revision,
                            ..
                        },
                        Some(source),
                        None,
                    ) if source == &format!("git+{repository}#{revision}")
                        && revision.len() == 40
                        && revision
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
                    _ => {
                        return Err(PackageError::invalid(
                            "original locked source/checksum mismatch",
                        ));
                    }
                }
                let resolved = row
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        let mut words = dependency.split_whitespace();
                        let name = words.next().unwrap_or("");
                        let version = words.next();
                        let matches = rows
                            .iter()
                            .zip(group)
                            .filter(|(r, _)| {
                                r.name == name && version.is_none_or(|v| v == r.version)
                            })
                            .map(|(_, id)| id.clone())
                            .collect::<Vec<_>>();
                        if matches.len() != 1 {
                            return Err(PackageError::invalid(
                                "unresolved/ambiguous original lock dependency",
                            ));
                        }
                        Ok(matches[0].clone())
                    })
                    .collect::<Result<Vec<_>, PackageError>>()?;
                if component.dependencies != resolved {
                    return Err(PackageError::invalid(
                        "declared dependency relationships differ from original lock",
                    ));
                }
            }
        }
        if self
            .bpf_dependency_names()?
            .iter()
            .any(|n| n == "osslscope-ebpf-common")
        {
            return Err(PackageError::invalid(
                "old GPL3 host common enters BPF closure",
            ));
        }
        for required in ["osslscope-ebpf", "osslscope-bpf-contract"] {
            if !self.bpf_dependency_names()?.iter().any(|n| n == required) {
                return Err(PackageError::invalid(
                    "accepted BPF source component missing",
                ));
            }
        }
        for required in ["core", "compiler_builtins", "stdarch", "portable-simd"] {
            if !self
                .build_std
                .iter()
                .any(|id| self.component(id).is_ok_and(|c| c.name == required))
            {
                return Err(PackageError::invalid(format!(
                    "missing build-std/linker/native source class {required}"
                )));
            }
        }
        let mut used = BTreeSet::new();
        let mut pending = self
            .host
            .iter()
            .chain(&self.bpf)
            .chain(&self.tool_sources)
            .chain(&self.runtime)
            .cloned()
            .collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if used.insert(id.clone()) {
                pending.extend(self.component(&id)?.dependencies.clone());
            }
        }
        if used.len() != self.components.len() {
            return Err(PackageError::invalid(
                "unreferenced source component outside admitted closures",
            ));
        }
        for component in &self.components {
            match &component.source {
                ComponentSource::Path { manifest } => {
                    check_input_path(manifest)?;
                    if !tree.contains(manifest.as_str()) {
                        return Err(PackageError::invalid(
                            "path dependency absent from original source",
                        ));
                    }
                    let actual = package_fields(&read_regular(&tree.root, manifest, 1_048_576)?)?;
                    if actual.get("name") != Some(&component.name)
                        || actual.get("version") != Some(&component.version)
                        || actual.get("license") != Some(&component.terms.spdx)
                    {
                        return Err(PackageError::invalid(
                            "actual path component version/terms mismatch",
                        ));
                    }
                }
                ComponentSource::Registry {
                    location,
                    checksum,
                    archive,
                    corresponding_source,
                } => {
                    if !location.starts_with("registry+") || archive.sha256 != *checksum {
                        return Err(PackageError::invalid("invalid registry source identity"));
                    }
                    if archive.bytes > RegistryArchiveLimits::DEFAULT.compressed_bytes
                        || corresponding_source.bytes
                            > RegistryArchiveLimits::DEFAULT.expanded_bytes
                    {
                        return Err(PackageError::invalid(
                            "registry source size limit before input open",
                        ));
                    }
                    let original = verify_entry(&self.root, archive)?;
                    let normalized = verify_entry(&self.root, corresponding_source)?;
                    verify_registry_source(
                        &original,
                        &normalized,
                        &component.name,
                        &component.version,
                        RegistryArchiveLimits::DEFAULT,
                    )?;
                }
                ComponentSource::Git {
                    repository,
                    revision,
                    archive,
                } => {
                    if repository.is_empty() || revision.len() != 40 {
                        return Err(PackageError::invalid("missing git source identity"));
                    }
                    validate_source_archive(&verify_entry(&self.root, archive)?)?;
                }
                ComponentSource::Native { location, archive } => {
                    if location.is_empty() {
                        return Err(PackageError::invalid("missing native/tool source origin"));
                    }
                    validate_source_archive(&verify_entry(&self.root, archive)?)?;
                }
            }
            for entry in component
                .terms
                .license_files
                .iter()
                .chain(&component.terms.notice_files)
                .chain(std::iter::once(&component.terms.source_availability))
            {
                verify_entry(&self.root, entry)?;
            }
        }
        for resource in &recipe.resources {
            if !used.contains(&resource.source_component) {
                return Err(PackageError::invalid("unbound tool corresponding source"));
            }
        }
        Ok(())
    }
    fn entries(&self) -> Vec<ContentEntry> {
        let mut entries = Vec::new();
        for component in &self.components {
            match &component.source {
                ComponentSource::Path { .. } => {}
                ComponentSource::Registry {
                    archive,
                    corresponding_source,
                    ..
                } => entries.extend([archive.clone(), corresponding_source.clone()]),
                ComponentSource::Git { archive, .. } | ComponentSource::Native { archive, .. } => {
                    entries.push(archive.clone())
                }
            }
            entries.extend(component.terms.license_files.clone());
            entries.extend(component.terms.notice_files.clone());
            entries.push(component.terms.source_availability.clone());
        }
        entries
    }
}

type RetainedAssets = BTreeMap<String, Arc<[u8]>>;
fn retain(
    map: &mut RetainedAssets,
    entry: &ContentEntry,
    bytes: Vec<u8>,
) -> Result<(), PackageError> {
    if bytes.len() as u64 != entry.bytes || sha256(&bytes) != entry.sha256 {
        return Err(PackageError::invalid("retained asset changed"));
    }
    if let Some(previous) = map.get(entry.path.as_str()) {
        if previous.as_ref() != bytes {
            return Err(PackageError::invalid("source asset path collision"));
        }
    } else {
        map.insert(entry.path.as_str().into(), Arc::from(bytes));
    }
    Ok(())
}
fn generated(
    map: &mut RetainedAssets,
    path: &RelativePath,
    bytes: Vec<u8>,
) -> Result<ContentEntry, PackageError> {
    let entry = content(path.as_str(), &bytes)?;
    if map.contains_key(path.as_str()) {
        return Err(PackageError::invalid(
            "generated asset collides with required source input",
        ));
    }
    retain(map, &entry, bytes)?;
    Ok(entry)
}
fn deduplicate(entries: &mut Vec<ContentEntry>) -> Result<(), PackageError> {
    entries.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    for adjacent in entries.windows(2) {
        if adjacent[0].path == adjacent[1].path && adjacent[0] != adjacent[1] {
            return Err(PackageError::invalid(
                "contradictory content identities for same source path",
            ));
        }
    }
    entries.dedup();
    Ok(())
}

pub(crate) fn collect_assets(
    tree: &SourceTree,
    config: &ReleaseConfig,
    deps: &DependencyInventory,
    recipe: &BuildRecipe,
    recipe_bytes: &[u8],
    source_archive: &[u8],
) -> Result<(SourceAssets, RetainedAssets, Vec<ContentEntry>), PackageError> {
    let mut retained = BTreeMap::new();
    let mut required = deps.entries();
    for resource in &recipe.resources {
        required.extend([resource.content.clone(), resource.acquisition.clone()]);
    }
    required.push(recipe.abi_evidence.clone());
    deduplicate(&mut required)?;
    for entry in &required {
        retain(&mut retained, entry, verify_entry(&deps.root, entry)?)?;
    }
    let source_archive = generated(
        &mut retained,
        &config.artifacts.source_archive,
        source_archive.to_vec(),
    )?;
    let mut dependency_archives = Vec::new();
    let mut tool_source_archives = Vec::new();
    let mut licenses = Vec::new();
    for component in &deps.components {
        let archives = if deps.tool_sources.contains(&component.id) {
            &mut tool_source_archives
        } else {
            &mut dependency_archives
        };
        match &component.source {
            ComponentSource::Path { .. } => {}
            ComponentSource::Registry {
                archive,
                corresponding_source,
                ..
            } => archives.extend([archive.clone(), corresponding_source.clone()]),
            ComponentSource::Git { archive, .. } | ComponentSource::Native { archive, .. } => {
                archives.push(archive.clone())
            }
        }
        licenses.extend(component.terms.license_files.clone());
    }
    deduplicate(&mut dependency_archives)?;
    deduplicate(&mut tool_source_archives)?;
    deduplicate(&mut licenses)?;
    let notices = generated(
        &mut retained,
        &config.artifacts.notices,
        json_bytes(
            &json!({"schema":"osslscope-source-notices-v1","components":deps.components.iter().map(|c|json!({"id":c.id,"name":c.name,"version":c.version,"notices":c.terms.notice_files})).collect::<Vec<_>>()}),
        )?,
    )?;
    let license_index = generated(
        &mut retained,
        &config.artifacts.license_index,
        json_bytes(
            &json!({"schema":"osslscope-source-license-index-v1","components":deps.components.iter().map(|c|json!({"id":c.id,"name":c.name,"version":c.version,"expression":c.terms.spdx,"license_files":c.terms.license_files})).collect::<Vec<_>>()}),
        )?,
    )?;
    let source_availability = generated(
        &mut retained,
        &config.artifacts.source_availability,
        json_bytes(
            &json!({"schema":"osslscope-source-availability-v1","source":tree.identity(),"source_archive":source_archive,"components":deps.components.iter().map(|c|json!({"id":c.id,"source":c.source,"availability":c.terms.source_availability})).collect::<Vec<_>>()}),
        )?,
    )?;
    let sbom = generated(
        &mut retained,
        &config.artifacts.sbom,
        source_sbom(tree, deps)?,
    )?;
    let mut tool_archives = recipe
        .resources
        .iter()
        .map(|r| r.acquisition.clone())
        .collect::<Vec<_>>();
    deduplicate(&mut tool_archives)?;
    let groups = AssetGroups {
        source_archive: &source_archive,
        dependency_archives: &dependency_archives,
        tool_source_archives: &tool_source_archives,
        tool_archives: &tool_archives,
        notices: &notices,
        license_index: &license_index,
        license_texts: &licenses,
        sbom: &sbom,
        source_availability: &source_availability,
    };
    let inventory_bytes =
        offline_bytes(tree, config, deps, recipe, recipe_bytes, &groups, &retained)?;
    let offline_inventory = generated(
        &mut retained,
        &config.artifacts.offline_inventory,
        inventory_bytes,
    )?;
    Ok((
        SourceAssets {
            source_archive,
            dependency_archives,
            tool_source_archives,
            tool_archives,
            offline_inventory,
            notices,
            license_index,
            license_texts: licenses,
            sbom,
            source_availability,
        },
        retained,
        required,
    ))
}
#[derive(Serialize)]
struct AssetGroups<'a> {
    source_archive: &'a ContentEntry,
    dependency_archives: &'a [ContentEntry],
    tool_source_archives: &'a [ContentEntry],
    tool_archives: &'a [ContentEntry],
    notices: &'a ContentEntry,
    license_index: &'a ContentEntry,
    license_texts: &'a [ContentEntry],
    sbom: &'a ContentEntry,
    source_availability: &'a ContentEntry,
}
fn offline_bytes(
    tree: &SourceTree,
    config: &ReleaseConfig,
    deps: &DependencyInventory,
    recipe: &BuildRecipe,
    recipe_bytes: &[u8],
    groups: &AssetGroups<'_>,
    retained: &RetainedAssets,
) -> Result<Vec<u8>, PackageError> {
    let entries = retained
        .iter()
        .filter(|(path, _)| path.as_str() != config.artifacts.offline_inventory.as_str())
        .map(|(path, bytes)| content(path, bytes))
        .collect::<Result<Vec<_>, _>>()?;
    json_bytes(
        &json!({"schema":"osslscope-offline-inventory-v1","source":tree.identity(),"locks":deps.locks,"dependencies":deps,"recipe_sha256":sha256(recipe_bytes),"config_sha256":config.release_toml_sha256,"tools":recipe.tools,"source_assets":groups,"assets":entries}),
    )
}
fn source_sbom(tree: &SourceTree, deps: &DependencyInventory) -> Result<Vec<u8>, PackageError> {
    let packages=deps.components.iter().map(|component|{
        let (download,checksums)=match &component.source{
            ComponentSource::Path{manifest}=>(format!("source:{}:{}",tree.identity().revision,manifest.as_str()),vec![json!({"algorithm":"SHA256","checksumValue":tree.identity().inventory_sha256})]),
            ComponentSource::Registry{location,archive,..}=>(location.clone(),vec![json!({"algorithm":"SHA256","checksumValue":archive.sha256})]),
            ComponentSource::Git{repository,archive,..}=>(repository.clone(),vec![json!({"algorithm":"SHA256","checksumValue":archive.sha256})]),
            ComponentSource::Native{location,archive}=>(location.clone(),vec![json!({"algorithm":"SHA256","checksumValue":archive.sha256})]),
        };
        json!({"SPDXID":format!("SPDXRef-{}",component.id),"name":component.name,"versionInfo":component.version,"downloadLocation":download,"filesAnalyzed":false,"licenseDeclared":component.terms.spdx,"licenseConcluded":"NOASSERTION","copyrightText":"NOASSERTION","checksums":checksums})
    }).collect::<Vec<_>>();
    let mut relationships = Vec::new();
    for component in &deps.components {
        relationships.push(json!({"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":format!("SPDXRef-{}",component.id)}));
        for dependency in &component.dependencies {
            relationships.push(json!({"spdxElementId":format!("SPDXRef-{}",component.id),"relationshipType":"DEPENDS_ON","relatedSpdxElement":format!("SPDXRef-{dependency}")}));
        }
        for (group, relation) in [
            (&deps.host, "BUILD_DEPENDENCY_OF"),
            (&deps.bpf, "BUILD_DEPENDENCY_OF"),
            (&deps.tool_sources, "BUILD_TOOL_OF"),
            (&deps.runtime, "RUNTIME_DEPENDENCY_OF"),
        ] {
            if group.contains(&component.id) {
                relationships.push(json!({"spdxElementId":format!("SPDXRef-{}",component.id),"relationshipType":relation,"relatedSpdxElement":"SPDXRef-DOCUMENT"}));
            }
        }
    }
    json_bytes(
        &json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"osslscope-corresponding-source","documentNamespace":format!("https://osslscope.invalid/spdx/source/{}",tree.identity().inventory_sha256),"creationInfo":{"creators":["Tool: osslscope-package"],"created":"2026-10-23T23:56:44Z"},"packages":packages,"relationships":relationships}),
    )
}

pub fn verify_closure(sealed: &SealedSource) -> Result<(), PackageError> {
    sealed.tree.verify()?;
    sealed.config.verify(&sealed.tree)?;
    let recipe_bytes = read_regular(
        &sealed.tree.root,
        &sealed.config.selected().builder,
        1_048_576,
    )?;
    if recipe_bytes != sealed.recipe_bytes {
        return Err(PackageError::invalid(
            "original selected builder recipe changed",
        ));
    }
    sealed
        .recipe
        .verify(&sealed.config, &sealed.inputs.tools, &sealed.dependencies)?;
    sealed.dependencies.verify(&sealed.tree, &sealed.recipe)?;
    for entry in &sealed.required_inputs {
        let bytes = verify_entry(&sealed.dependencies.root, entry)?;
        if sealed.asset_bytes(entry)? != bytes {
            return Err(PackageError::invalid(
                "required source bytes differ from retained asset",
            ));
        }
    }
    let inputs: BuildInputs = parse_canonical(&sealed.input_bytes)?;
    if inputs != sealed.inputs
        || inputs.source != sealed.original_source
        || inputs.source != *sealed.tree.identity()
        || inputs.locks != sealed.locks
        || inputs.locks != sealed.dependencies.locks
        || inputs.recipe.recipe_sha256 != sha256(&recipe_bytes)
        || inputs.recipe.config_sha256 != sealed.config.release_toml_sha256
        || inputs.product_version != sealed.config.product_version
        || inputs.package_epoch != 1
        || inputs.package_revision != 1
        || inputs.source_epoch != sealed.config.source_epoch
        || inputs.host_profile != sealed.recipe.host_profile
        || inputs.jobs != 2
        || inputs.argv != sealed.recipe.argv
        || inputs.environment != sealed.recipe.environment
        || inputs.offline_inventory_sha256 != sealed.assets.offline_inventory.sha256
    {
        return Err(PackageError::invalid(
            "sealed BuildInputs/source/config/recipe mismatch",
        ));
    }
    for entry in std::iter::once(&sealed.assets.source_archive)
        .chain(&sealed.assets.dependency_archives)
        .chain(&sealed.assets.tool_source_archives)
        .chain(&sealed.assets.tool_archives)
        .chain([
            &sealed.assets.offline_inventory,
            &sealed.assets.notices,
            &sealed.assets.license_index,
            &sealed.assets.sbom,
            &sealed.assets.source_availability,
        ])
        .chain(&sealed.assets.license_texts)
    {
        sealed.asset_bytes(entry)?;
    }
    let assets = &sealed.assets;
    let groups = AssetGroups {
        source_archive: &assets.source_archive,
        dependency_archives: &assets.dependency_archives,
        tool_source_archives: &assets.tool_source_archives,
        tool_archives: &assets.tool_archives,
        notices: &assets.notices,
        license_index: &assets.license_index,
        license_texts: &assets.license_texts,
        sbom: &assets.sbom,
        source_availability: &assets.source_availability,
    };
    let expected = offline_bytes(
        &sealed.tree,
        &sealed.config,
        &sealed.dependencies,
        &sealed.recipe,
        &recipe_bytes,
        &groups,
        &sealed.retained,
    )?;
    if expected != sealed.asset_bytes(&sealed.assets.offline_inventory)? {
        return Err(PackageError::invalid(
            "detached inventory differs from retained source/tool/legal closure",
        ));
    }
    // Enforce the same closed, bounded JSON decoder on generated detached records.
    super::records::decode_closed_json(&expected)?;
    let source = sealed.asset_bytes(&sealed.assets.source_archive)?;
    sealed.tree.verify_archive(source)?;
    if source.len() as u64 > MAX_ASSET_BYTES {
        return Err(PackageError::invalid("source archive exceeds bound"));
    }
    Ok(())
}

#[cfg(test)]
use super::{records::ToolInventory, source::seal_source};
#[cfg(test)]
#[path = "../../tests/support/package_source_fixtures.rs"]
pub(crate) mod source_fixtures;

#[cfg(test)]
mod tests {
    use super::*;
    use source_fixtures::Fixture;

    fn rebind_retained_archive(sealed: &mut SealedSource, archive: &[u8]) {
        let (assets, retained, required_inputs) = collect_assets(
            &sealed.tree,
            &sealed.config,
            &sealed.dependencies,
            &sealed.recipe,
            &sealed.recipe_bytes,
            archive,
        )
        .unwrap();
        sealed.assets = assets;
        sealed.retained = retained;
        sealed.required_inputs = required_inputs;
        sealed.inputs.offline_inventory_sha256 = sealed.assets.offline_inventory.sha256;
        sealed.input_bytes = super::super::records::canonical_bytes(&sealed.inputs);
        assert_eq!(
            sealed.asset_bytes(&sealed.assets.source_archive).unwrap(),
            archive
        );
        assert_eq!(
            sealed.inputs.offline_inventory_sha256,
            sha256(
                sealed
                    .asset_bytes(&sealed.assets.offline_inventory)
                    .unwrap()
            )
        );
        assert_eq!(
            parse_canonical::<BuildInputs>(&sealed.input_bytes).unwrap(),
            sealed.inputs
        );
    }

    #[test]
    fn retained_source_member_mismatch_refuses_with_all_outer_identities_rebound() {
        let fixture = Fixture::new();
        let mut sealed = seal_source(
            &fixture.tree(),
            &fixture.release(),
            &fixture.dependencies(),
            &fixture.tool_inventory(),
        )
        .unwrap();
        let original = &fixture.files["tests/fixtures/example.json"];
        let mut archive = sealed
            .asset_bytes(&sealed.assets.source_archive)
            .unwrap()
            .to_vec();
        let offset = archive
            .windows(original.len())
            .position(|data| data == original)
            .unwrap();
        archive[offset] ^= 1;
        assert!(
            SourceTree::extract_archive(
                &archive,
                &fixture.root.parent().unwrap().join("bad-inner-manifest")
            )
            .is_err()
        );
        rebind_retained_archive(&mut sealed, &archive);
        sealed.tree.verify().unwrap();
        assert!(
            verify_closure(&sealed).is_err(),
            "retained changed member was admitted after complete outer rebinding"
        );
    }

    #[test]
    fn retained_source_manifest_must_match_the_admitted_inventory_after_outer_rebinding() {
        let fixture = Fixture::new();
        let mut sealed = fixture.seal().unwrap();
        let path = fixture.root.join("tests/fixtures/example.json");
        std::fs::write(&path, b"a different complete source version\n").unwrap();
        let other = fixture.seal().unwrap();
        let archive = other
            .asset_bytes(&other.assets.source_archive)
            .unwrap()
            .to_vec();
        std::fs::write(path, &fixture.files["tests/fixtures/example.json"]).unwrap();
        let extracted = SourceTree::extract_archive(
            &archive,
            &fixture.root.parent().unwrap().join("valid-other-source"),
        )
        .unwrap();
        assert_ne!(extracted.identity(), &sealed.original_source);
        rebind_retained_archive(&mut sealed, &archive);
        sealed.tree.verify().unwrap();
        assert!(
            verify_closure(&sealed).is_err(),
            "a valid archive of another source inventory was admitted"
        );
    }
}
