// SPDX-License-Identifier: GPL-3.0-or-later
// Closed v1 metadata records. These content bindings carry no trust assertion.
use std::{collections::HashSet, fmt, sync::Arc};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};

pub use super::error::PackageError;

const MAX_RECORD_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

pub fn sha256(bytes: &[u8]) -> Digest {
    Digest(Sha256::digest(bytes).into())
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(de::Error::custom("expected lowercase 64-digit SHA-256"));
        }
        let mut bytes = [0; 32];
        for (i, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            bytes[i] = hi << 4 | lo;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RelativePath(String);

impl RelativePath {
    pub fn new(path: impl Into<String>) -> Result<Self, PackageError> {
        let path = path.into();
        if path.is_empty()
            || path.starts_with('/')
            || path.ends_with('/')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || path.contains('\\')
            || path.chars().any(char::is_control)
        {
            return Err(PackageError::invalid("unsafe relative path"));
        }
        Ok(Self(path))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for RelativePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub revision: String,
    pub inventory_sha256: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    pub target: String,
    pub abi_profile: String,
    pub abi_floor: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockIdentity {
    pub host_sha256: Digest,
    pub bpf_sha256: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeIdentity {
    pub recipe_sha256: Digest,
    pub config_sha256: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
    pub sha256: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInventory {
    pub host: ToolIdentity,
    pub bpf: ToolIdentity,
    pub linker: ToolIdentity,
    pub llvm: ToolIdentity,
    pub builder: ToolIdentity,
    pub components: Vec<ToolIdentity>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntry {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentEntry {
    pub path: RelativePath,
    pub sha256: Digest,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Harvest,
    Count,
    Members,
    Identity,
}
impl Role {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Harvest => "osslscope-harvest",
            Self::Count => "osslscope-count",
            Self::Members => "osslscope-members",
            Self::Identity => "osslscope-identity",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEntry {
    pub role: Role,
    pub file: RelativePath,
    pub sha256: Digest,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInputs {
    pub schema: String,
    pub source: SourceIdentity,
    pub product_version: String,
    pub package_epoch: u32,
    pub package_revision: u32,
    pub source_epoch: u64,
    pub host_profile: HostProfile,
    pub locks: LockIdentity,
    pub recipe: RecipeIdentity,
    pub tools: ToolInventory,
    pub jobs: u16,
    pub argv: Vec<String>,
    pub environment: Vec<EnvironmentEntry>,
    pub offline_inventory_sha256: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleContract {
    pub schema: String,
    pub input_id: Digest,
    pub source: SourceIdentity,
    pub product_version: String,
    pub host_profile: HostProfile,
    pub wire_abi: u32,
    pub loader_contract_sha256: Digest,
    pub roles: Vec<RoleEntry>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub path: RelativePath,
    pub sha256: Digest,
    pub bytes: u64,
    pub elf_machine: u16,
    #[serde(deserialize_with = "required_nullable_build_id")]
    pub elf_build_id: Option<String>,
}
fn required_nullable_build_id<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDeclaration {
    pub directory_mode: u32,
    pub executable_mode: u32,
    pub file_mode: u32,
    pub owner: String,
    pub group: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadManifest {
    pub schema: String,
    pub bundle_id: Digest,
    pub contract: ContentEntry,
    pub input_id: Digest,
    pub build_inputs: ContentEntry,
    pub host: HostEntry,
    pub roles: Vec<RoleEntry>,
    pub source: SourceIdentity,
    pub product_version: String,
    pub host_profile: HostProfile,
    pub locks: LockIdentity,
    pub recipe: RecipeIdentity,
    pub tools: ToolInventory,
    pub install: InstallDeclaration,
    pub docs: Vec<ContentEntry>,
    pub licenses: Vec<ContentEntry>,
    pub notices: Vec<ContentEntry>,
    pub sbom: ContentEntry,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProfile {
    pub abi_profile: String,
    pub payload_id: Digest,
    pub bundle_id: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub path: RelativePath,
    pub sha256: Digest,
    pub bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIndex {
    pub schema: String,
    pub source: SourceIdentity,
    pub product_version: String,
    pub package_epoch: u32,
    pub package_revision: u32,
    pub source_epoch: u64,
    pub profiles: Vec<ReleaseProfile>,
    pub unsigned_packages: Vec<ReleaseAsset>,
    pub signed_packages: Vec<ReleaseAsset>,
    pub source_assets: Vec<ReleaseAsset>,
    pub dependency_assets: Vec<ReleaseAsset>,
    pub builder_assets: Vec<ReleaseAsset>,
    pub sbom_assets: Vec<ReleaseAsset>,
    pub provenance_assets: Vec<ReleaseAsset>,
    pub reproducibility_assets: Vec<ReleaseAsset>,
    pub qualification_receipts: Vec<ReleaseAsset>,
    pub support_matrix: ReleaseAsset,
    pub signing_identity: String,
    pub verification_instructions: String,
}

mod sealed {
    pub trait Sealed {}
}
pub trait PackageRecord: sealed::Sealed + Serialize + for<'de> Deserialize<'de> {
    fn validate(&self) -> Result<(), PackageError>;
}

fn check_schema(actual: &str, expected: &str) -> Result<(), PackageError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PackageError::invalid("unsupported schema discriminator"))
    }
}
fn check_source(source: &SourceIdentity) -> Result<(), PackageError> {
    if source.revision.len() == 40
        && source
            .revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(PackageError::invalid(
            "source revision must be full lowercase Git object ID",
        ))
    }
}
fn check_profile(profile: &HostProfile) -> Result<(), PackageError> {
    if profile.abi_floor.is_empty() {
        return Err(PackageError::invalid("missing measured ABI floor"));
    }
    match (profile.abi_profile.as_str(), profile.target.as_str()) {
        ("linux-x86_64-gnu", "x86_64-unknown-linux-gnu")
        | ("linux-x86_64-musl", "x86_64-unknown-linux-musl") => Ok(()),
        _ => Err(PackageError::invalid("unsupported host profile/target")),
    }
}
fn check_tools(tools: &ToolInventory) -> Result<(), PackageError> {
    let identities = [
        &tools.host,
        &tools.bpf,
        &tools.linker,
        &tools.llvm,
        &tools.builder,
    ];
    if tools.components.is_empty()
        || identities
            .into_iter()
            .chain(tools.components.iter())
            .any(|t| t.name.is_empty() || t.version.is_empty())
    {
        return Err(PackageError::invalid("incomplete tool identity"));
    }
    Ok(())
}
fn check_roles(roles: &[RoleEntry]) -> Result<(), PackageError> {
    let mut seen = HashSet::new();
    if roles.len() != 3 {
        return Err(PackageError::invalid("v1 requires exactly three roles"));
    }
    for entry in roles {
        if entry.role == Role::Identity
            || !seen.insert(entry.role)
            || entry.file.as_str() != entry.role.file_name()
            || entry.bytes == 0
        {
            return Err(PackageError::invalid("invalid role entry"));
        }
    }
    Ok(())
}
fn check_content(entry: &ContentEntry) -> Result<(), PackageError> {
    if entry.bytes == 0 {
        Err(PackageError::invalid("zero-length content entry"))
    } else {
        Ok(())
    }
}
fn check_payload_paths(payload: &PayloadManifest) -> Result<(), PackageError> {
    let mut seen = HashSet::new();
    let paths = std::iter::once(payload.contract.path.as_str())
        .chain(std::iter::once(payload.build_inputs.path.as_str()))
        .chain(std::iter::once(payload.host.path.as_str()))
        .chain(payload.roles.iter().map(|r| r.file.as_str()))
        .chain(
            payload
                .docs
                .iter()
                .chain(&payload.licenses)
                .chain(&payload.notices)
                .map(|e| e.path.as_str()),
        )
        .chain(std::iter::once(payload.sbom.path.as_str()));
    for path in paths {
        let name = path.rsplit('/').next().unwrap_or(path);
        if !seen.insert(path)
            || matches!(
                name,
                "payload-manifest.json" | "release-index.json" | "postinst" | "prerm"
            )
            || name.ends_with(".deb")
            || name.ends_with(".rpm")
            || name.ends_with(".tar")
            || name.ends_with(".tar.zst")
        {
            return Err(PackageError::invalid(
                "payload path repeats or points to derived metadata/package",
            ));
        }
    }
    Ok(())
}
fn check_no_derived_inputs(input: &BuildInputs) -> Result<(), PackageError> {
    if input.product_version.is_empty()
        || input.jobs == 0
        || input.jobs > 256
        || input.argv.is_empty()
        || input.argv.iter().any(String::is_empty)
        || input
            .environment
            .iter()
            .any(|e| e.name.is_empty() || e.name == "OSSL_PACKAGE_RECORD_DIR")
    {
        return Err(PackageError::invalid("invalid build input value"));
    }
    let mut names = HashSet::new();
    for entry in &input.environment {
        if !names.insert(&entry.name) {
            return Err(PackageError::invalid("duplicate environment name"));
        }
    }
    Ok(())
}
impl sealed::Sealed for BuildInputs {}
impl PackageRecord for BuildInputs {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-build-inputs-v1")?;
        check_source(&self.source)?;
        check_profile(&self.host_profile)?;
        check_tools(&self.tools)?;
        check_no_derived_inputs(self)
    }
}
impl sealed::Sealed for BundleContract {}
impl PackageRecord for BundleContract {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-bundle-contract-v1")?;
        check_source(&self.source)?;
        check_profile(&self.host_profile)?;
        if self.product_version.is_empty() || self.wire_abi == 0 {
            return Err(PackageError::invalid("invalid bundle identity"));
        }
        check_roles(&self.roles)
    }
}
impl sealed::Sealed for PayloadManifest {}
impl PackageRecord for PayloadManifest {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-payload-manifest-v1")?;
        check_source(&self.source)?;
        check_profile(&self.host_profile)?;
        check_tools(&self.tools)?;
        check_roles(&self.roles)?;
        if self.product_version.is_empty()
            || self.contract.path.as_str() != "bundle-contract.json"
            || self.build_inputs.path.as_str() != "build-inputs.json"
            || self.build_inputs.sha256 != self.input_id
            || self.host.bytes == 0
            || self.host.elf_machine != 62
            || self.install.directory_mode != 0o755
            || self.install.executable_mode != 0o755
            || self.install.file_mode != 0o644
            || self.install.owner != "root"
            || self.install.group != "root"
        {
            return Err(PackageError::invalid(
                "invalid payload identity or install declaration",
            ));
        }
        for entry in [&self.contract, &self.build_inputs, &self.sbom] {
            check_content(entry)?;
        }
        for entry in self.docs.iter().chain(&self.licenses).chain(&self.notices) {
            check_content(entry)?;
        }
        if self.licenses.is_empty() || self.notices.is_empty() {
            return Err(PackageError::invalid("missing legal content"));
        }
        check_payload_paths(self)?;
        Ok(())
    }
}
impl sealed::Sealed for ReleaseIndex {}
impl PackageRecord for ReleaseIndex {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-release-index-v1")?;
        check_source(&self.source)?;
        if self.product_version.is_empty()
            || self.profiles.is_empty()
            || self.signing_identity.is_empty()
            || self.verification_instructions.is_empty()
        {
            return Err(PackageError::invalid("incomplete release index"));
        }
        let mut profiles = HashSet::new();
        for profile in &self.profiles {
            if !matches!(
                profile.abi_profile.as_str(),
                "linux-x86_64-gnu" | "linux-x86_64-musl"
            ) || !profiles.insert(&profile.abi_profile)
            {
                return Err(PackageError::invalid("invalid release profile"));
            }
        }
        let groups = [
            &self.unsigned_packages,
            &self.signed_packages,
            &self.source_assets,
            &self.dependency_assets,
            &self.builder_assets,
            &self.sbom_assets,
            &self.provenance_assets,
            &self.reproducibility_assets,
            &self.qualification_receipts,
        ];
        if groups.iter().any(|g| g.is_empty()) {
            return Err(PackageError::invalid(
                "missing release assets or qualification receipts",
            ));
        }
        let mut paths = HashSet::new();
        for asset in groups
            .into_iter()
            .flat_map(|group| group.iter())
            .chain(std::iter::once(&self.support_matrix))
        {
            let name = asset.path.as_str().rsplit('/').next().unwrap_or("");
            if asset.bytes == 0
                || !paths.insert(asset.path.as_str())
                || matches!(
                    name,
                    "release-index.json" | "release-index.sig" | "release-index.json.sig"
                )
            {
                return Err(PackageError::invalid(
                    "invalid release asset or index back-edge",
                ));
            }
        }
        Ok(())
    }
}

// serde_json::Value normally overwrites a duplicate map member. This visitor refuses it
// before any typed conversion, including arbitrary nested object and array depth.
struct NoDup(Value);
impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NoDupVisitor;
        impl<'de> Visitor<'de> for NoDupVisitor {
            type Value = NoDup;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON value without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<NoDup, E> {
                Ok(NoDup(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<NoDup, E> {
                Ok(NoDup(Value::Number(Number::from(value))))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<NoDup, E> {
                Ok(NoDup(Value::Number(Number::from(value))))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<NoDup, E> {
                Number::from_f64(value)
                    .map(|n| NoDup(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<NoDup, E> {
                Ok(NoDup(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<NoDup, E> {
                Ok(NoDup(Value::String(value)))
            }
            fn visit_none<E: de::Error>(self) -> Result<NoDup, E> {
                Ok(NoDup(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<NoDup, E> {
                Ok(NoDup(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDup, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<NoDup>()? {
                    values.push(value.0);
                }
                Ok(NoDup(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDup, A::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, NoDup>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(NoDup(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(NoDupVisitor)
    }
}

pub fn canonical_bytes<T: PackageRecord>(record: &T) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(&serde_json::to_value(record).expect("record serialization"))
            .expect("canonical JSON");
    bytes.push(b'\n');
    bytes
}

pub fn parse_canonical<T: PackageRecord>(bytes: &[u8]) -> Result<T, PackageError> {
    let value = decode_closed_json(bytes)?;
    let mut canonical =
        serde_json::to_vec(&value).map_err(|e| PackageError::invalid(e.to_string()))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(PackageError::invalid("noncanonical JSON bytes"));
    }
    let record: T =
        serde_json::from_value(value).map_err(|e| PackageError::invalid(e.to_string()))?;
    record.validate()?;
    if canonical_bytes(&record) != bytes {
        return Err(PackageError::invalid(
            "typed record changed canonical bytes",
        ));
    }
    Ok(record)
}

// Owning source/config parsers keep their own closed schemas and validation.
// This helper shares only duplicate detection, the size bound and complete JSON decoding.
pub(crate) fn decode_closed_json(bytes: &[u8]) -> Result<Value, PackageError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(PackageError::invalid(
            "record length exceeds 1 MiB or is empty",
        ));
    }
    let value: NoDup =
        serde_json::from_slice(bytes).map_err(|e| PackageError::invalid(e.to_string()))?;
    Ok(value.0)
}

#[derive(Clone, Debug)]
pub struct AdmittedMetadata {
    pub input_bytes: Arc<[u8]>,
    pub inputs: BuildInputs,
    pub input_id: Digest,
    pub contract_id: Digest,
    pub payload_id: Digest,
}

pub fn verify_metadata(
    contract: &BundleContract,
    payload: &PayloadManifest,
    input_bytes: Arc<[u8]>,
) -> Result<AdmittedMetadata, PackageError> {
    contract.validate()?;
    payload.validate()?;
    let inputs = parse_canonical::<BuildInputs>(&input_bytes)?;
    let input_id = sha256(&input_bytes);
    let contract_bytes = canonical_bytes(contract);
    let contract_id = sha256(&contract_bytes);
    if contract.input_id != input_id
        || payload.input_id != input_id
        || payload.build_inputs.sha256 != input_id
        || payload.build_inputs.bytes != input_bytes.len() as u64
        || payload.contract.sha256 != contract_id
        || payload.contract.bytes != contract_bytes.len() as u64
        || payload.bundle_id != contract_id
        || contract.source != inputs.source
        || payload.source != inputs.source
        || contract.product_version != inputs.product_version
        || payload.product_version != inputs.product_version
        || contract.host_profile != inputs.host_profile
        || payload.host_profile != inputs.host_profile
        || payload.locks != inputs.locks
        || payload.recipe != inputs.recipe
        || payload.tools != inputs.tools
        || contract.roles != payload.roles
    {
        return Err(PackageError::invalid(
            "build-input/contract/payload binding mismatch",
        ));
    }
    Ok(AdmittedMetadata {
        input_bytes,
        inputs,
        input_id,
        contract_id,
        payload_id: sha256(&canonical_bytes(payload)),
    })
}

// V2 identity admission records; recipe versions remain independent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInputsV2 {
    pub schema: String,
    pub source: SourceIdentity,
    pub product_version: String,
    pub package_epoch: u32,
    pub package_revision: u32,
    pub source_epoch: u64,
    pub host_profile: HostProfile,
    pub locks: LockIdentity,
    pub recipe: RecipeIdentity,
    pub tools: ToolInventory,
    pub jobs: u16,
    pub argv: Vec<String>,
    pub environment: Vec<EnvironmentEntry>,
    pub offline_inventory_sha256: Digest,
    pub identity_abi: u32,
    pub custody_protocol: u32,
    pub identity_profile_sha256: Digest,
}
impl BuildInputsV2 {
    pub fn legacy_fields(&self) -> BuildInputs {
        BuildInputs {
            schema: "osslscope-build-inputs-v1".into(),
            source: self.source.clone(),
            product_version: self.product_version.clone(),
            package_epoch: self.package_epoch,
            package_revision: self.package_revision,
            source_epoch: self.source_epoch,
            host_profile: self.host_profile.clone(),
            locks: self.locks.clone(),
            recipe: self.recipe.clone(),
            tools: self.tools.clone(),
            jobs: self.jobs,
            argv: self.argv.clone(),
            environment: self.environment.clone(),
            offline_inventory_sha256: self.offline_inventory_sha256,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleContractV2 {
    pub schema: String,
    pub input_id: Digest,
    pub source: SourceIdentity,
    pub product_version: String,
    pub host_profile: HostProfile,
    pub wire_abi: u32,
    pub loader_contract_sha256: Digest,
    pub roles: Vec<RoleEntry>,
    pub identity_abi: u32,
    pub custody_protocol: u32,
    pub identity_profile_sha256: Digest,
    pub custody_host: HostEntry,
}
impl BundleContractV2 {
    pub fn legacy_fields(&self) -> BundleContract {
        BundleContract {
            schema: "osslscope-bundle-contract-v1".into(),
            input_id: self.input_id,
            source: self.source.clone(),
            product_version: self.product_version.clone(),
            host_profile: self.host_profile.clone(),
            wire_abi: self.wire_abi,
            loader_contract_sha256: self.loader_contract_sha256,
            roles: self
                .roles
                .iter()
                .filter(|e| e.role != Role::Identity)
                .cloned()
                .collect(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadManifestV2 {
    pub schema: String,
    pub bundle_id: Digest,
    pub contract: ContentEntry,
    pub input_id: Digest,
    pub build_inputs: ContentEntry,
    pub host: HostEntry,
    pub roles: Vec<RoleEntry>,
    pub source: SourceIdentity,
    pub product_version: String,
    pub host_profile: HostProfile,
    pub locks: LockIdentity,
    pub recipe: RecipeIdentity,
    pub tools: ToolInventory,
    pub install: InstallDeclaration,
    pub docs: Vec<ContentEntry>,
    pub licenses: Vec<ContentEntry>,
    pub notices: Vec<ContentEntry>,
    pub sbom: ContentEntry,
    pub identity_abi: u32,
    pub custody_protocol: u32,
    pub identity_profile_sha256: Digest,
    pub custody_host: HostEntry,
}
impl PayloadManifestV2 {
    pub fn legacy_fields(&self) -> PayloadManifest {
        PayloadManifest {
            schema: "osslscope-payload-manifest-v1".into(),
            bundle_id: self.bundle_id,
            contract: self.contract.clone(),
            input_id: self.input_id,
            build_inputs: self.build_inputs.clone(),
            host: self.host.clone(),
            roles: self
                .roles
                .iter()
                .filter(|e| e.role != Role::Identity)
                .cloned()
                .collect(),
            source: self.source.clone(),
            product_version: self.product_version.clone(),
            host_profile: self.host_profile.clone(),
            locks: self.locks.clone(),
            recipe: self.recipe.clone(),
            tools: self.tools.clone(),
            install: self.install.clone(),
            docs: self.docs.clone(),
            licenses: self.licenses.clone(),
            notices: self.notices.clone(),
            sbom: self.sbom.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevAdmissionV2 {
    pub schema: String,
    pub build_inputs: ContentEntry,
    pub contract: ContentEntry,
    pub host: HostEntry,
    pub custody_host: HostEntry,
    pub roles: Vec<RoleEntry>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordVersion {
    V1,
    V2,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AdmittedContract {
    V1(BundleContract),
    V2(BundleContractV2),
}
impl sealed::Sealed for AdmittedContract {}
impl PackageRecord for AdmittedContract {
    fn validate(&self) -> Result<(), PackageError> {
        match self {
            Self::V1(c) => c.validate(),
            Self::V2(c) => c.validate(),
        }
    }
}
impl AdmittedContract {
    pub fn version(&self) -> RecordVersion {
        match self {
            Self::V1(_) => RecordVersion::V1,
            Self::V2(_) => RecordVersion::V2,
        }
    }
}
fn identity_fields(abi: u32, protocol: u32) -> Result<(), PackageError> {
    if abi != 4 || protocol != 1 {
        return Err(PackageError::invalid(
            "unsupported identity ABI/custody protocol",
        ));
    }
    Ok(())
}
fn check_roles_v2(roles: &[RoleEntry]) -> Result<(), PackageError> {
    if roles.len() != 4 || !roles.iter().any(|r| r.role == Role::Identity) {
        return Err(PackageError::invalid("v2 requires exactly four roles"));
    }
    let legacy: Vec<_> = roles
        .iter()
        .filter(|r| r.role != Role::Identity)
        .cloned()
        .collect();
    check_roles(&legacy)?;
    let identity = roles.iter().find(|r| r.role == Role::Identity).unwrap();
    if identity.file.as_str() != Role::Identity.file_name() || identity.bytes == 0 {
        return Err(PackageError::invalid("invalid identity role"));
    }
    Ok(())
}
fn check_custody(host: &HostEntry) -> Result<(), PackageError> {
    if host.path.as_str() != "osslscope-identity-custodian"
        || host.bytes == 0
        || host.elf_machine != 62
    {
        return Err(PackageError::invalid("invalid custody host"));
    }
    Ok(())
}
impl sealed::Sealed for BuildInputsV2 {}
impl PackageRecord for BuildInputsV2 {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-build-inputs-v2")?;
        identity_fields(self.identity_abi, self.custody_protocol)?;
        self.legacy_fields().validate()
    }
}
impl sealed::Sealed for BundleContractV2 {}
impl PackageRecord for BundleContractV2 {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-bundle-contract-v2")?;
        identity_fields(self.identity_abi, self.custody_protocol)?;
        check_roles_v2(&self.roles)?;
        check_custody(&self.custody_host)?;
        self.legacy_fields().validate()
    }
}
impl sealed::Sealed for PayloadManifestV2 {}
impl PackageRecord for PayloadManifestV2 {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-payload-manifest-v2")?;
        identity_fields(self.identity_abi, self.custody_protocol)?;
        check_roles_v2(&self.roles)?;
        check_custody(&self.custody_host)?;
        let legacy = self.legacy_fields();
        legacy.validate()?;
        let mut paths = HashSet::new();
        for path in std::iter::once(self.contract.path.as_str())
            .chain(std::iter::once(self.build_inputs.path.as_str()))
            .chain(std::iter::once(self.host.path.as_str()))
            .chain(std::iter::once(self.custody_host.path.as_str()))
            .chain(self.roles.iter().map(|r| r.file.as_str()))
            .chain(
                self.docs
                    .iter()
                    .chain(&self.licenses)
                    .chain(&self.notices)
                    .map(|e| e.path.as_str()),
            )
            .chain(std::iter::once(self.sbom.path.as_str()))
        {
            if !paths.insert(path) {
                return Err(PackageError::invalid("v2 payload repeats path"));
            }
        }
        Ok(())
    }
}
impl sealed::Sealed for DevAdmissionV2 {}
impl PackageRecord for DevAdmissionV2 {
    fn validate(&self) -> Result<(), PackageError> {
        check_schema(&self.schema, "osslscope-dev-admission-v2")?;
        check_content(&self.build_inputs)?;
        check_content(&self.contract)?;
        check_custody(&self.custody_host)?;
        check_roles_v2(&self.roles)?;
        if self.build_inputs.path.as_str() != "build-inputs.json"
            || self.contract.path.as_str() != "bundle-contract.json"
            || self.host.path.as_str() != "osslscope"
            || self.host.bytes == 0
            || self.host.elf_machine != 62
        {
            return Err(PackageError::invalid("invalid dev admission paths/host"));
        }
        Ok(())
    }
}
pub fn verify_contract_v2(
    c: &BundleContractV2,
    i: &BuildInputsV2,
    input_bytes: &[u8],
) -> Result<(), PackageError> {
    c.validate()?;
    i.validate()?;
    if c.input_id != sha256(input_bytes)
        || c.source != i.source
        || c.product_version != i.product_version
        || c.host_profile != i.host_profile
        || c.identity_abi != i.identity_abi
        || c.custody_protocol != i.custody_protocol
        || c.identity_profile_sha256 != i.identity_profile_sha256
    {
        return Err(PackageError::invalid("v2 input/contract binding mismatch"));
    }
    Ok(())
}
pub fn verify_metadata_v2(
    c: &BundleContractV2,
    p: &PayloadManifestV2,
    input_bytes: Arc<[u8]>,
) -> Result<AdmittedMetadata, PackageError> {
    let i: BuildInputsV2 = parse_canonical(&input_bytes)?;
    verify_contract_v2(c, &i, &input_bytes)?;
    p.validate()?;
    let cb = canonical_bytes(c);
    let id = sha256(&cb);
    if p.input_id != c.input_id
        || p.build_inputs.sha256 != c.input_id
        || p.build_inputs.bytes != input_bytes.len() as u64
        || p.bundle_id != id
        || p.contract.sha256 != id
        || p.contract.bytes != cb.len() as u64
        || p.source != i.source
        || p.product_version != i.product_version
        || p.host_profile != i.host_profile
        || p.locks != i.locks
        || p.recipe != i.recipe
        || p.tools != i.tools
        || p.roles != c.roles
        || p.custody_host != c.custody_host
        || p.identity_abi != c.identity_abi
        || p.custody_protocol != c.custody_protocol
        || p.identity_profile_sha256 != c.identity_profile_sha256
    {
        return Err(PackageError::invalid("v2 payload binding mismatch"));
    }
    Ok(AdmittedMetadata {
        input_bytes,
        inputs: i.legacy_fields(),
        input_id: c.input_id,
        contract_id: id,
        payload_id: sha256(&canonical_bytes(p)),
    })
}
