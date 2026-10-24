// SPDX-License-Identifier: GPL-3.0-or-later
// Shared owned synthetic source fixtures; never actual release inputs.
use super::{
    DependencyInventory, PackageError, ReleaseConfig, SourceTree, ToolInventory, seal_source,
    sha256,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    pub(crate) inputs: PathBuf,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
    pub(crate) config: Value,
    pub(crate) inventory: Value,
    pub(crate) tools: Value,
}
pub(crate) fn bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
impl Fixture {
    pub(crate) fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let private =
            PathBuf::from(std::env::var_os("TMPDIR").expect("leased TMPDIR")).join(format!(
                "package-source-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&private).unwrap();
        let root = private.join("source");
        let inputs = private.join("inputs");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&inputs).unwrap();
        let mut fixture = Self {
            root,
            inputs,
            files: BTreeMap::new(),
            config: Value::Null,
            inventory: Value::Null,
            tools: Value::Null,
        };
        fixture.source("Cargo.toml", format!("[package]\nname = \"osslscope\"\nversion = \"{}\"\nlicense = \"GPL-3.0-or-later\"\n", env!("CARGO_PKG_VERSION")).as_bytes());
        for (path, name, version, license) in [
            (
                "crates/ebpf/Cargo.toml",
                "osslscope-ebpf",
                "0.0.0",
                "GPL-2.0-only",
            ),
            (
                "crates/bpf-contract/Cargo.toml",
                "osslscope-bpf-contract",
                "0.0.0",
                "GPL-2.0-or-later",
            ),
            (
                "crates/ebpf-common/Cargo.toml",
                "osslscope-ebpf-common",
                "0.1.0",
                "GPL-3.0-or-later",
            ),
        ] {
            fixture.source(path, format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nlicense = \"{license}\"\n").as_bytes());
        }
        let host_lock = b"version = 4\n[[package]]\nname = \"osslscope\"\nversion = \"0.1.0\"\n[[package]]\nname = \"osslscope-ebpf-common\"\nversion = \"0.1.0\"\n";
        let bpf_lock = b"version = 4\n[[package]]\nname = \"osslscope-ebpf\"\nversion = \"0.0.0\"\n[[package]]\nname = \"osslscope-bpf-contract\"\nversion = \"0.0.0\"\n";
        fixture.source("Cargo.lock", host_lock);
        fixture.source("crates/ebpf/Cargo.lock", bpf_lock);
        fixture.source("scripts/build-dev.sh", b"#!/bin/sh\nexit 0\n");
        fixture.source("scripts/install-dev.sh", b"#!/bin/sh\nexit 0\n");
        fixture.source(
            "scripts/package-release.py",
            b"# synthetic adapter source\n",
        );
        fixture.source(
            "scripts/package-executor.py",
            b"# synthetic controller source only\n",
        );
        let layout =
            bytes(&json!({"schema":"osslscope-executor-layout-v1","archives":[],"bindings":[]}));
        for profile in ["gnu", "musl"] {
            fixture.source(
                &format!("packaging/builders/{profile}.layout.json"),
                &layout,
            );
        }
        fixture.source("LICENSE", b"synthetic GPL3 license fixture\n");
        fixture.source(
            "LICENSES/GPL-2.0-only.txt",
            b"synthetic GPL2 license fixture\n",
        );
        fixture.source("NOTICE.md", b"Synthetic fixture component index only.\n");
        fixture.source(
            "LICENSES/README.md",
            b"Synthetic fixture license index only.\n",
        );
        fixture.source("AGENTS.md", b"synthetic public source guidance\n");
        std::os::unix::fs::symlink("AGENTS.md", fixture.root.join("CLAUDE.md")).unwrap();
        fixture.source(
            "tests/fixtures/example.json",
            b"{\"public_fixture\":true}\n",
        );
        let release = include_bytes!("../../packaging/release.toml");
        fixture.source("packaging/release.toml", release);
        let mut components = Vec::new();
        for (id, name, version, manifest, spdx) in [
            (
                "host",
                "osslscope",
                "0.1.0",
                "Cargo.toml",
                "GPL-3.0-or-later",
            ),
            (
                "common",
                "osslscope-ebpf-common",
                "0.1.0",
                "crates/ebpf-common/Cargo.toml",
                "GPL-3.0-or-later",
            ),
            (
                "bpf",
                "osslscope-ebpf",
                "0.0.0",
                "crates/ebpf/Cargo.toml",
                "GPL-2.0-only",
            ),
            (
                "contract",
                "osslscope-bpf-contract",
                "0.0.0",
                "crates/bpf-contract/Cargo.toml",
                "GPL-2.0-or-later",
            ),
        ] {
            let terms = fixture.terms(id, spdx);
            components.push(json!({"id":id,"name":name,"version":version,"source":{"kind":"path","manifest":manifest},"terms":terms,"dependencies":[]}));
        }
        let identities: Vec<Value> = [
            ("host", "rustc", "1.88.0"),
            ("bpf", "rustc-bpf", "nightly-2026-05-20"),
            ("linker", "bpf-linker", "0.10.4"),
            ("llvm", "llvm-selected", "fixture"),
            ("builder", "rootfs", "fixture"),
            ("rust-src", "rust-src", "nightly-2026-05-20"),
            ("sysroot", "sysroot", "fixture"),
            ("native-compiler", "cc", "fixture"),
            ("native-linker", "ld", "fixture"),
            ("archive", "tar", "fixture"),
            ("package", "package-format-tools", "fixture"),
            ("host-cargo", "cargo", "1.88.0"),
            ("bpf-cargo", "cargo-bpf", "nightly-2026-05-20"),
            ("llvm-library", "llvm-real-library", "fixture"),
            ("host-sysroot", "rust-host-sysroot", "1.88.0"),
            ("bpf-sysroot", "rust-bpf-sysroot", "nightly-2026-05-20"),
            ("build-compiler", "build-cc", "fixture"),
            ("build-linker", "build-ld", "fixture"),
            ("build-archive", "build-ar", "fixture"),
            ("build-sysroot", "build-sysroot", "fixture"),
            ("executor-host", "executor-host", "fixture"),
            ("executor-layout", "executor-layout", "fixture"),
        ]
        .iter()
        .map(|(role, name, version)| {
            let bytes_role = match *role {
                "build-compiler" => "native-compiler",
                "build-archive" => "archive",
                "build-sysroot" => "sysroot",
                _ => role,
            };
            let data = match *role {
                "executor-host" => {
                    bytes(&json!({"schema":"osslscope-executor-host-v1","files":[],"links":[]}))
                }
                "executor-layout" => layout.clone(),
                _ => format!("synthetic {bytes_role} bytes\n").into_bytes(),
            };
            let content = fixture.input(&format!("tools/{role}.bin"), &data);
            json!({"name":name,"version":version,"sha256":content["sha256"]})
        })
        .collect();
        let mut resources = Vec::new();
        for (i, role) in [
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
            "build-compiler",
            "build-linker",
            "build-archive",
            "build-sysroot",
            "executor-host",
            "executor-layout",
        ]
        .iter()
        .enumerate()
        {
            let acquisition = if *role == "executor-layout" {
                fixture_tar("layout.json", &layout, b'0', "")
            } else {
                fixture_tar("input", b"synthetic input\n", b'0', "")
            };
            let archive = fixture.input(&format!("acquisition/{role}.tar"), &acquisition);
            let source_archive = fixture.input(
                &format!("sources/{role}.tar"),
                &fixture_tar("source.c", b"/* synthetic source */\n", b'0', ""),
            );
            let terms = fixture.terms(role, "MIT");
            components.push(json!({"id":role.to_string()+"-source","name":role,"version":"fixture","source":{"kind":"native","location":"https://example.invalid/synthetic","archive":source_archive},"terms":terms,"dependencies":[]}));
            resources.push(json!({"role":role,"identity":identities[i],"content":fixture.entry(&format!("tools/{role}.bin")),"acquisition":archive,"source_component":role.to_string()+"-source"}));
        }
        // Build-std and linker build prerequisites are independent closure members.
        for name in [
            "core",
            "compiler_builtins",
            "stdarch",
            "portable-simd",
            "linker-build",
            "native-runtime",
        ] {
            let source_archive = fixture.input(
                &format!("sources/{name}.tar"),
                &fixture_tar("source", b"synthetic source\n", b'0', ""),
            );
            let terms = fixture.terms(name, "MIT");
            components.push(json!({"id":name,"name":name,"version":"fixture","source":{"kind":"native","location":"https://example.invalid/synthetic","archive":source_archive},"terms":terms,"dependencies":[]}));
        }
        fixture.tools = json!({"host":identities[0],"bpf":identities[1],"linker":identities[2],"llvm":identities[3],"builder":identities[4],"components":identities[5..]});
        for (id, target, abi, formats) in [
            (
                "gnu",
                "x86_64-unknown-linux-gnu",
                "linux-x86_64-gnu",
                json!(["deb", "rpm", "prefix"]),
            ),
            (
                "musl",
                "x86_64-unknown-linux-musl",
                "linux-x86_64-musl",
                json!(["prefix"]),
            ),
        ] {
            let profile = json!({"target":target,"abi_profile":abi,"abi_floor":"synthetic measured fixture only"});
            let abi_receipt = fixture.input(&format!("abi/{id}.json"), &bytes(&json!({"schema":"osslscope-abi-evidence-v1","host_profile":profile,"cells":[{"name":"synthetic-required-cell","interpreter":{"kind":"dynamic","path":"/synthetic/loader"},"needed":["libc.synthetic"],"symbol_versions":[]}]})));
            let recipe = json!({"schema":"osslscope-build-recipe-v2","profile":id,"host_profile":profile,"tools":fixture.tools,"resources":resources,"abi_evidence":abi_receipt,"required_cells":["synthetic-required-cell"],"argv":["cargo","build","--release","--frozen","--offline","--target",target,"--jobs","2","--bin","osslscope","--message-format=json-render-diagnostics"],"bpf_argv":["cargo","build","--release","--frozen","--offline","-Z","build-std=core","--target","bpfel-unknown-none","--jobs","2","--bin","osslscope-harvest","--bin","osslscope-count","--bin","osslscope-members","--message-format=json-render-diagnostics"],"environment":[{"name":"LC_ALL","value":"C"},{"name":"TZ","value":"UTC"},{"name":"SOURCE_DATE_EPOCH","value":"1792799804"},{"name":"CARGO_NET_OFFLINE","value":"true"},{"name":"CARGO_BUILD_JOBS","value":"2"},{"name":"RUSTFLAGS","value":"--remap-path-prefix=/build=."}],"formats":formats,"jobs":2,"determinism":{"locale":"C","timezone":"UTC","umask":18,"uid":0,"gid":0,"file_mode":420,"executable_mode":493,"symlink_mode":511,"mtime":1792799804,"archive_order":"lexical","compression":"none","path_remap":"--remap-path-prefix=/build=."}});
            fixture.source(&format!("packaging/builders/{id}.json"), &bytes(&recipe));
        }
        fixture.inventory = json!({"schema":"osslscope-dependency-inventory-v1","locks":{"host_sha256":sha256(host_lock),"bpf_sha256":sha256(bpf_lock)},"components":components,"host":["host","common"],"bpf":["bpf","contract"],"tool_sources":resources.iter().map(|r| r["source_component"].clone()).chain(["core","compiler_builtins","stdarch","portable-simd","linker-build"].map(|s|json!(s))).collect::<Vec<_>>(),"build_std":["core","compiler_builtins","stdarch","portable-simd"],"linker_build":["linker-build"],"runtime":["native-runtime"]});
        fixture.config = json!({"schema":"osslscope-release-config-v1","product_version":env!("CARGO_PKG_VERSION"),"cargo_toml_sha256":sha256(&fixture.files["Cargo.toml"]),"release_toml_sha256":sha256(release),"package_epoch":1,"package_revision":1,"source_epoch":1792799804_u64,"jobs":2,"selected_profile":"gnu","profiles":[{"id":"gnu","target":"x86_64-unknown-linux-gnu","abi_profile":"linux-x86_64-gnu","builder":"packaging/builders/gnu.json","formats":["deb","rpm","prefix"]},{"id":"musl","target":"x86_64-unknown-linux-musl","abi_profile":"linux-x86_64-musl","builder":"packaging/builders/musl.json","formats":["prefix"]}],"artifacts":{"source_archive":"source.tar","offline_inventory":"offline-inventory.json","notices":"notices.json","license_index":"license-index.json","sbom":"source.spdx.json","source_availability":"source-availability.json"}});
        fixture
    }
    pub(crate) fn source(&mut self, path: &str, data: &[u8]) {
        let full = self.root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, data).unwrap();
        self.files.insert(path.to_owned(), data.to_vec());
    }
    pub(crate) fn input(&self, path: &str, data: &[u8]) -> Value {
        let full = self.inputs.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, data).unwrap();
        json!({"path":path,"sha256":sha256(data),"bytes":data.len()})
    }
    pub(crate) fn entry(&self, path: &str) -> Value {
        let data = fs::read(self.inputs.join(path)).unwrap();
        json!({"path":path,"sha256":sha256(&data),"bytes":data.len()})
    }
    pub(crate) fn terms(&self, id: &str, spdx: &str) -> Value {
        json!({"spdx":spdx,"license_files":[self.input(&format!("terms/{id}.txt"),format!("Synthetic {id} license fixture; no real grant.\n").as_bytes())],"notice_files":[self.input(&format!("notices/{id}.txt"),format!("Synthetic {id} notice.\n").as_bytes())],"source_availability":self.input(&format!("offers/{id}.txt"),b"All synthetic source retained in this fixture.\n")})
    }
    pub(crate) fn tree(&self) -> SourceTree {
        SourceTree::snapshot(&self.root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }
    pub(crate) fn release(&self) -> ReleaseConfig {
        ReleaseConfig::parse_json(&bytes(&self.config)).unwrap()
    }
    pub(crate) fn dependencies(&self) -> DependencyInventory {
        DependencyInventory::parse_json(&self.inputs, &bytes(&self.inventory)).unwrap()
    }
    pub(crate) fn tool_inventory(&self) -> ToolInventory {
        serde_json::from_value(self.tools.clone()).unwrap()
    }
    pub(crate) fn seal(&self) -> Result<super::SealedSource, PackageError> {
        let config = ReleaseConfig::parse_json(&bytes(&self.config))?;
        let dependencies = DependencyInventory::parse_json(&self.inputs, &bytes(&self.inventory))?;
        seal_source(&self.tree(), &config, &dependencies, &self.tool_inventory())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(self.root.parent().unwrap()).unwrap();
    }
}

// Independently constructed POSIX ustar entries exercise the decoder boundary.
pub(crate) fn fixture_tar(path: &str, data: &[u8], kind: u8, link: &str) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..path.len()].copy_from_slice(path.as_bytes());
    for (offset, width, value) in [
        (100, 8, 0o644_u64),
        (108, 8, 0),
        (116, 8, 0),
        (124, 12, data.len() as u64),
        (136, 12, 1792799804),
    ] {
        let s = format!("{:0width$o}\0", value, width = width - 1);
        h[offset..offset + width].copy_from_slice(s.as_bytes());
    }
    h[148..156].fill(b' ');
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| *b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out.extend_from_slice(&[0; 1024]);
    out
}
