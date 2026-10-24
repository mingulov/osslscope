#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python 3.11+ structural TOML adapter for the separate source validator.

This command seals source inputs. It performs no build, acquisition, install or
BPF operation. Missing mandatory inputs remain prerequisites.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

SOURCE_EPOCH = 1792799804
PROFILES = {
    "gnu": {"target": "x86_64-unknown-linux-gnu", "abi_profile": "linux-x86_64-gnu", "builder": "packaging/builders/gnu.json", "formats": ["deb", "rpm", "prefix"]},
    "musl": {"target": "x86_64-unknown-linux-musl", "abi_profile": "linux-x86_64-musl", "builder": "packaging/builders/musl.json", "formats": ["prefix"]},
}
ARTIFACTS = {"source_archive": "source.tar", "offline_inventory": "offline-inventory.json", "notices": "notices.json", "license_index": "license-index.json", "sbom": "source.spdx.json", "source_availability": "source-availability.json"}


def exact(actual, expected):
    """Check JSON-domain equality without bool/int or nested-type coercion."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
    return actual == expected


def bounded_bytes(path):
    with path.open("rb") as stream:
        data = stream.read(1048577)
    if not data or len(data) > 1048576:
        raise ValueError("configuration is empty or exceeds 1 MiB")
    return data


def release_config(root, profile):
    cargo_bytes = bounded_bytes(root / "Cargo.toml")
    release_bytes = bounded_bytes(root / "packaging/release.toml")
    cargo = tomllib.loads(cargo_bytes.decode("utf-8"))
    release = tomllib.loads(release_bytes.decode("utf-8"))
    package = cargo.get("package", {})
    version = package.get("version")
    if package.get("name") != "osslscope" or type(version) is not str or not version:
        raise ValueError("root Cargo package must provide osslscope's actual version")
    expected = {"schema": "osslscope-release-policy-v1", "package_epoch": 1, "package_revision": 1, "source_epoch": SOURCE_EPOCH, "jobs": 2, "profiles": PROFILES, "artifacts": ARTIFACTS}
    if not exact(release, expected):
        raise ValueError("unknown, missing, mistyped or unsupported release policy")
    if profile not in PROFILES:
        raise ValueError("explicit GNU or musl profile required")
    return {"schema": "osslscope-release-config-v1", "product_version": version, "cargo_toml_sha256": hashlib.sha256(cargo_bytes).hexdigest(), "release_toml_sha256": hashlib.sha256(release_bytes).hexdigest(), "package_epoch": release["package_epoch"], "package_revision": release["package_revision"], "source_epoch": release["source_epoch"], "jobs": release["jobs"], "selected_profile": profile, "profiles": [{"id": name, **release["profiles"][name]} for name in ("gnu", "musl")], "artifacts": release["artifacts"]}


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory JSON key")
        result[key] = value
    return result


def read_json(path):
    return json.loads(bounded_bytes(path), object_pairs_hook=no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--profile", choices=("gnu", "musl"), required=True)
    parser.add_argument("--emit-config", action="store_true", help="print typed configuration without source admission")
    parser.add_argument("--validator", type=Path, help="explicit already-built osslscope-package executable")
    parser.add_argument("--dependencies", type=Path)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        config = release_config(args.root, args.profile)
        if args.emit_config:
            print(json.dumps(config, sort_keys=True, separators=(",", ":")))
            return 0
        if any(value is None for value in (args.validator, args.dependencies, args.tools, args.inputs, args.output)):
            parser.error("sealing requires --validator, --dependencies, --tools, --inputs and --output")
        if not args.validator.is_absolute():
            parser.error("--validator must name an explicit absolute executable path")
        request = {"config": config, "dependencies": read_json(args.dependencies), "tools": read_json(args.tools)}
        wire = json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
        if len(wire.encode()) > 1048576:
            raise ValueError("sealing request exceeds 1 MiB")
        result = subprocess.run([str(args.validator), "seal-source", "--root", str(args.root), "--inputs", str(args.inputs), "--request", "-", "--output", str(args.output)], input=wire, text=True, check=False)
        return result.returncode
    except FileNotFoundError as error:
        print(f"unavailable required source input: {error.filename}", file=sys.stderr)
        return 3
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"invalid source configuration: {str(error)[:160]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
