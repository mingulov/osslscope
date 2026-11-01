#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare hash-pinned original archives for build-package.py.

This acquisition step may copy verified files from the local Cargo cache or
download the exact official archives named by the two Cargo.lock files and
packaging/runtime-sources.json. Every staged byte is SHA-256 verified.
build-package.py itself remains offline and repeats those checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_ARCHIVE_BYTES = 128 << 20


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified(path, checksum, size=None):
    return (
        path.is_file()
        and not path.is_symlink()
        and (size is None or path.stat().st_size == size)
        and sha256(path) == checksum
    )


def download(url, destination, checksum, size=None):
    temporary = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(
        url, headers={"User-Agent": "osslscope-source-archive-prep"}
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            with temporary.open("wb") as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise ValueError(f"download exceeds size bound: {url}")
                    output.write(chunk)
        if not verified(temporary, checksum, size):
            raise ValueError(f"download hash or size mismatch: {url}")
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def locked_crates():
    wanted = {}
    for lock_path in (ROOT / "Cargo.lock", ROOT / "crates/ebpf/Cargo.lock"):
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        for package in lock.get("package", []):
            if package.get("source") != REGISTRY:
                continue
            checksum = package.get("checksum")
            if not checksum:
                raise ValueError(f"registry package lacks checksum: {package}")
            key = (package["name"], package["version"])
            previous = wanted.setdefault(key, checksum)
            if previous != checksum:
                raise ValueError(f"inconsistent locked checksum: {key}")
    return wanted


def runtime_inputs():
    pins = json.loads((ROOT / "packaging/runtime-sources.json").read_text())
    if pins.get("schema") != "osslscope-runtime-sources-v1":
        raise ValueError("unreviewed runtime source pins")
    return pins


def cache_roots(explicit):
    if explicit:
        return explicit
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    return sorted((cargo_home / "registry/cache").glob("*"))


def stage_one(destination, checksum, *, size=None, cache_file=None, url=None, offline=False):
    if verified(destination, checksum, size):
        return "existing"
    for candidate in cache_file or ():
        if verified(candidate, checksum, size):
            shutil.copy2(candidate, destination)
            return "cache"
    if offline:
        return None
    if url is None:
        raise ValueError(f"no acquisition source for {destination.name}")
    download(url, destination, checksum, size)
    return "download"


def prepare(output, caches, offline=False):
    output.mkdir(parents=True, exist_ok=True)
    pins = runtime_inputs()
    wanted = {}
    for (name, version), checksum in locked_crates().items():
        wanted[f"{name}-{version}.crate"] = {
            "sha256": checksum,
            "bytes": None,
            "url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
        }
    for crate in pins["host_std_crates"]:
        name, version = crate["name"], crate["version"]
        prior = wanted.get(f"{name}-{version}.crate")
        if prior and prior["sha256"] != crate["sha256"]:
            raise ValueError(f"runtime crate pin disagrees with lock: {name} {version}")
        wanted[f"{name}-{version}.crate"] = {
            "sha256": crate["sha256"],
            "bytes": crate["bytes"],
            "url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
        }
    for component in pins["components"]:
        archive = component["archive"]
        if Path(archive).name != archive:
            raise ValueError(f"invalid runtime archive name: {archive}")
        wanted[archive] = {
            "sha256": component["sha256"],
            "bytes": component["bytes"],
            "url": component["url"],
        }

    counts = {"existing": 0, "cache": 0, "download": 0}
    missing = []
    for filename, spec in sorted(wanted.items()):
        cached = [root / filename for root in caches]
        outcome = stage_one(
            output / filename,
            spec["sha256"],
            size=spec["bytes"],
            cache_file=cached,
            url=spec["url"],
            offline=offline,
        )
        if outcome is None:
            missing.append(filename)
        else:
            counts[outcome] += 1
    if missing:
        for filename in missing:
            print(f"missing source archive: {filename}", file=sys.stderr)
        return 3
    print(
        "source archives ready: "
        f"{sum(counts.values())} files "
        f"({counts['existing']} existing, {counts['cache']} cached, "
        f"{counts['download']} downloaded)"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        action="append",
        default=[],
        help="Cargo registry cache directory (repeatable)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use only the output directory and local Cargo cache",
    )
    args = parser.parse_args()
    try:
        return prepare(args.output, cache_roots(args.cache_dir), args.offline)
    except (OSError, ValueError, tomllib.TOMLDecodeError, urllib.error.URLError) as error:
        print(f"source archive preparation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
