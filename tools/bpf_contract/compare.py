# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent, bounded host comparison for the BPF contract probes."""

import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys


class ContractError(ValueError):
    pass


MAX_LINE = 128 * 1024
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DEC = re.compile(r"(?:0|[1-9][0-9]*)\Z")
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
LIMIT = (1 << 64) - 1
LOSS = (0, 17, 18, 19, 23, 26, 24, 30, 32, 33, 34)
# Independently transcribed offset/width requirements, not probed struct output.
LAYOUT = {
    "CountValue": (24, 8, [8, 8, 8]),
    "PendQuery": (16, 8, [8, 8]),
    "ScanRec": (40, 8, [8, 8, 8, 4, 4, 8]),
    "TCacheValue": (16, 8, [8, 8]),
    "CtrlValue": (24, 8, [4, 1, 3, 8, 8]),
    "AlgEvent": (40, 8, [4, 4, 2, 1, 1, 4, 8, 8, 8]),
    "TripEvent": (16, 4, [4, 4, 2, 1, 1, 4]),
    "RowEvent": (48, 8, [4, 4, 4, 4, 8, 8, 8, 8]),
    "InitRetEvent": (32, 8, [4, 4, 4, 4, 8, 8]),
    "ScanCallEvent": (24, 8, [4, 4, 4, 4, 8]),
    "ScanRetEvent": (40, 8, [4, 4, 4, 4, 8, 8, 8]),
    "GuardEvent": (40, 8, [4, 4, 4, 4, 8, 8, 8]),
    "ScanAlgEvent": (56, 8, [4, 4, 2, 1, 1, 4, 8, 8, 8, 4, 4, 8]),
    "ScanRowEvent": (64, 8, [4, 4, 4, 4, 8, 8, 8, 8, 4, 4, 8]),
    "AlgClassValue": (42, 2, [2, 1, 1, 2, 36]),
    "TripClassValue": (22, 2, [2, 2, 2, 16]),
}
PADS = {"ScanRec": {4}, "CtrlValue": {2}, "AlgEvent": {5}, "TripEvent": {4, 5}, "RowEvent": {3}, "InitRetEvent": {3}, "ScanAlgEvent": {5, 10}, "ScanRowEvent": {3, 9}}
SOURCE_PATHS = (
    "Cargo.toml", "Cargo.lock", "crates/bpf-contract/Cargo.toml",
    "crates/bpf-contract/src/lib.rs", "crates/bpf-contract/src/scalars.rs",
    "crates/bpf-contract/src/classify.rs", "crates/bpf-contract/src/records.rs",
    "crates/bpf-contract/examples/contract_probe.rs",
    "crates/bpf-contract/examples/support/probe.rs",
    "crates/ebpf-common/src/lib.rs", "examples/bpf_contract_reference.rs",
    "tools/bpf_contract/compare.py", "tools/bpf_contract/test_compare.py",
)


def fail(message):
    raise ContractError(message)


def decimal(s, bits=64):
    if not isinstance(s, str) or not DEC.fullmatch(s) or int(s) >= (1 << bits):
        fail("invalid unsigned decimal or width")
    return int(s)


def bytes_hex(s, limit=None):
    if not isinstance(s, str) or not HEX.fullmatch(s) or (limit is not None and len(s) // 2 > limit):
        fail("invalid lowercase byte hex or length")
    return bytes.fromhex(s)


def fnv(data):
    h = 14695981039346656037
    for octet in data:
        h = ((h ^ octet) * 1099511628211) & LIMIT
    return h


def scalar(name, args):
    widths = {"make_key": [32, 32], "lat_bucket": [64], "make_termd": [32, 32], "make_seq": [16, 64], "split_seq": [64], "make_bucket": [8, 64], "split_bucket": [64], "make_rcount": [32, 32], "split_rcount": [64], "make_call_flags": [1, 8], "loss_for_skip_cause": [8]}
    if name not in widths or len(args) != len(widths[name]):
        fail("unknown scalar or arity")
    a = [decimal(s, w) if w != 1 else (decimal(s, 2) if s in ("0", "1") else fail("boolean")) for s, w in zip(args, widths[name])]
    if name == "make_key": out = [(a[0] << 32) + a[1]]
    elif name == "lat_bucket": out = [min(15, max(0, a[0].bit_length() - 1))]
    elif name == "make_termd": out = [(a[1] << 32) + a[0]]
    elif name == "make_seq": out = [(a[0] << 48) + (a[1] % (1 << 48))]
    elif name == "split_seq": out = [a[0] // (1 << 48), a[0] % (1 << 48)]
    elif name == "make_bucket": out = [((a[1] % (1 << 56)) << 8) + a[0]]
    elif name == "split_bucket": out = [a[0] % 256, a[0] // 256]
    elif name == "make_rcount": out = [(a[1] << 32) + a[0]]
    elif name == "split_rcount": out = [a[0] % (1 << 32), a[0] // (1 << 32)]
    elif name == "make_call_flags": out = [a[0] + (a[1] << 8)]
    else: out = [LOSS[a[0]] if a[0] < len(LOSS) else 0]
    return ["s", ",".join(map(str, out))]


def entries(cell, value_size, maximum):
    if cell == "-": return {}
    parts = cell.split(",")
    if len(parts) > maximum: fail("too many entries")
    result = {}
    for part in parts:
        pair = part.split(":")
        if len(pair) != 2 or len(pair[0]) != 16 or len(pair[1]) != value_size * 2:
            fail("entry shape")
        key = int.from_bytes(bytes_hex(pair[0]), "little")
        val = bytes_hex(pair[1])
        if key in result: fail("duplicate table key")
        result[key] = val
    return result


def algorithm(request):
    if len(request) != 5: fail("algorithm request fields")
    length = decimal(request[1], 64)
    sat = decimal(request[2], 1) if request[2] in ("0", "1") else fail("saturation")
    buf = bytes_hex(request[3])
    if len(buf) != 128: fail("algorithm buffer width")
    table = entries(request[4], 42, 1024)
    if sat or length >= 128: return ["a", "65535", "0", "2"]
    weak = False
    best = 65535
    canons = set()
    chunks = buf[:length].split(b":")
    for segment in chunks[:8]:
        value = table.get(fnv(segment))
        if value is None or len(segment) > 36 or value[3] != len(segment): continue
        cls = int.from_bytes(value[:2], "little")
        wk = value[2]
        canon = int.from_bytes(value[4:6], "little")
        if wk not in (0, 1) or not ((cls < 65535 and canon < 65535) or (cls == canon == 65535 and wk == 1)):
            fail("algorithm table outside stable domain")
        weak |= bool(wk)
        if cls < 65535:
            best = min(best, cls)
            canons.add(canon)
    status = 3 if len(chunks) > 8 else 1 if not canons else 5 if len(canons) > 1 else 0
    if status == 3: weak = True
    return ["a", str(best), str(int(weak)), str(status)]


def trip(request):
    if len(request) != 5: fail("trip request fields")
    sat = decimal(request[1], 1) if request[1] in ("0", "1") else fail("saturation")
    if request[2] not in ("E", "L"): fail("taxonomy")
    arg = b"" if request[3] == "-" else bytes_hex(request[3], 1024)
    table = entries(request[4], 22, 64)
    if sat or len(arg) >= 32: return ["t", "0", "2"]
    value = table.get(fnv(arg))
    if value is None or len(arg) > 16 or int.from_bytes(value[4:6], "little") != len(arg) or value[6:6+len(arg)] != arg:
        return ["t", "0", "0"]
    offset = 0 if request[2] == "E" else 2
    return ["t", str(int.from_bytes(value[offset:offset+2], "little")), "0"]


def wire(request):
    if len(request) != 3 or request[1] not in LAYOUT: fail("wire request")
    size, _, widths = LAYOUT[request[1]]
    fields = request[2].split(",")
    if len(fields) != len(widths): fail("wire field count")
    raw = bytearray()
    for i, (cell, width) in enumerate(zip(fields, widths)):
        b = bytes_hex(cell)
        if len(b) != width: fail("wire field width")
        if i in PADS.get(request[1], ()) and any(b): fail("nonzero pad")
        raw.extend(b)
    if len(raw) != size: fail("wire layout size")
    return ["w", raw.hex()]


def expected_for(case):
    request = case.get("request")
    if not isinstance(request, list) or not request or not all(isinstance(x, str) for x in request): fail("request shape")
    if request[0] == "s" and case.get("domain") == "scalar" and len(request) == 3:
        return scalar(request[1], request[2].split(","))
    if request[0] == "a" and case.get("domain") == "algorithm": return algorithm(request)
    if request[0] == "t" and case.get("domain") == "trip": return trip(request)
    if request[0] == "w" and case.get("domain") == "wire": return wire(request)
    fail("request domain")


def load_vectors(path):
    try:
        if path.stat().st_size > 256 * 1024 * 1024: fail("vector file too large")
        obj = json.loads(path.read_bytes(), object_pairs_hook=unique_pairs)
    except (OSError, ValueError) as exc: raise ContractError("vector parse") from exc
    if not isinstance(obj, dict) or set(obj) != {"version", "cases"} or type(obj["version"]) is not int or obj["version"] != 1 or not isinstance(obj["cases"], list) or not obj["cases"]:
        fail("vector version or shape")
    if len(obj["cases"]) > 2000: fail("too many cases")
    ids = set()
    for case in obj["cases"]:
        if not isinstance(case, dict) or set(case) != {"id", "domain", "request", "expected"} or not isinstance(case["id"], str) or not ID.fullmatch(case["id"]) or case["id"] in ids:
            fail("case ID/shape")
        ids.add(case["id"])
        if case["expected"] != expected_for(case): fail("mathematical expected mismatch: " + case["id"])
        line = "\t".join([case["id"], *case["request"]]).encode()
        if len(line) > MAX_LINE or b"\n" in line or b"\r" in line: fail("request line")
    return obj["cases"]


def parse_response(data, cases):
    if not data.endswith(b"\n") or b"\r" in data: fail("incomplete response")
    lines = data.split(b"\n")[:-1]
    if not lines or lines[0] != b"OSSLBC1" or len(lines) != len(cases) + 1: fail("response version/count")
    out = {}
    expected = {c["id"]: c for c in cases}
    for line in lines[1:]:
        if len(line) > MAX_LINE: fail("response line too long")
        try: cells = line.decode("ascii").split("\t")
        except UnicodeDecodeError as exc: raise ContractError("nonascii response") from exc
        if len(cells) < 2 or cells[0] not in expected or cells[0] in out: fail("response ID")
        case = expected[cells[0]]
        wanted = case["expected"]
        if len(cells) != len(wanted) + 1 or cells[1] != wanted[0]: fail("response fields/kind")
        if cells[1] == "w": bytes_hex(cells[2])
        else:
            for cell in cells[2:]:
                for value in cell.split(","): decimal(value)
        out[cells[0]] = cells[1:]
    return out


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj: fail("duplicate JSON key")
        obj[key] = value
    return obj


def read_report(path):
    try: return json.loads(path.read_text(), object_pairs_hook=unique_pairs)
    except (OSError, ValueError) as exc: raise ContractError("invalid existing report") from exc


def compare(candidate, reference, vectors, report):
    candidate, reference, vectors, report = map(pathlib.Path, (candidate, reference, vectors, report))
    if candidate.resolve() == reference.resolve(): fail("same executable identity")
    before = {k: digest(p) for k, p in (("candidate", candidate), ("reference", reference), ("vectors", vectors))}
    if before["candidate"] == before["reference"]: fail("identical executable bytes")
    cases = load_vectors(vectors)
    root = pathlib.Path(__file__).resolve().parents[2]
    sources = {path: digest(root / path) for path in SOURCE_PATHS}
    domains = dict(sorted(collections.Counter(c["domain"] for c in cases).items()))
    expected_results = {c["id"]: {"expected": c["expected"], "reference": c["expected"], "candidate": c["expected"]} for c in cases}
    expected_report = {"version": 1, "identities_sha256": before, "source_sha256": sources, "paths": {"candidate": str(candidate.resolve()), "reference": str(reference.resolve()), "vectors": str(vectors.resolve())}, "case_count": len(cases), "missing_count": 0, "domains": domains, "results": expected_results}
    if report.exists() and read_report(report) != expected_report:
        fail("stale, incomplete, or mismatched existing report")
    request = ("OSSLBC1\n" + "".join("\t".join([c["id"], *c["request"]]) + "\n" for c in cases)).encode("ascii")
    results = {}
    for label, executable in (("reference", reference), ("candidate", candidate)):
        try: run = subprocess.run([str(executable.resolve())], input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc: raise ContractError(label + " execution") from exc
        if run.returncode or run.stderr: fail(label + " exit/stderr")
        results[label] = parse_response(run.stdout, cases)
        if digest(executable) != before[label] or digest(vectors) != before["vectors"] or any(digest(root / path) != value for path, value in sources.items()):
            fail("identity changed during comparison")
    for c in cases:
        name = c["id"]
        if results["reference"][name] != c["expected"] or results["candidate"][name] != c["expected"]:
            fail("oracle disagreement: " + name)
    result = expected_report
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    for flag in ("candidate", "reference", "vectors", "report"): parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    try: result = compare(args.candidate, args.reference, args.vectors, args.report)
    except ContractError as exc:
        print("contract comparison failed: " + str(exc), file=sys.stderr)
        return 1
    print(f"OSSLBC1: {result['case_count']} cases, zero missing, all three oracles agree")
    return 0


if __name__ == "__main__": sys.exit(main())
