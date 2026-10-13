#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ledger-vs-observer oracle for the live-known-n workflow.

Compares the ordinary_ops_driver LEDGER stdout (independent count oracle,
captured via the observer's --workload-out file, never the observer's
own logs) against the observer's observed-crypto-v2 JSON across
current + fenced generations: the ledgered operation must be visible
as executed sites carrying the mode's op, algorithm class(es),
provider class and operation funcids on ONE candidate (split
evidence across candidates is never definite attribution). Per the
fixture contract, exact provider-internal counts are
implementation-defined: they are printed for the calibration record,
never asserted; the ledger lower-bounds observation instead.

Usage: live-oracle.py WORKLOAD_LOG REPORT_JSON MODE
Exits 0 on ORACLE PASS, 1 on ORACLE FAIL, 2 on usage error, 3 on
ORACLE SKIP (version-gated fixture: no observation asserted, and
every current call site treats SKIP as a failure).
"""

import json
import re
import sys

# Fixture mode -> expected OSSL op ids (src/kinds.rs OPS table: DIGEST=1,
# KDF=4, KEYEXCH=11, SIGNATURE=12, KEM=14).
MODE_OPS = {
    "ecdsa": {12},
    "keyexch": {11},
    "kdf": {4},
    "kem": {14},
    "md4": {1},
    "mixed": {1},
}

# Mode -> required algorithm-class sets (existential per leg: EACH set
# must appear on >=1 executed mode-op candidate TOGETHER WITH the
# leg's provider class and, when ledgered, the operation funcid: one
# candidate carries the full tuple). Multiple spellings in one set
# are provider-array aliases of one algorithm: live runs show the
# KEM and SHA2 entries emit OIDs, never friendly names, while
# X25519/HKDF/MD4 emit friendly names (P3 smoke, 2026-10-12).
MODE_CLASSES = {
    "ecdsa": ({"ECDSA"},),  # PROV_NAMES_ECDSA; live-unobserved (G02)
    "keyexch": ({"X25519"},),
    "kdf": ({"HKDF"},),
    "kem": ({"2.16.840.1.101.3.4.4.2", "ML-KEM-768"},),
    "md4": ({"MD4"},),
    "mixed": ({"2.16.840.1.101.3.4.2.1", "SHA2-256"}, {"MD4"}),
}

# Modes whose every executed mode-op site must carry the default
# provider (the fixture loads no other provider there; live: hundreds
# of sites, zero counterexamples). md4/mixed bind per class below.
MODE_PROVIDERS_ALL = {
    "ecdsa": {"default"},
    "keyexch": {"default"},
    "kdf": {"default"},
    "kem": {"default"},
}

# Modes with per-class provider bindings: ((class spellings),
# (accepted provider classes)) tuples, each existential. "unknown" is
# UNRESOLVED_PROVIDER_CLASS (policy.rs): the live honest state for the
# unenrolled legacy.so (T09 gap). Accepted, not enshrined: an MD4
# attributed to default still fails.
MODE_PROVIDERS_BIND = {
    "md4": (
        ({"MD4"}, {"legacy", "unknown"}),
    ),
    "mixed": (
        ({"2.16.840.1.101.3.4.2.1", "SHA2-256"}, {"default"}),
        ({"MD4"}, {"legacy", "unknown"}),
    ),
}

# Mode -> ((ledger counter, {operation funcids})...) (existential: when
# the summed counter is > 0, >=1 executed mode-op candidate per leg
# must carry one of the funcids TOGETHER WITH the leg's class and
# provider). Frozen ABI ids from src/kinds.rs; call paths
# source-confirmed in OpenSSL 3.5.8 crypto/evp/ (DigestSign/
# DigestVerify one-shots; EVP_Digest is Init+Update+Final, never the
# one-shot 5). Setup-only funcids (newctx/init/freectx/params) never
# satisfy an operation counter.
MODE_OPFUNC = {
    "ecdsa": (("signs", {11}), ("verifies", {15})),
    "keyexch": (("derives", {3}),),
    "kdf": (("derives", {5}),),
    "kem": (("encaps", {3}), ("decaps", {5})),
    "md4": (("digests", {3, 4}),),
    "mixed": (("digests", {3, 4}),),
}

FUNC_NAMES = {
    (1, 3): "UPDATE", (1, 4): "FINAL",
    (4, 5): "DERIVE",
    (11, 3): "DERIVE",
    (12, 11): "DIGEST_SIGN", (12, 15): "DIGEST_VERIFY",
    (14, 3): "ENCAPSULATE", (14, 5): "DECAPSULATE",
}


def candidate_matches_operation(candidate, op, algorithm_classes,
                                provider_classes, funcids):
    """Pure single-candidate operation predicate (R09).

    One candidate must carry the FULL operation tuple (op, algorithm
    class, provider class and operation funcid) to witness a
    ledgered operation. Split evidence (class on one candidate,
    provider or funcid on another) never witnesses an operation and
    is never reported as definite attribution. `op` is the accepted
    op-id set (a singleton int is tolerated); `funcids=None` checks
    leg presence (any funcid). Missing keys never match, never crash.
    """
    if isinstance(op, int):
        op = {op}
    if candidate.get("op") not in op:
        return False
    if not (set(algorithm_classes)
            & set(candidate.get("algorithm_classes") or [])):
        return False
    if candidate.get("provider_class") not in provider_classes:
        return False
    if funcids is not None and candidate.get("funcid") not in funcids:
        return False
    return True


def site_definitely_matches_operation(site, op, algorithm_classes,
                                      provider_classes, funcids):
    """Definite single-site operation evidence (R09 fix-round-1).

    A site definitely witnesses an operation only when it executed,
    its candidate set is explicitly complete, and EVERY alternative
    agrees on the full tuple (evidence model: complete set +
    all-match). An unknown (or any non-complete) set, a missing
    candidates_coverage key, an empty set, or conflicting
    alternatives are possible attribution, never definite. Missing
    evidence of candidate-set completeness cannot establish
    certainty (fail closed).
    """
    if site.get("calls", 0) < 1:
        return False
    cands = site.get("candidates", []) or []
    if not cands:
        return False
    if site.get("candidates_coverage") != "complete":
        return False
    return all(candidate_matches_operation(c, op, algorithm_classes,
                                           provider_classes, funcids)
               for c in cands)


def mode_legs(mode):
    """((algorithm-class spellings, accepted provider classes), ...).

    One leg per required class set: ALL-provider modes pair each
    MODE_CLASSES set with the mode-wide provider; per-class modes
    keep their adopted MODE_PROVIDERS_BIND pairs verbatim.
    """
    if mode in MODE_PROVIDERS_ALL:
        allowed = MODE_PROVIDERS_ALL[mode]
        return tuple((classes, allowed) for classes in MODE_CLASSES[mode])
    return MODE_PROVIDERS_BIND[mode]


def fail(msg):
    print("ORACLE FAIL: " + msg)
    return 1


def check_version_v2(v):
    # Mirrors src/schema.rs check_version_v2 (the documented v2
    # reader gate): accepts observed-crypto-v2 (implicit .0) and
    # observed-crypto-v2.<ascii-digits>; rejects other majors and
    # anything unparseable. Minor versions add OPTIONAL keys only,
    # so unknown site keys (e.g. installed_at) are ignored below.
    if not isinstance(v, str) or not v.startswith("observed-crypto-v"):
        return False
    rest = v[len("observed-crypto-v"):]
    if "." in rest:
        major, minor = rest.split(".", 1)
    else:
        major, minor = rest, None
    if major != "2":
        return False
    if minor is None:
        return True
    return bool(re.fullmatch(r"[0-9]+", minor))


def func_label(op, funcid):
    name = FUNC_NAMES.get((op, funcid))
    return "%d%s" % (funcid, " " + name if name else "")


def main(argv):
    if len(argv) != 4:
        print("usage: live-oracle.py WORKLOAD_LOG REPORT_JSON MODE")
        return 2
    workload_log_path, report_path, mode = argv[1], argv[2], argv[3]
    if mode not in MODE_OPS:
        print("unknown mode %r (want one of %s)" % (mode, sorted(MODE_OPS)))
        return 2
    try:
        with open(workload_log_path) as f:
            log = f.read()
    except OSError as e:
        return fail("cannot read workload log %s: %s" % (workload_log_path, e))
    ledgers = re.findall(r"^LEDGER (.*)$", log, re.M)
    if not ledgers:
        return fail("no LEDGER line in workload output")
    if not re.search(r"^ORDDONE mode=%s rc=0$" % re.escape(mode), log, re.M):
        return fail("driver did not complete rc=0 for mode %s" % mode)
    parsed = []
    for line in ledgers:
        try:
            parsed.append(dict(tok.split("=", 1) for tok in line.split()))
        except ValueError:
            # Workload and observer streams are separate files (H9);
            # a corrupt LEDGER line is a fixture bug, never shared-fd
            # interleave. Fail: skipping it would mask lost evidence.
            return fail("corrupt LEDGER line %r (fixture bug, not interleave)"
                        % line)
    # Bounded calibration record: the loop-totals LEDGER is last,
    # so first+last carry the shape without megabytes of spam.
    if len(parsed) <= 50:
        print("ledger: %s" % parsed)
    else:
        print("ledger: %d lines, first=%s last=%s"
              % (len(parsed), parsed[:3], parsed[-3:]))
    if any("skipped" in d for d in parsed):
        print("ORACLE SKIP: version-gated fixture, no observation asserted")
        return 3
    try:
        with open(report_path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        return fail("cannot parse report %s: %s" % (report_path, e))
    if not check_version_v2(rep.get("schema_version")):
        return fail("schema_version is %r, want observed-crypto-v2.x"
                    % (rep.get("schema_version"),))
    # Generation-inclusive site set: current sites plus every fenced
    # bucket's sites. A hit in any generation counts; totals sum all.
    collect = [("current", s) for s in rep.get("sites", [])]
    buckets = rep.get("fenced", []) or []
    for b in buckets:
        gen = b.get("generation")
        for s in b.get("sites", []):
            collect.append(("fenced gen %s" % gen, s))
    ngen = 1 + len(buckets)
    total = sum(s.get("calls", 0) for _, s in collect)
    print("observed sites: %d (%d current + %d fenced) total_calls: %d "
          "completeness: %s" % (
              len(collect), len(rep.get("sites", [])),
              len(collect) - len(rep.get("sites", [])), total,
              rep.get("completeness", {}).get("status")))
    # Duplicate join check (T01 conservation: each (site, generation)
    # is counted once): the same identity twice in one generation
    # inflates totals. Same identity in different generations is
    # reincarnation, not a duplicate. Sites without full identity
    # cannot be judged and are skipped, never failed.
    seen = {}
    for where, s in collect:
        if s.get("calls", 0) < 1:
            continue
        if where == "current":
            gen = s.get("generation")
        else:
            gen = where.split()[-1]
            gen = int(gen) if str(gen).isdigit() else gen
        key = (s.get("object"), s.get("device"), s.get("inode"),
               s.get("offset"), gen)
        if any(v is None for v in key):
            continue
        if key in seen:
            return fail("duplicate site %s counted twice in generation %r "
                        "(double join inflates totals; first seen %s)"
                        % (key[:4], gen, seen[key]))
        seen[key] = where
    want = MODE_OPS[mode]
    hits = [(w, s) for w, s in collect
            if s.get("calls", 0) >= 1
            and (want & {c.get("op") for c in s.get("candidates", [])})]
    for w, s in hits[:100]:
        cands = s.get("candidates", [])
        ops = sorted({c.get("op") for c in cands})
        print("  site calls=%d ops=%s [%s]" % (s.get("calls"), ops, w))
    if len(hits) > 100:
        print("  ... %d more hit sites" % (len(hits) - 100))
    if not hits:
        return fail("no executed site carries op %s for mode %s "
                    "(total %d calls over %d sites across %d generations)"
                    % (sorted(want), mode, total, len(collect), ngen))
    op_calls = sum(s.get("calls", 0) for _, s in hits)
    legs = mode_legs(mode)
    for classes, providers in legs:
        if any(site_definitely_matches_operation(
                s, want, classes, providers, None) for _, s in hits):
            continue
        if any(candidate_matches_operation(c, want, classes, providers, None)
               for _, s in hits for c in s.get("candidates", []) or []):
            return fail("no definite op-%s site carries class %r + "
                        "provider %r for mode %s (ambiguous attribution: "
                        "conflicting alternatives or unknown "
                        "candidates_coverage; possible attribution is not "
                        "definite operation evidence)"
                        % (sorted(want), sorted(classes),
                           sorted(providers), mode))
        if not any(classes & set(c.get("algorithm_classes") or [])
                   for _, s in hits for c in s.get("candidates", []) or []
                   if c.get("op") in want):
            return fail("no executed op-%s site carries class %r for mode %s "
                        "(wrong algorithm, e.g. DSA for ECDSA)"
                        % (sorted(want), sorted(classes), mode))
        return fail("no executed op-%s site binds class %r to provider "
                    "%r for mode %s (wrong provider)"
                    % (sorted(want), sorted(classes), sorted(providers),
                       mode))
    if mode in MODE_PROVIDERS_ALL:
        allowed = MODE_PROVIDERS_ALL[mode]
        for w, s in hits:
            provs = {c.get("provider_class") for c in s.get("candidates", [])
                     if c.get("op") in want}
            if not (provs & allowed):
                return fail("executed op-%s site (calls=%d [%s]) carries "
                            "provider %r, want %r for mode %s "
                            "(wrong provider)" % (
                                sorted(want), s.get("calls"), w,
                                sorted(p for p in provs if p is not None),
                                sorted(allowed), mode))
    counters = {}
    for d in parsed:
        for k, v in d.items():
            try:
                counters[k] = counters.get(k, 0) + int(v)
            except (ValueError, TypeError):
                pass
    for counter, funcids in MODE_OPFUNC[mode]:
        if counters.get(counter, 0) <= 0:
            continue
        for classes, providers in legs:
            if any(site_definitely_matches_operation(
                    s, want, classes, providers, funcids)
                   for _, s in hits):
                continue
            op = sorted(want)[0]
            if any(candidate_matches_operation(
                    c, want, classes, providers, funcids)
                   for _, s in hits
                   for c in s.get("candidates", []) or []):
                return fail("ledgered %d %s but no definite site "
                            "carries class %r + provider %r + function %s "
                            "on executed op-%s for mode %s (ambiguous "
                            "attribution: conflicting alternatives or "
                            "unknown candidates_coverage; possible "
                            "attribution is not definite operation "
                            "evidence; no single candidate carries the "
                            "tuple definitely)"
                            % (
                                counters[counter], counter,
                                sorted(classes), sorted(providers),
                                "/".join(func_label(op, f)
                                         for f in sorted(funcids)),
                                sorted(want), mode))
            return fail("ledgered %d %s but no single candidate "
                        "carries class %r + provider %r + function %s on "
                        "executed op-%s for mode %s (wrong function: split "
                        "attribution across candidates is not an operation)"
                        % (
                            counters[counter], counter,
                            sorted(classes), sorted(providers),
                            "/".join(func_label(op, f)
                                     for f in sorted(funcids)),
                            sorted(want), mode))
    # Lower-bound conservation (fixture contract: ledgered ops explain
    # observed execution from below): every loop iteration executes
    # >=1 mode-op callback, so mode-op calls >= ledgered iterations.
    # Exact counts stay implementation-defined (never asserted equal).
    loop_ops = [int(d["ops"]) for d in parsed if "ops" in d]
    if loop_ops and op_calls < max(loop_ops):
        return fail("mode-op calls %d below ledgered %d iterations "
                    "(ledger does not explain observation)"
                    % (op_calls, max(loop_ops)))
    print("ORACLE PASS: ledgered op %s execution is visible in observer JSON "
          "(%d op calls over %d ledgered iterations, aggregate lower "
          "bound, %d generations)"
          % (sorted(want), op_calls, max(loop_ops) if loop_ops else 0, ngen))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
