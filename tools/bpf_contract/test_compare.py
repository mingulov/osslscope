# SPDX-License-Identifier: GPL-3.0-or-later
"""Controller controls use fake processes; real compatibility needs Rust probes."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import compare


class MathematicalOracleTest(unittest.TestCase):
    def test_scalar_endpoints(self):
        self.assertEqual(compare.expected_for({"id": "x", "domain": "scalar", "request": ["s", "make_seq", "65535,18446744073709551615"]}), ["s", "18446744073709551615"])
        self.assertEqual(compare.expected_for({"id": "x", "domain": "scalar", "request": ["s", "lat_bucket", "32767"]}), ["s", "14"])
        self.assertEqual(compare.expected_for({"id": "x", "domain": "scalar", "request": ["s", "loss_for_skip_cause", "255"]}), ["s", "0"])

    def test_fnv_and_classification(self):
        # RFC 9923 FNV-1a-64("a") is 0xaf63dc4c8601ec8c.
        self.assertEqual(compare.fnv(b"a"), 0xAF63DC4C8601EC8C)
        entry = "0000000000000000"  # A wrong key must remain unknown.
        case = {"id": "a", "domain": "algorithm", "request": ["a", "1", "0", (b"a" + bytes(127)).hex(), f"{entry}:{(bytes(42)).hex()}"]}
        self.assertEqual(compare.expected_for(case), ["a", "65535", "0", "1"])


class FramingTest(unittest.TestCase):
    def setUp(self):
        self.case = {"id": "case_1", "domain": "scalar", "request": ["s", "make_key", "1,2"], "expected": ["s", "4294967298"]}

    def test_exact_good_response(self):
        compare.parse_response(b"OSSLBC1\ncase_1\ts\t4294967298\n", [self.case])

    def test_truncated_output(self):
        with self.assertRaises(compare.ContractError):
            compare.parse_response(b"OSSLBC1\n", [self.case])

    def test_wrong_duplicate_extra_ids(self):
        for data in (b"OSSLBC1\nwrong\ts\t4294967298\n", b"OSSLBC1\ncase_1\ts\t4294967298\ncase_1\ts\t4294967298\n", b"OSSLBC1\ncase_1\ts\t4294967298\nextra\ts\t0\n"):
            with self.subTest(data=data), self.assertRaises(compare.ContractError):
                compare.parse_response(data, [self.case])

    def test_version_extra_fields_and_incomplete_line(self):
        for data in (b"OSSLBC2\ncase_1\ts\t4294967298\n", b"OSSLBC1\ncase_1\ts\t4294967298\textra\n", b"OSSLBC1\ncase_1\ts\t4294967298"):
            with self.subTest(data=data), self.assertRaises(compare.ContractError):
                compare.parse_response(data, [self.case])

    def test_identical_wrong_probes_fail_math(self):
        with tempfile.TemporaryDirectory() as td:
            directory = pathlib.Path(td)
            vector = directory / "vectors.json"
            vector.write_text(json.dumps({"version": 1, "cases": [self.case]}))
            candidate = directory / "candidate"
            reference = directory / "reference"
            for executable in (candidate, reference):
                executable.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nprint('OSSLBC1\\ncase_1\\ts\\t0')\n")
                executable.chmod(0o755)
            with self.assertRaises(compare.ContractError):
                compare.compare(candidate, reference, vector, directory / "report.json")

    def test_same_executable_identity_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "same"
            p.write_bytes(b"x")
            vector = pathlib.Path(td) / "v.json"
            vector.write_text(json.dumps({"version": 1, "cases": [self.case]}))
            with self.assertRaises(compare.ContractError):
                compare.compare(p, p, vector, pathlib.Path(td) / "r.json")

    def test_vector_version_and_expected_are_strict(self):
        for bad in (
            {"version": 2, "cases": [self.case]},
            {"version": True, "cases": [self.case]},
            {"version": 1.0, "cases": [self.case]},
            {"version": 1, "cases": [{**self.case, "expected": ["s", "0"]}]},
            {"version": 1, "cases": [self.case, self.case]},
            {"version": 1, "cases": [{**self.case, "request": []}]},
        ):
            with tempfile.TemporaryDirectory() as td:
                p = pathlib.Path(td) / "v.json"
                p.write_text(json.dumps(bad))
                with self.assertRaises(compare.ContractError):
                    compare.load_vectors(p)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "v.json"
            p.write_text('{"version":1,"version":1,"cases":' + json.dumps([self.case]) + '}')
            with self.assertRaises(compare.ContractError):
                compare.load_vectors(p)

    def test_cli_controls_are_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            vector = d / "v.json"
            vector.write_text(json.dumps({"version": 1, "cases": [self.case]}))
            good = d / "good"
            bad = d / "bad"
            good.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nsys.stdout.write('OSSLBC1\\ncase_1\\ts\\t4294967298\\n')\n")
            good.chmod(0o755)
            for label, response in {
                "truncated": "OSSLBC1\n",
                "wrong-id": "OSSLBC1\nwrong\ts\t4294967298\n",
                "duplicate-id": "OSSLBC1\ncase_1\ts\t4294967298\ncase_1\ts\t4294967298\n",
                "extra-line": "OSSLBC1\ncase_1\ts\t4294967298\nextra\ts\t0\n",
                "version": "OSSLBC2\ncase_1\ts\t4294967298\n",
                "extra-cell": "OSSLBC1\ncase_1\ts\t4294967298\textra\n",
                "identical-wrong": "OSSLBC1\ncase_1\ts\t0\n",
            }.items():
                bad.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nsys.stdout.write(" + repr(response) + ")\n# " + label + "\n")
                bad.chmod(0o755)
                reference = bad if label == "identical-wrong" else good
                if label == "identical-wrong":
                    second = d / "second"
                    second.write_text(bad.read_text() + "# distinct executable bytes\n")
                    second.chmod(0o755)
                    reference = second
                run = subprocess.run([sys.executable, str(pathlib.Path(compare.__file__)), "--candidate", str(bad), "--reference", str(reference), "--vectors", str(vector), "--report", str(d / "report.json")], capture_output=True)
                with self.subTest(label=label):
                    self.assertNotEqual(run.returncode, 0)

    def test_report_identity_and_truncation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            vector = d / "v.json"
            vector.write_text(json.dumps({"version": 1, "cases": [self.case]}))
            probes = []
            for i in range(2):
                p = d / f"p{i}"
                p.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nprint('OSSLBC1\\ncase_1\\ts\\t4294967298')\n# " + str(i))
                p.chmod(0o755)
                probes.append(p)
            report = d / "report.json"
            result = compare.compare(*probes, vector, report)
            self.assertIn("source_sha256", result)
            self.assertIn(
                "crates/bpf-contract/examples/support/probe.rs", result["source_sha256"]
            )
            for mutation in (
                lambda r: r.update(case_count=0),
                lambda r: r["identities_sha256"].update(candidate="0" * 64),
                lambda r: r["results"].clear(),
            ):
                saved = json.loads(report.read_text())
                mutation(saved)
                report.write_text(json.dumps(saved))
                with self.assertRaises(compare.ContractError):
                    compare.compare(*probes, vector, report)
                report.write_text(json.dumps(result))


if __name__ == "__main__":
    unittest.main()
