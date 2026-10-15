"""Use synthetic scans only. These values are not customer results."""

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import generate_report as report


def grype_scan(severities):
    return {"matches": [{"vulnerability": {"id": f"CVE-2026-{index:04d}", "severity": sev},
                         "artifact": {"name": "example-package", "version": "1.0"}}
                        for index, sev in enumerate(severities)]}


def trivy_scan(severities):
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": "example:1",
            "Results": [{"Target": "example", "Vulnerabilities": [
                {"VulnerabilityID": f"CVE-2026-{index:04d}", "Severity": sev}
                for index, sev in enumerate(severities)]}]}


def fixture(root, scanner="grype"):
    scan = grype_scan if scanner == "grype" else trivy_scan
    for name, severities in (("before", ["Critical", "High", "High", "Low", "Unknown"]),
                             ("after", ["Low"])):
        (root / f"{name}.json").write_text(json.dumps(scan(severities)))

    def side(name, size_bytes):
        return {"ref": f"trial-{name}:api", "image_id": "sha256:" + ("a" if name == "before" else "b") * 64,
                "platform": "linux/amd64", "size_bytes": size_bytes, "scan": f"{name}.json",
                "scanned_at": "2026-10-15T10:00:00Z", "command": f"{scanner} synthetic scan {name}",
                "scanner": {"name": scanner, "version": "test-version", "database": "test-db",
                            "settings": "synthetic settings; all severities"}}

    return {"schema_version": 1, "project": "SYNTHETIC DEMO - Example project",
            "repository": "https://example.invalid/customer/project", "branch": "chainguard-trial",
            "organization": "example-org", "generated_at": "2026-10-15T12:00:00Z",
            "notes": ["SYNTHETIC DATA. This report tests the generator. It is not a customer result."],
            "services": [{"name": "api", "status": "migrated", "build": "passed",
                          "smoke_test": "passed", "tests": "not run",
                          "notes": ["Synthetic test fixture. No application test ran."],
                          "commands": ["synthetic build command"],
                          "before": side("before", 100 * 1024**2),
                          "after": side("after", 25 * 1024**2)}]}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = fixture(self.root)

    def model(self):
        path = self.root / "trial.json"
        path.write_text(json.dumps(self.manifest))
        return report.build_model(path)

    def test_measured_totals_severities_and_evidence_checksums(self):
        model = self.model()
        summary = model["summary"]
        self.assertEqual((summary["findings_before"], summary["findings_after"]), (5, 1))
        self.assertEqual(summary["reduction_percent"], 80)
        self.assertEqual(summary["critical_high_before"], 3)
        self.assertEqual(summary["counts_before"]["Unknown"], 1)
        self.assertEqual(summary["size_reduction_percent"], 75)
        self.assertEqual(summary["size_pairs"], 1)
        self.assertEqual(len(model["manifest_sha256"]), 64)
        side = model["services"][0]["before"]
        self.assertEqual(len(side["scan_sha256"]), 64)
        self.assertEqual(side["image_id"], "sha256:" + "a" * 64)

    def test_trivy_and_grype_count_the_same_synthetic_findings(self):
        grype = self.model()["summary"]
        self.manifest = fixture(self.root, "trivy")
        self.assertEqual(self.model()["summary"], grype)

    def test_other_advisory_ids_and_negligible_remain_visible(self):
        raw = grype_scan(["Negligible", "UNRECOGNIZED", None])
        raw["matches"][0]["vulnerability"]["id"] = "GHSA-example"
        (self.root / "after.json").write_text(json.dumps(raw))
        summary = self.model()["summary"]
        self.assertEqual(summary["findings_after"], 3)
        self.assertEqual(summary["counts_after"]["Negligible"], 1)
        self.assertEqual(summary["counts_after"]["Unknown"], 2)

    def test_matches_are_not_deduplicated_into_unique_cves(self):
        match = grype_scan(["High"])["matches"][0]
        (self.root / "after.json").write_text(json.dumps({"matches": [match, match]}))
        self.assertEqual(self.model()["summary"]["findings_after"], 2)

    def test_zero_baseline_has_no_reduction_percentage(self):
        (self.root / "before.json").write_text(json.dumps(grype_scan([])))
        summary = self.model()["summary"]
        self.assertEqual(summary["findings_before"], 0)
        self.assertEqual(summary["findings_removed"], -1)
        self.assertIsNone(summary["reduction_percent"])

    def test_clean_after_scan_is_a_real_zero(self):
        (self.root / "after.json").write_text(json.dumps(grype_scan([])))
        summary = self.model()["summary"]
        self.assertEqual(summary["findings_after"], 0)
        self.assertEqual(summary["reduction_percent"], 100)

    def test_trivy_allows_omitted_results_for_clean_image(self):
        self.manifest = fixture(self.root, "trivy")
        raw = {"SchemaVersion": 2, "ArtifactType": "container_image"}
        (self.root / "after.json").write_text(json.dumps(raw))
        self.assertEqual(self.model()["summary"]["findings_after"], 0)

    def test_increase_has_a_negative_reduction(self):
        (self.root / "after.json").write_text(json.dumps(grype_scan(["High"] * 10)))
        summary = self.model()["summary"]
        self.assertEqual(summary["reduction_percent"], -100)
        self.assertEqual(summary["findings_removed"], -5)

    def test_missing_scan_does_not_become_zero(self):
        (self.root / "after.json").unlink()
        model = self.model()
        self.assertEqual(model["summary"]["compared"], 0)
        self.assertIsNone(model["summary"]["findings_before"])
        self.assertIsNone(model["summary"]["findings_after"])
        self.assertIsNone(model["summary"]["counts_before"])
        self.assertIn("after:", model["services"][0]["exclusion"])

    def test_partial_trial_counts_only_the_valid_pair(self):
        for status in ("blocked", "skipped", "pending"):
            row = copy.deepcopy(self.manifest["services"][0])
            row.update(name=status, status=status, after=None, build="not run")
            self.manifest["services"].append(row)
        model = self.model()
        self.assertEqual(model["summary"]["in_scope"], 4)
        self.assertEqual(model["summary"]["compared"], 1)
        self.assertEqual(model["summary"]["findings_before"], 5)
        for status in ("blocked", "skipped", "pending"):
            self.assertEqual(model["summary"][status], 1)

    def test_incompatible_pairs_are_excluded(self):
        original = copy.deepcopy(self.manifest)
        for field in ("name", "version", "database", "settings", "platform"):
            with self.subTest(field=field):
                self.manifest = copy.deepcopy(original)
                after = self.manifest["services"][0]["after"]
                target = after if field == "platform" else after["scanner"]
                target[field] = "different"
                model = self.model()
                self.assertEqual(model["summary"]["compared"], 0)
                self.assertTrue(model["services"][0]["exclusion"])

    def test_project_totals_do_not_mix_scanner_databases(self):
        other = copy.deepcopy(self.manifest["services"][0])
        other["name"] = "worker"
        for side in ("before", "after"):
            other[side]["scanner"]["database"] = "different-db"
        self.manifest["services"].append(other)
        model = self.model()
        self.assertEqual(model["summary"]["compared"], 1)
        self.assertIn("other included services", model["services"][1]["exclusion"])

    def test_failed_checks_are_excluded_and_unrun_tests_stay_explicit(self):
        original = copy.deepcopy(self.manifest)
        for check in ("build", "smoke_test", "tests"):
            self.manifest = copy.deepcopy(original)
            self.manifest["services"][0][check] = "failed"
            self.assertEqual(self.model()["summary"]["compared"], 0)
        self.manifest = original
        model = self.model()
        self.assertEqual(model["summary"]["compared"], 1)
        self.assertEqual(model["services"][0]["tests"], "not run")

    def test_missing_size_uses_separate_coverage(self):
        self.manifest["services"][0]["after"]["size_bytes"] = None
        summary = self.model()["summary"]
        self.assertEqual(summary["compared"], 1)
        self.assertEqual(summary["size_pairs"], 0)
        self.assertIsNone(summary["size_before_bytes"])
        self.assertIsNone(summary["size_after_bytes"])

    def test_invalid_json_and_schema_never_look_clean(self):
        for data in ("", "{}", '{"matches": null}', '{"matches": [{}]}',
                     '{"matches": [{"vulnerability": {"severity": "High"}}]}'):
            with self.subTest(data=data):
                (self.root / "after.json").write_text(data)
                self.assertEqual(self.model()["summary"]["compared"], 0)

    def test_scan_version_and_image_identity_must_match(self):
        raw = grype_scan([])
        raw["descriptor"] = {"version": "other-version"}
        (self.root / "after.json").write_text(json.dumps(raw))
        self.assertIn("version differs", self.model()["services"][0]["exclusion"])
        raw.pop("descriptor")
        raw["source"] = {"target": {"imageID": "sha256:" + "c" * 64}}
        (self.root / "after.json").write_text(json.dumps(raw))
        self.assertIn("image_id differs", self.model()["services"][0]["exclusion"])

    def test_observed_grype_database_overrides_a_copied_metadata_label(self):
        for name, built in (("before", "2026-10-14T00:00:00Z"), ("after", "2026-10-15T00:00:00Z")):
            raw = grype_scan([])
            raw["descriptor"] = {"db": {"status": {"built": built, "valid": True}}}
            (self.root / f"{name}.json").write_text(json.dumps(raw))
        model = self.model()
        self.assertEqual(model["summary"]["compared"], 0)
        self.assertIn("database", model["services"][0]["exclusion"])

    def test_observed_image_platform_must_match(self):
        raw = grype_scan([])
        raw["source"] = {"target": {"os": "linux", "architecture": "arm64"}}
        (self.root / "after.json").write_text(json.dumps(raw))
        self.assertIn("platform differs", self.model()["services"][0]["exclusion"])

    def test_invalid_database_is_excluded(self):
        raw = grype_scan([])
        raw["descriptor"] = {"db": {"status": {"valid": False}}}
        (self.root / "after.json").write_text(json.dumps(raw))
        self.assertIn("database was not valid", self.model()["services"][0]["exclusion"])

    def test_scan_paths_cannot_escape_the_trial_directory(self):
        for path in ("../outside.json", str(self.root / "after.json")):
            self.manifest["services"][0]["after"]["scan"] = path
            self.assertIn("inside the trial directory", self.model()["services"][0]["exclusion"])

    def test_invalid_manifest_fails_instead_of_claiming_success(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("project", ""), ("services", []), ("schema_version", 7),
                           ("generated_at", "2026-10-15"), ("notes", "not a list")):
            with self.subTest(key=key):
                self.manifest = {**original, key: value}
                with self.assertRaises(ValueError):
                    self.model()
        self.manifest = original
        self.manifest["services"].append(copy.deepcopy(original["services"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate service"):
            self.model()

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "ReportLab is not installed")
    def test_pdf_and_cli_outputs_with_long_refs_and_partial_trial(self):
        row = self.manifest["services"][0]
        row["name"] = "api <staging> & worker"
        row["after"]["ref"] = "registry.example.invalid/" + "long-project-name/" * 20 + "api:1.2.3"
        row["notes"] = ["A & B < C. " + "Long evidence note. " * 100]
        skipped = copy.deepcopy(row)
        skipped.update(name="database", status="skipped", before=None, after=None)
        self.manifest["services"].append(skipped)
        self.model()
        result = subprocess.run([sys.executable, str(Path(report.__file__)), str(self.root / "trial.json")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "VALUE-REPORT.pdf").read_bytes().startswith(b"%PDF-"))
        metrics = json.loads((self.root / "metrics.json").read_text())
        self.assertEqual(metrics["summary"]["reduction_percent"], 80)
        self.assertEqual(metrics["summary"]["compared"], 1)
        self.assertEqual(metrics["summary"]["in_scope"], 2)
        for raw in (grype_scan([]), {}):
            (self.root / "before.json").write_text(json.dumps(raw))
            model = self.model()
            report.render_pdf(model, self.root / "edge-case.pdf")
            self.assertTrue((self.root / "edge-case.pdf").read_bytes().startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
