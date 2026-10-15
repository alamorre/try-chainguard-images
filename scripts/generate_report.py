#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["reportlab>=4.4,<5"]
# ///
"""Build a project value report from saved Grype or Trivy image scans.

The report shows summary metrics, severity counts, and image evidence.
This module does not build, pull, scan, or upload images.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from html import escape
from pathlib import Path

SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
STATUSES = ("migrated", "blocked", "skipped", "pending")
CHECKS = ("passed", "failed", "not run")
METHOD = (
    "Findings are package-vulnerability matches reported by the scanner. "
    "They include CVE and other advisory identifiers. They are not unique CVEs. "
    "All six severity groups count toward totals. Unknown stays separate from Negligible. "
    "Project totals add findings per service; shared images and packages can count more than once. "
    "Only migrated services with two valid, comparable scans enter finding totals. "
    "Missing scans never count as zero. Size totals use only compared services with both sizes. "
    "Sizes are local Docker image sizes, not download sizes or unique disk use. "
    "A zero baseline has no defined reduction percentage. "
    "These results measure scan findings at the recorded time. They do not measure exploitability, "
    "financial savings, or compliance. Version changes can affect the result."
)


def read_json(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: expected a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def text_field(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key}: expected non-empty text")
    return value


def timestamp(data: dict, key: str) -> str:
    value = text_field(data, key)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing time zone")
    except ValueError as exc:
        raise ValueError(f"{key}: expected an ISO timestamp with a time zone") from exc
    return value


def string_list(data: dict, key: str) -> list[str]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key}: expected a list of strings")
    return value


def scan_counts(raw: dict, scanner: str) -> dict[str, int]:
    """Reject unknown scan shapes instead of treating them as clean scans."""
    if scanner == "grype":
        if not isinstance(raw.get("matches"), list):
            raise ValueError("Grype JSON must contain a matches list")
        records = raw["matches"]
        fields = [(item.get("vulnerability"), "id", "severity") for item in records
                  if isinstance(item, dict)]
        if len(fields) != len(records):
            raise ValueError("invalid Grype match")
    elif scanner == "trivy":
        if raw.get("SchemaVersion") != 2 or raw.get("ArtifactType") != "container_image":
            raise ValueError("expected Trivy schema 2 container image JSON")
        results = raw.get("Results", [])
        if not isinstance(results, list):
            raise ValueError("Trivy Results must be a list")
        fields = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("invalid Trivy result")
            records = result.get("Vulnerabilities")
            if records is None:
                continue  # Trivy omits this field when a target has no findings.
            if not isinstance(records, list):
                raise ValueError("Trivy Vulnerabilities must be a list")
            fields.extend((item, "VulnerabilityID", "Severity") for item in records)
    else:
        raise ValueError(f"unsupported scanner: {scanner}")
    counts = dict.fromkeys(SEVERITIES, 0)
    for record, id_key, severity_key in fields:
        if not isinstance(record, dict):
            raise ValueError("invalid vulnerability record")
        text_field(record, id_key)
        severity = record.get(severity_key) or "Unknown"
        if not isinstance(severity, str):
            raise ValueError("severity must be text")
        severity = severity.title()
        counts[severity if severity in counts else "Unknown"] += 1
    return counts


def load_side(side: dict, root: Path) -> dict:
    if not isinstance(side, dict):
        raise ValueError("scan evidence not recorded")
    for key in ("ref", "image_id", "platform", "scan", "command"):
        text_field(side, key)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", side["image_id"]):
        raise ValueError("image_id must be a sha256 Docker image ID")
    timestamp(side, "scanned_at")
    scanner = side.get("scanner")
    if not isinstance(scanner, dict):
        raise ValueError("scanner metadata not recorded")
    for key in ("name", "version", "database", "settings"):
        text_field(scanner, key)
    scan_path = (root / side["scan"]).resolve()
    if Path(side["scan"]).is_absolute() or not scan_path.is_relative_to(root):
        raise ValueError("scan path must stay inside the trial directory")
    raw, digest = read_json(scan_path)
    name = scanner["name"]
    counts = scan_counts(raw, name)
    observed_database = None
    if name == "grype":
        descriptor = raw.get("descriptor") or {}
        if descriptor.get("version") and descriptor["version"] != scanner["version"]:
            raise ValueError("Grype version differs from the saved scan")
        target = (raw.get("source") or {}).get("target") or {}
        observed_id = target.get("imageID") if isinstance(target, dict) else None
        database = descriptor.get("db") or {}
        status = database.get("status", database)
        if status.get("valid") is False:
            raise ValueError("Grype database was not valid")
        observed_database = {key: status[key] for key in ("built", "checksum", "schemaVersion", "from")
                             if key in status} or None
        observed_os = target.get("os") if isinstance(target, dict) else None
        observed_arch = target.get("architecture") if isinstance(target, dict) else None
    else:
        metadata = raw.get("Metadata") or {}
        observed_id = metadata.get("ImageID")
        config = metadata.get("ImageConfig") or {}
        observed_os, observed_arch = config.get("os"), config.get("architecture")
    if observed_id and observed_id != side["image_id"]:
        raise ValueError("image_id differs from the saved scan")
    if observed_os and observed_arch:
        # The manifest platform can include a variant such as linux/arm64/v8.
        if side["platform"].split("/")[:2] != [observed_os, observed_arch]:
            raise ValueError("platform differs from the saved scan")
    size = side.get("size_bytes")
    if size is not None and (type(size) is not int or size < 0):
        raise ValueError("size_bytes must be a non-negative integer or null")
    return {**side, "counts": counts, "total": sum(counts.values()), "scan_sha256": digest,
            "observed_database": observed_database}


def signature(side: dict) -> tuple:
    scanner = side["scanner"]
    return tuple(scanner[key] for key in ("name", "version", "database", "settings")) + (
        json.dumps(side.get("observed_database"), sort_keys=True),
    )


def reduction(before: int, after: int) -> float | None:
    return round(100 * (before - after) / before, 2) if before else None


def build_model(manifest_path: Path) -> dict:
    manifest_path = manifest_path.resolve()
    manifest, digest = read_json(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("expected manifest schema_version 1")
    for key in ("project", "repository", "branch", "organization"):
        text_field(manifest, key)
    timestamp(manifest, "generated_at")
    string_list(manifest, "notes")
    services = manifest.get("services")
    if not isinstance(services, list) or not services:
        raise ValueError("services must be a non-empty list")
    rows, names, common_scanner = [], set(), None
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("each service must be an object")
        name = text_field(service, "name")
        if name in names:
            raise ValueError(f"duplicate service name: {name}")
        names.add(name)
        if service.get("status") not in STATUSES:
            raise ValueError(f"{name}: invalid migration status")
        for key in ("build", "smoke_test", "tests"):
            if service.get(key) not in CHECKS:
                raise ValueError(f"{name}: {key} must be passed, failed, or not run")
        string_list(service, "notes")
        string_list(service, "commands")
        row = {**service, "included": False, "exclusion": None}
        errors = []
        for key in ("before", "after"):
            supplied = service.get(key)
            row[f"{key}_ref"] = supplied.get("ref") if isinstance(supplied, dict) else None
            try:
                row[key] = load_side(service.get(key), manifest_path.parent)
            except (ValueError, OSError, AttributeError, TypeError) as exc:
                row[key] = None
                errors.append(f"{key}: {exc}")
        if service["status"] != "migrated":
            errors.insert(0, f"migration status: {service['status']}")
        elif service["build"] != "passed":
            errors.insert(0, "build has not passed")
        elif "failed" in (service["smoke_test"], service["tests"]):
            errors.insert(0, "validation failed")
        if not errors:
            before, after = row["before"], row["after"]
            if signature(before) != signature(after):
                errors.append("scanner, version, database, or settings differ")
            elif before["platform"] != after["platform"]:
                errors.append("image platforms differ")
            elif common_scanner is not None and signature(before) != common_scanner:
                errors.append("scanner metadata differs from other included services")
            else:
                common_scanner = signature(before)
                row["included"] = True
        row["exclusion"] = "; ".join(errors) or None
        rows.append(row)

    included = [row for row in rows if row["included"]]
    summary = {"in_scope": len(rows), "compared": len(included),
               **{status: sum(row["status"] == status for row in rows) for status in STATUSES}}
    for side in ("before", "after"):
        summary[f"counts_{side}"] = {
            sev: sum(row[side]["counts"][sev] for row in included) for sev in SEVERITIES
        } if included else None
        summary[f"findings_{side}"] = sum(row[side]["total"] for row in included) if included else None
        summary[f"critical_high_{side}"] = sum(
            row[side]["counts"][sev] for row in included for sev in ("Critical", "High")
        ) if included else None
    before, after = summary["findings_before"], summary["findings_after"]
    summary["findings_removed"] = before - after if included else None
    summary["reduction_percent"] = reduction(before, after) if included else None
    sized = [row for row in included if all(row[key].get("size_bytes") is not None
                                           for key in ("before", "after"))]
    summary["size_pairs"] = len(sized)
    for side in ("before", "after"):
        summary[f"size_{side}_bytes"] = sum(row[side]["size_bytes"] for row in sized) if sized else None
    summary["size_reduction_percent"] = reduction(
        summary["size_before_bytes"], summary["size_after_bytes"]
    ) if sized else None
    return {"schema_version": 1, "project": manifest["project"],
            "repository": manifest["repository"], "branch": manifest["branch"],
            "organization": manifest["organization"], "generated_at": manifest["generated_at"],
            "manifest_sha256": digest, "method": METHOD, "notes": manifest.get("notes", []),
            "summary": summary, "services": rows}


def number(value) -> str:
    return f"{value:,}" if value is not None else "not available"


def percent(value) -> str:
    return f"{value:+.2f}%" if value is not None else "not available"


def size(value) -> str:
    return f"{value / 1024**2:,.1f} MiB" if value is not None else "not available"


def render_pdf(model: dict, output: Path) -> None:
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import (
        KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, TableStyle,
    )

    purple = colors.HexColor("#5A1FFF")
    ink = colors.HexColor("#252D33")
    muted = colors.HexColor("#4A5359")
    styles = getSampleStyleSheet()
    for name, font, font_size, leading, color in (
        ("Title2", "Helvetica-Bold", 25, 29, ink),
        ("Section", "Helvetica-Bold", 13, 17, ink),
        ("Body2", "Helvetica", 9, 13, ink),
        ("Small", "Helvetica", 7.5, 10.5, muted),
        ("Head", "Helvetica-Bold", 8, 11, colors.white),
        ("Metric", "Helvetica-Bold", 21, 27, purple),
    ):
        styles.add(ParagraphStyle(name, fontName=font, fontSize=font_size, leading=leading,
                                  textColor=color, spaceAfter=6, splitLongWords=True))

    def p(value, style="Body2"):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])

    width = A4[0] - 80

    def table(data, widths, header=True):
        item = LongTable(data, colWidths=widths, repeatRows=1 if header else 0,
                         hAlign="LEFT", splitInRow=1)
        commands = [("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]
        if header:
            commands += [("BACKGROUND", (0, 0), (-1, 0), ink),
                         ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                          [colors.white, colors.HexColor("#F3F3F4")])]
        else:
            commands.append(("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1ECFE")))
        item.setStyle(TableStyle(commands))
        return item

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(purple)
        canvas.setLineWidth(2)
        canvas.line(40, A4[1] - 31, A4[0] - 40, A4[1] - 31)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(muted)
        canvas.drawString(40, A4[1] - 24, "CHAINGUARD / PROJECT VALUE REPORT")
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 24, "Project trial | " + model["generated_at"][:10])
        canvas.drawRightString(A4[0] - 40, 24, str(doc.page))
        canvas.restoreState()

    summary = model["summary"]
    story = [p("Container migration results", "Title2"), p(model["project"], "Section"),
             p(model["repository"], "Small"),
             p(f"Branch: {model['branch']} | Organization: {model['organization']}", "Small"),
             p(f"Report time: {model['generated_at']}", "Small"), Spacer(1, 8)]
    metrics = [("Before findings", number(summary["findings_before"])),
               ("After findings", number(summary["findings_after"])),
               ("Finding reduction", percent(summary["reduction_percent"]))]
    story.append(table([[p(label, "Small") for label, _ in metrics],
                        [p(value, "Metric") for _, value in metrics]], [width / 3] * 3, False))
    story += [Spacer(1, 12), p(
        f"Comparison coverage: {summary['compared']} of {summary['in_scope']} services. "
        f"Migration status: {summary['migrated']} migrated, {summary['blocked']} blocked, "
        f"{summary['skipped']} skipped, {summary['pending']} pending."),
        p(f"Critical and High findings: {number(summary['critical_high_before'])} before; "
          f"{number(summary['critical_high_after'])} after."),
        p(f"Image size: {size(summary['size_before_bytes'])} before; "
          f"{size(summary['size_after_bytes'])} after. "
          f"Size reduction: {percent(summary['size_reduction_percent'])}. "
          f"Compared services with size evidence: {summary['size_pairs']}.")]

    if summary["compared"]:
        chart = Drawing(width, 72)
        values = (summary["findings_before"], summary["findings_after"])
        scale = (width - 150) / max(*values, 1)
        for label, value, y, color in zip(("Before", "After"), values, (42, 12), (muted, purple)):
            chart.add(String(0, y + 5, label, fontName="Helvetica", fontSize=9, fillColor=ink))
            chart.add(Rect(48, y, value * scale, 17, fillColor=color, strokeColor=None))
            chart.add(String(55 + value * scale, y + 5, f"{value:,}",
                             fontName="Helvetica-Bold", fontSize=9, fillColor=ink))
        story += [Spacer(1, 8), chart]
    else:
        story.append(p("No valid comparison is available. No reduction claim is made."))
    story += [p("Findings by severity", "Section")]
    data = [[p(value, "Head") for value in ("Severity", "Before", "After", "Removed")]]
    for sev in SEVERITIES:
        before = summary["counts_before"][sev] if summary["compared"] else None
        after = summary["counts_after"][sev] if summary["compared"] else None
        data.append([p(sev), p(number(before)), p(number(after)),
                     p(number(before - after if before is not None else None))])
    story += [table(data, [width * .34, width * .22, width * .22, width * .22]),
              Spacer(1, 8), p("How to read the result", "Section"), p(METHOD, "Small"),
              p("A positive reduction means fewer findings. A negative reduction means more findings.", "Small")]
    for note in model["notes"]:
        story.append(p(note, "Small"))

    story += [PageBreak(), p("Service results", "Title2"),
              p("Only rows marked yes enter finding totals. "
                "A smoke test starts the service and checks its health. "
                "A test marked not run does not prove compatibility.", "Small")]
    data = [[p(value, "Head") for value in
             ("Service / status", "Compared", "Findings before / after", "Build / smoke test / tests")]]
    for row in model["services"]:
        values = [number(row[key]["total"]) if row[key] else "not available" for key in ("before", "after")]
        data.append([p(f"{row['name']}\n{row['status']}"), p("yes" if row["included"] else "no"),
                     p(" / ".join(values)), p(f"{row['build']} / {row['smoke_test']} / {row['tests']}")])
    story.append(table(data, [width * .25, width * .13, width * .27, width * .35]))
    for row in model["services"]:
        if row["exclusion"]:
            story += [Spacer(1, 6), p(f"{row['name']}: excluded. {row['exclusion']}", "Small")]

    story += [PageBreak(), p("Image evidence", "Title2"),
              p("Scan paths are relative to the trial directory. SHA-256 values identify the saved files. "
                "See REPORT.md for remaining advisories, blocked work, and next steps.", "Small")]
    for row in model["services"]:
        prefix = [Spacer(1, 8), p(row["name"], "Section"),
                  p(f"Migration status: {row['status']}", "Small")]
        for label, key in (("Before", "before"), ("After", "after")):
            side = row[key]
            if side is None:
                parts = [p(f"{label}: valid scan evidence not available.", "Small")]
                if row.get(f"{key}_ref"):
                    parts.append(p(f"Recorded reference: {row[f'{key}_ref']}", "Small"))
            else:
                scanner = side["scanner"]
                parts = [p(f"{label}: {side['ref']}"), p(f"Image ID: {side['image_id']}", "Small"),
                         p(f"Platform: {side['platform']} | Size: {size(side.get('size_bytes'))}", "Small"),
                         p(f"Scanner: {scanner['name']} {scanner['version']} | Database: {scanner['database']}", "Small"),
                         p(f"Settings: {scanner['settings']}", "Small"),
                         p(f"Scan time: {side['scanned_at']} | File: {side['scan']}", "Small"),
                         p(f"Scan SHA-256: {side['scan_sha256']}", "Small"),
                         p(f"Scan command: {side['command']}", "Small")]
            story.append(KeepTogether(prefix + parts))
            prefix = []
        for note in row.get("notes", []):
            story.append(p(note, "Small"))
        for command in row.get("commands", []):
            story.append(p(f"Build or test command: {command}", "Small"))
    story += [Spacer(1, 10), p(f"Input manifest SHA-256: {model['manifest_sha256']}", "Small")]
    doc = SimpleDocTemplate(str(output), pagesize=A4, leftMargin=40, rightMargin=40,
                            topMargin=48, bottomMargin=42,
                            title=f"{model['project']} - Chainguard project value report",
                            author="Chainguard trial")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="trial.json with saved scan paths and test results")
    parser.add_argument("--output-dir", type=Path, help="default: manifest directory")
    args = parser.parse_args()
    try:
        model = build_model(args.manifest)
        destination = args.output_dir or args.manifest.resolve().parent
        destination.mkdir(parents=True, exist_ok=True)
        render_pdf(model, destination / "VALUE-REPORT.pdf")
        (destination / "metrics.json").write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    except ImportError as exc:
        print(f"Report dependency missing: {exc}. Run this script with uv run.", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"Report input error: {exc}", file=sys.stderr)
        return 1
    print(destination / "VALUE-REPORT.pdf")
    print(destination / "metrics.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
