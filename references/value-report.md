# Project value report

Read this file when you take baseline scans and when you finish Phase 5.
The bundled generator reads local scan files. It does not need another
reporting application, a browser, an API key, or access to a Chainguard service.

## Collect comparable evidence

Create `chainguard-trial/trial.json`. Keep one entry for each service
in scope. Update it as the trial proceeds. Use the schema below.

Before the first scan, update the scanner database once. Save its
identity and the scanner version. Keep database updates off for all
baseline and after scans:

- Grype: run `grype db update`. Save `grype db status -o json`.
  Set `GRYPE_DB_AUTO_UPDATE=false` for each scan.
- Trivy: prepare the vulnerability database and Java database, if used.
  Use `--skip-db-update --skip-java-db-update --scanners vuln` for
  each scan. Save `trivy --version` and the database metadata.

Record a database checksum or a database build identifier in `database`.
For Trivy, include the Java database identity if used. Record the
effective flags, configuration, ignore files, and vulnerability exchange
(VEX) inputs in `settings`. VEX inputs can suppress findings.
Include file checksums where a path alone does not identify the input.
Keep these files with the scans. Settings must match on both sides.

Scan each built or pulled image by its Docker image ID. An image ID is
an immutable SHA-256 value. A tag can change between inspection and scan.
Save the full `docker image inspect` output for that image. Record its
ID, operating system and architecture, and `.Size` in bytes. Use the
same platform on both sides. For example:

```bash
docker image inspect trial-before:api > chainguard-trial/baseline/api.image.json
docker image inspect trial-before:api --format '{{.Id}}'
# Use the exact ID printed above as <image-id>.
GRYPE_DB_AUTO_UPDATE=false grype docker:<image-id> -o json \
  > chainguard-trial/baseline/api.json
```

Record the scan command and scan time. Add a scan path only after the
scanner succeeds. A failed scan can leave an empty or partial JSON file.
For Trivy, use `trivy image --image-src docker --format json` with the
database flags above and the exact image ID.

Before the final scans, check the scanner version and database identity
again. If either changed, scan both saved image IDs again with one
version, database, and settings. Keep the original baseline files.
If this is not possible, leave the service out of the comparison.

## Input schema

Paths are relative to the directory that contains `trial.json`.
Scan paths must stay inside that directory. Use `null` for a side
that was not scanned. Use `null` for a size that was not measured.
Never use zero for missing evidence.

This is a template. Replace all example values with session evidence.
The zero image IDs below are placeholders, not real image evidence.

```json
{
  "schema_version": 1,
  "project": "Customer project name",
  "repository": "https://github.com/customer/project",
  "branch": "chainguard-trial",
  "organization": "customer-org",
  "generated_at": "2026-10-15T12:00:00Z",
  "notes": ["Record application version changes and other limits here."],
  "services": [
    {
      "name": "api",
      "status": "migrated",
      "build": "passed",
      "smoke_test": "passed",
      "tests": "not run",
      "notes": ["Record why tests did not run. Record mapping and advisory evidence in REPORT.md."],
      "commands": ["Copy the build and test commands that actually ran."],
      "before": {
        "ref": "trial-before:api",
        "image_id": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "platform": "linux/amd64",
        "size_bytes": null,
        "scan": "baseline/api.json",
        "scanned_at": "2026-10-15T11:00:00Z",
        "command": "Copy the exact successful scan command.",
        "scanner": {
          "name": "grype",
          "version": "COPY VERSION",
          "database": "COPY DATABASE IDENTITY",
          "settings": "COPY EFFECTIVE SETTINGS AND INPUT CHECKSUMS"
        }
      },
      "after": null
    }
  ]
}
```

Use the same fields for `after`. `ref` is the exact tag used to build
or pull the scanned image. For built images, record the old and new
base image references in `notes`. Keep Dockerfile changes on the trial
branch. Keep source inspection files and scan logs with the evidence.

Use these migration states:

| State | Meaning |
| --- | --- |
| `migrated` | The service uses the replacement image. |
| `blocked` | Conversion, build, or validation could not finish. |
| `skipped` | The service was not converted. Record the reason. |
| `pending` | Access or another required step is still pending. |

`build`, `smoke_test`, and `tests` each accept `passed`, `failed`,
or `not run`. Explain blocked, skipped, pending, and failed work in
`notes`. Also explain application version changes. Never copy the
example test status without evidence.

## Generate and check the report

Run the bundled script from the project directory. Replace `<skill-dir>`
with the installed skill path. Use the full path to the project manifest
if the current directory is different.

```bash
uv run <skill-dir>/scripts/generate_report.py chainguard-trial/trial.json
```

The script requires Python 3.10 or later. `uv` installs the one PDF
dependency, ReportLab, in an isolated environment. If `uv` is absent,
use a separate Python environment:

```bash
python3 -m venv /tmp/chainguard-report-venv
/tmp/chainguard-report-venv/bin/python -m pip install 'reportlab>=4.4,<5'
/tmp/chainguard-report-venv/bin/python <skill-dir>/scripts/generate_report.py \
  chainguard-trial/trial.json
```

The script writes these files beside the manifest:

- `VALUE-REPORT.pdf`: project summary, before and after chart, severity
  table, service results, validation status, and image evidence.
- `metrics.json`: the same report data, exclusion reasons, and SHA-256
  checksums for the manifest and valid raw scan files.

Use `metrics.json` as the number source for `REPORT.md`. Keep the
detailed Markdown report for remaining advisories, exact reproduction
steps, undo steps, and next steps. Do not hand-edit PDF numbers.

Open the PDF or render it to page images. Check every page for clipped
text, table breaks, long references, and readable labels. Confirm that
the PDF and Markdown summary agree with `metrics.json`. Return links to
both reports and the raw evidence. If rendering fails, fix the error
and retry. If a dependency cannot be installed, state that the PDF was
not generated. Deliver the Markdown report and evidence that exist.

## Counting rules

The generator counts scanner package-vulnerability matches. The counts
include CVE and other advisory IDs.
The report calls them **findings**, because they are not unique CVEs.
Repeated package matches and findings shared across services can count
more than once. All severities count. Unknown and Negligible stay separate.

Only migrated services with a passed build and two valid scans enter
finding totals. Failed smoke tests or test suites exclude the service.
A test marked `not run` remains visible. It does not prove compatibility.
Scanner name, version, database identity, and settings must match for all
included services. Each pair must also use the same platform.
Different platforms across services remain visible in the evidence.
When Grype JSON includes database metadata, that metadata must also
match. Image IDs, platforms, and Grype versions must agree with the
raw scan when those fields are present. Trivy database identity comes
from the separately recorded metadata.

Missing or malformed scans and incomplete pairs are excluded with a
reason. Exclusions never become zero findings. If no pair qualifies,
the report shows that no comparison is available. A zero baseline has
no reduction percentage. A negative reduction means findings increased.
Size totals use only compared services with measured sizes on both sides.
They are sums per service, not unique storage use.
