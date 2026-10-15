# Try Chainguard Images

The `$try-chainguard-images` skill lets a coding agent migrate
a repo's container images to Chainguard at no charge and
measure the risk reduction.

The agent inventories every image reference in the repo,
creates a free Catalog Starter org if you have none, converts
your Dockerfiles on a `chainguard-trial` branch, builds and
tests each service, and scans the old and new images with the
same scanner. You get a customer PDF with the measured value for
your project. You also get a detailed Markdown report with scan findings
before and after, image size changes, and the commands to reproduce or
undo the trial. `main` is never touched.

## Quick start

```bash
cd your-repo
claude   # or your agent of choice
```

Then paste this prompt:

```text
Use this skill to migrate this repo's images to Chainguard:
https://github.com/alamorre/try-chainguard-images

If I don't have a Chainguard org, make a Catalog Starter
(free self-serve) org for me.
```

That is the whole setup. Your agent reads the skill from the
link and runs it. It will still show you the exact image list
before it uses a Starter image slot, because slots cannot be
swapped later.

You need Docker running and `chainctl` installed. The skill
checks both first and gives you the exact fix if one is missing.

You get back:

- A `chainguard-trial` branch with converted Dockerfiles.
- Build and test results for every service.
- `chainguard-trial/VALUE-REPORT.pdf` — project summary, before and
  after chart, findings by severity, service results, validation status,
  and image evidence.
- `chainguard-trial/REPORT.md` — findings before and after by severity,
  image size change, what blocked and why, exact commands to
  reproduce it, and how to undo.
- `chainguard-trial/metrics.json`, `trial.json`, and raw scans — the
  report data and evidence. Missing scans are excluded with a reason.

The report measures scanner package-vulnerability findings. These are
not unique CVEs. It includes all severities and shows the comparison
coverage. It reports increases and missing tests as well as reductions.
It does not estimate money saved.

## How it works

Five phases:

1. **Discover** — find every image reference (Dockerfiles, Compose,
   Kubernetes, Helm, Terraform), classify each one, and take
   baseline builds and CVE scans.
2. **Access** — use your existing Chainguard org, or create a free
   Catalog Starter org with your confirmation.
3. **Convert** — swap images on a `chainguard-trial` feature
   branch. Package names come from the Chainguard docs MCP server
   (`find_package_equivalent`) or verified `apk search`, never
   from model memory.
4. **Test** — build each service, smoke test it, and run the
   repo's own test suite.
5. **Scan and report** — scan the new images with the same scanner
   version, database, settings, and platform as the baseline. Generate
   `VALUE-REPORT.pdf` and `metrics.json` from saved project scans.
   Write `REPORT.md` with the same numbers, remaining advisories,
   commands to test it yourself, and undo steps.

Safety rules: work only on the trial branch, confirm before any
account or org creation, confirm before spending a Starter image
slot (slots cannot be swapped later), and report only numbers
from tools actually run.

## Requirements

- `git`, `docker`, `jq`
- [`chainctl`](https://edu.chainguard.dev/platform/chainctl-usage/how-to-install-chainctl/)
- One scanner: `grype` (preferred) or `trivy`
- A work email for Catalog Starter sign-up (personal email
  cannot create a Starter org)
- Python 3.10 or later and ReportLab for the final PDF. The bundled
  script declares this dependency. Use `uv run` or a separate Python
  environment. See the [report guide](references/value-report.md).

Optional: the Chainguard MCP servers for live facts. The docs
server needs no sign-in:

```bash
claude mcp add --transport http --scope user chainguard-docs https://mcp.edu.chainguard.dev/mcp
```

## Other install options

Install the skill once, so you do not need the link each time:

```bash
npx skills add alamorre/try-chainguard-images -g
```

Muse:

```bash
git clone https://github.com/alamorre/try-chainguard-images.git
cd try-chainguard-images
muse skills install .
```

Or copy this directory to `~/.agents/skills/try-chainguard-images`
(read by most agent tools) or to `.agents/skills/` in a project.

## Validate

```bash
chainctl skills validate . --strict
python3 -m unittest discover -s tests
# Also run the PDF rendering test with the report dependency installed:
uv run --with 'reportlab>=4.4,<5' python -m unittest discover -s tests
```

The report generator is a small local tool. It does not require another
reporting application, a browser, or an API key. It reads saved Grype or Trivy JSON.
See the [report guide](references/value-report.md) for the input schema,
generation command and counting rules.

## Related

- [metalstormbass/chainctl-skill](https://github.com/metalstormbass/chainctl-skill)
  — deep `chainctl` command reference skill. This skill gives
  the workflow; that skill gives the flags.
- [Chainguard MCP servers](https://edu.chainguard.dev/platform/mcp-servers/overview/)

## License

MIT
