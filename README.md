# Try Chainguard Images

An agent skill that runs a safe, evidence-based Chainguard trial in
the repo you are in.

It works in five phases:

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
5. **Scan and report** — scan the new images with the same
   scanner as the baseline and write `chainguard-trial/REPORT.md`
   with the CVE difference, size change, per-service results,
   exact commands to test it yourself, and undo steps.

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

Optional: the Chainguard MCP servers for live facts. The docs
server needs no sign-in:

```bash
claude mcp add --transport http --scope user chainguard-docs https://mcp.edu.chainguard.dev/mcp
```

## Install

Muse:

```bash
git clone https://github.com/alamorre/try-chainguard-images.git
cd try-chainguard-images
muse skills install .
```

Other agents (skills CLI):

```bash
npx skills add alamorre/try-chainguard-images -g
```

Or copy this directory to `~/.agents/skills/try-chainguard-images`
(read by most agent tools) or to `.agents/skills/` in a project.

## Use

Open your agent in the target repo and ask it to try Chainguard
images. Example prompt:

```text
Use the try-chainguard-images skill to run a Chainguard trial
in this repo. Stop and ask me before you create an org and
before you spend an image slot.
```

## Validate

```bash
chainctl skills validate . --strict
```

## Related

- [metalstormbass/chainctl-skill](https://github.com/metalstormbass/chainctl-skill)
  — deep `chainctl` command reference skill. This skill gives
  the workflow; that skill gives the flags.
- [Chainguard MCP servers](https://edu.chainguard.dev/platform/mcp-servers/overview/)

## License

MIT
