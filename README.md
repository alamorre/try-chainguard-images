# Try Chainguard Images

**How many of your CVEs are just your base image? Find out in one
agent session — with proof, not a sales deck.**

Point your coding agent at a repo. It swaps your base images to
Chainguard on a throwaway branch, builds and tests everything,
scans before and after, and hands you one report: your CVE count,
before → after, per service. Like the numbers? Keep the branch.
Hate them? Delete it. Your `main` never changes, and the agent
asks before it creates an account or spends anything.

No Chainguard account? The skill sets up the free Catalog
Starter plan for you, with your approval.

## Quick start

```bash
# 1. Install the skill (once)
npx skills add alamorre/try-chainguard-images -g

# 2. Open your repo in your agent
cd your-repo
claude   # or your agent of choice
```

Then paste this prompt:

```text
Use the try-chainguard-images skill to run a Chainguard trial
in this repo. Stop and ask me before you create an org and
before you spend an image slot. Report each phase before
you continue.
```

You need Docker running and `chainctl` installed. The skill
checks both first and gives you the exact fix if one is missing.

You get back:

- A `chainguard-trial` branch with converted Dockerfiles.
- Build and test results for every service.
- `chainguard-trial/REPORT.md` — CVE before → after by severity,
  image size change, what blocked and why, exact commands to
  reproduce it, and how to undo.

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

## Other install options

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
```

## Related

- [metalstormbass/chainctl-skill](https://github.com/metalstormbass/chainctl-skill)
  — deep `chainctl` command reference skill. This skill gives
  the workflow; that skill gives the flags.
- [Chainguard MCP servers](https://edu.chainguard.dev/platform/mcp-servers/overview/)

## License

MIT
