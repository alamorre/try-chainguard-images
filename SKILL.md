---
name: try-chainguard-images
description: "Trial-migrate the current repo to Chainguard images — discover image references, set up Catalog Starter access if needed, convert, build and test, scan before and after, and write a CVE reduction report: use when a user wants to try, evaluate, or test Chainguard images in a project."
license: MIT
---

# Try Chainguard Images

Run a safe, evidence-based Chainguard trial in the repo the user is in.
Five phases: discover, access, convert, test, scan and report. Finish
each phase before you start the next. Show the user the result of each
phase in a few lines before you continue.

The deliverable is a branch named `chainguard-trial`, plus a report at
`chainguard-trial/REPORT.md`. The user can delete the branch to undo
everything.

## Rules

- Work only on the trial branch agreed in Preflight step 3
  (default name `chainguard-trial`). Never commit to the default
  branch. Never push unless the user asks.
- Change image references, Dockerfiles, and deployment files only.
  Never change application source code, library versions, or lockfiles.
- The user must name or confirm the Chainguard organization in this
  session. Never infer it from the repo, git remote, or config. Pass
  it explicitly as `--parent <org>` on every command that accepts it.
  Never accept an auto-selected org or pick from an interactive list.
- Confirm before you create any account or org. Confirm before you
  spend a Catalog Starter image slot: slots cannot be swapped later.
- Confirm destructive actions (delete, reset) before you run them.
- Use long timeouts for `chainctl`: 300000 ms by default, 1800000 ms
  for `chainctl agent dockerfile` commands. Never use a 2-minute
  default.
- Authenticate only with `chainctl auth login`. Never hand-write
  tokens or credential files.
- Never guess a package name or image tag. Look it up (Phase 3).
- Report numbers only from tool output you ran in this session.
  If a scan or test did not run, write "not run", never a guess.
- Scan the old and new images with the same scanner and settings.
  A CVE difference from two different scanners is not evidence.

For deep `chainctl` command detail, load the `chainctl` skill if it
is installed. This skill gives the workflow; that skill gives flags.

## Tools this skill uses

Required: `git`, `docker`, `chainctl`, `jq`, and one scanner
(`grype` preferred, else `trivy`). Optional but preferred when
configured: the Chainguard MCP servers. Use them for facts, not
guesses:

- Docs MCP (`https://mcp.edu.chainguard.dev/mcp`, no sign-in):
  `find_package_equivalent` for APT/RPM to APK name mapping,
  `find_image_equivalent` for base image mapping, `search_docs`.
- `cg-apk`: confirm a Wolfi package name and version exists.
- `cg-oci`: confirm the org can pull an image; read its SBOM.
- `cg-versions`: check a version is not end-of-life.

If MCP is absent, use the `chainctl` equivalents named in each phase.
Say which source you used for each mapping in the report.

## Preflight

1. Check the tools: `docker version`, `chainctl version`,
   `jq --version`, and `grype version` or `trivy version`.
   If `chainctl` is missing, give the install command from the
   README of the chainctl skill (`brew install
   chainguard-dev/tap/chainctl` on macOS) and stop.
   If Docker is not running, stop and say so.
   If no scanner exists, offer `brew install grype` (macOS) or the
   scanner's documented install, and wait for the user's choice.
2. Check repo state: `git status --short`. If the tree has
   uncommitted changes, tell the user and ask how to proceed.
   Do not stash or discard anything on your own.
3. Set up the trial branch now, before you write any file.
   Run `git branch --show-current`.
   - On the default branch (`main`, `master`, or the value of
     `git symbolic-ref refs/remotes/origin/HEAD`): recommend a
     feature branch, get the user's yes, then run
     `git switch -c chainguard-trial`.
   - On another branch already: ask which base the trial should
     use — a new `chainguard-trial` branch from here, a new one
     from the default branch, or this branch. Recommend a new
     trial branch. If the user picks this branch, record that
     choice in the work log and the report.
   - If `chainguard-trial` already exists: ask whether to reuse
     it or create `chainguard-trial-<date>`. Never delete or
     reset an existing branch on your own.
   - If the repo has no Git history: stop. This skill needs a
     branch to keep the trial reversible. Ask the user to run
     `git init` and make a first commit, or to say where to work.
4. Check auth: `chainctl auth status`. If the session is missing
   or expired, run `chainctl auth login` and let the user complete
   the browser step.
5. Ask which org to use, and wait for the answer. If the user has
   no org, finish Phase 1 read-only, then do Phase 2.

## Phase 1 — Discover and take the baseline (read-only)

1. Run discovery and save the raw output:

   ```bash
   mkdir -p chainguard-trial/baseline
   chainctl images discover . --parent <org> -o json \
     > chainguard-trial/discover.json
   ```

   Without an org yet, run `chainctl images discover --image <ref>`
   once per reference you find by hand in step 2. Add
   `--fips=false` unless the user asks for FIPS.
2. Find what discovery misses. Search the repo for `FROM `,
   `image:`, and `COPY --from=` in Dockerfiles, Compose files,
   Kubernetes manifests, Helm values, and Terraform. Discovery
   skips `COPY --from` images, template-computed Helm refs, and
   `FROM` lines with no `ARG` default. List missed refs by hand.
3. Classify each reference. Record source ref, file and line,
   Chainguard candidate, and discovery status. Assign a path:
   - **A — simple swap:** only the `FROM` or `image:` ref changes.
   - **B — package conversion:** the Dockerfile runs `apt`, `yum`,
     or `dnf` installs, so package names need mapping.
   - **C — no equivalent:** no Chainguard candidate. Report only.
4. Take the baseline now, before any edit. For each Dockerfile
   that builds today:

   ```bash
   docker build -f <Dockerfile> -t trial-before:<name> <context>
   grype trial-before:<name> -o json \
     > chainguard-trial/baseline/<name>.json
   docker image inspect trial-before:<name> \
     --format '{{.Size}}' >> chainguard-trial/baseline/sizes.txt
   ```

   Use `trivy image --format json` if `grype` is absent, and use
   the same scanner again in Phase 5. Also pull and scan plain
   `image:` references the same way. If a baseline build fails,
   record the failure and mark that service "baseline broken —
   excluded from CVE comparison".
5. Show the user the inventory table. Ask which services are in
   scope if the repo has many (more than ten). Then continue.

## Phase 2 — Access (Catalog Starter if needed)

Skip this phase if discovery shows the candidates as `entitled`
or the user already pulls them. Prove access in step 4 either way.

1. List orgs with `chainctl iam organizations list`. Let the
   user confirm which org is theirs. Use that exact name as
   `--parent <org>` from here on.
2. If the user has no org, explain Catalog Starter before you act:
   - It is free and tied to the work email domain. Personal email
     (Gmail and similar) and GitHub/GitLab sign-in cannot create
     one. Sign-in must be email plus password, or Google on the
     company domain.
   - It grants a small number of images (read the exact quota from
     `chainctl starter status`). No FIPS images.
   - **Chosen images cannot be swapped or replaced later.**
   - An added image can take up to a few hours before it pulls.
   Get an explicit yes, then run `chainctl starter init` and hand
   control to the user for the interactive sign-in. If an org for
   the domain already exists, run `chainctl starter
   request-access` and tell the user to wait for approval.
3. Choose images up to the quota. Order by: most services served,
   then highest baseline CVE count. Show the exact list and get
   an explicit yes. Then run:

   ```bash
   chainctl starter add-images <image> [<image> ...]
   chainctl starter status
   ```

   Poll `status` until each image is `READY`. Continue the trial
   with the `READY` subset; list pending images in the report.
   Never present a pending image as a failure.
4. Prove pulls before you edit anything:

   ```bash
   chainctl auth configure-docker
   docker pull cgr.dev/<org>/<image>:<tag>
   ```

   Run one pull per candidate image. If a pull fails, check the
   discovery status and `starter status` first. Do not edit a
   Dockerfile toward an image you cannot pull.
5. For CI later, Starter orgs cannot create OIDC identities.
   Note in the report: CI uses `chainctl auth pull-token create`,
   not `setup-chainctl` identity federation.

## Phase 3 — Convert on the trial branch

Verify the branch first: `git branch --show-current` must print
the trial branch agreed in Preflight step 3. If it prints the
default branch, stop and create or switch to the trial branch
before you edit any file.

Convert one service at a time. Keep a work log in
`chainguard-trial/worklog.md`: service, path (A or B), what you
changed, and each fact source (tool name or command).

**Path A — simple swap.** Change only the reference to the exact
candidate from discovery (same version line where offered). For
Helm, prefer generated overrides:
`helm install -f <(chainctl images helm values <chart> --org <org>)`
over hand-edited values, and say so if you edit values instead.

**Path B — package conversion.** Pick one method per Dockerfile:

1. Deterministic first pass, if `dfc` is installed:
   `dfc <Dockerfile> --org <org>` (prints to stdout and writes
   nothing; review the output, then write it). It rewrites the
   base image, `apt`/`yum` lines, and package names by rule.
2. Iterative migration for hard Dockerfiles:

   ```bash
   chainctl agent dockerfile build -f <Dockerfile> \
     -t trial-after:<name> --parent <org>
   chainctl agent dockerfile validate -f <Dockerfile>
   ```

   Use the 1800000 ms timeout. Review the generated Dockerfile
   diff before you accept it. Add `--log-file` if it stalls.
3. Manual conversion when neither fits. Map every package, in
   this order:
   - Docs MCP `find_package_equivalent`, one call per package
     (`distro` = `debian` or `fedora`). No Alpine mappings exist.
   - Else search by content in the pulled `-dev` image:
     `apk search cmd:<binary>` or `apk search so:<lib>.so*`.
   - Confirm each name exists (`cg-apk` `search_packages`, or
     `apk search <name>` in the `-dev` image). Bundling differs:
     one APT package can map to several APK packages.

**Conversion rules for every path:**

- Builder stage uses a `-dev` variant; runtime stage uses the
  standard variant, or stays on `-dev` only if the service needs
  a shell or package manager at runtime. Say which and why.
- `apt install` becomes `apk add`. Add `USER root` before package
  installs; switch back to the non-root user after.
- The default shell is BusyBox `ash`, not `bash`. Rewrite
  bash-only syntax or install `bash` on purpose.
- Chainguard images rarely ship the Docker Hub entrypoint wrapper.
  Check `ENTRYPOINT` and `CMD` against the new image config
  (`docker image inspect`) and fix them explicitly.
- Keep the same application version line where a maintained tag
  exists. If conversion forces a version change, flag it in the
  work log and the report. Never move to an older version.
- For extra packages in a distroless runtime, prefer a
  multi-stage build that copies the built app, not loose binaries
  (loose files get no package entry and escape CVE scanning).
- Do not touch files for path C services. List them as skipped.

## Phase 4 — Build and test

For each converted service, in order:

1. Build: `docker build -f <Dockerfile> -t trial-after:<name>
   <context>` (or `docker compose build <service>`). A build
   that does not finish is a failed conversion, not a pass.
2. Smoke test: start the container the way the repo documents
   (Compose file, README, or Makefile). Check the process stays
   up and the documented port or health path answers. If the
   repo documents no way to run it, say "smoke test: not run".
3. Run the repo's own tests. Detect them from repo files:
   `Makefile` test targets, `package.json` scripts, `pytest`,
   `go test ./...`, `mvn test`. If you cannot identify the test
   command, ask the user. Never invent a passing result.
4. On failure, fix forward: read the error, adjust the
   Dockerfile (package, user, entrypoint, shell), rebuild.
   Stop after three failed fix attempts on one service. Mark it
   "blocked", record the last error in the work log, restore its
   original files (`git checkout -- <files>`), and move on.
   A partial trial with honest blocks beats a forced full pass.
5. Compare each result to the baseline state. A test that failed
   before conversion and fails after is "no change", not a
   regression. Say which case applies.

## Phase 5 — Scan and report

1. Scan every `trial-after:<name>` image with the same scanner
   and flags as Phase 1. Save to `chainguard-trial/after/`.
   Record new sizes next to the baseline sizes.
2. Count CVEs by severity from the JSON files with `jq`. Count
   only services scanned on both sides. For Chainguard-side
   remainders, run `chainctl images advisories list <ref>` and
   note the status (for example `pending-upstream`). Never read
   `analysis-not-planned` as "not vulnerable".
3. Write `chainguard-trial/REPORT.md` with this structure:

   ```markdown
   # Chainguard Trial Report
   Date, repo, branch `chainguard-trial`, org, scanner + version.

   ## Summary
   Services in scope N. Migrated X. Blocked Y. Skipped (no
   equivalent) Z. Total CVEs before A, after B (reduction C%).
   Critical/High before → after. Total image size before → after.

   ## Per-service results
   | Service | Before | After | Build | Tests | CVEs before → after | Size before → after |
   Use exact refs with tags. One row per service.

   ## Remaining CVEs
   Each CVE left on a migrated image, with advisory status.
   State plainly if a remainder is in application dependencies,
   which base image migration does not fix.

   ## Blocked and skipped
   Service, reason, last error, what a human should try next.

   ## How to test this yourself
   Exact commands: check out the branch, build, run, run the
   test suite, re-run the scan. Copy commands you actually ran.

   ## How to undo
   `git switch <default-branch> && git branch -D chainguard-trial`

   ## Next steps
   Review the diff; pin by digest if that is team policy; add a
   pull token for CI (Starter has no OIDC identities); Starter
   slots used U of Q; talk to Chainguard about production
   entitlements for the blocked and path C images.
   ```

4. Show the user `git diff --stat` and the report summary. Ask
   before you commit. If yes, commit on `chainguard-trial` only,
   including the `chainguard-trial/` folder. Do not push unless
   the user asks.

## Stop conditions

Stop and report, with work so far intact, when: Docker or
`chainctl` is unusable; the user cannot sign in with a work
email; no candidate image is pullable; every build fails; or
the user says stop. A stopped trial still delivers the Phase 1
inventory and baseline scans — say where they are.
