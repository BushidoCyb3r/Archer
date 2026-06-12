# Releasing Archer

Operator runbook for cutting a new Archer release. Follow this when shipping
a tagged version. Pre-1.0 releases are minor-bumps for any of the four
breaking-change categories (HTTP/SSE API, DB schema, Quiver protocol,
detection semantics) plus normal additive minors.

## 1. Pick the version

Archer uses semantic versioning under the **0.x prefix**: `v0.MAJOR.MINOR`.

- **Patch (`v0.1.0` → `v0.1.1`)**: bug fixes only. No behavior change a
  user would notice, no new features, no schema changes.
- **Minor (`v0.1.0` → `v0.2.0`)**: anything else. New features, refactors,
  detection tweaks, breaking API/schema/protocol changes — all minor pre-1.0.

When you reach 1.0 (the API/schema/protocol/detection surfaces are
deliberately stable), the rules tighten and major bumps mean breakage.

## 2. Update CHANGELOG.md

Move entries out of the `## [Unreleased]` section into a new
`## [v0.x.y] — YYYY-MM-DD` heading. Use these section headers in this order:

```
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
### Detection changes
### Breaking
```

`### Detection changes` is the section to watch. Any change to score
formulas, thresholds, finding types, or feed-matching logic goes here.
Operators reading the changelog use this to decide whether to re-baseline
their hunt findings.

`### Breaking` calls out anything that requires a downstream update —
external scripts parsing `/api/*`, sensors talking to a new server, etc.
Always pair with the relevant API/schema/Quiver/detection note.

Update the comparison links at the bottom of the file.

## 3. Bump the version

Two edits:

- `internal/version/version.go` — bump the `Version` default. This is the
  fallback used when the build doesn't pass `-ldflags` (e.g., air-gap
  tarball builds with no git history).
- `CHANGELOG.md` — already done in step 2.

## 4. Commit and tag

```bash
git add CHANGELOG.md internal/version/version.go
git commit -m "release: v0.x.y"
git tag -a v0.x.y -m "v0.x.y — <one-line summary>"
git push origin main
git push origin v0.x.y
```

The tag is annotated (not lightweight) so `git describe --tags` returns
the tag name and `git show v0.x.y` shows the release notes.

## 5. Verify the build picks up the new version

```bash
./start.sh up
curl -sk https://localhost:8443/api/version | jq
```

Expected output:

```json
{
  "version": "v0.x.y",
  "commit": "<short-sha>",
  "build_time": "<iso-8601>"
}
```

`start.sh` reads the version from `git describe --tags --always --dirty`,
so a checkout sitting exactly on the tag reports `v0.x.y`. A checkout
ahead of the tag reports `v0.x.y-N-g<sha>`. A dirty worktree appends
`-dirty` — useful for spotting "I forgot to commit something" before the
release lands.

The OCI image labels (`docker inspect archer | grep version`) should also
reflect the new version.

## 6. Optional: smoke-test the upgrade path

For minor bumps with breaking changes:

- Quiver protocol bump: deploy one sensor on the previous protocol version
  and confirm enrollment fails with the expected structured error.
- DB schema change: spin up against an existing v0.x-1 database and confirm
  migrations apply cleanly. The runner logs `applied schema migration NNNN`
  for each new file; the schema_migrations table records every applied
  version. A fresh DB applies 0001 from scratch; an existing pre-Phase-3
  install gets 0001 stamped without re-running so operator data is preserved.
- Detection-semantics change: re-run `go test ./internal/analysis/...`
  against the golden fixture — the diff should match the CHANGELOG entry.
  When the change is intentional, regenerate the golden:
  `go test ./internal/analysis/... -run TestGoldenZeek -update`. Inspect
  the resulting `internal/analysis/testdata/zeek/expected_findings.json`
  diff before staging it — every line of change should be explainable
  from the CHANGELOG entry. *(See "Detection-semantics tests" below.)*

## 7. Communicate

For internal-team releases, drop a one-paragraph note in whatever channel
the team uses. The bullet points: what version, what changed, what (if
anything) breaks, what to do about it.

A draft template:

> **Archer v0.x.y is out** — [one-line summary]
>
> Highlights:
> - [bullet]
> - [bullet]
>
> Breaking changes: [none, or list]
>
> Upgrade: `git pull && ./start.sh up`. *(Or, for sensors: `./quiver-update.sh`
> on each sensor — pending Phase 2.)*

## Deprecation policy

How an `/api/*` endpoint, response field, or query parameter is retired
without breaking integrations on the release it disappears.

**The contract: one minor-version cycle of overlap.**

1. **Announce.** The release that deprecates a surface keeps it fully
   working and adds a `### Deprecated` CHANGELOG entry naming the
   surface, the replacement, and the earliest version it may be
   removed (always ≥ the *next* minor). Example:
   `Deprecated: GET /api/foo — use GET /api/bar; removed no earlier than v0.27.0`.
2. **Signal at runtime.** For the entire deprecation window the
   endpoint sends a `Deprecation: <YYYY-MM-DD>` response header (the
   date the deprecation shipped, per the draft `Deprecation` HTTP
   header convention) and, where a successor exists, a
   `Link: <successor>; rel="successor-version"` header. A scripted
   consumer can detect the header and migrate before removal; nothing
   silently changes under it.
3. **Remove.** No earlier than the version named in step 1, and never
   in the same minor that announced it. Removal is a `### Removed` +
   `### Breaking` CHANGELOG pair (pre-1.0: minor bump), referencing the
   deprecation entry so the trail is auditable.

**Scope.** This applies to the HTTP/SSE API contract surface only.
DB schema, Quiver protocol, and detection semantics have their own
breaking-change handling (forward-only migrations; protocol-version
negotiation; golden-diff + `### Detection changes`) and do not use the
`Deprecation:` header.

**Why a header and not just a CHANGELOG line:** integrations don't read
CHANGELOGs, they make requests. A response header is the only signal a
machine consumer actually sees in time to act. Precedent for
remove-by-minor exists (the v0.7.0 `/api/upload` removal, the v0.14.8
plaintext-listener removal, the v0.25.1 `window.INIT_CONFIG` removal) —
this codifies the orderly path so future removals announce before they
cut.

## Detection-semantics stability contract

Detection semantics is the fourth breaking surface, but unlike the other
three it cannot freeze whole: scores are calibrated against real corpora
and must keep moving (the v0.37 → v0.57 beacon-scoring overhaul is the
proof). At v1.0 the surface splits into a frozen vocabulary and a tunable
calibration layer. Pre-1.0, this section is the definition we harden
toward; post-1.0 it is the contract.

**Stable — breaking, major bump post-1.0:**

- The finding-type catalog: renaming or removing an emitted type.
  (Adding a new type is additive — minor.)
- The `Finding` JSON field set: names and types of existing fields.
  (Adding fields is minor.)
- The severity tier vocabulary (critical / high / medium / low / info).
- The query language: grammar, and the names + semantics of existing
  fields. (Adding queryable fields is minor.)
- Fingerprint identity inputs (`Type, SrcIP, DstIP, DstPort, Sensor,
  Channel`): changing these orphans analyst notes/status on the next
  re-analysis — the same blast radius as a schema break, handled with
  the same gravity.

**Tunable — minor bump with a `### Detection changes` entry, never major:**

- Score formulas, sub-score blends, gates, thresholds, and calibration
  constants (including everything in `internal/config` defaults).
- HRS weight-table values.
- The severity tier a given score maps to for a type.
- `Detail` string contents — human-facing context, not a machine
  contract; external consumers must not parse it.
- Feed-matching internals and TI heuristics.

**Why this split:** analyst automation, saved queries, and SIEM mappings
key on type names and field names, never on exact scores. Freezing the
vocabulary while keeping the numbers tunable protects integrations
without fossilizing detection quality. The golden-fixture diff plus the
`### Detection changes` CHANGELOG section remain the audit trail for
every tunable-layer change.

## Schema migrations

DB schema changes use the migration framework added in Phase 3.

**Adding a schema change**:

1. Create a new file in `internal/store/migrations/` named
   `NNNN_short_title.sql` where `NNNN` is the next integer (zero-padded
   to four digits by convention, but the runner accepts any positive
   integer prefix). Example: `0002_add_finding_confidence_column.sql`.
2. Write the SQL — `ALTER TABLE`, `CREATE INDEX`, etc. The whole file
   runs in a single transaction; multiple statements separated by `;`
   are fine. Avoid `IF NOT EXISTS` / `IF EXISTS` on new migrations so
   any inconsistency surfaces as a startup error rather than being
   silently papered over.
3. Update Go code that reads or writes the affected table — new columns
   on existing rows pick up `DEFAULT` values; `NOT NULL` columns
   without a default need a backfill `UPDATE` in the same migration.
4. Update `docs/ARCHITECTURE.md` (Storage section) if the schema dump
   should reflect the new shape.
5. CHANGELOG entry under `### Breaking` (pre-1.0 minor bump). Mention
   any data backfill the migration performs and what the rollback
   story is (typically: "rollback requires restoring `/data` from
   backup — there's no down-migration tooling").

**Rules**:

- Never edit a migration that's been released. The runner records
  applied versions; editing `0001_init.sql` after release won't re-run
  it on existing installs, and a fresh install would diverge from the
  state operators in the field have.
- Never re-use a version number. The runner detects duplicates at load
  and refuses to start.
- Migrations are atomic per-version. A failure rolls back the
  transaction and aborts startup. Half-applied schemas don't reach
  handler code.
- The framework is **forward-only**. There's no down-migration. To
  reverse a change, write a new migration that undoes it.

**Where the code lives**:

- Runner: `internal/store/migrate.go` (`RunMigrations`)
- Migrations: `internal/store/migrations/*.sql` (embedded via `embed.FS`)
- Tracking: `schema_migrations` table (`version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL`)
- Tests: `internal/store/migrate_test.go`

## Detection-semantics tests

Detection changes (score formulas, thresholds, finding types,
feed-matching logic) get caught by the golden-file test in
`internal/analysis/golden_test.go`, which runs the full `Analyze`
pipeline over a synthetic Zeek NDJSON fixture under
`internal/analysis/testdata/zeek/` and diffs the resulting findings
against `expected_findings.json`.

**Workflow when a detection change is intentional**:

1. Make the code change in `internal/analysis/` and confirm the existing
   golden test fails (`go test ./internal/analysis/... -run TestGoldenZeek`)
   — that failure is the change being detected.
2. Inspect the diff carefully: the failure message lists every finding
   that drifted. Confirm each drift is the expected consequence of your
   change and not collateral.
3. Regenerate the golden:
   `go test ./internal/analysis/... -run TestGoldenZeek -update`.
4. Stage `internal/analysis/testdata/zeek/expected_findings.json` in
   the same commit as the code change. The diff in the JSON file
   becomes part of the PR review surface.
5. Add a `### Detection changes` entry to the CHANGELOG describing what
   moved and why. Operators reading this section decide whether to
   re-baseline their hunt findings.

**Adding new fixtures**: drop a new `.log` file (NDJSON Zeek format)
into `testdata/zeek/`. The test discovers all `*.log` files in the
directory and feeds them to one analyzer pass. For new detection
families that don't fit the current scenario, prefer a new
subdirectory and a new test (e.g., `TestGoldenDNSTunnel`) over
overloading the existing fixture — golden stability degrades when one
fixture has to satisfy too many expectations.

**Math helpers** in `internal/analysis/stats.go` have unit tests in
`stats_test.go` — pure-function table tests, no fixture machinery. Run
those alongside the golden test on every detection-touching change.

## Notes

- **Do not edit a tagged commit.** If something is wrong post-tag, ship a
  patch release. Force-pushing a tag confuses downstream pulls and
  invalidates deployed image references.
- **Do not skip the CHANGELOG.** A release without a changelog entry is a
  release nobody can understand six months later.
- **The maturation roadmap** (`MATURATION_PLAN.md`, gitignored) tracks
  longer-arc work that will eventually replace parts of this manual
  process — schema migrations, detection tests, CI gating, etc. Update
  that file when a phase finishes.
