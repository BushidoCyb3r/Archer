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
curl -s http://localhost:8080/api/version | jq
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
  migrations apply cleanly. *(Requires Phase 3 of the maturation plan.)*
- Detection-semantics change: re-run `go test ./internal/analysis/...`
  against the golden fixture — the diff should match the CHANGELOG entry.
  *(Requires Phase 4.)*

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
