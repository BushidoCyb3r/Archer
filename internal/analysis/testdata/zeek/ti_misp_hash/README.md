# ti_misp_hash

Exercises the **TI Hit (Hash)** detector via the file-hash match
path (`checkFileHashes` in `internal/analysis/files.go`). Hash
matching against MISP / OpenCTI feed indicators landed in v0.7.0;
before that, hash-typed feed entries were silently discarded by
`Store.EnabledFeedIndicators` because no analyzer-side field
carried a hash candidate. The `TI Hit (Hash)` finding type was
split out from the unified `Threat Intel Hit` in v0.7.0 so the
Type filter dropdown surfaces hash matches separately from IP
and domain matches.

## Inputs

- `files.log` — two file-download rows:
  - row 1 carries md5 / sha1 / sha256; the md5 matches the stub
    feed's hashes.
  - row 2 carries md5 / sha256; the sha256 matches; the md5 does
    not.
- `feeds.json` — one stub `feed:demo-hash` with two hashes (one
  md5, one sha256) and a tag on the md5.

## Findings produced

- 2 × `TI Hit (Hash)` (HIGH, 90):
  - row 1: matched on md5, tags `malware:emotet` surfaced inline.
  - row 2: matched on sha256, no tags.
- 2 × `Suspicious File Download` (HIGH, 72) — collateral from the
  MIME / extension detector firing on the same rows.
- 2 × `Host Risk Score` (MEDIUM, 35) — composite roll-up per
  downloader.

## What this covers

- `checkFileHashes` correctly extracts md5 / sha1 / sha256 columns
  from `files.log` and tests each against the algorithm-agnostic
  Hashes bucket.
- The dedup-by-(downloader, hashvalue) fingerprint prevents
  duplicate hits when multiple algorithms of the same file would
  all match (not exercised here directly, but the scenario relies
  on the dedup to ensure row 1 only fires once even though it
  carries three hash columns).
- Detail formatting includes algorithm + hash hex + filename + MIME
  + tags (when present).
- The `SrcIP` is set to the downloader (`rx_hosts`), matching the
  convention of `Suspicious File Download`, so the host-risk
  roll-up attributes the hit to the correct host.
