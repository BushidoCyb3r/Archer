-- v0.14.0: admin-action audit log. For any team running under a
-- compliance regime (SOC 2, ISO 27001, NIST, DoD STIG), "who did
-- what when" on state-changing admin endpoints is table-stakes.
-- Pre-v0.14.0 nothing was recorded; this is the post-fix table.
--
-- Schema choices (all per the v0.14.0 audit response):
--
--   * One row per admin-side mutation. Read-only endpoints (GETs,
--     /api/findings, exports) do not log — they're noise that
--     drowns out the actual decisions. login_success and
--     login_failure DO log because the auth boundary is where
--     incident response wants to start the trail.
--
--   * actor_id is FK-shaped but not declared as FK (no ON DELETE
--     CASCADE). When an admin is deleted, the audit trail of their
--     actions stays — that's the whole point of the log.
--     actor_email is denormalised alongside for the same reason:
--     the email at the time of the action is what matters, not
--     what the row looks like after a possible later rename or
--     after the user is removed entirely.
--
--   * target_type + target_id locate the affected entity; the
--     additional target_name column is what an analyst reading
--     the log six months later actually wants — "sensor 12" is
--     unhelpful; "sensor 12 (edge-fw-east)" is. Denormalised at
--     write time for the same reason as actor_email.
--
--   * before_value + after_value JSON capture state transitions
--     for true mutations (role change, feed update, allowlist
--     edit). Empty for non-transition events (login, refresh,
--     import). The "before/after" pattern is what makes the log
--     useful for incident response — "the allowlist had X added
--     on date Y by user Z" is a question that comes up.
--
--   * details JSON is the fallback for events without a clean
--     before/after shape (login_success records the session token
--     prefix; feed_refresh records the indicator counts; import
--     records the bundle sizes).
--
--   * source_ip is the request RemoteAddr at the time of the
--     action.
--
--   * Composite indexes: (ts DESC, action) supports the dominant
--     "most-recent-first, filtered by action" query the UI runs;
--     (actor_id, ts DESC) supports the "show me everything user X
--     did" incident-response query.
--
-- Append-only is a code-side invariant, not a trigger. SQLite
-- triggers would block a future retention-pruning sweep too — see
-- OPERATIONS.md for the documented retention-prune path. The
-- store package contains no UPDATE or DELETE statements against
-- audit_log; preserve that discipline.

CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor_id      INTEGER,
    actor_email   TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    target_type   TEXT NOT NULL DEFAULT '',
    target_id     TEXT NOT NULL DEFAULT '',
    target_name   TEXT NOT NULL DEFAULT '',
    before_value  TEXT NOT NULL DEFAULT '',
    after_value   TEXT NOT NULL DEFAULT '',
    details       TEXT NOT NULL DEFAULT '',
    source_ip     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_log_ts_action ON audit_log(ts DESC, action);
CREATE INDEX idx_audit_log_actor_ts  ON audit_log(actor_id, ts DESC);
