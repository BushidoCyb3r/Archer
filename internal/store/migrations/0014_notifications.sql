-- 0014_notifications.sql
-- Persists the bell notification queue across server restart. Pre-fix
-- the store kept notifications and notifCounter as in-memory state on
-- the Store struct, so a restart wiped every active alarm — the
-- operator's last surface for "what alerted today" disappeared on any
-- redeploy. Same shape as NEW-72 (Correlations were in-memory; restart
-- cleared them; fixed by adding a persistence column).
--
-- Columns mirror model.Notification 1:1 plus created_at for ordering
-- and a kind index for the bell dispatch's same-target dedup.
--
-- Dismissed alarms stay in the table indefinitely today; a retention
-- policy is a future item (see TODO.md). The expected steady-state row
-- count is low (operators dismiss as part of normal triage), so the
-- table doesn't need pruning to keep the hot path fast.

CREATE TABLE notifications (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL DEFAULT '',      -- 'finding' | 'sensor' | 'feed'
    target      TEXT    NOT NULL DEFAULT '',      -- sensor or feed name; empty for finding
    detail      TEXT    NOT NULL DEFAULT '',      -- human-readable description
    finding_id  INTEGER NOT NULL DEFAULT 0,       -- 0 for sensor/feed alarms
    severity    TEXT    NOT NULL DEFAULT '',
    type        TEXT    NOT NULL DEFAULT '',
    src_ip      TEXT    NOT NULL DEFAULT '',
    dst_ip      TEXT    NOT NULL DEFAULT '',
    dst_port    TEXT    NOT NULL DEFAULT '',
    dismissed   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_notifications_kind_target ON notifications(kind, target);
