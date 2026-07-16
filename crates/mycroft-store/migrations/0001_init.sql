-- Mycroft schema v1 — the source of truth (CLAUDE.md invariant §3).
-- Applied atomically by mycroft-store's migration runner; keyed on PRAGMA user_version.
-- All timestamps are RFC3339 UTC text. Enums are stored as their stable text form.

CREATE TABLE engagement (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    client      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL            -- active | paused | closed
);

CREATE TABLE scope_rules (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    pattern       TEXT NOT NULL,
    kind          TEXT NOT NULL,          -- in | out
    "type"        TEXT NOT NULL,          -- cidr | domain | url
    created_at    TEXT NOT NULL,
    UNIQUE(engagement_id, pattern, kind, "type")
);

CREATE TABLE commands (
    id              INTEGER PRIMARY KEY,
    engagement_id   INTEGER NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    raw_cmd         TEXT NOT NULL,
    tool            TEXT NOT NULL,
    target          TEXT NOT NULL,
    resolved_target TEXT,                 -- IP the guard approved (DNS/redirect evidence)
    blocked         INTEGER NOT NULL DEFAULT 0,   -- 1 = out-of-scope attempt, never ran
    scope_check     TEXT NOT NULL,        -- human-readable guard verdict
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    exit_code       INTEGER,
    stdout_ref      TEXT,
    stderr_ref      TEXT,
    issued_by       TEXT NOT NULL         -- human | ai
);

CREATE TABLE findings (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,          -- info | low | medium | high | critical
    source_tool   TEXT NOT NULL,
    target        TEXT NOT NULL,
    description   TEXT NOT NULL,
    status        TEXT NOT NULL,          -- new | confirmed | dead | manual
    command_id    INTEGER REFERENCES commands(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE evidence (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    finding_id    INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    command_id    INTEGER REFERENCES commands(id) ON DELETE SET NULL,
    kind          TEXT NOT NULL,          -- output | screenshot | file
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

-- Tamper-evident, append-only audit chain (CLAUDE.md deviation §5).
-- hash = sha256(prev_hash || "\n" || canonical(event,ref_table,ref_id,ts)).
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    event         TEXT NOT NULL,
    ref_table     TEXT,
    ref_id        INTEGER,
    ts            TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL
);

CREATE INDEX idx_scope_engagement    ON scope_rules(engagement_id);
CREATE INDEX idx_commands_engagement ON commands(engagement_id);
CREATE INDEX idx_findings_engagement ON findings(engagement_id);
CREATE INDEX idx_findings_command    ON findings(command_id);
CREATE INDEX idx_evidence_finding    ON evidence(finding_id);
CREATE INDEX idx_evidence_command    ON evidence(command_id);
CREATE INDEX idx_audit_engagement    ON audit_log(engagement_id, id);
