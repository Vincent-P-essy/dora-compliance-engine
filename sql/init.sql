-- dora-compliance-engine — PostgreSQL schema.
-- Applied automatically on first container start (docker-entrypoint-initdb.d).
-- The SQLAlchemy layer uses create_all(checkfirst) so both stay compatible;
-- this file additionally installs what only PostgreSQL can enforce: the
-- append-only trigger on the evidence vault.

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role        VARCHAR(16)  NOT NULL CHECK (role IN ('CISO', 'DevOps', 'Auditor')),
    created_at  TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE TABLE IF NOT EXISTS evidence (
    id          SERIAL PRIMARY KEY,
    source      VARCHAR(64)  NOT NULL,
    type        VARCHAR(64)  NOT NULL,
    control_ids JSONB        NOT NULL,
    payload     JSONB        NOT NULL,
    sha256      VARCHAR(64)  NOT NULL,
    collected_at VARCHAR(40) NOT NULL,
    stored_at   TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS ix_evidence_type   ON evidence (type);
CREATE INDEX IF NOT EXISTS ix_evidence_sha256 ON evidence (sha256);

CREATE TABLE IF NOT EXISTS posture_snapshots (
    id          SERIAL PRIMARY KEY,
    framework   VARCHAR(32)  NOT NULL,
    score       DOUBLE PRECISION NOT NULL,
    passed      INTEGER      NOT NULL,
    total       INTEGER      NOT NULL,
    results     JSONB        NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);
CREATE INDEX IF NOT EXISTS ix_posture_snapshots_framework  ON posture_snapshots (framework);
CREATE INDEX IF NOT EXISTS ix_posture_snapshots_created_at ON posture_snapshots (created_at);

CREATE TABLE IF NOT EXISTS drift_alerts (
    id             SERIAL PRIMARY KEY,
    framework      VARCHAR(32) NOT NULL,
    baseline_score DOUBLE PRECISION NOT NULL,
    current_score  DOUBLE PRECISION NOT NULL,
    delta          DOUBLE PRECISION NOT NULL,
    message        VARCHAR(512) NOT NULL,
    created_at     TIMESTAMP   NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

-- ── Evidence Vault immutability ──────────────────────────────────────────────
-- The vault is append-only by design: reject UPDATE and DELETE at the engine
-- level so not even a direct SQL session can rewrite collected evidence.

CREATE OR REPLACE FUNCTION forbid_evidence_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'evidence vault is append-only: % is forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS evidence_immutable ON evidence;
CREATE TRIGGER evidence_immutable
    BEFORE UPDATE OR DELETE ON evidence
    FOR EACH ROW EXECUTE FUNCTION forbid_evidence_mutation();
