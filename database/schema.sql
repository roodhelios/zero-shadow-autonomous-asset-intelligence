PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY,
    kind_summary_json TEXT NOT NULL
        CHECK (json_valid(kind_summary_json) AND json_type(kind_summary_json) = 'array'),
    primary_hostname TEXT,
    created_at TEXT NOT NULL CHECK (datetime(created_at) IS NOT NULL),
    updated_at TEXT NOT NULL CHECK (datetime(updated_at) IS NOT NULL),
    CHECK (length(trim(asset_id)) > 0),
    CHECK (updated_at >= created_at)
);

CREATE TABLE asset_observations (
    observation_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE RESTRICT,
    source TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('synthetic', 'owned', 'authorized')),
    observed_at TEXT NOT NULL CHECK (datetime(observed_at) IS NOT NULL),
    payload_json TEXT NOT NULL
        CHECK (json_valid(payload_json) AND json_type(payload_json) = 'object'),
    UNIQUE (source, source_record_id),
    CHECK (length(trim(observation_id)) > 0),
    CHECK (length(trim(source)) > 0),
    CHECK (length(trim(source_record_id)) > 0)
);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE RESTRICT,
    source TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    exposure TEXT NOT NULL CHECK (exposure IN ('internal', 'limited', 'internet')),
    exploit_evidence TEXT NOT NULL
        CHECK (exploit_evidence IN ('none', 'proof-of-concept', 'observed')),
    control_state TEXT NOT NULL
        CHECK (control_state IN ('effective', 'unknown', 'missing')),
    identity_confidence TEXT NOT NULL
        CHECK (identity_confidence IN ('low', 'medium', 'high')),
    evidence_json TEXT NOT NULL
        CHECK (json_valid(evidence_json) AND json_type(evidence_json) = 'object'),
    observed_at TEXT NOT NULL CHECK (datetime(observed_at) IS NOT NULL),
    CHECK (length(trim(finding_id)) > 0),
    CHECK (length(trim(source)) > 0),
    CHECK (length(trim(description)) > 0)
);

CREATE TABLE ownership_decisions (
    decision_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('resolved', 'unmatched', 'ambiguous')),
    team_id TEXT,
    matched_rule_ids_json TEXT NOT NULL
        CHECK (
            json_valid(matched_rule_ids_json)
            AND json_type(matched_rule_ids_json) = 'array'
        ),
    candidate_team_ids_json TEXT NOT NULL
        CHECK (
            json_valid(candidate_team_ids_json)
            AND json_type(candidate_team_ids_json) = 'array'
        ),
    explanation TEXT NOT NULL,
    decided_at TEXT NOT NULL CHECK (datetime(decided_at) IS NOT NULL),
    CHECK (
        (status = 'resolved' AND team_id IS NOT NULL AND length(trim(team_id)) > 0)
        OR (status IN ('unmatched', 'ambiguous') AND team_id IS NULL)
    ),
    CHECK (length(trim(decision_id)) > 0),
    CHECK (length(trim(explanation)) > 0)
);

CREATE TABLE remediation_plans (
    plan_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE RESTRICT,
    plan_version INTEGER NOT NULL CHECK (plan_version >= 1),
    priority TEXT NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3')),
    owner_team_id TEXT,
    opened_on TEXT NOT NULL CHECK (date(opened_on) IS NOT NULL),
    due_date TEXT NOT NULL CHECK (date(due_date) IS NOT NULL),
    overdue INTEGER NOT NULL CHECK (overdue IN (0, 1)),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_band TEXT NOT NULL CHECK (risk_band IN ('low', 'moderate', 'high', 'critical')),
    actions_json TEXT NOT NULL
        CHECK (json_valid(actions_json) AND json_type(actions_json) = 'array'),
    factors_json TEXT NOT NULL
        CHECK (json_valid(factors_json) AND json_type(factors_json) = 'array'),
    created_at TEXT NOT NULL CHECK (datetime(created_at) IS NOT NULL),
    UNIQUE (finding_id, plan_version),
    CHECK (length(trim(plan_id)) > 0),
    CHECK (due_date >= opened_on)
);

CREATE INDEX idx_observations_asset_time
    ON asset_observations(asset_id, observed_at);
CREATE INDEX idx_findings_asset_severity
    ON findings(asset_id, severity);
CREATE INDEX idx_ownership_asset_time
    ON ownership_decisions(asset_id, decided_at);
CREATE INDEX idx_plans_finding_version
    ON remediation_plans(finding_id, plan_version);
CREATE INDEX idx_plans_priority_due
    ON remediation_plans(priority, due_date);

CREATE TRIGGER asset_observations_no_update
BEFORE UPDATE ON asset_observations
BEGIN
    SELECT RAISE(ABORT, 'asset observations are append-only');
END;

CREATE TRIGGER asset_observations_no_delete
BEFORE DELETE ON asset_observations
BEGIN
    SELECT RAISE(ABORT, 'asset observations are append-only');
END;

CREATE TRIGGER findings_no_update
BEFORE UPDATE ON findings
BEGIN
    SELECT RAISE(ABORT, 'findings are append-only');
END;

CREATE TRIGGER findings_no_delete
BEFORE DELETE ON findings
BEGIN
    SELECT RAISE(ABORT, 'findings are append-only');
END;

CREATE TRIGGER ownership_decisions_no_update
BEFORE UPDATE ON ownership_decisions
BEGIN
    SELECT RAISE(ABORT, 'ownership decisions are append-only');
END;

CREATE TRIGGER ownership_decisions_no_delete
BEFORE DELETE ON ownership_decisions
BEGIN
    SELECT RAISE(ABORT, 'ownership decisions are append-only');
END;

CREATE TRIGGER remediation_plans_no_update
BEFORE UPDATE ON remediation_plans
BEGIN
    SELECT RAISE(ABORT, 'remediation plans are append-only');
END;

CREATE TRIGGER remediation_plans_no_delete
BEFORE DELETE ON remediation_plans
BEGIN
    SELECT RAISE(ABORT, 'remediation plans are append-only');
END;
