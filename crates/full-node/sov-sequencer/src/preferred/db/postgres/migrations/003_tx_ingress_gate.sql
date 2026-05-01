CREATE TABLE IF NOT EXISTS tx_ingress_gate (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    enabled BOOLEAN NOT NULL,
    reason TEXT,
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generation BIGINT NOT NULL DEFAULT 0
);

INSERT INTO tx_ingress_gate (id, enabled, reason, updated_by, generation)
VALUES (TRUE, TRUE, NULL, NULL, 0)
ON CONFLICT (id) DO NOTHING;
