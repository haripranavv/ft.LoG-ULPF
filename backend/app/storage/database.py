import os

import psycopg


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ulpf:ulpf_dev_password@localhost:5432/ulpf",
)


def get_connection():
    return psycopg.connect(DATABASE_URL)


def initialize_database():
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS normalized_events (
                    id UUID PRIMARY KEY,
                    timestamp TIMESTAMPTZ,
                    event_type VARCHAR(100),
                    action VARCHAR(100),
                    severity INTEGER,

                    source_ip INET,
                    source_port INTEGER,

                    destination_ip INET,
                    destination_port INTEGER,

                    protocol VARCHAR(50),

                    source_format VARCHAR(100),
                    parser_name VARCHAR(100),
                    parser_version VARCHAR(50),

                    mapping_id VARCHAR(150),
                    mapping_version VARCHAR(50),

                    processing_mode VARCHAR(50),
                    normalization_status VARCHAR(50),

                    valid BOOLEAN NOT NULL,

                    raw_event_hash VARCHAR(64),
                    trace_id UUID,
                    collector_id VARCHAR(150),

                    raw_payload TEXT NOT NULL,
                    normalized_event JSONB NOT NULL,

                    ingestion_timestamp TIMESTAMPTZ,
                    processing_timestamp TIMESTAMPTZ,

                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_normalized_events_timestamp
                    ON normalized_events(timestamp);

                CREATE INDEX IF NOT EXISTS idx_normalized_events_source_format
                    ON normalized_events(source_format);

                CREATE INDEX IF NOT EXISTS idx_normalized_events_action
                    ON normalized_events(action);

                CREATE INDEX IF NOT EXISTS idx_normalized_events_trace_id
                    ON normalized_events(trace_id);

                CREATE INDEX IF NOT EXISTS idx_normalized_events_raw_hash
                    ON normalized_events(raw_event_hash);
                """
            )

        conn.commit()