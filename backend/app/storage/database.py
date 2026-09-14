import os
from typing import Any
import psycopg


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://ulpf:ulpf_dev_password@localhost:5432/ulpf",
)


def get_connection():
    return psycopg.connect(DATABASE_URL, connect_timeout=2)


def initialize_database():
    """Initializes the production PostgreSQL schema for ULPF with all core tables and indexes."""
    try:
        with get_connection() as conn:
            with conn.cursor() as cursor:
                # 1. Ingestions table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ingestions (
                        id UUID PRIMARY KEY,
                        filename VARCHAR(255) NOT NULL,
                        sha256_hash VARCHAR(64) NOT NULL,
                        file_size_bytes BIGINT NOT NULL,
                        content_type VARCHAR(100) DEFAULT 'text/plain',
                        total_events INT NOT NULL DEFAULT 0,
                        valid_events INT NOT NULL DEFAULT 0,
                        invalid_events INT NOT NULL DEFAULT 0,
                        status VARCHAR(50) NOT NULL DEFAULT 'completed',
                        storage_path TEXT NOT NULL,
                        batch_merkle_root VARCHAR(64),
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_ingestions_hash
                        ON ingestions(sha256_hash);

                    CREATE INDEX IF NOT EXISTS idx_ingestions_created_at
                        ON ingestions(created_at DESC);
                    """
                )

                # 2. Normalized Events table
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

                        ingestion_id UUID REFERENCES ingestions(id) ON DELETE SET NULL,
                        batch_merkle_root VARCHAR(64),

                        ingestion_timestamp TIMESTAMPTZ,
                        processing_timestamp TIMESTAMPTZ,

                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_timestamp
                        ON normalized_events(timestamp);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_source_ip
                        ON normalized_events(source_ip);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_source_format
                        ON normalized_events(source_format);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_action
                        ON normalized_events(action);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_trace_id
                        ON normalized_events(trace_id);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_raw_hash
                        ON normalized_events(raw_event_hash);

                    CREATE INDEX IF NOT EXISTS idx_normalized_events_ingestion_id
                        ON normalized_events(ingestion_id);
                    """
                )

                # 3. Discovered Devices table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS devices (
                        id VARCHAR(150) PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        ip_address INET,
                        mac_address VARCHAR(50),
                        manufacturer VARCHAR(150),
                        device_type VARCHAR(50) NOT NULL DEFAULT 'unknown',
                        device_type_confidence FLOAT NOT NULL DEFAULT 1.0,
                        discovery_method VARCHAR(150),
                        first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        status VARCHAR(50) NOT NULL DEFAULT 'new',
                        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_devices_ip
                        ON devices(ip_address);

                    CREATE INDEX IF NOT EXISTS idx_devices_mac
                        ON devices(mac_address);

                    CREATE INDEX IF NOT EXISTS idx_devices_type
                        ON devices(device_type);

                    CREATE INDEX IF NOT EXISTS idx_devices_status
                        ON devices(status);

                    CREATE INDEX IF NOT EXISTS idx_devices_last_seen
                        ON devices(last_seen DESC);
                    """
                )

                # 4. Mappings table (persisted custom / approved mappings)
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mappings (
                        mapping_id VARCHAR(150) PRIMARY KEY,
                        version VARCHAR(50) NOT NULL DEFAULT '1.0',
                        source_format VARCHAR(100),
                        vendor VARCHAR(100),
                        product VARCHAR(100),
                        definition JSONB NOT NULL,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_mappings_format
                        ON mappings(source_format);
                    """
                )

                # 5. Exports table (track export jobs and integrations)
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS exports (
                        id UUID PRIMARY KEY,
                        target_type VARCHAR(50) NOT NULL,
                        destination TEXT,
                        status VARCHAR(30) NOT NULL DEFAULT 'pending',
                        event_count INT NOT NULL DEFAULT 0,
                        config JSONB NOT NULL DEFAULT '{}'::jsonb,
                        error_message TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_exports_status
                        ON exports(status);

                    CREATE INDEX IF NOT EXISTS idx_exports_created_at
                        ON exports(created_at DESC);
                    """
                )

            conn.commit()
    except Exception as e:
        # In testing or when Postgres is not yet up, log warning without crashing import
        print(f"[ULPF Database] Warning during database initialization: {e}")