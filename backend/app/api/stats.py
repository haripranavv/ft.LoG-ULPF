from typing import Any

from fastapi import APIRouter

from app.storage.database import get_connection


router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
def get_stats() -> dict[str, Any]:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (WHERE valid = TRUE),
                    COUNT(*) FILTER (WHERE valid = FALSE),
                    COUNT(DISTINCT source_format),
                    COUNT(DISTINCT mapping_id),
                    COUNT(DISTINCT collector_id)
                FROM normalized_events
                """
            )

            row = cursor.fetchone()

    return {
        "total_events": row[0],
        "valid_events": row[1],
        "invalid_events": row[2],
        "source_formats": row[3],
        "mappings": row[4],
        "collectors": row[5],
    }