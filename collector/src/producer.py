import json
import os
from datetime import datetime, timezone

from kafka import KafkaProducer


KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

TOPIC = os.getenv(
    "ULPF_RAW_TOPIC",
    "ulpf.raw.events",
)


def create_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )


def publish_raw_event(
    producer: KafkaProducer,
    raw_payload: str,
    source: str = "firewall",
    collector_id: str = "ulpf-collector-01",
) -> None:

    event = {
        "raw_payload": raw_payload,
        "source": source,
        "collector_id": collector_id,
        "ingestion_timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    future = producer.send(TOPIC, value=event)
    metadata = future.get(timeout=10)

    print("Published raw event")
    print(f"Topic     : {metadata.topic}")
    print(f"Partition : {metadata.partition}")
    print(f"Offset    : {metadata.offset}")


if __name__ == "__main__":
    producer = create_producer()

    raw_payload = (
        "2026-09-05T10:00:00Z FW01 ALLOW "
        "SRC=10.10.10.25 DST=172.16.1.20 "
        "SP=49152 DP=443 PROTO=TCP "
        "RULE=ALLOW_WEB USER=alice"
    )

    publish_raw_event(
        producer,
        raw_payload,
    )

    producer.flush()
    producer.close()