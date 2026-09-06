import json
import os
import signal
import sys

from kafka import KafkaConsumer

from app.storage.event_store import store_event


KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092",
)

KAFKA_TOPIC = os.getenv(
    "KAFKA_NORMALIZED_TOPIC",
    "ulpf.normalized.events",
)

KAFKA_GROUP_ID = os.getenv(
    "KAFKA_STORAGE_GROUP_ID",
    "ulpf-postgres-storage-v1",
)


running = True


def shutdown_handler(signum, frame):
    global running
    running = False


def main():
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        value_deserializer=lambda value: json.loads(
            value.decode("utf-8")
        ),
    )

    print(
        f"ULPF storage consumer listening on "
        f"{KAFKA_BOOTSTRAP_SERVERS}/{KAFKA_TOPIC}",
        flush=True,
    )

    try:
        while running:
            records = consumer.poll(timeout_ms=1000)

            for _, messages in records.items():
                for message in messages:
                    try:
                        store_event(message.value)

                        consumer.commit()

                        print(
                            f"Stored normalized event: "
                            f"{message.value['event']['id']}",
                            flush=True,
                        )

                    except Exception as exc:
                        print(
                            f"Failed to store event: {exc}",
                            file=sys.stderr,
                            flush=True,
                        )

    finally:
        consumer.close()
        print("ULPF storage consumer stopped", flush=True)


if __name__ == "__main__":
    main()