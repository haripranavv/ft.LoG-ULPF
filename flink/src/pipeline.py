import json
import sys
KAFKA_CONNECTOR_JAR = (
    "file:///opt/flink/lib/ulpf/"
    "flink-connector-kafka-5.0.0-2.2.jar"
)

KAFKA_CLIENT_JAR = (
    "file:///opt/flink/lib/ulpf/"
    "kafka-clients-4.2.0.jar"
)

from pyflink.common import (
    SimpleStringSchema,
    Types,
    WatermarkStrategy,
)
from pyflink.datastream import StreamExecutionEnvironment
from pyflink.datastream.connectors.kafka import (
    KafkaOffsetsInitializer,
    KafkaSource,
    KafkaSink,
    KafkaRecordSerializationSchema,
)

sys.path.insert(0, "/opt/ulpf/backend")

from app.processing import ULPFProcessor


MAPPING_DIR = "/opt/ulpf/backend/app/mapping/definitions"


def process_event(value: str) -> str:
    envelope = json.loads(value)

    raw_payload = envelope.get("raw_payload")

    if not raw_payload:
        raise ValueError("Kafka event does not contain raw_payload")

    processor = ULPFProcessor(
        mapping_dir=MAPPING_DIR,
        collector_id=envelope.get(
            "collector_id",
            "ulpf-collector-unknown",
        ),
    )

    result = processor.process(raw_payload)

    return json.dumps(
        result,
        separators=(",", ":"),
    )

def main() -> None:
    env = StreamExecutionEnvironment.get_execution_environment()

    env.add_jars(
        KAFKA_CONNECTOR_JAR,
        KAFKA_CLIENT_JAR,
    )

    env.set_parallelism(1)

    source = (
        KafkaSource.builder()
        .set_bootstrap_servers("kafka:29092")
        .set_topics("ulpf.raw.events")
        .set_group_id("ulpf-flink-processor-v2")
        .set_starting_offsets(
            KafkaOffsetsInitializer.earliest()
        )
        .set_value_only_deserializer(
            SimpleStringSchema()
        )
        .build()
    )

    stream = env.from_source(
        source,
        watermark_strategy=WatermarkStrategy.no_watermarks(),
        source_name="ULPF Kafka Raw Events",
    )
    processed = stream.map(
        process_event,
        output_type=Types.STRING(),
    )

    sink = (
        KafkaSink.builder()
        .set_bootstrap_servers("kafka:29092")
        .set_record_serializer(
            KafkaRecordSerializationSchema.builder()
            .set_topic("ulpf.normalized.events")
            .set_value_serialization_schema(SimpleStringSchema())
            .build()
        )
        .build()
    )

    processed.sink_to(sink)

    env.execute("ULPF Canonical Processing")


if __name__ == "__main__":
    main()