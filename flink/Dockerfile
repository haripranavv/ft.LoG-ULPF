FROM flink:2.2.0-scala_2.12-java21

USER root

RUN apt-get update \
    && apt-get install -y python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/pyflink \
    && /opt/pyflink/bin/pip install --no-cache-dir \
    apache-flink==2.2.0 \
    "pydantic>=2,<3"

ENV PATH="/opt/pyflink/bin:${PATH}"

USER flink