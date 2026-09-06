from app.processing.processor import ULPFProcessor
import json

processor = ULPFProcessor(
    "backend/app/mapping/definitions"
)

logs = [
    (
        "AcmeGuard Firewall",
        "2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB USER=alice"
    ),

    (
        "OpenVPN",
        "2026-09-06T10:20:00Z alice CONNECTED SRC=203.0.113.10 VPN_IP=10.8.0.5"
    ),

    (
        "Cisco IOS",
        "2026-09-06T10:30:00Z R1 %SYS-5-CONFIG_I: Configured from console"
    ),

    (
        "Suricata IDS",
        json.dumps({
            "timestamp": "2026-09-06T10:40:00Z",
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dest_ip": "10.0.0.10",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "Possible malicious traffic",
                "severity": 2,
                "category": "Attempted Admin"
            }
        })
    )
]

for name, raw_log in logs:
    print("\n" + "=" * 60)
    print(f"SOURCE: {name}")

    detected = processor.parser_registry.detect(raw_log)

    print(f"DETECTED PARSER: {detected}")

    try:
        result = processor.process(raw_log)

        print(f"VALID: {result['processing']['valid']}")
        print(f"MAPPING: {result['ulpf']['mapping_id']}")

        print("NORMALIZED EVENT:")
        print(
            json.dumps(
                result,
                indent=2,
                default=str
            )
        )

    except Exception as error:
        print(f"ERROR: {error}")