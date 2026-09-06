from app.parsers import ParserRegistry


registry = ParserRegistry()

samples = [
    (
        "ACMEGUARD",
        "2026-09-05T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB USER=alice",
    ),
    (
        "SYSLOG",
        "<134>Sep 5 10:00:00 FW01 firewall: ALLOW SRC=10.10.10.25 DST=172.16.1.20 DP=443",
    ),
    (
        "CEF",
        "CEF:0|AcmeGuard|Firewall|4.2|1001|Allowed Connection|3|src=10.10.10.25 dst=172.16.1.20 spt=49152 dpt=443 proto=TCP",
    ),
    (
        "JSON",
        '{"vendor":"AcmeGuard","product":"Firewall","src":"10.10.10.25","dst":"172.16.1.20","action":"ALLOW"}',
    ),
]


for expected_format, sample in samples:
    parser = registry.detect(sample)
    parsed = registry.parse(sample)

    print(f"Expected format : {expected_format}")
    print(f"Detected parser : {parser}")
    print(f"Source format   : {parsed.source_format}")
    print(f"Vendor          : {parsed.vendor}")
    print(f"Product         : {parsed.product}")
    print(f"Fields          : {parsed.fields}")
    print("-" * 60)