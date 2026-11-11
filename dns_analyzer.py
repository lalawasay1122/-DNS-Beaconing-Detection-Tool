
import subprocess
from collections import Counter
from datetime import datetime

PCAP_FILE = "dns_multi.pcapng"
REPORT_FILE = "DNS_Threat_Report.txt"

print("=" * 55)
print("       SOC DNS THREAT DETECTION ENGINE V1")
print("=" * 55)

try:
    result = subprocess.run(
        [
            "tshark", "-r", PCAP_FILE,
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "dns.qry.name"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    queries = []

    for line in result.stdout.splitlines():
        fields = line.split("\t")

        if len(fields) >= 2 and fields[1]:
            queries.append((fields[0], fields[1].lower()))

    counts = Counter(domain for ip, domain in queries)

    report = [
        "=" * 55,
        "       SOC DNS INVESTIGATION REPORT",
        "=" * 55,
        f"Generated: {datetime.now()}",
        "Analyst: Lalawasay",
        "Environment: Controlled Training Lab",
        f"PCAP Evidence: {PCAP_FILE}",
        "",
        f"Total DNS queries: {len(queries)}",
        f"Unique domains: {len(counts)}",
        "",
        "----- DOMAIN ANALYSIS -----"
    ]

    for domain, count in counts.items():
        report.append(f"Domain: {domain}")
        report.append(f"Query count: {count}")

        if len(domain) > 50:
            report.append("[REVIEW] Unusually long domain name")

        if count >= 10:
            report.append("[REVIEW] High query frequency")

        report.append("")

    report.extend([
        "----- INVESTIGATION SUMMARY -----",
        "No confirmed malicious activity from this sample.",
        "Length and frequency indicators require further review.",
        "",
        "Investigation completed."
    ])

    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report) + "\n")

    print("\n".join(report))
    print(f"\nReport saved: {REPORT_FILE}")

except FileNotFoundError:
    print("ERROR: PCAP file or TShark not found.")

except subprocess.CalledProcessError as error:
    print("TShark analysis failed:", error.stderr)
