import subprocess
import math
from collections import Counter, defaultdict
from datetime import datetime

PCAP_FILE = "dns_multi.pcapng"
REPORT_FILE = "DNS_Threat_Report_V2.txt"

def entropy(value):
    if not value:
        return 0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

def analyze_domain(domain):
    labels = domain.rstrip(".").lower().split(".")
    findings = []

    if len(domain) > 50:
        findings.append("Long domain name")

    if any(len(label) > 30 for label in labels):
        findings.append("Unusually long DNS label")

    if labels and len(labels[0]) >= 12:
        score = entropy(labels[0])

        if score > 3.5:
            findings.append(
                f"High-entropy first label ({score:.2f})"
            )

    return findings

print("=" * 55)
print("       SOC DNS THREAT DETECTION ENGINE V2")
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
            queries.append(
                (fields[0], fields[1].lower().rstrip("."))
            )

    domain_counts = Counter(
        domain for ip, domain in queries
    )

    source_counts = Counter(
        ip for ip, domain in queries
    )

    report = [
        "=" * 55,
        "       SOC DNS INVESTIGATION REPORT V2",
        "=" * 55,
        f"Generated: {datetime.now()}",
        "Analyst: Lalawasay",
        "Environment: Controlled Training Lab",
        f"Evidence: {PCAP_FILE}",
        "",
        f"Total DNS queries: {len(queries)}",
        f"Unique domains: {len(domain_counts)}",
        f"Unique source IPs: {len(source_counts)}",
        "",
        "----- DOMAIN ANALYSIS -----"
    ]

    for domain, count in domain_counts.items():
        report.append(f"\nDomain: {domain}")
        report.append(f"Query count: {count}")

        findings = analyze_domain(domain)

        if count >= 10:
            findings.append("High query frequency")

        if findings:
            for finding in findings:
                report.append(f"[REVIEW] {finding}")
        else:
            report.append("[INFO] No configured indicator triggered")

    report.extend([
        "",
        "----- SOURCE IP ANALYSIS -----"
    ])

    for ip, count in source_counts.items():
        report.append(f"{ip}: {count} queries")

    report.extend([
        "",
        "----- INVESTIGATION SUMMARY -----",
        "Review indicators are not proof of malicious activity.",
        "Further context and traffic correlation are required.",
        "",
        "Investigation completed."
    ])

    with open(REPORT_FILE, "w") as file:
        file.write("\n".join(report) + "\n")

    print("\n".join(report))
    print(f"\nReport saved: {REPORT_FILE}")

except FileNotFoundError:
    print("ERROR: TShark or input file not found.")

except subprocess.CalledProcessError as error:
    print("TShark analysis failed:", error.stderr)
