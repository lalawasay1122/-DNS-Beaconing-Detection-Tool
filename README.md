# DNS Beaconing Detection Tool

A hands-on cybersecurity project for DNS traffic analysis and periodic beacon-like pattern investigation using Python and TShark.

## Project Overview

This project demonstrates how DNS traffic can be analyzed to identify repeated queries and suspicious communication patterns.

## Key Features

- DNS packet analysis with TShark
- DNS query frequency analysis
- Source IP and domain investigation
- Synthetic DNS traffic generation
- Periodic query interval analysis
- SOC-style investigation reporting

## Lab Findings

Controlled synthetic traffic produced this pattern:

| Field | Result |
|---|---|
| Source IP | 192.168.100.129 |
| Domain | updates.example.net |
| Queries | 4 |
| Intervals | 30s, 30s, 30s |
| Average interval | 30 seconds |

**Result:** Periodic DNS pattern flagged for further investigation.

This is synthetic lab traffic, not evidence of real malware.

## Technologies Used

- Python
- TShark
- Wireshark
- Kali NetHunter Rootless
- Termux

## Project Status

- [x] DNS packet analysis
- [x] Synthetic DNS traffic generation
- [x] DNS analyzer V1 and V2
- [x] Timed PCAPNG verification
- [ ] Periodic beacon detection V3

## Disclaimer

Educational cybersecurity lab project. All traffic used in this demonstration is synthetic.

## Author

Cybersecurity Learner | Aspiring SOC Analyst | Ethical Hacking Enthusiast
