
import struct
import socket

OUTPUT_FILE = "dns_v3.hex"

# Domain and time offset (seconds)
events = [
    ("example.com", 0),
    ("google.com", 2),
    ("updates.example.net", 5),
    ("updates.example.net", 35),
    ("updates.example.net", 65),
    ("updates.example.net", 95),
    ("updates.example.net", 125),
]

def checksum(data):
    if len(data) % 2:
        data += b"\0"

    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)

    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff

with open(OUTPUT_FILE, "w") as output:
    for index, (domain, timestamp) in enumerate(events, 1):

        qname = b"".join(
            bytes([len(label)]) + label.encode()
            for label in domain.split(".")
        ) + b"\0"

        dns = struct.pack(
            "!HHHHHH", index, 0x0100, 1, 0, 0, 0
        )
        dns += qname + struct.pack("!HH", 1, 1)

        udp = struct.pack(
            "!HHHH", 50000 + index, 53,
            8 + len(dns), 0
        )

        src = socket.inet_aton("192.168.100.129")
        dst = socket.inet_aton("8.8.8.8")

        total_len = 20 + len(udp) + len(dns)

        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, index,
            0x4000, 64, 17, 0, src, dst
        )

        ip_sum = checksum(ip)
        ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]

        ethernet = bytes.fromhex(
            "0200000000020200000000010800"
        )

        packet = ethernet + ip + udp + dns

        output.write(
            f"# Frame {index} - time offset {timestamp}s\n"
        )
        output.write("000000  ")
        output.write(" ".join(f"{b:02x}" for b in packet))
        output.write("\n\n")

print(f"Generated {len(events)} synthetic DNS events.")
print(f"Output: {OUTPUT_FILE}")
