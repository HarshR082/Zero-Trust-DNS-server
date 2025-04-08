# test_dns_query.py

import socket
from dnslib import DNSRecord
import time

# Change the domain here to test anything you want
domain = "google.com"
q = DNSRecord.question(domain)

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)  # Set timeout for better error handling

try:
    print(f"[TEST] Sending DNS query for: {domain}")
    sock.sendto(q.pack(), ("127.0.0.1", 5053))  # Make sure this port matches dns_gateway.py
    data, _ = sock.recvfrom(4096)

    reply = DNSRecord.parse(data)
    print("[RESPONSE] Received DNS reply:")
    print(reply)

except socket.timeout:
    print("[ERROR] DNS query timed out. Is your DNS server running on 127.0.0.1:5353?")

except Exception as e:
    print(f"[ERROR] {e}")

finally:
    sock.close()
