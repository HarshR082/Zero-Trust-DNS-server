from dnslib.server import DNSServer, BaseResolver
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
import socket
import sqlite3
import time
import os

DB_PATH = "dns_logs.db"
DNS_PORT = 53  # change to 5353 if 53 is unavailable

# ================== DB SETUP ==================
def setup_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            country TEXT,
            city TEXT,
            domain TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_stats (
            domain TEXT PRIMARY KEY,
            count INTEGER
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            domain TEXT PRIMARY KEY
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS client_stats (
            client_ip TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()

setup_db()

# ================== GEO STUB ==================
def get_geo_info(ip):
    return ("Unknown", "Unknown")  # Stub – replace with actual geo IP logic if needed

# ================== DNS RESOLVER ==================
class EnhancedDNSResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.')
        qname_lower = qname.lower()
        client_ip = handler.client_address[0]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        country, city = get_geo_info(client_ip)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            # ===== Log Request =====
            cursor.execute("""
                INSERT INTO dns_logs (timestamp, client_ip, country, city, domain)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, client_ip, country, city, qname))

            # ===== Domain Stats =====
            cursor.execute("SELECT count FROM domain_stats WHERE domain = ?", (qname,))
            row = cursor.fetchone()
            if row:
                cursor.execute("UPDATE domain_stats SET count = ? WHERE domain = ?", (row[0] + 1, qname))
            else:
                cursor.execute("INSERT INTO domain_stats (domain, count) VALUES (?, ?)", (qname, 1))

            cursor.execute("INSERT OR IGNORE INTO client_stats (client_ip) VALUES (?)", (client_ip,))

            # ===== Blocked Domain Logic =====
            cursor.execute("SELECT domain FROM blocked_domains")
            blocked_domains = [row[0].lower() for row in cursor.fetchall()]

            if any(qname_lower == bd or qname_lower.endswith("." + bd) for bd in blocked_domains):
                print(f"[BLOCKED] {client_ip} tried to access {qname}")
                reply = request.reply()
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
                conn.commit()
                return reply

            # ===== Forward to Upstream DNS =====
            try:
                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                upstream.settimeout(3)
                upstream.sendto(request.pack(), ("8.8.8.8", 53))
                data, _ = upstream.recvfrom(4096)
                conn.commit()
                return DNSRecord.parse(data)
            except Exception as e:
                print(f"[!] Upstream DNS Error for {qname}: {e}")
                reply = request.reply()
                reply.header.rcode = RCODE.SERVFAIL
                return reply

        except Exception as e:
            print(f"[!] General DNS handling error for {qname}: {e}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

        finally:
            conn.close()
            print(f"[{timestamp}] {client_ip} → {qname}")

# ================== LAUNCH SERVER ==================
def start_dns_server():
    try:
        resolver = EnhancedDNSResolver()
        server = DNSServer(resolver, port=DNS_PORT, address="0.0.0.0", logger=None)
        server.start_thread()
        print(f"[+] Zero Trust DNS Gateway running on 0.0.0.0:{DNS_PORT}")
    except PermissionError:
        print(f"[!] Permission denied on port {DNS_PORT}. Try running with admin or use port 5353.")
    except Exception as e:
        print(f"[!] Failed to start DNS server: {e}")

if __name__ == "__main__":
    start_dns_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[-] DNS server stopped.")
