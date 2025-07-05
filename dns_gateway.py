from dnslib.server import DNSServer, BaseResolver
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
import socket
import sqlite3
import time
import smtplib
from email.message import EmailMessage
import requests
from threading import Thread

# === CONFIG ===
DB_PATH = "dns_logs.db"
DNS_PORT = 53

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "SENDER EMAIL"
EMAIL_PASSWORD = "SENDER EMAIL PASSWORD"
EMAIL_RECEIVER = "RECEIVER EMAIL"

def send_email_alert(client_ip, domain, country):
    try:
        msg = EmailMessage()
        msg["Subject"] = f"DNS BLOCK ALERT: {domain}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg.set_content(f"""
[DNS Gateway Alert]
Client IP: {client_ip}
Blocked Domain: {domain}
Country: {country}
Time: {time.strftime("%Y-%m-%d %H:%M:%S")}
        """)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"[EMAIL SENT] Alert for {domain}")
    except Exception as e:
        print(f"[!] Email send error: {e}")

def get_geo_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        d = r.json()
        return d.get("country", "IN"), d.get("city", "Unknown")
    except:
        return "IN", "Unknown"

def setup_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS dns_logs (id INTEGER PRIMARY KEY, timestamp TEXT, client_ip TEXT, country TEXT, city TEXT, domain TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT PRIMARY KEY)")
    c.execute("CREATE TABLE IF NOT EXISTS blocked_countries (country_code TEXT PRIMARY KEY)")
    c.execute("CREATE TABLE IF NOT EXISTS domain_stats (domain TEXT PRIMARY KEY, count INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS client_stats (client_ip TEXT PRIMARY KEY)")
    conn.commit()
    conn.close()

setup_db()

class ZeroTrustResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower()
        client_ip = handler.client_address[0]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Immediate DB connection
        conn = sqlite3.connect(DB_PATH, timeout=1)
        c = conn.cursor()

        # Get geo info (safe default)
        country, city = "UN", "Unknown"
        geo_thread = Thread(target=self._update_geo_and_log, args=(client_ip, qname, timestamp))
        geo_thread.start()

        # Get blocklists
        c.execute("SELECT domain FROM blocked_domains")
        blocked_domains = [row[0].lower() for row in c.fetchall()]
        c.execute("SELECT country_code FROM blocked_countries")
        blocked_countries = [row[0].upper() for row in c.fetchall()]
        conn.close()

        # Domain + Geo match
        domain_blocked = any(qname == bd or qname.endswith("." + bd) for bd in blocked_domains)
        geo_blocked = False  # Will be detected async in logging thread

        if domain_blocked:
            print(f"[BLOCKED:DOMAIN] {client_ip} tried {qname}")
            Thread(target=send_email_alert, args=(client_ip, qname, country)).start()
            return self._block_response(request, qname)

        # TEMPORARY: You can move this into _update_geo_and_log to avoid delay
        try:
            country, _ = get_geo_info(client_ip)
        except:
            country = "IN"
        geo_blocked = country.upper() in blocked_countries and country.upper() not in ["IN", "UN"]

        if geo_blocked:
            print(f"[BLOCKED:GEO] {client_ip} from {country} tried {qname}")
            Thread(target=send_email_alert, args=(client_ip, qname, country)).start()
            return self._block_response(request, qname)

        # Forward to upstream if allowed
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(request.pack(), ("8.8.8.8", 53))
            data, _ = sock.recvfrom(4096)
            return DNSRecord.parse(data)
        except Exception as e:
            print(f"[!] Upstream fail: {e}")
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

    def _block_response(self, request, qname):
        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0")))
        return reply

    def _update_geo_and_log(self, client_ip, qname, timestamp):
        country, city = get_geo_info(client_ip)
        if not country: country = "IN"
        if not city: city = "Unknown"

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO dns_logs (timestamp, client_ip, country, city, domain) VALUES (?, ?, ?, ?, ?)",
                  (timestamp, client_ip, country, city, qname))
        c.execute("INSERT OR IGNORE INTO client_stats (client_ip) VALUES (?)", (client_ip,))
        c.execute("SELECT count FROM domain_stats WHERE domain = ?", (qname,))
        row = c.fetchone()
        if row:
            c.execute("UPDATE domain_stats SET count = ? WHERE domain = ?", (row[0] + 1, qname))
        else:
            c.execute("INSERT INTO domain_stats (domain, count) VALUES (?, ?)", (qname, 1))
        conn.commit()
        conn.close()
        print(f"[LOGGED] {client_ip} → {qname} ({country}, {city})")

def start_dns_server():
    global DNS_PORT
    try:
        resolver = ZeroTrustResolver()
        server = DNSServer(resolver, port=DNS_PORT, address="0.0.0.0", logger=None)
        server.start_thread()
        print(f"[+] DNS Gateway running on port {DNS_PORT}")
    except PermissionError:
        print("[!] Port 53 failed. Trying fallback port 5353...")
        DNS_PORT = 5353
        resolver = ZeroTrustResolver()
        server = DNSServer(resolver, port=5353, address="0.0.0.0", logger=None)
        server.start_thread()
        print("[+] DNS Gateway running on port 5353")
    except Exception as e:
        print(f"[!] DNS server error: {e}")

if __name__ == "__main__":
    start_dns_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[-] DNS Gateway stopped.")
