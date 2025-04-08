from dnslib import DNSRecord, QTYPE, RR, A
import socketserver
from datetime import datetime
import sqlite3

def log_to_file(client_ip, domain, action):
    with open("dns_logs.txt", "a") as f:
        f.write(f"{datetime.now()} | {client_ip} | {domain} | {action}\n")

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        client_ip = self.client_address[0]

        request = DNSRecord.parse(data)
        domain = str(request.q.qname)[:-1]
        qtype = QTYPE[request.q.qtype]

        conn = sqlite3.connect("access_control.db")
        cursor = conn.cursor()

        # Create table if not exists
        cursor.execute("CREATE TABLE IF NOT EXISTS blocked_domains (domain TEXT)")
        cursor.execute("CREATE TABLE IF NOT EXISTS dns_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, client_ip TEXT, domain TEXT, action TEXT, timestamp TEXT)")

        # Check if blocked
        cursor.execute("SELECT 1 FROM blocked_domains WHERE domain=?", (domain,))
        is_blocked = cursor.fetchone() is not None

        action = "BLOCKED" if is_blocked else "ALLOWED"
        log_to_file(client_ip, domain, action)
        cursor.execute("INSERT INTO dns_logs (client_ip, domain, action, timestamp) VALUES (?, ?, ?, ?)", (client_ip, domain, action, str(datetime.now())))
        conn.commit()
        conn.close()

        if is_blocked:
            reply = request.reply()
            socket.sendto(reply.pack(), self.client_address)
        else:
            # Forward to real DNS
            real_response = DNSRecord.parse(request.send("8.8.8.8", 53))
            socket.sendto(real_response.pack(), self.client_address)

if __name__ == "__main__":
    print("🔐 Zero Trust DNS Gateway running on UDP port 5053")
    server = socketserver.UDPServer(('0.0.0.0', 5053), DNSHandler)
    server.serve_forever()
