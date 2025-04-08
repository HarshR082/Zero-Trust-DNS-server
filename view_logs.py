import sqlite3

# Connect to your log database
conn = sqlite3.connect("dns_logs.db")
cursor = conn.cursor()

# Show last 10 DNS queries
print("\n🧾 Last 10 DNS Queries:")
cursor.execute("SELECT timestamp, client_ip, country, city, domain FROM dns_logs ORDER BY id DESC LIMIT 10")
rows = cursor.fetchall()
for row in rows:
    print(f"[{row[0]}] {row[1]} ({row[2]}, {row[3]}) → {row[4]}")

# Show most queried domains
print("\n📊 Top Queried Domains:")
cursor.execute("SELECT domain, count FROM domain_stats ORDER BY count DESC LIMIT 10")
top_domains = cursor.fetchall()
for domain, count in top_domains:
    print(f"{domain} - {count} times")

conn.close()
