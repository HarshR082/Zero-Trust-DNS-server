import sqlite3

conn = sqlite3.connect("access_control.db")
cursor = conn.cursor()

# Table for policies
cursor.execute('''
CREATE TABLE IF NOT EXISTS access_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip TEXT,
    domain TEXT,
    start_time TEXT,
    end_time TEXT,
    allowed INTEGER
)
''')

# Table for logs
cursor.execute('''
CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    client_ip TEXT,
    domain TEXT,
    action TEXT
)
''')

print("✅ Database and tables created.")
conn.commit()
conn.close()
