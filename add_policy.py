import sqlite3

conn = sqlite3.connect("access_control.db")
cursor = conn.cursor()

# Replace IP and domain as needed
cursor.execute('''
    INSERT INTO access_policies (client_ip, domain, start_time, end_time, allowed)
    VALUES (?, ?, ?, ?, ?)
''', ('127.0.0.1', 'example.com.', '09:00', '18:00', 1))

print("✅ Policy added.")
conn.commit()
conn.close()
