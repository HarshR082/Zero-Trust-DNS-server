import streamlit as st
st.set_page_config(layout="wide", page_title="Zero Trust DNS Dashboard")  # Must be first Streamlit command

import sqlite3
import pandas as pd
import os
from streamlit_autorefresh import st_autorefresh
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


# ========== Flush Chrome DNS ==========
def flush_chrome_dns():
    options = Options()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)
    driver.get("chrome://net-internals/#dns")
    driver.execute_script("chrome.send('clearHostResolverCache');")
    driver.quit()

# ========== Button to flush DNS ==========
if st.button("🧹 Flush Chrome DNS Cache"):
    try:
        flush_chrome_dns()
        st.success("Chrome DNS cache flushed.")
    except Exception as e:
        st.error(f"Failed to flush DNS cache: {e}")

# ========== Auto-refresh every 10s ==========
st_autorefresh(interval=10000, key="dns-refresh")  # Refresh every 10 seconds

# ========== Dashboard Title ==========
st.title("🔐 Zero Trust DNS Gateway Dashboard")
st.caption("Live Monitoring & Domain Control")

db_path = "dns_logs.db"

if not os.path.exists(db_path):
    st.warning("DNS database not found.")
    st.stop()

# ========== DB Connection ==========
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# ========== Accurate Query & Client Counts ==========
cursor.execute("SELECT COUNT(*) FROM dns_logs")
total_queries = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(DISTINCT client_ip) FROM dns_logs")
unique_clients = cursor.fetchone()[0]

# ========== DNS Traffic Metrics ==========
st.subheader("📊 DNS Traffic Overview")
col1, col2 = st.columns(2)
col1.metric("Total DNS Queries", total_queries)
col2.metric("Unique Clients", unique_clients)

# ========== Top Queried Domains ==========
st.subheader("🏆 Top Queried Domains")
top_domains = pd.read_sql("SELECT domain, count FROM domain_stats ORDER BY count DESC LIMIT 10", conn)

if not top_domains.empty:
    st.bar_chart(top_domains.set_index("domain"))
else:
    st.info("No domain stats to show yet.")

# ========== Recent DNS Logs ==========
st.subheader("📋 Recent DNS Logs")
logs_df = pd.read_sql("SELECT * FROM dns_logs ORDER BY id DESC LIMIT 100", conn)

if not logs_df.empty:
    st.dataframe(logs_df, use_container_width=True, height=300)
else:
    st.info("No DNS logs available.")

# ========== Blocked Domains Section ==========
st.subheader("🚫 Blocked Domains Management")
blocked = pd.read_sql("SELECT domain FROM blocked_domains", conn)

if blocked.empty:
    st.info("No domains are currently blocked.")
else:
    st.write("📌 Currently Blocked Domains")
    for domain in blocked['domain']:
        col1, col2 = st.columns([6, 1])
        col1.write(domain)
        if col2.button("Unblock", key=f"unblock-{domain}"):
            cursor.execute("DELETE FROM blocked_domains WHERE domain = ?", (domain,))
            conn.commit()
            st.success(f"✅ {domain} unblocked.")
            st.rerun()

# ========== Add Domain to Blocklist ==========
st.write("➕ Block a New Domain")
new_domain = st.text_input("Enter domain to block", "")

if st.button("Block Domain"):
    domain_clean = new_domain.strip().lower()
    if domain_clean:
        try:
            cursor.execute("INSERT OR IGNORE INTO blocked_domains (domain) VALUES (?)", (domain_clean,))
            conn.commit()
            st.success(f"✅ {domain_clean} has been blocked.")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Error blocking domain: {e}")
    else:
        st.warning("⚠️ Please enter a valid domain name.")

conn.close()
