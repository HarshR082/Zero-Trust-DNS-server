import streamlit as st
import sqlite3
import pandas as pd
import os
from streamlit_autorefresh import st_autorefresh
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

st.set_page_config(layout="wide", page_title="Zero Trust DNS Dashboard")

# ========== Flush Chrome DNS ==========
def flush_chrome_dns():
    options = Options()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)
    driver.get("chrome://net-internals/#dns")
    driver.execute_script("chrome.send('clearHostResolverCache');")
    driver.quit()

# ========== DNS DB Setup ==========
db_path = "dns_logs.db"

if not os.path.exists(db_path):
    st.error("❌ DNS database not found. Please start the DNS gateway first.")
    st.stop()

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# ========== Auto-refresh ==========
st_autorefresh(interval=10000, key="dns-refresh")

# ========== Top Title ==========
st.title("🔐 Zero Trust DNS Gateway Dashboard")
st.caption("Real-Time Monitoring | Domain & Geo Blocking | DNS Control")

# ========== Flush Button ==========
if st.button("🧹 Flush Chrome DNS Cache"):
    try:
        flush_chrome_dns()
        st.success("Chrome DNS cache flushed successfully.")
    except Exception as e:
        st.error(f"Failed to flush DNS cache: {e}")

# ========== DNS Traffic Metrics ==========
st.subheader("📊 DNS Traffic Overview")

cursor.execute("SELECT COUNT(*) FROM dns_logs")
total_queries = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(DISTINCT client_ip) FROM dns_logs")
unique_clients = cursor.fetchone()[0]

col1, col2 = st.columns(2)
col1.metric("Total DNS Queries", total_queries)
col2.metric("Unique Clients", unique_clients)

# ========== Top Queried Domains ==========
st.subheader("🏆 Top Queried Domains")
top_domains = pd.read_sql("SELECT domain, count FROM domain_stats ORDER BY count DESC LIMIT 10", conn)
if not top_domains.empty:
    st.bar_chart(top_domains.set_index("domain"))
else:
    st.info("No queries recorded yet.")

# ========== Recent DNS Logs ==========
st.subheader("📋 Recent DNS Logs")
logs_df = pd.read_sql("SELECT * FROM dns_logs ORDER BY id DESC LIMIT 100", conn)
if not logs_df.empty:
    st.dataframe(logs_df, use_container_width=True, height=300)
else:
    st.info("No DNS logs available yet.")

# ========== Blocked Domains ==========
st.subheader("🚫 Blocked Domains")
blocked = pd.read_sql("SELECT domain FROM blocked_domains", conn)

if blocked.empty:
    st.info("No domains are currently blocked.")
else:
    for domain in blocked["domain"]:
        col1, col2 = st.columns([6, 1])
        col1.write(domain)
        if col2.button("Unblock", key=f"unblock-{domain}"):
            cursor.execute("DELETE FROM blocked_domains WHERE domain = ?", (domain,))
            conn.commit()
            st.success(f"✅ {domain} has been unblocked.")
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
            st.error(f"Error blocking domain: {e}")
    else:
        st.warning("⚠️ Please enter a valid domain.")

# ========== Blocked Countries (Geo) ==========
st.subheader("🌍 Blocked Countries (Geo-Based Blocking)")
if "BLOCKED_COUNTRIES" not in st.session_state:
    st.session_state.BLOCKED_COUNTRIES = ["CN", "RU"]

blocked_countries = st.session_state.BLOCKED_COUNTRIES

for country in blocked_countries:
    col1, col2 = st.columns([6, 1])
    col1.write(country)
    if col2.button("Unblock Country", key=f"unblock-country-{country}"):
        blocked_countries.remove(country)
        st.success(f"🗺️ {country} unblocked.")
        st.rerun()

new_country = st.text_input("➕ Block a Country (ISO Code)", "")
if st.button("Block Country"):
    iso = new_country.strip().upper()
    if iso and iso not in blocked_countries:
        blocked_countries.append(iso)
        st.success(f"🌐 Country {iso} is now blocked.")
        st.rerun()
    else:
        st.warning("⚠️ Invalid or already blocked country.")

# ========== Blocked Activity ==========
st.subheader("📌 Blocked Activity Logs")
blocked_logs = pd.read_sql(
    "SELECT * FROM dns_logs WHERE domain IN (SELECT domain FROM blocked_domains) "
    "OR country IN ({seq}) ORDER BY id DESC LIMIT 100".format(
        seq=','.join(['?']*len(blocked_countries))
    ), conn, params=blocked_countries)

if not blocked_logs.empty:
    st.dataframe(blocked_logs, use_container_width=True, height=300)
else:
    st.info("No blocked activities recorded yet.")

conn.close()
