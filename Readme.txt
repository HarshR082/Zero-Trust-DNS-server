# 🛡️ Zero Trust DNS Gateway

A powerful Python-based DNS gateway designed with a Zero Trust approach. This project provides DNS-level monitoring, domain blocking, real-time visualization, and alerting for suspicious queries. Built for educational, research, and security-focused use cases.

---

## 🚀 Features

- 🔐 **Zero Trust DNS Gateway**: Only allows trusted DNS queries, blocks malicious or suspicious domains.
- 📊 **Real-Time Dashboard**: Built with Streamlit to monitor DNS activity live.
- 📦 **SQLite Logging**: Logs all queries with timestamp, IP, domain, and basic geo info.
- 🚫 **Domain Blocking**: Easily block domains/subdomains from a database or UI.
- 🧠 **Subdomain-aware Filtering**: Automatically blocks subdomains of known bad domains.
- 📧 **Email Alerts**: Sends email alerts when suspicious domains are queried (configurable).
- 🖥️ **Client Stats**: Tracks unique IPs querying the gateway.

---

## 🧱 Tech Stack

- Python 3.10+
- [dnslib](https://github.com/paulc/dnslib) — DNS protocol handling
- SQLite — lightweight logging database
- Streamlit — real-time interactive dashboard
- socket & threading — for network and server communication
- smtplib (optional) — for sending email notifications

---

## 📂 Project Structure

```bash
.
├── dns_gateway.py       # Main DNS server script (port 53)
├── dashboard.py         # Streamlit dashboard for real-time monitoring
├── dns_logs.db          # SQLite database (auto-created)
├── requirements.txt     # Dependencies
└── README.md            # This file
