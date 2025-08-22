# IT Auditor App – Python Telegram Bot for Compliance & Power BI Reporting  

Automated IT audit & compliance oversight app with **Telegram bot integration**, **Power BI dashboards**, and **real-time engineer activity monitoring**.

MIT Licensed and supports **NIST, GDPR, HIPAA, ISO 27001, Essential Eight, SAMA, QCB** and more for Enterprise and Government teams.  

[![MIT License](https://img.shields.io/badge/License-MIT-green?logo=mit&logoColor=white)](LICENSE) 
[![Python](https://img.shields.io/badge/Python-3.8%2B-purple?logo=python&logoColor=white)](https://www.python.org/) 
[![Telegram Bot](https://img.shields.io/badge/Integration-Telegram%20Bot-blue?logo=telegram&logoColor=white)](https://core.telegram.org/bots)
[![PowerBI](https://img.shields.io/badge/Reporting-PowerBI-yellow?logo=power-bi&logoColor=black)](https://powerbi.microsoft.com/)
[![Bash](https://img.shields.io/badge/Bash-Shell-red?logo=gnu&logoColor=white)](https://www.gnu.org/software/bash/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-2025.2-black?logo=kali-linux&logoColor=white)](https://www.kali.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-25.04-orange?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![RHEL](https://img.shields.io/badge/Red_Hat_RHEL-8.8-%238B0000?logo=redhat&logoColor=white)](https://www.redhat.com/)
[![Parrot OS](https://img.shields.io/badge/Parrot_OS-6.4-%23008080?logo=parrot&logoColor=white)](https://www.parrotsec.org/)
[![Windows](https://img.shields.io/badge/Windows-Server-cyan?logo=windows&logoColor=white)](https://www.microsoft.com/windows)


> **Enterprise-grade audit automation telegram-bot app** for cybersecurity compliance and IT operations team management and monitoring. Aligns with global regulatory frameworks while providing real-time oversight of engineer activities.

## 🌍 Global Compliance Coverage
| Region | Supported Frameworks | Target Markets |
|--------|----------------------|----------------|
| **🇺🇸 North America** | NIST CSF, CMMC, HIPAA, SOX | Fortune 500, Tech Giants |
| **🇪🇺 EU/UK** | GDPR, ENISA, ISO 27001 | Government, Finance, Healthcare |
| **🇦🇺 Australia** | Essential Eight, ISM, PSPF | Critical Infrastructure, Telcos |
| **🌏 GCC** | NESA, SAMA, QCB | Oil/Gas, Banking, Government, Telcos, Construction |

## ✨ Key Features
| Feature | Benefit | Tech Implementation |
|---------|---------|---------------------|
| **🔐 Automated Compliance Audits** | Real-time framework gap analysis | PostgreSQL + Custom Rule Engine |
| **👥 Engineer Activity Monitoring** | Shift adherence & punctuality tracking | Telegram Bot + Time Logging |
| **📊 KPI Visualization** | Executive-ready risk dashboards | Pandas/Matplotlib + PowerBI Snapshots |
| **🔔 Audit Trail System** | Tamper-proof operation records | Encrypted .log + Blockchain-style DB |
| **⚙️ Enterprise Integration** | Ready for SOC/SIEM pipelines | Python API + .env Configuration |

## 🚀 Getting Started
```bash
# 1. Clone repository
git clone https://github.com/MOsamaShaikh15TL125/it-auditor-app.git

# 2. Configure environment (Linux/macOS)
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt

# 3. Configure secrets (create .env file)
echo "TELEGRAM_TOKEN='your_own_bot_token_via_@botFather'" >> .env
echo "DATABASE_URL='postgresql://your_own_user:pass@localhost:5432/audit_db'" >> .env
echo "POWERBI_CREDS='encrypted://your_own_power-bi_creds'" >> .env

# 4. Initialize database
python3 db_init.py

# 5. Launch application
python3 it_auditor_app.py
```

## 🛠️ Tech Architecture
```mermaid
graph LR
A[Telegram Bot] --> B(Python Core)
B --> C{PostgreSQL DB}
C --> D[Compliance Engine]
D --> E[PowerBI Reports]
B --> F[Matplotlib Dashboards]
F --> G[Admin Portal]
C --> H[.log Audit Trail]
H --> I[Cron Backups]
```

## 📈 Enterprise Use Cases
1. **Government Auditors**  
   Continuous compliance monitoring for Essential Eight/NIST frameworks
2. **Financial Sector**  
   SOX/HIPAA audit automation with tamper-evident logs
3. **Research Institutions**  
   Dataset generation for GRC (Governance, Risk, Compliance) studies
4. **Forbes 2000 Companies**  
   Real-time engineer shift adherence tracking

## 🔬 Research Opportunities
This project enables academic collaboration in:
- Automated compliance mapping (NIST → GDPR → Essential Eight)
- Behavioral analysis of IT operations teams
- Blockchain applications for audit trails
- AI-powered anomaly detection in shift logs

*Available for joint research with enterprise and corporate grade R&D teams.*

## 📜 License
Distributed under **MIT License**. See `LICENSE` for details.

## 🤝 Contribution & Partnerships
**Seeking:**
- Cybersecurity researchers (paper co-authorship)
- GRC framework specialists
- Enterprise pilot partners
- Government compliance advisors

## 🔁 Roadmap
**Planned enhancements:**
1. *AI-driven compliance assistant & remediation playbooks (Ansible RHEL Enhancements)*
2. *Deeper SOC / SIEM connectors (Splunk, Elastic, Azure Sentinel)*
3. *Hardened KMS integration for keys & secrets*
