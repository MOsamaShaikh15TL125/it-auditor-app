# 🔒 IT Auditor App – Open Source Python Telegram Bot for Compliance & Power BI Reporting

Automated IT audit & compliance oversight tool with **Telegram bot integration**, **Power BI dashboards**, and **real-time engineer activity monitoring**.

**MIT Licensed**, supporting **NIST, GDPR, HIPAA, ISO 27001, Essential Eight, SAMA, QCB**, designed for **Enterprise, Government, and Research teams**.

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

---

> **Enterprise-grade audit automation Telegram bot** for cybersecurity compliance and IT operations team management. Aligns with global regulatory frameworks while providing real-time oversight of engineer activities.

---

## 🌍 Global Compliance Coverage

| Region | Supported Frameworks | Target Sectors |
|--------|---------------------|----------------|
| **🇺🇸 North America** | NIST CSF, CMMC, HIPAA, SOX | Fortune 500, Tech Giants, Government |
| **🇪🇺 EU / UK** | GDPR, ENISA, ISO 27001 | Finance, Healthcare, Government |
| **🇦🇺 Australia** | Essential Eight, ISM, PSPF | Critical Infrastructure, Telcos |
| **🌏 GCC** | NESA, SAMA, QCB | Banking, Oil & Gas, Government, Telcos, Construction |

---

## ✨ Key Features

| Feature | Benefit | Technology |
|---------|---------|------------|
| **🔐 Automated Compliance Audits** | Real-time compliance gap analysis | Python + PostgreSQL + Custom Rule Engine |
| **👥 Engineer Activity Monitoring** | Shift adherence & punctuality tracking | Telegram Bot + Time Logging |
| **📊 KPI Visualization** | Executive-ready dashboards | Pandas / Matplotlib + Power BI Snapshots |
| **🔔 Tamper-proof Audit Trail** | Immutable records for SOC/SIEM | Encrypted logs + Blockchain-style DB |
| **⚙️ Enterprise Integration** | SOC/SIEM pipelines ready | Python API + .env Configuration |

---

## 🚀 Getting Started

```bash
# 1. Clone repository
git clone https://github.com/MOsamaShaikh15TL125/it-auditor-app.git

# 2. Setup virtual environment
python3 -m venv .venv && source .venv/bin/activate
pip3 install -r requirements.txt

# 3. Configure environment variables (.env)
echo "TELEGRAM_TOKEN='your_bot_token_from_botfather'" >> .env
echo "DATABASE_URL='postgresql://user:pass@localhost:5432/audit_db'" >> .env
echo "POWERBI_CREDS='encrypted://your_powerbi_creds'" >> .env

# 4. Initialize database
python3 db_init.py

# 5. Run application
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
