# 🛡️ Automated SOC Incident Triage Tool (Python SecOps Project)

> **Problem:** Manual threat hunting and IOC enrichment slows down response time in Security Operations Centers (SOCs).
>
> **Solution:** This tool automates the **Triage and Enrichment** process for Indicators of Compromise (IOCs) using public **Threat Intelligence (TI)** APIs. It calculates a unified risk score and a critical operational recommendation, significantly reducing **Mean Time to Respond (MTTR)**.

---
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python) 
![Project Status](https://img.shields.io/badge/Status-Complete-success?style=flat-square) 
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
---

## ⚙️ Setup and Installation

The project uses a Python virtual environment (`venv`) for dependency isolation and securely loads API keys via a `.env` file.

For the complete, detailed, step-by-step instructions on cloning the repository, setting up your environment, configuring your API keys, and executing the script, please refer to the dedicated **Installation Guide** below.

---

### ➡️ [View Full Installation and Setup Guide](./docs/INSTALL.md)

---

## 🧠 Technical Deep Dive (System Rationale)

* **Security Principle (Key Management):** API keys are managed using the **`.env`** file and the `python-dotenv` library. This ensures that sensitive credentials are never hard-coded or exposed.
* **Scalability (Modular Design):** The core logic is built with separate functions, making it easy to add more Threat Intelligence sources without rewriting the main scoring logic.

## 🧪 Test Cases and Results

The tool was tested against IPs representing Low, Medium, and High threat levels.

### Command Example:
The script provides immediate operational feedback upon completion:

```bash
(venv) $ python triage_tool.py -i 8.8.8.8
✅ Starting triage for IOC: 8.8.8.8

Report Summary:
  Score: 0.0/10
  Action: 🟢 LOW: Close ticket, no action required.

✅ Triage complete. Report saved to: 8_8_8_8_triage_report.json
```

## 💡 Future Enhancements
* **IOC Type Expansion:** Include logic to parse and check URLs and domains.
* **Web Interface:** Implement a simple user interface using a framework like Flask.
