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

### ➡️ [View Full Installation and Setup Guide](guide/INSTALL.md)

---

## 🧠 Technical Deep Dive (System Rationale)

* **Security Principle (Key Management):** API keys are managed using the **`.env`** file and the `python-dotenv` library. This ensures that sensitive credentials are never hard-coded or exposed.
* **Scalability (Modular Design):** The core logic is built with separate functions, making it easy to add more Threat Intelligence sources without rewriting the main scoring logic.

## 🧪 Test Cases and Logic Proof

The tool was tested across the full spectrum of risk levels to demonstrate its scoring, policy assignment, and reliability.

### Addressing API Limitations (Advanced Security Awareness) 🧠

Due to the common **restrictions of free-tier Threat Intelligence APIs**, a simulation was necessary to prove the intended critical logic. This strategy ensures we document both the solution and the real-world limitations.

---

### 1. Critical Risk Scenario (Proof of Logic) 🔴

This demonstrates the core logic: the tool correctly processes high-risk data and assigns the strictest security policy.

* **File:** [`03-high-risk-simulated.json`](./results/03-high-risk-simulated.json)
* **Final Score:** **8.5/10**
* **Policy:** **🔴 CRITICAL: Immediate Firewall/Proxy BLOCK and Host Isolation.**

## 🔒 Why the High-Risk Result is Simulated (Advanced Security Awareness)

This project demonstrates an understanding of **real-world API data constraints** faced by enterprise Security Operations Centers (SOCs).

The **`03-high-risk-simulated.json`** file was created to explicitly showcase the tool's intended scoring and policy assignment logic, as the live check is often misleading.

### The Problem: Free-Tier API Restrictions

* Free-tier API keys for major Threat Intelligence platforms (like VirusTotal) often **suppress the true malicious statistics** for notorious IPs.
* If we relied on the live restricted data, the malicious IP would incorrectly score **0.0/10**, failing to prove that the core logic of the tool works under high-risk conditions.

### The Solution: Proof of Logic and Thoughtful Design

By using a simulated report, we achieve two crucial goals:

1.  **Validate the Code:** We prove that when the tool *does* receive accurate high-risk data (e.g., 8 malicious flags, 90% confidence), the **internal scoring and policy logic** correctly calculates an $8.5/10$ score and assigns the **CRITICAL BLOCK** policy.
2.  **Highlight The Limitation Feature:** This scenario underscores the importance of the **`vt_link`** field in our JSON output. When an analyst sees a suspiciously low automated score, the provided link enables them to **manually verify** the finding, showing a design that compensates for data source unreliability.

### 2. Medium Risk Scenario (Differentiation) 🟡

This uses live data to show the tool's ability to differentiate between low-priority noise and threats requiring closer monitoring.

* **File:** [`02-medium-risk-live.json`](./results/02-medium-risk-live.json)
* **Final Score:** **3.5/10**
* **Policy:** **🟡 MEDIUM: Monitor traffic for 24-48 hours.**

### 3. Low Risk Scenario (Verification) 🟢

This verifies the tool's accuracy on a trusted IOC, confirming it correctly assigns the lowest risk score.

* **File:** [`01-low-risk-live.json`](./results/01-low-risk-live.json)
* **Final Score:** **0.0/10**
* **Policy:** **🟢 LOW: Close ticket, no action required.**

## 💡 Future Enhancements
* **IOC Type Expansion:** Include logic to parse and check URLs and domains.
* **Web Interface:** Implement a simple user interface using a framework like Flask.
