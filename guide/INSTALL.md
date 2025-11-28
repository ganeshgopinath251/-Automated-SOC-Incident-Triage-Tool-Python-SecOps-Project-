# 🛠️ Detailed Installation and Setup Guide

This guide provides the necessary steps to securely set up and execute the **Automated SOC Incident Triage Tool**.

## 1. Prerequisites

Before starting, ensure you have the following:

* **Python 3.8+** installed on your system.
* **Free API keys** obtained from the two required Threat Intelligence services:
    * **VirusTotal** (VT API Key)
    * **AbuseIPDB** (AbuseIPDB API Key)

## 2. Get the Project Files

Since this project is hosted on GitHub, you or any future user will need to clone the repository to run the code locally.

```bash
# Clone the repository using the correct .git URL:
git clone [https://github.com/ganeshgopinath251/-Automated-SOC-Incident-Triage-Tool-Python-SecOps-Project-.git](https://github.com/ganeshgopinath251/-Automated-SOC-Incident-Triage-Tool-Python-SecOps-Project-.git)

# Navigate into the project folder:
cd -Automated-SOC-Incident-Triage-Tool-Python-SecOps-Project-
```

## 3. Setup Virtual Environment and Dependencies

Isolate the project dependencies:

Install Dependencies:

```bash
# Create and Activate the environment (Linux/macOS)
python3 -m venv venv 
source venv/bin/activate

# Install Required Libraries:
pip install -r requirements.txt
```

## 4. Secure API Key Configuration

⚠️ API keys must be kept secret!

Create the .env file: Create a local file named .env (it is listed in .gitignore and will not be uploaded).

Add Your Keys: Paste your actual keys:

```bash
VT_API_KEY="YOUR_ACTUAL_VIRUSTOTAL_KEY_STRING_HERE"
ABUSE_IPDB_KEY="YOUR_ACTUAL_ABUSEIPDB_KEY_STRING_HERE"
```

## 5. Running the Tool

Execute the script from the command line:

```bash
(venv) $ python triage_tool.py -i 8.8.8.8
```
