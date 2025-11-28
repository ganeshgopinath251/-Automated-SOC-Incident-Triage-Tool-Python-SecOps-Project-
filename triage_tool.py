import requests
import json
import argparse
import os
import datetime
from dotenv import load_dotenv

# --- 1. CONFIGURATION AND KEY LOADING ---

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_IPDB_KEY = os.getenv("ABUSE_IPDB_KEY")

# --- 2. API CHECK FUNCTIONS (Phase 2) ---

def check_virustotal(ioc):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }
    
    vt_result = {
        'status': 'Error', 
        'data': {}, 
        'score': 0,
        'message': 'No data received'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() 
        data = response.json()
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        malicious_count = stats.get('malicious', 0)
        reputation = attributes.get('reputation', 0)
        
        risk_score = min(malicious_count * 1, 10) 

        vt_result['status'] = 'Success'
        vt_result['data'] = {
            'malicious_vendors': malicious_count,
            'reputation_score': reputation,
            'vt_link': f"https://www.virustotal.com/gui/ip-address/{ioc}/details"
        }
        vt_result['score'] = risk_score
        vt_result['message'] = f"{malicious_count} vendors flagged IOC."
        
    except requests.exceptions.RequestException as e:
        vt_result['message'] = f"VT Request failed: {e}"
    except Exception as e:
        vt_result['message'] = f"VT Data parsing error: {e}"
        
    return vt_result

def check_abuseipdb(ioc):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSE_IPDB_KEY 
    }
    params = {
        'ipAddress': ioc,
        'maxAgeInDays': '90',
        'verbose': True
    }
    
    abuse_result = {
        'status': 'Error', 
        'data': {}, 
        'score': 0,
        'message': 'No data received'
    }

    try:
        response = requests.get(url=url, headers=headers, params=params)
        response.raise_for_status() 
        data = response.json()
        
        abuse_data = data.get('data', {})
        
        confidence_score = abuse_data.get('abuseConfidenceScore', 0)
        total_reports = abuse_data.get('totalReports', 0)
        
        risk_score = confidence_score / 10

        abuse_result['status'] = 'Success'
        abuse_result['data'] = {
            'confidence_score': confidence_score,
            'total_reports': total_reports,
            'country': abuse_data.get('countryCode')
        }
        abuse_result['score'] = risk_score
        abuse_result['message'] = f"Confidence: {confidence_score}%, Reports: {total_reports}"
        
    except requests.exceptions.RequestException as e:
        abuse_result['message'] = f"AbuseIPDB Request failed: {e}"
    except Exception as e:
        abuse_result['message'] = f"AbuseIPDB Data parsing error: {e}"
        
    return abuse_result

# --- 3. MAIN EXECUTION AND REPORTING (Phase 3) ---

def main():
    parser = argparse.ArgumentParser(
        description="Automated IOC Triage Tool. Checks IP/URL against multiple Threat Intelligence sources."
    )
    parser.add_argument(
        '-i', '--ioc', required=True, 
        help="The Indicator of Compromise (IP or URL) to check."
    )
    args = parser.parse_args()
    ioc = args.ioc
    
    if not VT_API_KEY or not ABUSE_IPDB_KEY:
        print("❌ Error: One or more API keys are missing. Check your .env file.")
        return

    print(f"✅ Starting triage for IOC: {ioc}")

    vt_result = check_virustotal(ioc)
    abuse_result = check_abuseipdb(ioc)

    final_report = {
        'IOC': ioc,
        'Timestamp': datetime.datetime.now().isoformat(),
        'Vendor_Data': {
            'VirusTotal': vt_result['data'],
            'AbuseIPDB': abuse_result['data']
        }
    }

    scores = []
    if vt_result['status'] == 'Success':
        scores.append(vt_result['score'])
    if abuse_result['status'] == 'Success':
        scores.append(abuse_result['score'])

    if scores:
        final_report['Final_Risk_Score'] = round(sum(scores) / len(scores), 1)
    else:
        final_report['Final_Risk_Score'] = 0.0

    final_score = final_report['Final_Risk_Score']
    action = ""
    if final_score > 8.0:
        action = "🔴 CRITICAL: Immediate Firewall/Proxy BLOCK and Host Isolation."
    elif final_score >= 5.0:
        action = "🟠 HIGH: Initiate IR investigation (Log Correlation)."
    elif final_score >= 1.0:
        action = "🟡 MEDIUM: Monitor traffic for 24-48 hours."
    else:
        action = "🟢 LOW: Close ticket, no action required."

    final_report['Recommended_Action'] = action

    output_filename = f"{ioc.replace('.', '_')}_triage_report.json"
    
    with open(output_filename, 'w') as f:
        json.dump(final_report, f, indent=4) 
        
    print(f"\nReport Summary:")
    print(f"  Score: {final_report['Final_Risk_Score']}/10")
    print(f"  Action: {action}")
    print(f"\n✅ Triage complete. Report saved to: {output_filename}")

if __name__ == "__main__":
    main()
