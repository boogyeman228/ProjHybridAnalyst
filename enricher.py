import sys
import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_TOKEN = os.getenv("API_TOKEN","").strip()
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

HEADERS = {
    "api-token": API_TOKEN,
    "api-key": API_TOKEN,
    "user-agent": "Falcon Sandbox",
    "accept": "application/json"
}

def print_report(data: dict):
    file_name = data.get('last_file_name') or data.get('submit_name') or 'N/A'
        
# Fallback to multiscan_result if threat_score is omitted or None
    threat_score = data.get('threat_score')
    if threat_score is None:
        threat_score = data.get('multiscan_result', 0)
    
    print("\n" + "="*50)
    print("__ SOC HASH ANALYSIS REPORT (Hybrid Analysis)__")
    print("="*50)
    print(f" [+] File name:        {file_name}")
    print(f" [+] File Type:        {data.get('type', 'N/A')}")
    print(f" [+] Threat Score:   {threat_score} / 100")
    print(f" [+] Verdict:          {str(data.get('verdict', 'N/A')).upper()}")
    print(f" [+] Malware Family:        {data.get('vx_family', 'Не определена')}")
    print(f" [+] SHA256:           {data.get('sha256', 'N/A')}")
    print(f" [+] Report URL:  https://www.hybrid-analysis.com/sample/{data.get('sha256')}")
    print("="*50 + "\n")

# Queries Hybrid Analysis API endpoints for the provided hash.
def check_hash(file_hash: str):
    if not API_TOKEN:
        print("!!! ERROR: API_TOKEN is missing from the .env file !!!")
        return

    file_hash = file_hash.strip()
    print(f" Querying Hybrid Analysis API for hash: {file_hash}...")

    try:
        # 1. Primary lookup: Direct overview endpoint
        url = f"{BASE_URL}/overview/{file_hash}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 200:
            print_report(response.json())
            return

# 2. Secondary fallback lookup: Search endpoint (for MD5, SHA1, etc.)
        search_url = f"{BASE_URL}/search/hash"
        search_resp = requests.get(search_url, headers=HEADERS, params={"hash": file_hash})

        if search_resp.status_code == 200:
            results = search_resp.json()
            if results:
                print_report(results[0])
                return

        print(f"--Hash {file_hash} was not found in the Hybrid Analysis database.")

    except Exception as e:
        print(f"[!] Request error encountered: {e}")
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python enricher.py <HASH>")
    else:
        check_hash(sys.argv[1])