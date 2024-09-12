from dotenv import load_dotenv

import ipaddress
import requests
import os
import sys
import time

load_dotenv('API_KEYS.env')
VT_URL = "https://www.virustotal.com/vtapi/v2/ip-address/report"
IPDB_URL = "https://api.abuseipdb.com/api/v2/check"

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        # # Test for confirmation
        # print(f"{ip} is a valid IP")
        return True
    except ValueError:
        print(f"{ip} is NOT a valid IP")
        sys.exit(1)

def check_ip_virustotal(ip):
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    # Test api_key injestion
    # print(f"{api_key}")
    # Queries VirusTotal API to check the status of the IP.
    params = {'apikey': api_key, 'ip': ip}

    response = requests.get(VT_URL, params=params)

    if response.status_code == 200:
        result = response.json()
        if 'detected_urls' in result:
            print(f"IP {ip} found in VirusTotal with malicious activity.")
            for url in result['detected_urls']:
                print(f"Malicious URL: {url['url']} with {url['positives']} positives.")
        else:
            print(f"No malicious activity found for IP {ip} on VirusTotal.")
    elif response.status_code == 204:
        print("Rate limit exceeded for VirusTotal API.")
        sys.exit(1)
    else:
        print(f"Error: {response.status_code}")

def check_ip_abuseipdb(ip):
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    # Test api_key injestion
    # print(f"{api_key}")
    # Queries AbuseIPDB API to check the status of the IP.
    headers = {
        'Accept': 'applications/json',
        'Key': api_key
    }
    params = {'ipAddress': ip, 'maxAgeInDays': 90}

    response = requests.get(IPDB_URL, headers=headers, params=params)

    if response.status_code == 200:
        result = response.json()
        if result['data']['abuseConfidenceScore'] > 0:
            print(f"IP {ip} found in AbuseIPDB with an Abuse Confidence Score of {result['data']['abuseConfidenceScore']}")
        else:
            print(f"No malicious activity found for IP {ip} on AbuseIPDB.")
    elif response.status_code == 204 or response.status_code == 429:
        print("Rate limit exceeded for AbuseIPDB API.")
        sys.exit(1)
    else:
        print(f"Error: {response.status_code}")

def main():
    ip = input("Enter IP address to check: ")
    # Checks for valid input
    is_valid_ip(ip)
    # Will call the API's and return results
    print("\n--- AbuseIPDB Results ---")
    check_ip_abuseipdb(ip)
    print("\n--- VirusTotal Results ---")
    check_ip_virustotal(ip)

if __name__ == "__main__":
    main()
