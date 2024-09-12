from dotenv import load_dotenv

import requests
import os
import sys
import time

load_dotenv('API_KEYS.env')
VT_URL = "https://www.virustotal.com/vtapi/v2/ip-address/report"

def check_ip_virustotal(ip):
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    # Test api_key injestion
    # print(f"{api_key}")
    # Queries VirusTotal API to check the status of the hash.
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
    pass # Function to be implemented

def main():
    ip = input("Enter IP address to check: ")
    # Will call the API's and return results
    check_ip_virustotal(ip)
    check_ip_abuseipdb(ip)

if __name__ == "__main__":
    main()
