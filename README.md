IP Reputation Checker
Overview

The IP Reputation Checker is a Python-based tool that checks IP addresses against known threat intelligence feeds like VirusTotal and AbuseIPDB. The tool provides a reputation score for each IP address, helping security analysts quickly identify potentially malicious IPs. This is particularly useful in threat hunting and incident response to reduce manual effort and accelerate investigations.
Features

    IP Validation: The tool ensures that only valid IPv4 and IPv6 addresses are checked.
    VirusTotal Integration: Queries the VirusTotal API to retrieve IP reputation data.
    AbuseIPDB Integration: (Future feature) Check IPs against AbuseIPDB for further threat intelligence.
    Batch Processing: Supports checking multiple IP addresses from a file.
    Rate Limiting Handling: Detects API rate limits and gracefully stops the script to avoid errors.
    Output: Prints results to the console, including the number of detections and whether the IP was found to be malicious.

Installation

    Clone the Repository

git clone https://github.com/ViridianImpact/IP-Reputation-Checker.git
cd IP-Reputation-Checker

Install Dependencies Ensure you have Python 3.x installed. Install the required dependencies by running:

bash

pip install -r requirements.txt

Set up Environment Variables

    Create a .env file in the root directory of the project.
    Add your VirusTotal API key to the .env file like this:

    VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

Running the Script

    Ensure you have a file ips.txt with a list of IP addresses (one IP per line).
    Run the IP checker by using:

        python ip_reputation_checker.py

Usage

    Input IP Addresses: The script reads from a file (ips.txt by default), containing one IP address per line. Example file format:

    192.168.1.1
    8.8.8.8
    2001:db8::ff00:42:8329

    Output: The script will output the results of the IP reputation checks to the console, displaying the number of detections or if the IP is not found in the database.

API Rate Limiting

The script automatically detects if the API rate limit has been exceeded and stops further processing. This avoids unnecessary API requests and errors when the rate limit has been reached.
Example Output

makefile

8.8.8.8: Not found in VirusTotal
192.168.1.1: Not found in VirusTotal
2001:db8::ff00:42:8329: 2 detections
Rate limit exceeded. Please wait and try again.

Contribution

Feel free to fork the repository and submit pull requests to improve the functionality of the IP Reputation Checker. We welcome contributions related to:

    Adding more threat intelligence sources (e.g., AbuseIPDB)
    Enhancing error handling
    Improving reporting formats (e.g., exporting to CSV)
