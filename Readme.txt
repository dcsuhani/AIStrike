Threat Intelligence Enrichment Tool
Overview
The Threat Intelligence Enrichment Tool is a Python-based utility that allows users to gather and enrich information about domains, IP addresses, and URLs from external threat intelligence sources like WHOIS, VirusTotal, and IPinfo.

This tool can be used for various cybersecurity tasks such as investigating suspicious domains, IPs, or URLs, looking up reputation scores, and gathering metadata to help in decision-making.

Features
Perform enrichment using the following data sources:

WHOIS Lookup: Fetch domain registration details using the whois library.
VirusTotal API: Retrieve reputation scores and threat intelligence from VirusTotal.
IPinfo API: Get detailed information on IP addresses (geolocation, organization, etc.).
Accepts inputs from:

Text files: A file containing one domain/IP/URL per line.
Command-line arguments: For custom domain/IP/URL input.
API: Allows enriching a domain/IP/URL via an API.
Supports multi-threaded lookups for faster processing of multiple targets.

Outputs the enriched data in a structured JSON format.

Includes logging for better traceability and error handling.

Requirements
Python 3.x
Install the required Python libraries using pip:
bash
Copy
pip install requests python-whois
You will also need to obtain API keys for the external services:
VirusTotal API Key: Sign up for VirusTotal API
IPinfo API Key: Sign up for IPinfo API
File Structure
graphql
Copy
threat-intelligence-enrichment-tool/
│
├── config.py           # Contains the API keys for VirusTotal and IPinfo
├── main.py             # The main script for running the tool
├── utils.py            # Helper functions for performing lookups and handling data
├── logs/               # Directory for storing log files
│   └── app.log         # Application log file
├── enriched_data.json  # Output file containing enriched data in JSON format
└── README.md           # This readme file
Setup
API Keys:

Open config.py and add your VirusTotal and IPinfo API keys in the API_KEYS dictionary. Example:
python
Copy
API_KEYS = {
    "virustotal": "your_virustotal_api_key_here",
    "ipinfo": "your_ipinfo_api_key_here"
}
Install Dependencies: Use the following command to install the necessary Python libraries:

bash
Copy
pip install -r requirements.txt
Or manually install the libraries:

bash
Copy
pip install requests python-whois
Usage
You can run the tool in different ways depending on your input source.

1. Command-Line Input
To provide a single domain/IP/URL for enrichment via command-line arguments, run:

bash
Copy
python main.py -i <domain_or_ip>
Example:

bash
Copy
python main.py -i example.com
2. File Input
To use a file containing a list of domains/IPs/URLs (one per line), run:

bash
Copy
python main.py -f <file_path>
Example:

bash
Copy
python main.py -f targets.txt
3. API Lookup
You can enable API-based lookup by providing the -a flag:

bash
Copy
python main.py -a
Output
The enriched data will be saved as a JSON file called enriched_data.json in the current directory.

Logging
Logs are saved in the logs/app.log file. You can check this file to see detailed information about the operations, including any errors or warnings.

Example
Here's an example of how the tool enriches a single target (example.com):

bash
Copy
python main.py -i example.com
This will:

Perform a WHOIS lookup on example.com.
Fetch the reputation score and details from VirusTotal.
Fetch IPinfo details (if applicable).
The results will be saved to enriched_data.json.