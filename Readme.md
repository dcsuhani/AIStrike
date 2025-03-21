# Threat Intelligence Enrichment Tool

## Overview

The **Threat Intelligence Enrichment Tool** is a Python-based utility designed for cybersecurity professionals and enthusiasts. It enables users to gather and enrich information about domains, IP addresses, and URLs from external threat intelligence sources like **WHOIS**, **VirusTotal**, and **IPinfo**.

This tool can be used for various cybersecurity tasks such as:
- Investigating suspicious domains, IPs, or URLs.
- Looking up reputation scores.
- Gathering metadata to aid in decision-making.

## Features

- **Enrichment Sources**:
  - **WHOIS Lookup**: Fetch domain registration details using the `whois` library.
  - **VirusTotal API**: Retrieve reputation scores and threat intelligence from VirusTotal.
  - **IPinfo API**: Get detailed information on IP addresses (geolocation, organization, etc.).

- **Input Methods**:
  - **Text files**: A file containing one domain/IP/URL per line.
  - **Command-line arguments**: For custom domain/IP/URL input.

- **Performance**:
  - Multi-threaded lookups for faster processing of multiple targets.

- **Output**:
  - Enriched data is provided in a structured **JSON** format.

- **Logging & Error Handling**:
  - Includes logging for better traceability and error handling.
 
- **Usage**:
  - Command line input:____python main.py -i <domain_or_ip_or_url>
  - File input:________________python main.py -f <file_name>


