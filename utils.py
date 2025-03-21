import requests
import re
import base64
import logging
import whois
from datetime import datetime
from config import API_KEYS  # Import API keys from config.py
from concurrent.futures import ThreadPoolExecutor, as_completed


# Recursively converts datetime objects in dictionaries or lists to string format
def convert_datetimes(obj):
    if isinstance(obj, dict):
        return {key: convert_datetimes(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetimes(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    else:
        return obj


# WHOIS Lookup
def whois_lookup(domain_or_ip):
    try:
        logging.info(f"Performing WHOIS lookup for: {domain_or_ip}")
        result = whois.whois(domain_or_ip)
        # Convert all datetime objects to string format for JSON compatibility
        result = convert_datetimes(result)
        return result
    except Exception as e:
        logging.error(f"Error during WHOIS lookup for {domain_or_ip}: {str(e)}")
        return None


# VirusTotal Lookup
def virustotal_lookup(domain_or_ip):
    if not API_KEYS.get('virustotal'):
        logging.error("VirusTotal API key is not configured in config.py.")
        return None

    if is_domain(domain_or_ip):
        url = f"https://www.virustotal.com/api/v3/domains/{domain_or_ip}"
    elif is_ip(domain_or_ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{domain_or_ip}"
    elif is_url(domain_or_ip):
        # For URLs, we need to base64 encode the URL
        encoded_url = base64.urlsafe_b64encode(domain_or_ip.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    else:
        logging.error(f"Invalid target type for VirusTotal lookup: {domain_or_ip}")
        return None

    headers = {
        "x-apikey": API_KEYS['virustotal']
    }

    try:
        logging.info(f"Making request to VirusTotal for: {domain_or_ip} with URL: {url}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response_data = response.json()
            if "data" in response_data:
                logging.info(f"Data found for {domain_or_ip}.")
                return response_data
            else:
                logging.warning(f"No data found for {domain_or_ip} in VirusTotal response.")
                return None
        elif response.status_code == 404:
            logging.warning(f"VirusTotal did not find any data for {domain_or_ip}. It may not be indexed.")
            return None
        else:
            logging.error(f"Error fetching VirusTotal data for {domain_or_ip}: {response.text}")
            return None

    except Exception as e:
        logging.error(f"Error during VirusTotal lookup for {domain_or_ip}: {str(e)}")
        return None


# IPinfo Lookup
def ipinfo_lookup(domain_or_ip):
    if not API_KEYS.get('ipinfo'):
        logging.error("IPinfo API key is not configured in config.py.")
        return None

    url = f"https://ipinfo.io/{domain_or_ip}/json"
    headers = {
        "Authorization": f"Bearer {API_KEYS['ipinfo']}"
    }

    try:
        logging.info(f"Fetching IPinfo data for: {domain_or_ip}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Error fetching IPinfo data for {domain_or_ip}: {response.text}")
            return None
    except Exception as e:
        logging.error(f"Error during IPinfo lookup for {domain_or_ip}: {str(e)}")
        return None


# Helper functions to identify the type of target
def is_domain(target):
    """Check if the target is a domain."""
    return bool(re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', target)) and not is_ip(target)


def is_ip(target):
    """Check if the target is an IP address."""
    try:
        parts = target.split('.')
        return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False


def is_url(target):
    """Check if the target is a URL."""
    return bool(re.match(r'^(http://|https://)[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+', target))


# Perform lookups in parallel
def perform_lookup_in_parallel(targets):
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []

        for target in targets:
            futures.append(executor.submit(enrich_target_data, target))

        results = []
        for future in as_completed(futures):
            results.append(future.result())

        return results


# Enrich each target
def enrich_target_data(target):
    whois_data = None
    if is_ip(target) or is_domain(target):
        whois_data = whois_lookup(target)

    virustotal_data = virustotal_lookup(target)

    ipinfo_data = None
    if is_ip(target):
        ipinfo_data = ipinfo_lookup(target)

    return {
        "target": target,
        "whois": whois_data,
        "virustotal": virustotal_data,
        "ipinfo": ipinfo_data
    }
