import argparse
import json
import logging
import os
from utils import perform_lookup_in_parallel


# Configure logging
logging.basicConfig(filename=os.path.join('logs', 'app.log'), level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def parse_arguments():
    """
    Parse command-line arguments for input.
    """
    parser = argparse.ArgumentParser(description="Threat Intelligence Enrichment Tool")
    parser.add_argument('-f', '--file', help='Path to a file containing domains/IPs/URLs (one per line)')
    parser.add_argument('-i', '--input', help='Single domain/IP/URL to look up')
    parser.add_argument('-a', '--api', action='store_true', help='Indicates API lookup')
    return parser.parse_args()


def handle_file_input(file_path):
    """
    Process domains/IPs from a file.
    """
    with open(file_path, 'r') as file:
        lines = [line.strip() for line in file.readlines()]
    return lines


def main():
    args = parse_arguments()

    # Check if there's an input from a file or custom input
    if args.file:
        targets = handle_file_input(args.file)
        logging.info(f"Loaded {len(targets)} targets from file: {args.file}")
    elif args.input:
        targets = [args.input]
        logging.info(f"Single target provided: {args.input}")
    else:
        logging.error("No input provided. Please provide a domain/IP through command line or a file.")
        return

    # Enrich data in parallel
    enriched_data = perform_lookup_in_parallel(targets)

    # Output the enriched data as JSON
    with open('enriched_data.json', 'w') as outfile:
        json.dump(enriched_data, outfile, indent=4)

    logging.info("Enrichment completed and data saved to enriched_data.json.")


if __name__ == "__main__":
    main()
