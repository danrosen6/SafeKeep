# src/features/url_checker/virus_total_analysis.py

import os
import requests
from dotenv import load_dotenv
from logs.logger import SafeKeepLogger

# Load environment variables from the .env file
load_dotenv()

def initiate_virus_total_analysis(url, callback_signal=None):
    """
    Initiates a URL analysis using the VirusTotal API.

    Args:
        url (str): The URL to be analyzed.
        callback_signal (function): The function to call with the analysis results.

    Returns:
        str: The result of the VirusTotal analysis or an error message.
    """
    logger = SafeKeepLogger().get_logger()
    logger.info(f"Initiating VirusTotal analysis for URL: {url}")

    # Retrieve the VirusTotal API key from the environment variables
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        error_message = "VirusTotal API key is missing in the environment variables. Please set 'VIRUSTOTAL_API_KEY' in your .env file."
        logger.error(error_message)
        return error_message

    # Set the VirusTotal API endpoint
    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"

    # Set up the parameters for the API call
    params = {
        'apikey': api_key,
        'resource': url,
        'scan': 1  # Optional: initiate a scan if not already done
    }

    try:
        # Make the request to the VirusTotal API
        response = requests.get(endpoint, params=params)
        logger.info(f"VirusTotal API request made to {endpoint} with params {params}")

        # Handle potential API errors
        if response.status_code == 403:
            error_message = "Access denied by VirusTotal. Please check your API key and permissions."
            logger.error(error_message)
            return error_message
        elif response.status_code == 429:
            error_message = "Too many requests to VirusTotal. Please try again later."
            logger.error(error_message)
            return error_message
        elif response.status_code != 200:
            error_message = f"Unexpected error from VirusTotal: {response.status_code} - {response.text}"
            logger.error(error_message)
            return error_message

        # Parse the JSON response
        result = response.json()
        logger.info(f"VirusTotal analysis response received: {result}")

        # Extract relevant information from the response
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        scan_date = result.get('scan_date', 'Unknown')
        scans = result.get('scans', {})
        scan_details = "\n".join([f"{scanner}: {scan['result']}" for scanner, scan in scans.items() if scan.get('result')])

        # Prepare the report
        report = f"VirusTotal Report:\nDetected: {positives}/{total}\nScan Date: {scan_date}\nScan Results:\n{scan_details}"
        logger.info("VirusTotal analysis completed successfully.")

        # If a callback signal is provided, emit the result
        if callback_signal:
            callback_signal(report)
        return report

    except Exception as e:
        error_message = f"Failed to analyze URL with VirusTotal: {e}"
        logger.error(error_message)
        return error_message
