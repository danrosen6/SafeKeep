# src/features/url_checker/virus_total_analysis.py

import os
import requests
import time
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
    api_key = os.getenv('vt_key')
    if not api_key:
        error_message = "VirusTotal API key is missing in the environment variables. Please set 'VIRUSTOTAL_API_KEY' in your .env file."
        logger.error(error_message)
        return error_message

    # Set the VirusTotal API endpoint for submitting the URL
    submission_endpoint = "https://www.virustotal.com/vtapi/v2/url/scan"
    submission_params = {'apikey': api_key, 'url': url}

    try:
        # Step 1: Submit the URL to VirusTotal
        submission_response = requests.post(submission_endpoint, data=submission_params)
        logger.info(f"URL submission request made to {submission_endpoint} with params {submission_params}")

        if submission_response.status_code == 200:
            # Extract the scan_id from the submission response
            scan_id = submission_response.json().get('scan_id')
            logger.info(f"URL submitted successfully, scan_id: {scan_id}")

            # Step 2: Wait for 15 seconds before fetching the analysis results
            logger.info("Waiting 15 seconds before retrieving analysis results...")
            time.sleep(15)

            # Fetch the analysis results using the scan_id
            return fetch_analysis_results(scan_id, api_key, callback_signal)

        else:
            # Handle any errors during URL submission
            error_message = f"Failed to submit URL to VirusTotal: {submission_response.status_code} - {submission_response.text}"
            logger.error(error_message)
            return error_message

    except Exception as e:
        error_message = f"Exception occurred during VirusTotal analysis: {e}"
        logger.error(error_message)
        return error_message


def fetch_analysis_results(scan_id, api_key, callback_signal=None):
    """
    Fetches analysis results from VirusTotal using the provided scan_id.

    Args:
        scan_id (str): The scan_id received after submitting the URL.
        api_key (str): The VirusTotal API key.
        callback_signal (function): The function to call with the analysis results.

    Returns:
        str: The analysis report or an error message.
    """
    logger = SafeKeepLogger().get_logger()
    # Endpoint to get the analysis report using the scan_id
    result_endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    result_params = {'apikey': api_key, 'resource': scan_id}

    try:
        # Make the request to retrieve the analysis results
        result_response = requests.get(result_endpoint, params=result_params)
        logger.info(f"Retrieving analysis results from {result_endpoint} with scan_id: {scan_id}")

        if result_response.status_code == 200:
            # Parse the JSON response and generate the report
            result = result_response.json()
            logger.info(f"Analysis results retrieved successfully: {result}")

            report = summarize_analysis(result)

            # If a callback signal is provided, emit the result
            if callback_signal:
                callback_signal(report)
            return report
        else:
            # Handle errors in fetching the analysis results
            error_message = f"Failed to fetch analysis results: {result_response.status_code} - {result_response.text}"
            logger.error(error_message)
            return error_message

    except Exception as e:
        error_message = f"Exception occurred while fetching analysis results: {e}"
        logger.error(error_message)
        return error_message


def summarize_analysis(result):
    """
    Processes the JSON response from the VirusTotal API and generates a detailed summary report.

    Args:
        result (dict): The JSON response from the VirusTotal API.

    Returns:
        str: A formatted string summarizing the analysis results.
    """
    positives = result.get('positives', 0)
    total = result.get('total', 0)
    scan_date = result.get('scan_date', 'Unknown')
    scans = result.get('scans', {})

    # Summary of the main report
    report = (
        f"VirusTotal Report Summary:\n"
        f"Detected Malicious: {positives}/{total}\n"
        f"Scan Date: {scan_date}\n\n"
        f"Detailed Scan Results:\n"
    )

    # Track if any malicious or suspicious results are found
    has_warnings = False

    # Detailed report of each scanner's results
    for scanner, details in scans.items():
        # Extract category and result fields from each scanner's report
        result = details.get('result')
        category = details.get('category', 'N/A')  # Get the category if available
        method = details.get('method', 'N/A')      # Get the method of detection if available

        if result and result not in ['clean site', 'unrated site']:  # Only include if result indicates an issue
            has_warnings = True
            # Include the scanner name, category (if available), method, and result in the detailed report
            report += f"{scanner}: [Category - {category}] [Method - {method}] Result - {result}\n"

    # If no malicious or suspicious results were found, indicate this
    if not has_warnings:
        report += "No malicious or suspicious results found.\n"

    return report
