# src/features/url_checker/url_decomposition.py

from urllib.parse import urlparse, parse_qs
import tldextract
import whois
import requests
from bs4 import BeautifulSoup
from logs.logger import SafeKeepLogger

def analyze_url(url):
    """
    Decompose the given URL into its components and extract relevant information, including WHOIS data and webpage metadata.

    Args:
        url (str): The URL to analyze.

    Returns:
        str: A formatted string containing the decomposition of the URL, WHOIS info, and webpage metadata.
    """
    logger = SafeKeepLogger().get_logger()
    logger.info(f"Analyzing URL: {url}")

    # Initialize result container
    result = []

    try:
        # Parse the URL using urlparse
        parsed_url = urlparse(url)
        logger.info(f"Parsed URL: {parsed_url}")

        # Extract components using urlparse
        scheme = parsed_url.scheme
        netloc = parsed_url.netloc
        path = parsed_url.path
        params = parsed_url.params
        query = parsed_url.query
        fragment = parsed_url.fragment

        result.append(f"Scheme: {scheme}")
        result.append(f"Network Location (Netloc): {netloc}")
        result.append(f"Path: {path}")
        result.append(f"Parameters: {params}")
        result.append(f"Query: {query}")
        result.append(f"Fragment: {fragment}")

        # Use tldextract to break down the domain into subdomain, domain, and suffix
        domain_parts = tldextract.extract(url)
        logger.info(f"Domain Parts: {domain_parts}")
        subdomain = domain_parts.subdomain
        domain = domain_parts.domain
        suffix = domain_parts.suffix

        result.append(f"Subdomain: {subdomain}")
        result.append(f"Domain: {domain}")
        result.append(f"Suffix: {suffix}")

        # WHOIS Lookup
        try:
            whois_data = whois.whois(domain + '.' + suffix)
            logger.info(f"WHOIS data retrieved for domain: {domain}.{suffix}")
            result.append(f"\nWHOIS Information for {domain}.{suffix}:")
            result.append(f"Registrar: {whois_data.registrar}")
            result.append(f"Creation Date: {whois_data.creation_date}")
            result.append(f"Expiration Date: {whois_data.expiration_date}")
            result.append(f"Name Servers: {', '.join(whois_data.name_servers)}")
        except Exception as e:
            logger.error(f"Failed to retrieve WHOIS data: {e}")
            result.append(f"Failed to retrieve WHOIS data: {e}")

        # Parse query parameters
        query_params = parse_qs(parsed_url.query)
        if query_params:
            result.append("\nQuery Parameters:")
            for param, value in query_params.items():
                result.append(f"  {param}: {value}")

        # Fetch and parse HTML with BeautifulSoup
        if scheme and netloc:
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else "No title found"
                description = soup.find('meta', attrs={'name': 'description'})
                description = description['content'] if description else "No description found"
                
                result.append(f"\nWebpage Title: {title}")
                result.append(f"Webpage Description: {description}")
            except Exception as e:
                logger.error(f"Failed to fetch webpage metadata: {e}")
                result.append(f"Failed to fetch webpage metadata: {e}")

        # Add final results to output
        result_text = "\n".join(result)
        logger.info(f"URL decomposition completed successfully.")
        return result_text

    except Exception as e:
        error_message = f"Failed to analyze URL '{url}': {e}"
        logger.error(error_message)
        return error_message
