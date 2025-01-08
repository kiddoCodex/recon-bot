import requests
import subprocess
import whois
import nmap
import openai
from theHarvester import discover
import json
from datetime import datetime

# Set your API keys for OpenAI and other services
OPENAI_API_KEY = 'your-openai-api-key'
CENSYS_API_ID = 'your-censys-api-id'
CENSYS_API_SECRET = 'your-censys-api-secret'
SPYSE_API_KEY = 'your-spyse-api-key'
SECURITYTRAILS_API_KEY = 'your-securitytrails-api-key'

# Initialize Nmap
nm = nmap.PortScanner()

# Function to perform WHOIS lookup
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error in WHOIS lookup: {e}"

# Function to use Nmap for scanning
def scan_ip_nmap(ip):
    try:
        nm.scan(ip, '1-1024')  # Scan ports 1-1024
        return nm[ip]
    except Exception as e:
        return f"Error in Nmap scan: {e}"

# Function to get subdomains and emails using TheHarvester
def get_theharvester_info(domain):
    try:
        result = subprocess.check_output(['theHarvester', '-d', domain, '-b', 'all'])
        return result.decode('utf-8')
    except Exception as e:
        return f"Error in TheHarvester: {e}"

# Function to use Censys API to get device/service data
def get_censys_info(domain):
    try:
        url = f'https://search.censys.io/api/v2/hosts/search'
        headers = {'Authorization': f'Basic {CENSYS_API_ID}:{CENSYS_API_SECRET}'}
        response = requests.get(url, params={'q': domain}, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return f"Error in Censys API: {e}"

# Function to use Spyse API for reconnaissance data
def get_spyse_info(domain):
    try:
        url = f'https://api.spyse.com/v4/data/host'
        params = {'apikey': SPYSE_API_KEY, 'host': domain}
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return f"Error in Spyse API: {e}"

# Function to use SecurityTrails API for domain data
def get_securitytrails_info(domain):
    try:
        url = f'https://api.securitytrails.com/v1/domain/{domain}'
        headers = {'APIKEY': SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        return f"Error in SecurityTrails API: {e}"

# Function to use OpenAI for summarizing results
def summarize_results(results):
    openai.api_key = OPENAI_API_KEY
    prompt = f"Summarize the following recon results: {results}"

    try:
        # Using OpenAI's correct API method
        response = openai.Completion.create(
            model="gpt-3.5-turbo",  # Use GPT-3.5 or GPT-4 model
            prompt=prompt,
            max_tokens=200
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Error summarizing with OpenAI: {e}"

# Function to save results to a file
def save_results(domain, results):
    filename = f"{domain}_recon_results_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)

# Main function for recon
def recon(domain):
    print(f"Starting recon on {domain}...")

    # WHOIS lookup
    whois_info = get_whois_info(domain)
    print("\nWHOIS Information:")
    print(whois_info)

    # Nmap scan for open ports
    nmap_results = scan_ip_nmap(domain)
    print("\nNmap Scan Results:")
    print(nmap_results)

    # TheHarvester subdomains and email data
    theharvester_results = get_theharvester_info(domain)
    print("\nTheHarvester Results:")
    print(theharvester_results)

    # Censys data
    censys_info = get_censys_info(domain)
    print("\nCensys Info:")
    print(censys_info)

    # Spyse data
    spyse_info = get_spyse_info(domain)
    print("\nSpyse Info:")
    print(spyse_info)

    # SecurityTrails data
    securitytrails_info = get_securitytrails_info(domain)
    print("\nSecurityTrails Info:")
    print(securitytrails_info)

    # Summarize using OpenAI
    summarized = summarize_results({
        'WHOIS': whois_info,
        'Nmap': nmap_results,
        'TheHarvester': theharvester_results,
        'Censys': censys_info,
        'Spyse': spyse_info,
        'SecurityTrails': securitytrails_info
    })
    print("\nSummarized Results:")
    print(summarized)

    # Save the results to a file
    results = {
        'WHOIS': whois_info,
        'Nmap': nmap_results,
        'TheHarvester': theharvester_results,
        'Censys': censys_info,
        'Spyse': spyse_info,
        'SecurityTrails': securitytrails_info,
        'Summarized': summarized
    }
    save_results(domain, results)

# Run the recon bot
domain_to_recon = input("Enter a domain to recon: ")
recon(domain_to_recon)