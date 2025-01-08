import requests
import subprocess
import whois
import nmap
import openai
import dns.resolver
import logging
from flask import Flask, render_template, request
from concurrent.futures import ThreadPoolExecutor
from theHarvester import discover

# Set your API keys for OpenAI and other services
OPENAI_API_KEY = 'your-openai-api-key'
CENSYS_API_ID = 'your-censys-api-id'
CENSYS_API_SECRET = 'your-censys-api-secret'
SPYSE_API_KEY = 'your-spyse-api-key'
SECURITYTRAILS_API_KEY = 'your-securitytrails-api-key'
VIRUSTOTAL_API_KEY = 'your-virustotal-api-key'

# Initialize Nmap
nm = nmap.PortScanner()

# Initialize Flask app
app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to log information
def log_info(message):
    logging.info(message)

# Function to log errors
def log_error(message):
    logging.error(message)

# Function to perform WHOIS lookup
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        log_error(f"WHOIS Lookup Error: {e}")
        return f"Error: {e}"

# Function to use Nmap for scanning
def scan_ip_nmap(ip):
    try:
        nm.scan(ip, '1-1024')  # Scan ports 1-1024
        return nm[ip]
    except Exception as e:
        log_error(f"Nmap Scan Error: {e}")
        return f"Error: {e}"

# Function to get subdomains and emails using TheHarvester
def get_theharvester_info(domain):
    try:
        result = subprocess.check_output(['theHarvester', '-d', domain, '-b', 'all'])
        return result.decode('utf-8')
    except Exception as e:
        log_error(f"TheHarvester Error: {e}")
        return f"Error: {e}"

# Function to get DNS Info
def get_dns_info(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')  # Get A record (IP addresses)
        return [ip.address for ip in result]
    except Exception as e:
        log_error(f"DNS Lookup Error: {e}")
        return f"Error: {e}"

# Function to get VirusTotal Info
def get_virustotal_info(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        log_error(f"VirusTotal API Error: {e}")
        return f"Error: {e}"

# Function to get Censys Info
def get_censys_info(domain):
    try:
        url = f'https://search.censys.io/api/v2/hosts/search'
        headers = {'Authorization': f'Basic {CENSYS_API_ID}:{CENSYS_API_SECRET}'}
        response = requests.get(url, params={'q': domain}, headers=headers)
        return response.json()
    except Exception as e:
        log_error(f"Censys API Error: {e}")
        return f"Error: {e}"

# Function to get Spyse Info
def get_spyse_info(domain):
    try:
        url = f'https://api.spyse.com/v4/data/host'
        params = {'apikey': SPYSE_API_KEY, 'host': domain}
        response = requests.get(url, params=params)
        return response.json()
    except Exception as e:
        log_error(f"Spyse API Error: {e}")
        return f"Error: {e}"

# Function to get SecurityTrails Info
def get_securitytrails_info(domain):
    try:
        url = f'https://api.securitytrails.com/v1/domain/{domain}'
        headers = {'APIKEY': SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        log_error(f"SecurityTrails API Error: {e}")
        return f"Error: {e}"

# Function to use OpenAI for summarizing results
def summarize_results(results):
    openai.api_key = OPENAI_API_KEY
    prompt = f"Summarize the following recon results: {results}"

    try:
        response = openai.Completion.create(
            model="gpt-3.5-turbo",  # Use GPT-3.5 or GPT-4 model
            prompt=prompt,
            max_tokens=200
        )
        return response.choices[0].text.strip()
    except Exception as e:
        log_error(f"OpenAI API Error: {e}")
        return f"Error: {e}"

# Function to perform recon on the domain
def recon(domain):
    log_info(f"Starting recon on {domain}...")

    # WHOIS lookup
    whois_info = get_whois_info(domain)

    # DNS Lookup
    dns_info = get_dns_info(domain)

    # Nmap scan for open ports
    nmap_results = scan_ip_nmap(domain)

    # TheHarvester subdomains and email data
    theharvester_results = get_theharvester_info(domain)

    # VirusTotal Info
    virustotal_info = get_virustotal_info(domain)

    # Censys data
    censys_info = get_censys_info(domain)

    # Spyse data
    spyse_info = get_spyse_info(domain)

    # SecurityTrails data
    securitytrails_info = get_securitytrails_info(domain)

    # Summarize using OpenAI
    summarized = summarize_results({
        'WHOIS': whois_info,
        'DNS': dns_info,
        'Nmap': nmap_results,
        'TheHarvester': theharvester_results,
        'VirusTotal': virustotal_info,
        'Censys': censys_info,
        'Spyse': spyse_info,
        'SecurityTrails': securitytrails_info
    })

    return {
        'whois': whois_info,
        'dns': dns_info,
        'nmap': nmap_results,
        'theharvester': theharvester_results,
        'virustotal': virustotal_info,
        'censys': censys_info,
        'spyse': spyse_info,
        'securitytrails': securitytrails_info,
        'summarized': summarized
    }

# Flask route for the homepage
@app.route('/')
def home():
    return render_template('index.html')

# Flask route for the recon results
@app.route('/recon', methods=['POST'])
def recon_page():
    domain = request.form['domain']
    results = recon(domain)

    return render_template('results.html', domain=domain, results=results)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)