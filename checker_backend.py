# checker_backend.py
# Description: A local Flask server to perform domain lookups and serve the frontend from the same directory.
# Dependencies: Flask, dnspython, python-whois, requests
# To run: python checker_backend.py

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import dns.resolver
import whois
import requests
import socket
import ssl
import os

# Configure the app to serve static files from the current directory
app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
CORS(app)

@app.route('/')
def index():
    """Serves the main HTML user interface."""
    return app.send_static_file('checker_frontend.html')

def get_dns_records(domain, record_type, nameserver_str):
    """Helper function to query specific DNS records using a custom resolver."""
    try:
        resolver = dns.resolver.Resolver()
        ip = nameserver_str
        port = 53  # Default DNS port

        if ':' in nameserver_str:
            parts = nameserver_str.split(':')
            ip = parts[0]
            try:
                port = int(parts[1])
            except (ValueError, IndexError):
                port = 53 # Fallback to default if port is invalid
        
        resolver.nameservers = [ip]
        resolver.port = port

        answers = resolver.resolve(domain, record_type)

        if record_type in ['A', 'AAAA']:
            return [r.to_text() for r in answers]
        if record_type == 'MX':
            return sorted([f"{r.preference} {r.exchange.to_text()}" for r in answers])
        if record_type == 'TXT':
            return [''.join(s.decode() for s in r.strings) for r in answers]
        if record_type == 'SOA':
            r = answers[0]
            return [f"MNAME: {r.mname.to_text()}", f"RNAME: {r.rname.to_text()}", f"Serial: {r.serial}"]
        return [r.to_text() for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    except Exception as e:
        print(f"Error resolving {record_type} for {domain} with NS {nameserver_str}: {e}")
        return [f"Error: {e}"] # Return error message to frontend

@app.route('/check')
def check_domain():
    """Main endpoint to gather all domain information."""
    domain = request.args.get('domain')
    nameserver = request.args.get('nameserver', '9.9.9.9') # Default to 9.9.9.9

    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0]

    results = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "security": {},
        "server": {}
    }

    # --- 1. WHOIS / Registrar Information ---
    try:
        w = whois.whois(domain)
        registrar = w.registrar
        if isinstance(registrar, list): registrar = registrar[0]
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        results["whois"] = {
            "registrar": registrar,
            "creation_date": creation_date.isoformat() if creation_date else "N/A",
            "expiration_date": expiration_date.isoformat() if expiration_date else "N/A",
            "name_servers": w.name_servers,
        }
    except Exception as e:
        results["whois"]["error"] = f"Could not fetch WHOIS data. Error: {str(e)}"

    # --- 2. DNS Health & Configuration ---
    a_records = get_dns_records(domain, 'A', nameserver)
    results["dns"]["A"] = a_records
    results["dns"]["AAAA"] = get_dns_records(domain, 'AAAA', nameserver)
    results["dns"]["CNAME_www"] = get_dns_records(f"www.{domain}", 'CNAME', nameserver)
    results["dns"]["NS"] = get_dns_records(domain, 'NS', nameserver)
    results["dns"]["MX"] = get_dns_records(domain, 'MX', nameserver)
    results["dns"]["SOA"] = get_dns_records(domain, 'SOA', nameserver)
    
    # --- 3. Reverse DNS ---
    if a_records and not a_records[0].startswith("Error:"):
        try:
            addr = socket.gethostbyaddr(a_records[0])
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": addr[0]}
        except socket.herror:
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": "No rDNS record found."}

    # --- 4. Security & Email Authentication ---
    txt_records = get_dns_records(domain, 'TXT', nameserver) or []
    results["security"]["SPF"] = next((r for r in txt_records if r.startswith('v=spf1')), None)
    results["security"]["DMARC"] = get_dns_records(f"_dmarc.{domain}", 'TXT', nameserver)
    results["security"]["CAA"] = get_dns_records(domain, 'CAA', nameserver)
    results["security"]["DNSSEC"] = "Enabled" if get_dns_records(domain, 'DNSKEY', nameserver) else "Not Enabled or Not Found"

    # --- 5. Server Information (HTTP Headers) ---
    try:
        response = requests.get(f"https://{domain}", timeout=5, verify=True, allow_redirects=True)
        results["server"] = {
            "protocol": 'https',
            "headers": dict(response.headers),
            "status_code": response.status_code,
            "final_url": response.url
        }
    except requests.exceptions.RequestException:
        try:
            response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
            results["server"] = {
                "protocol": 'http',
                "headers": dict(response.headers),
                "status_code": response.status_code,
                "final_url": response.url
            }
        except requests.exceptions.RequestException as e_http:
            results["server"]["error"] = f"Could not connect to the server. Error: {str(e_http)}"

    # --- 6. SSL Certificate Information ---
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                results["server"]["ssl_info"] = {
                    "issuer_common_name": issuer.get('commonName', 'N/A'),
                    "subject_common_name": subject.get('commonName', 'N/A'),
                    "expires": cert.get('notAfter')
                }
    except Exception as e:
        results["server"]["ssl_info"] = {"error": f"Could not retrieve SSL certificate. Error: {str(e)}"}

    return jsonify(results)

if __name__ == '__main__':
    print("Starting Domain Checker Backend Server...")
    print(f"Place 'checker_frontend.html' in the same directory: {os.path.dirname(os.path.abspath(__file__))}")
    print("Navigate to http://127.0.0.1:4500 in your browser to use the tool.")
    app.run(host='0.0.0.0', port=4500, debug=False)
