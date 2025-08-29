# checker_backend.py
# Description: A local Flask server to perform domain and reverse IP lookups.
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
import ipaddress # New import for IP address validation

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
        port = 53

        # FIX for IPv6 and custom ports
        # Handles [ipv6]:port, ipv6, ipv4:port, and ipv4
        if nameserver_str.startswith('[') and ']:' in nameserver_str:
            parts = nameserver_str.split(']:')
            ip = parts[0][1:]
            port = int(parts[1])
        elif ':' in nameserver_str and nameserver_str.count(':') > 1:
            # This is likely a bare IPv6 address
            ip = nameserver_str
            port = 53
        elif ':' in nameserver_str:
            # This is likely an IPv4 with a port
            parts = nameserver_str.split(':')
            ip = parts[0]
            port = int(parts[1])
        
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
        return [f"Error: {e}"]

def is_ip_address(query):
    """Check if the query string is a valid IP address."""
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False

@app.route('/check')
def check_query():
    """Main endpoint that handles both domain and IP queries."""
    query = request.args.get('query')
    nameserver = request.args.get('nameserver', '9.9.9.9')

    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    # --- NEW: Route between IP lookup and Domain lookup ---
    if is_ip_address(query):
        # Perform Reverse IP Lookup
        try:
            api_url = f"https://api.hackertarget.com/reverseiplookup/?q={query}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200 and not response.text.startswith("error"):
                hostnames = response.text.strip().split('\n')
                return jsonify({"type": "ip_lookup", "hostnames": hostnames})
            else:
                return jsonify({"type": "ip_lookup", "hostnames": [f"API Error: {response.text.strip()}"]})
        except requests.RequestException as e:
            return jsonify({"type": "ip_lookup", "hostnames": [f"API Request Failed: {e}"]})
    else:
        # Perform Domain Check (existing logic)
        return perform_domain_check(query, nameserver)

def perform_domain_check(domain, nameserver):
    """The original domain checking logic, now in its own function."""
    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0]

    results = {
        "domain": domain, "whois": {}, "dns": {}, "security": {}, "server": {}
    }

    try:
        w = whois.whois(domain)
        registrar = w.registrar
        if isinstance(registrar, list): registrar = registrar[0]
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        results["whois"] = {
            "registrar": registrar, "creation_date": creation_date.isoformat() if creation_date else "N/A",
            "expiration_date": expiration_date.isoformat() if expiration_date else "N/A", "name_servers": w.name_servers,
        }
    except Exception as e:
        results["whois"]["error"] = f"Could not fetch WHOIS data. Error: {str(e)}"

    a_records = get_dns_records(domain, 'A', nameserver)
    results["dns"]["A"] = a_records
    results["dns"]["AAAA"] = get_dns_records(domain, 'AAAA', nameserver)
    results["dns"]["CNAME_www"] = get_dns_records(f"www.{domain}", 'CNAME', nameserver)
    results["dns"]["NS"] = get_dns_records(domain, 'NS', nameserver)
    results["dns"]["MX"] = get_dns_records(domain, 'MX', nameserver)
    results["dns"]["SOA"] = get_dns_records(domain, 'SOA', nameserver)
    
    if a_records and not a_records[0].startswith("Error:"):
        try:
            addr = socket.gethostbyaddr(a_records[0])
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": addr[0]}
        except socket.herror:
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": "No rDNS record found."}

    txt_records = get_dns_records(domain, 'TXT', nameserver) or []
    results["security"]["SPF"] = next((r for r in txt_records if r.startswith('v=spf1')), None)
    results["security"]["DMARC"] = get_dns_records(f"_dmarc.{domain}", 'TXT', nameserver)
    results["security"]["CAA"] = get_dns_records(domain, 'CAA', nameserver)
    results["security"]["DNSSEC"] = "Enabled" if get_dns_records(domain, 'DNSKEY', nameserver) else "Not Enabled or Not Found"

    try:
        response = requests.get(f"https://{domain}", timeout=5, verify=True, allow_redirects=True)
        results["server"] = {
            "protocol": 'https', "headers": dict(response.headers),
            "status_code": response.status_code, "final_url": response.url
        }
    except requests.exceptions.RequestException:
        try:
            response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
            results["server"] = {
                "protocol": 'http', "headers": dict(response.headers),
                "status_code": response.status_code, "final_url": response.url
            }
        except requests.exceptions.RequestException as e_http:
            results["server"]["error"] = f"Could not connect to the server. Error: {str(e_http)}"

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

    return jsonify({"type": "domain_check", "data": results})

if __name__ == '__main__':
    print("Starting Domain Checker Backend Server...")
    print(f"Place 'checker_frontend.html' in the same directory: {os.path.dirname(os.path.abspath(__file__))}")
    print("Navigate to http://127.0.0.1:4500 in your browser to use the tool.")
    app.run(host='0.0.0.0', port=4500, debug=False)
