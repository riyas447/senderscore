from flask import Flask, render_template, request, jsonify
import dns.resolver
import dns.reversename
import re

app = Flask(__name__)

def get_ip_reputation(ip):
    ip = ip.strip()
    result = {
        "ip": ip,
        "score": "N/A",
        "rating": "Unknown",
        "hostname": "N/A",
        "volume": "Unknown",
        "status": "Failed"
    }

    # 1. Reverse PTR Hostname lookup
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        ptr_answers = resolver.resolve(rev_name, "PTR")
        result["hostname"] = str(ptr_answers[0]).rstrip('.')
    except Exception:
        result["hostname"] = "No PTR Record"

    # 2. Validity SenderScore DNSBL lookup (127.0.4.X)
    try:
        octets = ip.split('.')
        if len(octets) == 4:
            lookup_host = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.score.senderscore.com"
            answers = resolver.resolve(lookup_host, "A")
            for rdata in answers:
                resp = str(rdata)
                if resp.startswith("127.0.4."):
                    score = int(resp.split('.')[-1])
                    result["score"] = score
                    result["status"] = "Success"
                    if score >= 80:
                        result["rating"] = "GOOD"
                        result["volume"] = "HIGH"
                    elif score >= 70:
                        result["rating"] = "FAIR"
                        result["volume"] = "MEDIUM"
                    else:
                        result["rating"] = "POOR"
                        result["volume"] = "LOW"
                    break
    except dns.resolver.NXDOMAIN:
        result["score"] = "Low/No Volume"
        result["rating"] = "Not Rated"
        result["volume"] = "LOW"
        result["status"] = "No SenderScore History"
    except Exception as e:
        result["score"] = "Error"
        result["status"] = str(e)

    return result

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_ips():
    data = request.get_json() or {}
    raw_text = data.get('ips', '')
    
    # IPv4 regex extraction
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    extracted_ips = list(dict.fromkeys(re.findall(ip_pattern, raw_text)))

    if not extracted_ips:
        return jsonify({"error": "No valid IPv4 addresses found"}), 400

    results = []
    for ip in extracted_ips[:50]:  # Free tier render safety limit
        results.append(get_ip_reputation(ip))

    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)