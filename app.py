from flask import Flask, request, jsonify, render_template_string
import dns.resolver
import dns.reversename
import re

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ta">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bulk SenderScore Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-900 text-white min-h-screen p-6">
    <div class="max-w-5xl mx-auto">
        <header class="mb-8 text-center">
            <h1 class="text-3xl font-extrabold text-blue-400">Bulk SenderScore & Reputation Auditor</h1>
            <p class="text-slate-400 mt-2">Enter multiple IP addresses to check live SenderScore and hostnames</p>
        </header>

        <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg mb-8">
            <label class="block text-sm font-semibold mb-2 text-slate-300">Enter IP Addresses (One per line or comma separated):</label>
            <textarea id="ipInput" rows="5" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm focus:outline-none focus:border-blue-500 font-mono text-white" placeholder="8.219.25.82&#10;209.85.220.41&#10;40.107.76.106"></textarea>
            
            <div class="mt-4 flex gap-4">
                <button onclick="checkReputation()" id="btnSubmit" class="bg-blue-600 hover:bg-blue-500 px-6 py-2.5 rounded-lg font-semibold text-white transition">Check Sender Scores</button>
                <button onclick="document.getElementById('ipInput').value='8.219.25.82\\n209.85.220.41\\n40.107.76.106'" class="bg-slate-700 hover:bg-slate-600 px-4 py-2.5 rounded-lg text-sm text-slate-300">Load Sample</button>
            </div>
        </div>

        <div id="loader" class="hidden text-center py-6 text-blue-400 font-medium">Checking scores via DNSBL... Please wait.</div>

        <div id="resultTableContainer" class="hidden bg-slate-800 rounded-xl border border-slate-700 overflow-hidden shadow-lg">
            <table class="w-full text-left text-sm">
                <thead class="bg-slate-700/50 text-slate-300 uppercase text-xs">
                    <tr>
                        <th class="p-4">IP Address</th>
                        <th class="p-4">Sender Score</th>
                        <th class="p-4">Rating</th>
                        <th class="p-4">Hostname (rDNS PTR)</th>
                        <th class="p-4">Volume Class</th>
                    </tr>
                </thead>
                <tbody id="resultBody" class="divide-y divide-slate-700 font-mono"></tbody>
            </table>
        </div>
    </div>

    <script>
        async function checkReputation() {
            const raw = document.getElementById('ipInput').value;
            const btn = document.getElementById('btnSubmit');
            const loader = document.getElementById('loader');
            const tableContainer = document.getElementById('resultTableContainer');
            const tbody = document.getElementById('resultBody');

            if (!raw.trim()) {
                alert('Please enter at least one IP address.');
                return;
            }

            btn.disabled = true;
            btn.classList.add('opacity-50');
            loader.classList.remove('hidden');
            tableContainer.classList.add('hidden');
            tbody.innerHTML = '';

            try {
                const res = await fetch('/api/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ips: raw})
                });
                const data = await res.json();

                if (data.results) {
                    data.results.forEach(item => {
                        let badgeColor = 'bg-slate-700 text-slate-300';
                        if (item.rating === 'GOOD') badgeColor = 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
                        if (item.rating === 'POOR') badgeColor = 'bg-rose-500/20 text-rose-400 border border-rose-500/30';

                        const tr = document.createElement('tr');
                        tr.className = "hover:bg-slate-750";
                        tr.innerHTML = `
                            <td class="p-4 font-bold text-slate-200">\${item.ip}</td>
                            <td class="p-4 text-xl font-extrabold \${item.score >= 80 ? 'text-amber-400' : 'text-slate-300'}">\${item.score}</td>
                            <td class="p-4"><span class="px-2 py-1 rounded text-xs font-bold \${badgeColor}">\${item.rating}</span></td>
                            <td class="p-4 text-xs text-slate-400 break-all">\${item.hostname}</td>
                            <td class="p-4 text-xs font-bold text-slate-300">\${item.volume}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                    tableContainer.classList.remove('hidden');
                } else {
                    alert(data.error || 'Check failed.');
                }
            } catch (err) {
                alert('Connection error: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.classList.remove('opacity-50');
                loader.classList.add('hidden');
            }
        }
    </script>
</body>
</html>
"""

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
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    try:
        rev_name = dns.reversename.from_address(ip)
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
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/check', methods=['POST'])
def check_ips():
    data = request.get_json() or {}
    raw_text = data.get('ips', '')
    
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    extracted_ips = list(dict.fromkeys(re.findall(ip_pattern, raw_text)))

    if not extracted_ips:
        return jsonify({"error": "No valid IPv4 addresses found"}), 400

    results = []
    for ip in extracted_ips[:50]:
        results.append(get_ip_reputation(ip))

    return jsonify({"results": results})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
