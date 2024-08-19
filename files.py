from flask import Flask, request, jsonify, render_template, send_from_directory
import subprocess
import os
import re

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Static files route (CSS, JS, etc.)
@app.route('/css/<path:filename>')
def serve_static(filename):
    return send_from_directory('css', filename)

def scan_for_malware(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return {"status": "Clean", "details": result.stdout.strip()}
        elif result.returncode == 1:
            infected_files = []
            for line in result.stdout.splitlines():
                if "FOUND" in line:
                    infected_files.append(line.strip())
            return {"status": "Infected", "infected_files": infected_files}
        else:
            return {"status": "Error", "details": result.stderr.strip()}
    except Exception as e:
        return {"status": "Error", "details": str(e)}

def detect_sensitive_data(file_path):
    with open(file_path, 'r', errors='ignore') as file:
        content = file.read()

    patterns = {
        'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }

    findings = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[key] = matches

    return findings

def check_hard_coded_credentials(file_path):
    with open(file_path, 'r', errors='ignore') as file:
        content = file.read()

    patterns = {
        'AWS_access_key': r'AKIA[0-9A-Z]{16}',
        'AWS_secret_key': r'(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
        'API_key': r'[A-Za-z0-9]{32,}'
    }

    findings = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[key] = matches

    return findings

def check_file_permissions(file_path):
    permissions = os.stat(file_path).st_mode
    readable_by_others = permissions & 0o004
    writable_by_others = permissions & 0o002

    findings = {
        'readable_by_others': bool(readable_by_others),
        'writable_by_others': bool(writable_by_others)
    }

    return findings

def calculate_vulnerability_score(scan_results, sensitive_data, hard_coded_credentials, file_permissions):
    score = 0

    if scan_results['status'] == 'Infected':
        score += 5
    
    if sensitive_data:
        score += 2
    
    if hard_coded_credentials:
        score += 3
    
    if file_permissions['writable_by_others']:
        score += 2
    
    if file_permissions['readable_by_others']:
        score += 1
    
    return score

def determine_risk_level(score):
    if score >= 9:
        return "High"
    elif score >= 4:
        return "Medium"
    else:
        return "Low"

@app.route('/')
def index():
    return render_template('files.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Perform malware scan
            scan_results = scan_for_malware(file_path)
            
            # Perform additional analyses
            sensitive_data = detect_sensitive_data(file_path)
            hard_coded_credentials = check_hard_coded_credentials(file_path)
            file_permissions = check_file_permissions(file_path)
            
            # Calculate vulnerability score
            vulnerability_score = calculate_vulnerability_score(scan_results, sensitive_data, hard_coded_credentials, file_permissions)
            
            # Determine risk level based on the vulnerability score
            risk_level = determine_risk_level(vulnerability_score)
            
            result = {
                'scan_results': scan_results,
                'sensitive_data': sensitive_data,
                'hard_coded_credentials': hard_coded_credentials,
                'file_permissions': file_permissions,
                'vulnerability_score': vulnerability_score,
                'risk_level': risk_level
            }
            
            return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
