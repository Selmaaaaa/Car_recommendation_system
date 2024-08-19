from flask import Flask, request, render_template, send_from_directory
import subprocess
import tempfile
import os
import json
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('python.html')

@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory('css', filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('js', filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    if file.filename == '':
        return "No selected file", 400

    if file and file.filename.endswith('.py'):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            file.save(temp_file.name)
            temp_file_path = temp_file.name
        
        analysis_result = run_combined_analysis(temp_file_path)
        os.remove(temp_file_path)
        
        return render_template('python.html', analysis_result=analysis_result)
    
    return "Invalid file type. Please upload a .py file.", 400


def run_combined_analysis(file_path):
    bandit_issues = run_bandit_analysis(file_path)
    malware_scan = scan_for_malware(file_path)
    sensitive_data = detect_sensitive_data(file_path)
    hard_coded_credentials = check_hard_coded_credentials(file_path)
    file_permissions = check_file_permissions(file_path)

    severity_mapping = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

    for issue in bandit_issues:
        severity_score = severity_mapping.get(issue['severity'], 1)
        if malware_scan['status'] == 'Infected':
            severity_score += 2
        if sensitive_data:
            severity_score += 1
        if hard_coded_credentials:
            severity_score += 2
        if file_permissions['writable_by_others']:
            severity_score += 1
        
        if severity_score > 4:
            issue['severity'] = 'CRITICAL'
        elif severity_score == 4:
            issue['severity'] = 'HIGH'
        elif severity_score == 3:
            issue['severity'] = 'MEDIUM'
        else:
            issue['severity'] = 'LOW'

    return bandit_issues

def run_bandit_analysis(file_path):
    try:
        result = subprocess.run(['bandit', '-r', file_path, '-f', 'json'], capture_output=True, text=True)
        bandit_output = json.loads(result.stdout)
        issues = [
            {
                'filename': issue['filename'],
                'line_number': issue['line_number'],
                'issue_text': issue['issue_text'],
                'severity': issue['issue_severity'],
                'confidence': issue['issue_confidence'],
                'more_info': issue['more_info'],
            }
            for issue in bandit_output.get('results', [])
        ]
        return issues
    except subprocess.CalledProcessError as e:
        return [{"issue_text": f"Bandit failed with error:\n{e.stderr}"}]
    except Exception as e:
        return [{"issue_text": str(e)}]

def scan_for_malware(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return {"status": "Clean", "details": result.stdout.strip()}
        elif result.returncode == 1:
            infected_files = [line.strip() for line in result.stdout.splitlines() if "FOUND" in line]
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

    findings = {key: re.findall(pattern, content) for key, pattern in patterns.items()}
    return {k: v for k, v in findings.items() if v}

def check_hard_coded_credentials(file_path):
    with open(file_path, 'r', errors='ignore') as file:
        content = file.read()

    patterns = {
        'AWS_access_key': r'AKIA[0-9A-Z]{16}',
        'AWS_secret_key': r'(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
        'API_key': r'[A-Za-z0-9]{32,}'
    }

    findings = {key: re.findall(pattern, content) for key, pattern in patterns.items()}
    return {k: v for k, v in findings.items() if v}

def check_file_permissions(file_path):
    permissions = os.stat(file_path).st_mode
    return {
        'readable_by_others': bool(permissions & 0o004),
        'writable_by_others': bool(permissions & 0o002)
    }

if __name__ == '__main__':
    app.run(debug=True)
