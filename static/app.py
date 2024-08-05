from flask import Flask, request, jsonify, render_template_string
import subprocess
import os
import re

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def scan_for_malware(file_path):
    try:
        result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

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

@app.route('/')
def index():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Analysis Tool</title>
    <style>
        /* Basic loading spinner styles */
        .spinner {
            display: none;
            width: 40px;
            height: 40px;
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-radius: 50%;
            border-top-color: #333;
            animation: spin 1s ease-in-out infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>Upload a File for Analysis</h1>
    <form action="/scan" method="post" enctype="multipart/form-data">
        <label for="file">Select file to upload:</label>
        <input type="file" id="file" name="file" required>
        <button type="submit">Upload and Analyze</button>
    </form>
    <div class="spinner" id="spinner"></div>
    <hr>
    <div id="results"></div>

    <script>
        const form = document.querySelector('form');
        const resultsDiv = document.getElementById('results');
        const spinner = document.getElementById('spinner');

        form.addEventListener('submit', async (event) => {
            event.preventDefault(); // Prevent the form from submitting the default way

            const formData = new FormData(form);

            // Show the spinner while the request is being processed
            spinner.style.display = 'block';
            resultsDiv.innerHTML = '';

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    body: formData
                });

                // Hide the spinner once the request is complete
                spinner.style.display = 'none';

                if (response.ok) {
                    const result = await response.json();
                    resultsDiv.innerHTML = `
                        <h2>Analysis Results:</h2>
                        <pre>${JSON.stringify(result, null, 2)}</pre>
                    `;
                } else {
                    resultsDiv.innerHTML = `<h2>Error:</h2><pre>${JSON.stringify(await response.json(), null, 2)}</pre>`;
                }
            } catch (error) {
                spinner.style.display = 'none';
                resultsDiv.innerHTML = `<h2>Exception Occurred:</h2><pre>${error.message}</pre>`;
            }
        });
    </script>
</body>
</html>
""")


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
            
            # Compile results
            results = {
                'scan_results': scan_results,
                'sensitive_data': sensitive_data,
                'hard_coded_credentials': hard_coded_credentials,
                'file_permissions': file_permissions
            }
            
            return jsonify(results)
        else:
            return jsonify({'error': 'File not provided'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
