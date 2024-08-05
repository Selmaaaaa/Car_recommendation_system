from flask import Flask, request, jsonify, render_template_string
import os
import subprocess

app = Flask(__name__)

# Define the path to the temporary directory where files will be saved
TEMP_DIR = '/path/to/temp/dir'
# Ensure the temporary directory exists
os.makedirs(TEMP_DIR, exist_ok=True)

def run_sonar_scanner(file_path):
    """
    Run SonarQube Scanner on the specified file.
    """
    # Define the SonarQube Scanner command
    sonar_scanner_cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey=my-flask-app",
        f"-Dsonar.projectName=My Flask App",
        f"-Dsonar.projectVersion=1.0",
        f"-Dsonar.sources={file_path}",
        f"-Dsonar.host.url=http://localhost:9000",
        f"-Dsonar.login=my-auth-token"
    ]
    
    # Run the SonarQube Scanner command
    result = subprocess.run(sonar_scanner_cmd, capture_output=True, text=True)
    
    return result.stdout, result.stderr

# HTML template for file upload
UPLOAD_FORM_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
</head>
<body>
    <h1>Upload a File for SonarQube Analysis</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <label for="file">Choose file to upload:</label>
        <input type="file" id="file" name="file" required>
        <button type="submit">Upload</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    """
    Serve the HTML file for file upload.
    """
    return render_template_string(UPLOAD_FORM_HTML)

@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle file upload, save the file, and run SonarQube Scanner on it.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        # Save the uploaded file
        file_path = os.path.join(TEMP_DIR, file.filename)
        file.save(file_path)

        # Run SonarQube Scanner
        stdout, stderr = run_sonar_scanner(file_path)

        # Optionally, delete the file after scanning
        os.remove(file_path)
        
        # Return results
        return jsonify({"stdout": stdout, "stderr": stderr}), 200

if __name__ == "__main__":
    app.run(debug=True)
