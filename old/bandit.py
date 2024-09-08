from flask import Flask, request, render_template_string
import subprocess
import tempfile
import os
import json

app = Flask(__name__)

# HTML template for the upload form
UPLOAD_FORM_HTML = """
<!doctype html>
<html>
<head><title>Upload and Analyze Python File</title></head>
<body>
    <h1>Upload your Python file</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".py">
        <input type="submit" value="Upload">
    </form>
    {% if analysis_result %}
        <h2>Bandit Analysis Result</h2>
        <table border="1" cellpadding="5">
            <tr>
                <th>Filename</th>
                <th>Line Number</th>
                <th>Issue</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>More Info</th>
            </tr>
            {% for issue in analysis_result %}
            <tr>
                <td>{{ issue['filename'] }}</td>
                <td>{{ issue['line_number'] }}</td>
                <td>{{ issue['issue_text'] }}</td>
                <td>{{ issue['severity'] }}</td>
                <td>{{ issue['confidence'] }}</td>
                <td><a href="{{ issue['more_info'] }}" target="_blank">Link</a></td>
            </tr>
            {% endfor %}
        </table>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(UPLOAD_FORM_HTML)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    if file.filename == '':
        return "No selected file", 400

    if file and file.filename.endswith('.py'):
        # Save the file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
            file.save(temp_file.name)
            temp_file_path = temp_file.name
        
        # Run Bandit on the file and parse the results
        analysis_result = run_bandit_analysis(temp_file_path)

        # Clean up the temporary file
        os.remove(temp_file_path)
        
        # Render the template with the structured Bandit analysis result
        return render_template_string(UPLOAD_FORM_HTML, analysis_result=analysis_result)
    
    return "Invalid file type. Please upload a .py file.", 400

def run_bandit_analysis(file_path):
    try:
        # Run Bandit and capture the output in JSON format
        result = subprocess.run(
            ['bandit', '-r', file_path, '-f', 'json'],
            capture_output=True,  # Capture stdout and stderr
            text=True  # Return output as a string
        )

        # Parse the JSON output from Bandit
        bandit_output = json.loads(result.stdout)
        issues = []

        # Organize the issues into a more readable format
        for issue in bandit_output.get('results', []):
            issues.append({
                'filename': issue['filename'],
                'line_number': issue['line_number'],
                'issue_text': issue['issue_text'],
                'severity': issue['issue_severity'],
                'confidence': issue['issue_confidence'],
                'more_info': issue['more_info'],
            })

        return issues

    except subprocess.CalledProcessError as e:
        # Capture and return error details
        return [{"issue_text": f"Bandit failed with error:\n{e.stderr}"}]
    except Exception as e:
        # Capture and return other errors
        return [{"issue_text": str(e)}]

if __name__ == '__main__':
    app.run(debug=True)
