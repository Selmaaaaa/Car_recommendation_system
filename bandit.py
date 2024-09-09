import subprocess
import os
import json
import argparse

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

def main():
    parser = argparse.ArgumentParser(description='Run security analysis on a Python file.')
    parser.add_argument('file', help='Path to the Python file to analyze')

    args = parser.parse_args()

    file_path = args.file

    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return

    analysis_result = run_bandit_analysis(file_path)

    print("Analysis Results:")
    for issue in analysis_result:
        print(f"File: {issue['filename']}")
        print(f"Line: {issue['line_number']}")
        print(f"Issue: {issue['issue_text']}")
        print(f"Severity: {issue['severity']}")
        print(f"Confidence: {issue['confidence']}")
        print(f"More Info: {issue['more_info']}")
        print("-" * 40)

if __name__ == '__main__':
    main()
