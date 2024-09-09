import os
import io
from flask import Flask, Response, jsonify, redirect, render_template, request, send_from_directory, url_for, make_response, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_mysqldb import MySQL
from files import detect_sensitive_data, check_hard_coded_credentials, check_file_permissions, calculate_vulnerability_score, determine_risk_level,scan_for_malware
from bandit import run_bandit_analysis
from flask import session
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.colors import HexColor

from reportlab.pdfgen import canvas

from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image


from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime 
app = Flask(__name__)
@app.after_request
def add_header(response):
    response.cache_control.no_store = True
    return response
app.config['SECRET_KEY'] = 'salma' 
app.config['MYSQL_HOST'] = 'localhost' 
app.config['MYSQL_USER'] = 'root'  
app.config['MYSQL_PASSWORD'] = '3619' 
app.config['MYSQL_DB'] = 'analysis_db' 
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

#
login_manager = LoginManager()
login_manager.init_app(app)
mysql = MySQL(app)

class User(UserMixin):
    def __init__(self, id, email, password, first_name=None, last_name=None):
        self.id = id
        self.email = email
        self.password = password
        self.first_name = first_name
        self.last_name = last_name


class BackgroundCanvas(canvas.Canvas):
    def drawBackground(self):
        self.setFillColor(colors.lightgrey)
        self.rect(0, 0, self.pagesize[0], self.pagesize[1], fill=1)



# Function to draw the background
def draw_background(c, doc):
    c.setFillColor(HexColor('#4d234a'))
    c.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1)

def generate_pdf_report(analysis_result, report_type):
    try:
        print("Starting PDF generation...")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)  # Use A4 size

        story = []
        styles = getSampleStyleSheet()
        paragraph_style = styles['BodyText']
        paragraph_style.wordWrap = 'CJK'  # Ensure text wraps correctly

        logo_path = r'.\static\assets\img\PIC2.png'  # Use raw string to handle backslashes
  # Update this path to your logo file
        if os.path.exists(logo_path):
            logo = Image(logo_path, width=1.5 * inch, height=1 * inch)
            story.append(logo)
        # Add a title with the report type
        current_date = datetime.now().strftime("%B %d, %Y")  # Correct usage of datetime.now()
        date_style = ParagraphStyle(
            name='DateStyle',
            fontSize=10,
            alignment=2,  # Right align
            textColor=colors.black
        )
        date_paragraph = Paragraph(current_date, date_style)
        story.append(date_paragraph)
        story.append(Spacer(1, 24))
        title_style = styles['Title'].clone('TitleCustom')
        title_style.textColor = colors.white
        title = Paragraph(f"Analysis Report for: {report_type} ",title_style)
        story.append(title)
        story.append(Paragraph(" ", styles['Normal']))  # Space between title and table
        
        # Table headers and data
        header = ["Line", "Issue", "Severity", "Confidence", "More Info"]
        data = [header]

        for issue in analysis_result:
            if isinstance(issue, dict):
                line_number = issue.get("line_number", "N/A")
                issue_text = issue.get("issue_text", "N/A")
                severity = issue.get("severity", "N/A")
                confidence = issue.get("confidence", "N/A")
                more_info = issue.get("more_info", "N/A")

                data.append([
                    Paragraph(str(line_number), paragraph_style),
                    Paragraph(str(issue_text), paragraph_style),
                    Paragraph(str(severity), paragraph_style),
                    Paragraph(str(confidence), paragraph_style),
                    Paragraph(str(more_info), paragraph_style)
                ])
            else:
                data.append([Paragraph("Invalid Data", paragraph_style)] * len(header))
        story.append(Spacer(1, 34))
        # Column width scaling based on content size
        col_widths = [60, 150, 80, 80, 150]  # Adjust column widths to fit page

        # Create table
        table = Table(data, colWidths=col_widths)

        # Table styles for formatting
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.black),  # Header background color
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),  # Header align center
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font bold
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),  # Padding for header
            ('FONTSIZE', (0, 0), (-1, 0), 12),  # Reduce font size for better fit
            ('BOTTOMPADDING', (0, 0), (-1, 0), 18),  # Add padding for the header row
            ('TOPPADDING', (0, 1), (-1, -1), 12),  # Add top padding to data rows
            ('BOTTOMPADDING', (0, 1), (-1, -1), 12),  # Add bottom padding to data rows
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),  # Data row background
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),  # Data text color
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),  # Align data to left
            ('FONTSIZE', (0, 0), (-1, -1), 10),  # Reduce font size for better fit
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),  # Add grid lines
        ]))

        story.append(table)

        # Build PDF document with background function (optional)
        doc.build(story, onFirstPage=lambda c, d: draw_background(c, d), onLaterPages=lambda c, d: draw_background(c, d))

        # Return the generated PDF
        buffer.seek(0)
        print("PDF generation successful")
        return buffer.getvalue()

    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None



@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    # Retrieve analysis result and filename from session
    analysis_result = session.get('analysis_result')
    filename = session.get('filename')

    if not analysis_result:
        flash("No analysis result found", 'danger')
        return redirect(url_for('scanpage'))
    try:
        # Generate the PDF report using the analysis result
        pdf_data = generate_pdf_report(analysis_result, filename)

        # Save the PDF to a file
        report_filename = f"{filename}_analysis_report.pdf"
        report_path = os.path.join('reports', report_filename)
        os.makedirs('reports', exist_ok=True)
        with open(report_path, 'wb') as f:
            f.write(pdf_data)

        # Save report metadata to the database
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO reports (user_id, filename, created_at) VALUES (%s, %s, %s)",
            (current_user.id, report_filename, datetime.now())
        )
        mysql.connection.commit()
        cur.close()

        # Return PDF file as a downloadable attachment
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={report_filename}'
        return response
    except Exception as e:
        flash(f"An error occurred while generating the report: {str(e)}", 'danger')
        return redirect(url_for('scanpage'))
    
@app.route('/reports')
@login_required
def reports():
    cur = mysql.connection.cursor()
    cur.execute("SELECT filename, created_at FROM reports WHERE user_id = %s", (current_user.id,))
    reports = cur.fetchall()
    cur.close()
    print(reports)  # Debugging line
    return render_template('reports.html', reports=reports, user=current_user)



@app.route('/download_report/<filename>')
@login_required
def download_report(filename):
    return send_from_directory('reports', filename)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user: 
            flash("Email already exists!", 'danger')
            return render_template('signup.html') 

        cur.execute("INSERT INTO users (nom, prenom, email, mdp) VALUES (%s, %s, %s, %s)", (first_name, last_name, email, password))
        mysql.connection.commit()
        cur.close()
        flash("Signup successful! Please log in.", 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Debugging statement to see if the user is already authenticated
    print(f"Current user is authenticated: {current_user.is_authenticated}")

    # If the user is already authenticated, redirect to the scan page
    if current_user.is_authenticated:
        print("Redirecting to scan page")
        return redirect(url_for('scanpage'))

    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from database based on email
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        # Check if user exists and the password matches
        if user and user[4] == password:
            # Create a user object and log in the user
            user_obj = User(id=user[0], email=user[3], password=user[4], first_name=user[1], last_name=user[2])
            login_user(user_obj)  # Flask-Login function to log in the user

            # Debugging statement to confirm successful login
            print("Login successful, redirecting to scan page")
            
            # Redirect the user to the scan page
            return redirect(url_for('scanpage'))
        else:
            # If credentials are incorrect, flash an error message
            print("Invalid email or password")
            flash("Invalid email or password", 'danger')

    # If not a POST request or invalid login, render the login page
    return render_template('login.html')





@app.route('/logout')
@login_required
def logout():
    session.clear()  # Clear the session completely
    flash("You have been successfully logged out.", 'info')
    return redirect(url_for('login'))  # Redirect to the login page after logout

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, email, nom, prenom, mdp FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    
    if user:
        return User(id=user[0], email=user[1], password=user[4], first_name=user[2], last_name=user[3])
    return None

@app.route('/css/<path:filename>')
def serve_css(filename):
    return send_from_directory('static/css', filename)

@app.route('/js/<path:filename>')
def serve_js(filename):
    return send_from_directory('static/js', filename)

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    return send_from_directory('static/assets', filename)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scanpage', methods=['GET', 'POST'])
@login_required
def scanpage():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        if scan_type == 'files':
            return redirect(url_for('files_scan'))
        elif scan_type == 'python':
            return redirect(url_for('python_scan'))
    return render_template('scanpage.html', user=current_user)

@app.route('/python_scan', methods=['GET', 'POST'])
def python_scan():
    analysis_result = None
    filename = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part", 'danger')
            return redirect(url_for('python_scan'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash("No selected file", 'danger')
            return redirect(url_for('python_scan'))

        filename = file.filename  # Get the filename
        
        # Save the file with its original name in the uploads directory
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            analysis_result = run_combined_analysis(file_path)
        finally:
            # Remove the file after analysis
            os.remove(file_path)
            
            if 'generate_pdf' in request.form:
                pdf_data = generate_pdf_report(analysis_result)
                return Response(pdf_data, mimetype='application/pdf', headers={"Content-Disposition": "attachment;filename=analysis_report.pdf"})
    session['analysis_result'] = analysis_result
    session['filename'] = filename
    return render_template('python.html', analysis_result=analysis_result, user=current_user, filename=filename)




def run_combined_analysis(file_path):
    issues = []
    
    bandit_issues = run_bandit_analysis(file_path)
    issues.extend(bandit_issues)
    
    return issues

@app.route('/files_scan', methods=['GET', 'POST'])
def files_scan():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part", 400
        
        file = request.files['file']
        
        if file.filename == '':
            return "No selected file", 400

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        result = run_file_analysis(file_path)
        os.remove(file_path)
        return jsonify(result)
    
    return render_template('files.html', user=current_user)

def run_file_analysis(file_path):
    scan_results = scan_for_malware(file_path)
    sensitive_data = detect_sensitive_data(file_path)
    hard_coded_credentials = check_hard_coded_credentials(file_path)
    file_permissions = check_file_permissions(file_path)
    
    vulnerability_score = calculate_vulnerability_score(scan_results, sensitive_data, hard_coded_credentials, file_permissions)
    risk_level = determine_risk_level(vulnerability_score)
    
    result = {
        'scan_results': scan_results,
        'sensitive_data': sensitive_data,
        'hard_coded_credentials': hard_coded_credentials,
        'file_permissions': file_permissions,
        'vulnerability_score': vulnerability_score,
        'risk_level': risk_level
    }
    
    return result

if __name__ == '__main__':
    app.run(debug=True)
