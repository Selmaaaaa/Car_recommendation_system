import os
from pyexpat import model

from flask import Flask, redirect, render_template, request, send_from_directory, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_mysqldb import MySQL

from flask import session
import joblib
import pandas as pd


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


@app.route('/landingpage', methods=['GET', 'POST'])
@login_required
def scanpage():
    if request.method == 'POST':
        # Redirect to the form page when the button is clicked
        return redirect(url_for('form'))
    return render_template('scanpage.html', user=current_user)


model = joblib.load('car_recommendation_model.pkl')
data = pd.read_csv('cars_with_hp.csv')




def process_input_data(input_data):
    # One-hot encode the categorical variables like Fuel_Type
    input_data = pd.get_dummies(input_data)

    # Align columns between training data and input data
    trained_columns = model.feature_names_in_  # The feature names used during training
    missing_cols = set(trained_columns) - set(input_data.columns)
    
    # Add missing columns with default value of 0
    for col in missing_cols:
        input_data[col] = 0
    
    # Reorder columns to match the training data
    input_data = input_data[trained_columns]
    
    return input_data
@app.route('/form', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        # Get form data
        fuel_type = request.form.get('fuel_type')
        budget = float(request.form.get('budget'))  # Budget as float
        priority = request.form.get('priority')  # 'performance' or 'efficiency'
        print(f"Received Data: {fuel_type}, {budget}, {priority}")  # Debugging statement

        # Set up the input data structure for prediction
        if priority == 'performance':
            # For performance, prioritize Horsepower
            input_data = pd.DataFrame([{
                'Price': budget,
                'Fuel_Type': fuel_type,
                'Horsepower': 250,  # Default value for performance
                'Mileage': 25,  # Lower mileage for performance
                'Num_Features': 3  # Example value
            }])
        elif priority == 'efficiency':
            # For efficiency, prioritize Mileage
            input_data = pd.DataFrame([{
                'Price': budget,
                'Fuel_Type': fuel_type,
                'Horsepower': 200,  # Lower horsepower for efficiency
                'Mileage': 35,  # Higher mileage for efficiency
                'Num_Features': 3  # Example value
            }])
        else:
            flash("Please select a valid priority ('performance' or 'efficiency')", 'danger')
            return render_template('form.html')

        # Process the input data to align columns with the training data
        input_data = process_input_data(input_data)

        # Predict the car type (this may return a string like "Sedan")
        predicted_car_type = model.predict(input_data)[0]  # Predict car type
        print(f"Predicted car type: {predicted_car_type}")  # Debugging line to see the predicted car type

        # Check if the predicted car type exists in the dataset
        if predicted_car_type not in data['Model'].values:
            flash(f"No matching car model found for prediction: {predicted_car_type}", 'danger')
            return render_template('form.html')

        # Map the predicted car type to its index in the dataset
        predicted_car_index = data[data['Model'] == predicted_car_type].index[0]
        print(f"Predicted car index: {predicted_car_index}")  # Debugging line to see the predicted index

        # Fetch the recommended car details from the dataset using the index
        recommended_car_details = data.iloc[predicted_car_index]  # Get the full details of the recommended car

        # Extract the details to display
        recommended_car = {
            'Make': recommended_car_details['Make'],
            'Model': recommended_car_details['Model'],
            'Price': recommended_car_details['Price'],
            'Fuel_Type': recommended_car_details['Fuel_Type'],
            'Horsepower': recommended_car_details['Horsepower'],
            'Mileage': recommended_car_details['Mileage'],
            'Features': recommended_car_details['Features']
        }

        print(f"Recommended car details: {recommended_car_details}")

        # Return the recommendation to the user
        return render_template('form.html', recommended_car=recommended_car)

    return render_template('form.html', recommended_car=None)


if __name__ == '__main__':
    app.run(debug=True)
