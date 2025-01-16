import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Step 1: Load the dataset
data = pd.read_csv('cars_with_hp.csv')

# Check if 'Features' column exists
if 'Features' not in data.columns:
    raise ValueError("The dataset does not contain a 'Features' column!")

# Step 2: Clean and preprocess the data

# Clean 'Mileage' column: Remove non-numeric characters and convert to float (handling MPG)
data['Mileage'] = data['Mileage'].astype(str).str.replace(r'[^0-9.]', '', regex=True).astype(float)

# Ensure 'Horsepower' is numeric, converting errors to NaN
data['Horsepower'] = pd.to_numeric(data['Horsepower'], errors='coerce')

# Fill missing values in 'Mileage' and 'Horsepower' columns (if any)
data['Mileage'] = data['Mileage'].fillna(data['Mileage'].mean())
data['Horsepower'] = data['Horsepower'].fillna(data['Horsepower'].mean())

# Handle 'Features' column: Assuming it's a string representation of a list, convert to list and count length
data['Num_Features'] = data['Features'].apply(lambda x: len(eval(x)) if isinstance(x, str) else 0)

# Step 3: Define features (X) and target variable (y)
# Use 'Body_Styles' as target instead of 'Car_Type'
X = data[['Price', 'Mileage', 'Horsepower', 'Num_Features', 'Fuel_Type']]  # Features
y = data['Body_Styles']  # Target: body styles

# One-hot encode categorical variables (Fuel_Type)
X = pd.get_dummies(X, drop_first=True)

# Step 4: Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 5: Train the model (Random Forest)
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Step 6: Evaluate the model
accuracy = model.score(X_test, y_test)
print(f"Model accuracy: {accuracy * 100:.2f}%")

# Step 7: Save the trained model
joblib.dump(model, 'car_recommendation_model.pkl')

# Save the column names to ensure we align the features during prediction
columns = X_train.columns
joblib.dump(columns, 'columns.pkl')

# Step 8: Prediction function that returns full car details with efficiency/performance filtering and budget check
def recommend_car(input_data, preference, budget):
    # Create input DataFrame
    input_df = pd.DataFrame([input_data], columns=['Price', 'Mileage', 'Horsepower', 'Num_Features', 'Fuel_Type'])
    
    # One-hot encode the input data using the same columns as the training data
    input_df = pd.get_dummies(input_df, drop_first=True)
    
    # Add any missing columns with zeros (for unseen categories during training)
    missing_cols = set(columns) - set(input_df.columns)
    for col in missing_cols:
        input_df[col] = 0
    input_df = input_df[columns]  # Ensure the columns match exactly with training data
    
    # Make the prediction
    predicted_body_style = model.predict(input_df)[0]
    
    # Filter the dataset based on user input and budget
    recommended_cars = data[data['Body_Styles'] == predicted_body_style]
    
    # Filter based on preference (Efficiency vs Performance)
    if preference == 'efficiency':
        # Efficiency: Sort by mileage (higher mileage = more efficient)
        recommended_cars = recommended_cars.sort_values(by='Mileage', ascending=False)
    elif preference == 'performance':
        # Performance: Sort by horsepower (higher horsepower = better performance)
        recommended_cars = recommended_cars.sort_values(by='Horsepower', ascending=False)
    
    # Filter by budget
    recommended_cars = recommended_cars[recommended_cars['Price'] <= budget]
    
    # Return the top recommended car within the budget
    if not recommended_cars.empty:
        return recommended_cars.iloc[0]
    else:
        return "No cars within the specified budget."

# Example user input
input_data = {
    'Price': 25000,
    'Mileage': 30,
    'Horsepower': 200,
    'Num_Features': 5,
    'Fuel_Type': 'Petrol'
}

preference = 'performance'  # Or 'efficiency'
budget = 27000  # User's budget

recommended_car = recommend_car(input_data, preference, budget)
print(f"Recommended car details:\n{recommended_car}")
