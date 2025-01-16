import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Step 1: Load the dataset
data = pd.read_csv('synthetic_car_data.csv')

# Step 2: Clean and preprocess the data

# Clean 'Mileage' column: Convert to string first, then remove non-numeric characters, and convert to float
data['Mileage'] = data['Mileage'].astype(str).str.replace(r'[^0-9.]', '', regex=True).astype(float)

# Ensure 'Horsepower' is numeric
data['Horsepower'] = pd.to_numeric(data['Horsepower'], errors='coerce')

# Step 3: Define features (X) and target variable (y)
X = data[['Price', 'Mileage', 'Horsepower', 'Num_Features', 'Fuel_Type']]  # Features
y = data['Car_Type']  # Target: car type

# One-hot encode categorical variables (Fuel_Type)
X = pd.get_dummies(X, drop_first=True)  # Drop first to avoid multicollinearity

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
