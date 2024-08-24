import pickle
import pandas as pd

# Load the trained model
with open('ddos_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Function to predict if a packet is part of an attack
def is_attack(features):
    df = pd.DataFrame([features])
    prediction = model.predict(df)
    return prediction[0] == 1
