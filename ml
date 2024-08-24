import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import pickle

# Example synthetic data
data = {
    'request_rate': np.random.rand(1000) * 100,  # Requests per second
    'packet_size': np.random.rand(1000) * 1500,  # Packet size in bytes
    'source_ip_variety': np.random.randint(1, 100, 1000),  # Number of unique IPs
    'is_attack': np.concatenate([np.zeros(900), np.ones(100)])  # 10% attacks
}

df = pd.DataFrame(data)
X = df.drop('is_attack', axis=1)
y = df['is_attack']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train a RandomForest model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save the model
with open('ddos_model.pkl', 'wb') as f:
    pickle.dump(model, f)
