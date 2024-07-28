import pandas as pd
import re
import streamlit as st
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

# Load the dataset from the CSV file
df = pd.read_csv('malicious_phish.csv')

# Feature extraction function
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_subdomains'] = len(re.findall(r'\.', url)) - 1
    features['contains_https'] = 1 if 'https' in url else 0
    features['contains_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    features['suspicious_keywords'] = sum([1 if kw in url else 0 for kw in ['login', 'update', 'verify', 'secure']])
    return features

# Apply feature extraction
df_features = df['url'].apply(extract_features).apply(pd.Series)
df_features['label'] = df['type']

# Encode labels
label_encoder = LabelEncoder()
df_features['label'] = label_encoder.fit_transform(df_features['label'])

# Train/test split
X = df_features.drop('label', axis=1)
y = df_features['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train XGBoost model
clf = XGBClassifier(random_state=42)
clf.fit(X_train, y_train)

# Predict and evaluate
y_pred = clf.predict(X_test) 
# Streamlit UI
st.title("URL Malicious Detector")

# User input
user_input = st.text_input("Enter a URL to check if it's malicious:")

if user_input:
    input_features = extract_features(user_input)
    input_df = pd.DataFrame([input_features])
    prediction = clf.predict(input_df)
    prediction_label = label_encoder.inverse_transform(prediction)[0]

    st.write(f"The URL is classified as: **{prediction_label}**")
    if prediction_label in ['malware', 'phishing', 'defacement']:
        st.write("**Action:** The URL should be **removed** as it is malicious.")
    else:
        st.write("**Action:** The URL is safe to **allow**.")
 