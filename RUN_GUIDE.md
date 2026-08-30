# PhishGuard - Run Guide

## 1. Install Dependencies

pip install -r requirements.txt

---

## 2. Add Gmail OAuth Credentials

Place your:
credentials.json

inside the backend folder.

---

## 3. Run the Flask Backend

cd backend
python app.py

Server will start on:
http://127.0.0.1:5000

---

## 4. Open Frontend

Open:
frontend/index.html

in browser.

---

## Features

- Email phishing detection
- URL phishing detection
- SHAP explainability graphs
- Gmail inbox scanning
- Risk score visualization
- XGBoost-based ML prediction

---

## Technologies Used

- Flask
- XGBoost
- SHAP
- Plotly
- Gmail API
- OAuth 2.0
- HTML/CSS/JavaScript
