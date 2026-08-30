# 🛡️ PhishGuard 

PhishGuard is a machine learning-based web application designed to detect and prevent phishing attacks. It analyzes URLs and email-related features to determine whether a link is legitimate or malicious.

---

## 🚀 Features

* 🔍 Detects phishing URLs using ML models
* 📊 Feature extraction from URLs and email data
* 🌐 Simple frontend interface for testing links
* ⚡ Fast predictions using trained model
* 🧠 Train your own model using provided scripts

---

## 🏗️ Project Structure

```
PhishGuard/
│
├── backend/
│   ├── app.py
│   ├── extract_email_address_features.py
│   └── train.py
│
├── frontend/
│   ├── index.html
│   └── plotly.min.js
│
├── .gitignore
└── README.md
```

---

## ⚙️ How It Works

1. User enters a URL
2. Backend extracts features
3. Machine learning model analyzes patterns
4. Returns prediction: **Phishing or Safe**

---

## 🧪 Setup & Installation

### 1. Clone the repository

```
git clone https://github.com/AyushI7G/PhishGaurd2.0.git
cd PhishGaurd2.0
```

---

### 2. Install dependencies

```
pip install -r requirements.txt
```

---

### 3. Train the model

```
python backend/train.py
```

This will generate the trained model files required for predictions.

---

### 4. Run the backend server

```
python backend/app.py
```

---

### 5. Open frontend

Open `frontend/index.html` in your browser.

---

## 📊 Dataset

Dataset is **not included** due to size and security reasons.

You can use:

* PhishTank dataset
* Kaggle phishing datasets

---

## 🛠️ Technologies Used

* Python
* Machine Learning (XGBoost / Scikit-learn)
* HTML, CSS, JavaScript
* Plotly (for visualization)

---

## ⚠️ Notes

* Model files are not included—generate them using `train.py`
* Dataset must be downloaded separately
* Ensure correct file paths while running locally

---

## 📌 Future Improvements

* Chrome extension integration
* Real-time URL scanning API
* Better UI/UX
* Deployment on cloud

---

## 👨‍💻 Author

**Ayushi Gupta**

---

## ⭐ Contribute

Feel free to fork this repo and improve it!

---

## 📄 License

This project is open-source and available under the MIT License.
