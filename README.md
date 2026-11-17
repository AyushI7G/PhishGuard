# PhishGuard

### Hybrid Machine Learning-Based Phishing Detection System

PhishGuard is a phishing detection platform that combines machine learning, feature engineering, and heuristic-based analysis to identify phishing emails, malicious URLs, suspicious sender identities, and potentially harmful email attachments.

### Features

- XGBoost-based email and URL classification
- Machine learning pipeline with feature extraction and engineering
- Heuristic-based phishing detection
- Five-model benchmarking: XGBoost, BERT, RoBERTa, CNN and LSTM
- SHAP-based explainable AI and feature contribution analysis
- Sender identity verification and email header analysis
- Gmail integration with OAuth 2.0
- Email attachment security analysis
- AI-assisted threat investigation
- Risk scoring and interactive threat visualization

---

### Tech Stack

**Frontend:** React, TypeScript, Vite  
**Backend:** Node.js, Express.js  
**Machine Learning:** Python, XGBoost, Scikit-learn, PyTorch  
**Explainability:** SHAP  
**Integration:** Gmail API, Google OAuth 2.0  
**Analysis:** Feature Engineering, Heuristic Detection

---

### Architecture

```text
Email / URL / Attachment
          ↓
    Feature Extraction
          ↓
   Heuristic Analysis
          ↓
   ML Inference Pipeline
          ↓
       XGBoost
          ↓
   Threat Classification
          ↓
   Risk Scoring + SHAP
          ↓
    Detection Dashboard
```

---

### Getting Started

```bash
git clone <repository-url>
cd PhishGuard
npm install
pip install -r ml/requirements.txt
```

Configure the required environment variables and Gmail OAuth credentials.

Start the application and ML inference service following the instructions in `RUN_GUIDE.md`.

---

**Built with React, TypeScript, Node.js, Python, XGBoost and SHAP.**

## Author

**Ayushi Gupta**