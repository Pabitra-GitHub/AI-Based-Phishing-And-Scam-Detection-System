# Product Requirement Document (PRD)
## 7th Semester — Minor Project
**Project**: AI-Based Phishing & Scam Detection System  
**Project Objective**: Build a focused web application that analyzes suspicious URLs using machine learning, deterministic security rules, explainable risk scoring, authentication, and scan history.

---

### 1. Product Vision
Provide a simple and trustworthy first-line safety check for users who receive suspicious links. The minor project is intentionally URL-centric so that the team can complete, test, document, and demonstrate a coherent end-to-end system within one semester.

---

### 2. Minor Scope Boundary

| Included in Minor | Explicitly Deferred to Major |
|---|---|
| URL analysis | Email/message NLP analysis |
| ML-based URL classification | QR-code image scanning |
| Rule-based URL checks | Browser extension |
| Risk score + explanation | Real-time threat-intelligence orchestration |
| User registration/login | Cloud-scale deployment |
| User scan history | Advanced multi-modal AI |
| Basic user dashboard | Security operations / analyst dashboard |

---

### 3. Target Users
- General users who want to check a suspicious link before opening or submitting information.
- Students and faculty using the application as a cybersecurity learning/demo platform.
- Project administrators who need basic statistics and user management.

---

### 4. Core Features

| Feature | Minor Requirement | Acceptance Criteria |
|---|---|---|
| **URL input** | HTTP/HTTPS URL submission | Invalid/empty input rejected with clear message. |
| **Feature extraction** | Extract URL-based indicators | At least 10 deterministic features available to ML/rules. |
| **ML classification** | Binary or multi-class phishing prediction | Saved model returns probability and version. |
| **Rule engine** | Independent security heuristics | Each triggered rule produces an explanation. |
| **Risk score** | Normalize evidence to 0–100 | Stable classification thresholds are configurable. |
| **Scan history** | Authenticated users view own scans | Pagination and ownership enforced server-side. |
| **Authentication** | Register/login/logout | Passwords are hashed; protected routes require authentication. |
| **Dashboard** | Basic statistics | Totals and recent scans are shown reliably. |

---

### 5. Primary User Workflow
1. Open the application.
2. Paste a suspicious URL.
3. Client validates the input.
4. Backend extracts URL features.
5. ML model produces a phishing probability.
6. Rule engine evaluates deterministic indicators.
7. Risk engine calculates the final risk score.
8. System generates human-readable reasons.
9. Result is displayed and saved to the authenticated user’s history.

---

### 6. Result Experience
```
Classification: HIGH RISK
Risk Score: 87/100
ML Probability: 0.91
Reasons:
- Suspicious domain structure
- Login-related keyword detected
- Excessive URL complexity
Recommendation: Do not enter credentials or payment details.
```

---

### 7. Success Metrics
- **ML Evaluation**: Report accuracy, precision, recall, F1, ROC-AUC, confusion matrix.
- **Security**: Track false negatives and explain key failure cases.
- **Performance**: Typical scan completes within a few seconds in the development environment.
- **Usability**: A first-time user can perform a scan without instructions.
- **Reliability**: Graceful handling of model/database/API failures.
- **Completeness**: All critical features pass functional test cases.
