# 🛡️ PhishGuard AI — AI-Based Phishing & Scam Detection System

> An intelligent, locally-running web application that analyses any URL for phishing and scam indicators using Machine Learning, deterministic security algorithms, and real-time network checks.

---

## 📌 What is PhishGuard AI?

PhishGuard AI lets anyone paste a website link and instantly get a **safety report** before opening it.

It works by:

- 🔍 Checking URL structure for suspicious patterns, typosquatting, and scam keywords
- 🏛️ Recognizing trusted government portals and known brand domains
- 🌐 Performing live DNS, HTTPS/SSL, redirect, and HTTP security header checks
- 🤖 Running a trained **Machine Learning model** for phishing risk scoring
- 📊 Using algorithms like Trie matching, Levenshtein distance, Shannon entropy, and redirect-graph analysis
- 💾 Storing scan history locally (auto-cleared after 2 hours)
- 🧪 Providing an API dashboard and interactive API documentation

> ⚠️ **Disclaimer:** This is a defensive and educational tool. A `SAFE` result is not a guarantee. Never enter sensitive information on a website solely based on this tool's result.

---

## 🚀 Risk Score Classifications

| Classification | Score Range | Meaning |
|---|:---:|---|
| ✅ **SAFE** | 0 – 29 | Very few suspicious indicators found |
| ⚠️ **SUSPICIOUS** | 30 – 59 | Some caution indicators detected |
| 🔴 **HIGH RISK** | 60 – 84 | Several strong phishing indicators found |
| ☠️ **CRITICAL** | 85 – 100 | Severe malicious or credential-theft indicators |

---

## 💻 System Requirements

Before you start, make sure your PC has the following installed:

| Requirement | Minimum Version | Download Link |
|---|---|---|
| **Python** | 3.10 or newer | [python.org/downloads](https://www.python.org/downloads/) |
| **Node.js** | LTS (any recent) | [nodejs.org](https://nodejs.org/) |

> 💡 **Windows Tip:** During Python installation, make sure to tick **"Add Python to PATH"** checkbox — this is very important!

---

## 📥 How to Download & Run (Complete Guide)

> Follow these steps **exactly in order**. No programming knowledge needed.

---

### ✅ STEP 1 — Download the Project from GitHub

**Option A — Download as ZIP (Easiest)**

1. Go to the GitHub repository page
2. Click the green **`< > Code`** button
3. Select **"Download ZIP"**
4. Once downloaded, **right-click** the ZIP file → **"Extract All..."**
5. Choose a folder (e.g., `C:\Projects\PhishGuard`) and click **Extract**

**Option B — Clone with Git** *(if Git is installed)*

Open Command Prompt or PowerShell and run:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
cd "AI-Based Phishing & Scam Detection System"
```

---

### ✅ STEP 2 — Install Python

1. Go to [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Click **"Download Python 3.x.x"** (latest stable version)
3. Run the installer
4. ⚠️ **IMPORTANT:** On the first screen, check the box that says **"Add Python to PATH"**
5. Click **"Install Now"** and wait for it to finish
6. Close the installer

**Verify Python is installed** — open Command Prompt and type:

```cmd
python --version
```

You should see something like: `Python 3.12.0`

---

### ✅ STEP 3 — Install Node.js

1. Go to [https://nodejs.org/](https://nodejs.org/)
2. Click the **LTS** (Long Term Support) version — the left green button
3. Run the installer with default settings — just keep clicking **Next**
4. When done, close the installer

**Verify Node.js is installed** — open Command Prompt and type:

```cmd
node --version
npm --version
```

You should see version numbers like `v20.x.x` and `10.x.x`

---

### ✅ STEP 4 — Open the Project Folder

Navigate to the folder where you extracted the project.

**Easy way on Windows:**
1. Open **File Explorer**
2. Go to your extracted project folder (e.g., `C:\Projects\PhishGuard\AI-Based Phishing & Scam Detection System`)
3. You should see files like `run_dev.bat`, `README.md`, `backend/`, `frontend/`, etc.

---

### ✅ STEP 5 — Run the Application

**Double-click `run_dev.bat`** in the project folder.

That's it! 🎉

The launcher will **automatically**:

| Step | What it does |
|:---:|---|
| 1️⃣ | Check that Python and Node.js are installed |
| 2️⃣ | Create a Python virtual environment (`.venv`) |
| 3️⃣ | Install all backend Python packages automatically |
| 4️⃣ | Install all frontend Node.js packages automatically |
| 5️⃣ | Train the AI/ML model if it's not found |
| 6️⃣ | Run database setup and migrations |
| 7️⃣ | Start the **Backend server** on port `8000` |
| 8️⃣ | Start the **Frontend UI** on port `5173` |
| 9️⃣ | Open your browser automatically at `http://localhost:5173` |

> ⏳ **First run takes 2–5 minutes** because it downloads and installs all packages. After that, it starts in under 10 seconds.

> 🖥️ **Keep both terminal windows open** (Backend + Frontend) while using the app. Closing them will stop the application.

---

### ✅ STEP 6 — Use PhishGuard AI

1. Your browser should open automatically at **[http://localhost:5173](http://localhost:5173)**
2. If it doesn't open, go there manually in any browser
3. **Paste any URL** (e.g., `https://example.com`) into the scanner box
4. Click **"Scan Threat"**
5. View the **risk score**, classification, and detailed reasons

**Quick Test URLs you can try:**

| URL | Expected Result |
|---|---|
| `https://india.gov.in` | ✅ SAFE (Government portal) |
| `https://google.com` | ✅ SAFE (Trusted brand) |
| `https://paypa1-secure-login.tk` | ☠️ CRITICAL (Typosquatting) |

---

### 🛑 How to Stop the Application

**Double-click `stop_app.bat`** in the project folder.

Or simply **close both terminal windows** (Backend and Frontend).

---

## 🔧 Manual Setup (If `run_dev.bat` Doesn't Work)

If the launcher doesn't work for any reason, follow these manual steps:

### Step A — Install backend packages

Open Command Prompt in the project folder and run:

```cmd
python -m pip install -r backend\requirements.txt
```

### Step B — Install frontend packages

```cmd
cd frontend
npm install
cd ..
```

### Step C — Train the ML model (only needed once)

```cmd
python ml\training\train_models.py
```

### Step D — Start the Backend (Terminal 1)

```cmd
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step E — Start the Frontend (Terminal 2 — open a new window)

```cmd
cd frontend
npm run dev
```

Then open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 🌐 Important URLs (While App is Running)

| URL | Purpose |
|---|---|
| [http://localhost:5173](http://localhost:5173) | 🖥️ Main Web Interface — Use this! |
| [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | 📖 Swagger API Documentation |
| [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc) | 📖 ReDoc API Documentation |
| [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health) | ❤️ Backend Health Check |

**Healthy backend response:**

```json
{
  "status": "healthy",
  "model_loaded": true
}
```

---

## 🗂️ Project Structure

```
AI-Based Phishing & Scam Detection System/
│
├── 🚀 run_dev.bat              ← Double-click to START the app (Windows)
├── 🛑 stop_app.bat             ← Double-click to STOP the app
├── 📋 README.md                ← This file
├── 🔧 .env.example             ← Configuration template (copy to .env)
│
├── backend/                    ← Python FastAPI backend
│   ├── app/
│   │   ├── main.py             ← App entry point
│   │   ├── api/v1/             ← API endpoints (scan, auth, dashboard)
│   │   ├── services/           ← Core logic and ML integration
│   │   ├── services/dsa/       ← Trie, Levenshtein, entropy algorithms
│   │   ├── models/             ← Database models
│   │   └── schemas/            ← API request/response validation
│   ├── tests/                  ← Automated backend tests
│   └── requirements.txt        ← Python dependencies list
│
├── frontend/                   ← React + TypeScript web interface
│   ├── src/
│   │   ├── components/         ← UI components (scanner, gauge, results)
│   │   ├── services/api.ts     ← API communication layer
│   │   └── types/              ← TypeScript type definitions
│   └── package.json            ← Node.js dependencies list
│
├── ml/                         ← Machine Learning module
│   ├── datasets/               ← Training data and brand domains list
│   ├── models/                 ← Trained model files (auto-generated)
│   ├── training/               ← Model training scripts
│   └── evaluation/             ← Model accuracy metrics
│
├── migrations/                 ← Database migration files (Alembic)
├── scripts/                    ← Helper scripts
└── docs/                       ← Project documentation and figures
```

---

## ⚙️ Optional Configuration

The app works perfectly with default settings. If you want to customise:

1. Find `.env.example` in the project folder
2. Make a copy and rename it to `.env`
3. Open `.env` with Notepad and edit the values
4. Restart the app

**Optional API Keys** *(all free, all optional — app works without them)*:

| Key | Service | What it adds |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Extra malware database checks |
| `GOOGLE_SAFE_BROWSING_KEY` | Google | Google's Safe Browsing database |
| `PHISHTANK_API_KEY` | PhishTank | Crowdsourced phishing database |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IP reputation checks |
| `GEMINI_API_KEY` | Google AI | AI-powered URL analysis |

> 🔒 **Never share your `.env` file.** It contains private keys and is excluded from GitHub automatically.

---

## 🐳 Optional: Run with Docker

If you have **Docker Desktop** installed:

```bash
docker compose up --build
```

Then visit [http://localhost:5173](http://localhost:5173).

To stop:

```bash
docker compose down
```

---

## 🛠️ Troubleshooting

### ❌ "Python is not recognized" or "'python' is not recognized"

**Fix:** Reinstall Python from [python.org](https://www.python.org/downloads/) and during installation **check "Add Python to PATH"**. Then close and reopen Command Prompt.

Alternatively, try `py` instead of `python`:

```cmd
py --version
```

---

### ❌ "npm is not recognized"

**Fix:** Install Node.js from [nodejs.org](https://nodejs.org/), restart your computer, then try again.

---

### ❌ Browser shows "This site can't be reached" or "Connection refused"

**Fix:**
1. Make sure both terminal windows (Backend + Frontend) are **still open and running**
2. Wait 10–15 seconds and refresh the browser
3. Check health URL: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

---

### ❌ "Port 8000 or 5173 is already in use"

**Fix:** Another program is using that port. Close any other running servers, or restart your PC and try again.

---

### ❌ "Model is not loaded" or model missing

**Fix:** The AI model binary is not included in the GitHub download (too large). The launcher trains it automatically on first run. If it's missing, run manually:

```cmd
python ml\training\train_models.py
```

---

### ❌ App is very slow on first scan

**Fix:** This is normal. The first scan performs live DNS and network checks which take a few seconds. Subsequent scans are faster.

---

## 🔒 Security & Privacy Notes

- All data is stored **locally** on your PC only — nothing is sent to the cloud
- Passwords (if used) are stored as **PBKDF2-HMAC-SHA256 hashes** — never plaintext
- Scan history is **automatically deleted after 2 hours**
- URL scans include protection against **SSRF** (private/local IP requests)
- Change `JWT_SECRET_KEY` in `.env` before deploying outside your local machine
- Do not use this tool to scan URLs without permission from the site owner

---

## 🧬 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Axios |
| **Backend** | Python 3.10+, FastAPI, Uvicorn, SQLAlchemy |
| **Database** | SQLite (default), PostgreSQL (supported) |
| **ML / AI** | scikit-learn, pandas, NumPy, Joblib |
| **Algorithms** | Trie, Levenshtein, Shannon Entropy, Redirect Graph |
| **Migrations** | Alembic |
| **Testing** | Pytest (backend), Vite (frontend build) |
| **Container** | Docker + Docker Compose (optional) |

---

## 📚 For Developers — Advanced Commands

**Run backend tests:**

```cmd
pytest
```

**Retrain the ML model** *(only if you update the dataset)*:

```cmd
python ml\training\train_models.py
```

**Evaluate model accuracy:**

```cmd
python ml\evaluation\evaluate.py
```

**Build frontend for production:**

```cmd
cd frontend
npm run build
```

---

## 🎓 Academic Project Note

PhishGuard AI is an academic **cybersecurity and machine-learning** project built for defensive analysis, demonstration, and learning purposes. It is not intended for commercial use or as a substitute for enterprise-grade security tools.

---

## 👨‍💻 Author

<table>
  <tr>
    <td align="center">
      <strong>Ch. Pabitra Kumar Nayak</strong><br/>
      <em>Developer & Project Author</em><br/>
      AI-Based Phishing &amp; Scam Detection System<br/>
      <sub>Academic Cybersecurity &amp; Machine Learning Project</sub>
    </td>
  </tr>
</table>

---

<div align="center">

**PhishGuard AI** — Built with ❤️ by **Ch. Pabitra Kumar Nayak**

*Protecting users from phishing, one scan at a time.*

</div>
