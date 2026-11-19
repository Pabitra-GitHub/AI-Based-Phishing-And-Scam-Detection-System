# Technical Architecture Document
## 7th Semester — Minor Project

### 1. Architecture Goal
Build a clean three-tier application with a React client, FastAPI backend, and relational database. Keep the ML pipeline modular but local so the team can understand and demonstrate every component.

---

### 2. Recommended Tech Stack

| Layer | Technology | Reason |
|---|---|---|
| Frontend | React + TypeScript + Vite | Fast development and component reuse. |
| UI | Tailwind CSS | Consistent responsive styling. |
| Backend | Python + FastAPI | Good fit for ML integration and API development. |
| ORM | SQLAlchemy | Structured database access. |
| Database | PostgreSQL / SQLite | Robust relational database; SQLite used for local demo. |
| ML | pandas, NumPy, scikit-learn | Standard academic ML stack. |
| Testing | Pytest + frontend testing | Automated regression testing. |
| Local deployment | Docker Compose optional | Reproducible development environment. |

---

### 3. Database Schema

- **`users`**: `id`, `name`, `email`, `password_hash`, `role`, `is_active`, `created_at`
- **`scans`**: `id`, `user_id`, `input_type`, `input_value`, `risk_score`, `classification`, `ml_probability`, `model_version`, `created_at`
- **`detection_reasons`**: `id`, `scan_id`, `reason`, `severity`, `source`
- **`audit_logs`**: `id`, `user_id`, `action`, `ip_address`, `metadata`, `created_at`

---

### 4. Core APIs

- `POST /api/v1/auth/register` : Create user account
- `POST /api/v1/auth/login` : Authenticate user
- `GET /api/v1/auth/me` : Return current user
- `POST /api/v1/scans` : Analyze URL
- `GET /api/v1/scans` : List own scan history
- `GET /api/v1/scans/{id}` : View one scan
- `GET /api/v1/dashboard/summary` : Return user statistics
- `GET /api/v1/health` : Service health check
