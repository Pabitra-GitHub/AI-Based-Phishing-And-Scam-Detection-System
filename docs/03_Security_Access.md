# Security & Access Document
## 7th Semester — Minor Project

### 1. Security Objective
Protect user accounts and application data while ensuring that URL analysis itself cannot become a new attack surface. The minor focuses on authentication, ownership, validation, rate limiting, safe error handling, and auditability.

---

### 2. Authentication & Roles
- Register with email and password.
- Hash passwords securely with PBKDF2/Bcrypt/Argon2 with individual salt.
- Short-lived JWT Bearer access token for protected API calls.
- Roles:
  - **USER**: Create scans, view/delete own history, view own dashboard, update profile.
  - **ADMIN**: User management, global scan statistics, audit review, model reload & system metrics.

---

### 3. API Security & URL Safety
- Validate request bodies using typed schemas (Pydantic v2).
- Restrict CORS to approved origins (`http://localhost:5173`).
- Apply rate limiting to login and scan endpoints.
- Generic error codes and generic authentication failure messages (prevent username enumeration / timing attacks).
- SSRF protections on URL inputs; static analysis is prioritized.
- Audit logging for administrative events, authentication, and security triggers.
