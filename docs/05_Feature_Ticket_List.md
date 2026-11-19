# Feature Ticket List — LLM-Assisted Development
## 7th Semester — Minor Project

| ID | Feature | Ready-to-Use LLM Prompt / Description |
|---|---|---|
| T001 | Repository setup | Create monorepo with frontend, backend, ml, tests and docs directories. Add README, .gitignore and .env.example. |
| T002 | React setup | Initialize React + TypeScript + Vite and create planned src directory structure. |
| T003 | FastAPI setup | Create a modular FastAPI application with /api/v1/health. |
| T004 | Database | Configure SQLAlchemy with PostgreSQL and environment-based DATABASE_URL. |
| T005 | User model | Implement User model with UUID, email uniqueness, role and active status. |
| T006 | Authentication | Implement secure password hashing, registration, login and current-user endpoint. |
| T007 | RBAC | Implement USER and ADMIN authorization dependencies with tests. |
| T008 | URL validator | Validate HTTP/HTTPS URLs, size limits and malformed inputs. |
| T009 | Feature extractor | Extract URL length, domain length, subdomains, digits, special characters, HTTPS, IP usage and suspicious keywords. |
| T010 | Dataset pipeline | Build cleaning, deduplication, label normalization and train/validation/test split without leakage. |
| T011 | Baseline ML | Train Logistic Regression and report accuracy, precision, recall, F1 and ROC-AUC. |
| T012 | Candidate ML | Train Random Forest or XGBoost and compare fairly with the baseline. |
| T013 | Model artifact | Serialize preprocessing + selected model and record version metadata. |
| T014 | Rule engine | Create configurable URL security rules that return structured evidence. |
| T015 | Risk engine | Combine ML probability and rule evidence into a 0–100 score and classification. |
| T016 | Explanation | Generate human-readable reasons from structured evidence without claiming certainty. |
| T017 | Scan model | Create Scan and DetectionReason models with ownership relationships. |
| T018 | Scan API | Implement POST /api/v1/scans for validation, inference, scoring and persistence. |
| T019 | History API | Implement paginated GET /api/v1/scans with ownership enforcement. |
| T020 | Frontend design system | Create shared design tokens and reusable UI primitives. |
| T021 | Landing page | Build responsive landing page and URL scan entry. |
| T022 | Scan result | Build result screen for risk score, class, reasons and recommendation. |
| T023 | Dashboard | Build authenticated dashboard with counts and recent scans. |
| T024 | History UI | Build paginated scan history and scan-detail navigation. |
| T025 | Admin UI | Build basic admin statistics and user-management views. |
| T026 | Rate limiting | Add configurable rate limiting to login and scan endpoints. |
| T027 | Security hardening | Add CORS allowlist, secure headers, validation, generic errors and safe logging. |
| T028 | Tests | Add backend unit/integration tests and frontend tests for critical flows. |
| T029 | Docker | Create development Docker Compose for frontend/backend/database. |
| T030 | Final QA | Run functional, ML and security checklists; fix defects and prepare minor demonstration. |
