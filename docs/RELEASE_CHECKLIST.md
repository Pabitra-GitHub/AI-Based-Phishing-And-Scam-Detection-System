# PhishGuard AI - Production Release Checklist & Runbook

This document outlines the standard verification gates, rollback plans, and deployment procedures for PhishGuard AI.

---

## 1. Pre-Release Verification Gates

- [x] **Model & Dataset Integrity**: Model `v2.0.0` evaluated on held-out test set (`phishing_dataset_v2.csv`) with zero domain leakage.
- [x] **Test Suite**: 100% of test suites pass (`pytest backend/tests/ -v`).
- [x] **Type Safety**: TypeScript check passes with zero errors (`tsc --noEmit`).
- [x] **Production Bundle**: Frontend bundle builds cleanly (`npm run build`).
- [x] **SSRF Hardening**: Rebinding, IMDS (`169.254.169.254`), loopback, and obfuscated numeric notation blocked.
- [x] **Guest Isolation**: Unauthenticated requests without session token receive empty lists; cross-tenant scan deletion rejected.

---

## 2. Environment Configuration

- **`APP_ENV`**: Set to `"production"` in live deployments.
- **`JWT_SECRET_KEY`**: Must be rotated and set to a high-entropy secret (default dev secrets rejected in production).
- **`DATABASE_URL`**: SQLite for local desktop single-user (`sqlite:///./app.db`) or PostgreSQL for multi-tenant deployment.

---

## 3. Database Migration & Rollback

### Apply Migrations
```bash
alembic upgrade head
```

### Rollback (One Revision)
```bash
alembic downgrade -1
```

---

## 4. Service Health & Diagnostics

- **Health Endpoint**: `GET /api/v1/health`
- **Expected Status**: `HTTP 200 OK` with `status: "healthy"`
- **Monitored Subsystems**:
  - `database`: Connectivity to SQLite/PostgreSQL
  - `machine_learning`: Loaded model version and feature schema
  - `threat_intelligence`: Active feeds and TTL cache status

---

## 5. Startup & Shutdown Operations

### Windows (Desktop)
- **Start**: Double-click `start_app.bat`
- **Stop**: Double-click `stop_app.bat`

### Linux / Headless Server
- **Start Backend**: `uvicorn backend.app.main:app --host 0.0.0.0 --port 8000`
- **Build Frontend**: `npm run build` (served via Nginx or static file server)
