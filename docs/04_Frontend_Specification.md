# Frontend Specification Document
## 7th Semester — Minor Project

### 1. Design System Tokens

| Token | Hex Value | Semantic Meaning |
|---|---|---|
| Primary | `#2563EB` | Actions, brand highlight |
| Primary Dark | `#1D4ED8` | Active/hover state |
| Background | `#F8FAFC` | Page canvas (light theme) |
| Surface | `#FFFFFF` | Card & modal background |
| Text | `#0F172A` | Primary typography |
| Muted | `#64748B` | Secondary details, captions |
| Border | `#E2E8F0` | Dividers & card boundaries |
| Safe | `#16A34A` | 0–29 Risk Score (Legitimate URL) |
| Suspicious | `#F59E0B` | 30–59 Risk Score (Anomalies detected) |
| High Risk | `#F97316` | 60–84 Risk Score (Likely phishing) |
| Critical | `#DC2626` | 85–100 Risk Score (Severe threat) |

---

### 2. Page Directory

- **Landing**: Introduction, trust stats, quick URL scan input, feature overview.
- **Login/Register**: User authentication with demo account quick-fill.
- **Dashboard**: High-level statistics, recent scan activity, risk breakdown chart.
- **Scan**: Interactive security scanner with instant analysis and signal breakdown.
- **Scan Detail**: In-depth inspection view (Radar breakdown, heuristic list, ML confidence, safety checklist).
- **History**: Paginated, filterable table of past scans with search and export.
- **Admin**: User management, system health, and audit trail.
- **Settings**: Profile, preferences, and API configuration.
