# CuSTaRD: Cyber Support Tool for Risk Decisions

[![CI](https://github.com/A-m-anuel/custard/actions/workflows/ci.yml/badge.svg)](https://github.com/A-m-anuel/custard/actions/workflows/ci.yml)

CuSTaRD replaces cyber-risk spreadsheets with a web application. It lets an organisation register its assets, score them against CIA security checklists, see the vulnerabilities and mitigations that apply to each one, and track the resulting risks to closure.

It started as my MSc dissertation at the University of Manchester (2023, supervised by Professor Daniel Dresner). This repository is a full rewrite of that prototype, built to run inside an organisation: role-based access, an audit trail, a NIST SP 800-30 risk register, PDF and CSV reporting, a read-only API, Docker deployment and an automated test suite.

![Dashboard](docs/screenshots/dashboard.png)

<details><summary>More screenshots</summary>

| Asset registration with live CIA score | Asset detail |
|---|---|
| ![Register](docs/screenshots/register.png) | ![Asset](docs/screenshots/asset.png) |
| **Risk register** | **Risk with NIST matrix and treatment plan** |
| ![Risk register](docs/screenshots/risk-register.png) | ![Risk](docs/screenshots/risk.png) |
| **Dependency map** | |
| ![Dependency map](docs/screenshots/dependency-map.png) | |

</details>

## What it does

| Area | Capability |
|------|------------|
| **Asset inventory** | Register hardware, software and information assets (29 categories shipped), with owner, location and business impact on confidentiality, integrity and availability. Bulk-import from CSV to move off spreadsheets. |
| **Security scoring** | Each category has a 10-item security checklist drawn from vendor hardening guidance, grouped by CIA pillar. Scores are calculated on the server and every assessment is kept as history. |
| **Risk mapping** | On registration, CuSTaRD maps the category's typical weaknesses, their likelihood and recommended mitigations onto the asset automatically. |
| **Risk register** | Risk = likelihood × impact per NIST SP 800-30. Risks have owners, treatments with due dates, residual risk, and formal risk acceptance with a review date. |
| **Dependency map** | Assets → weaknesses → mitigations, showing where one control removes several risks. |
| **Dashboard and reports** | Score chart, risk heat map, exposed assets, overdue treatments, expired acceptances. PDF reports, plus CSV exports of assets and the risk register. |
| **Knowledge base** | Categories, checklists, vulnerabilities and mitigations are data, not code. Analysts add custom categories in the UI. |
| **Governance** | Three roles (Administrator, Security Analyst, Viewer), an append-only audit log, sign-in throttling and a read-only token API for SIEM or GRC integration. |

## Methodology

**Security score (dissertation section 3.4.4).** Each checklist item belongs to one CIA pillar. Each pillar scores the share of its checks in place × 10, and the asset score normalises the three pillars to 0–10:

```
pillar score  = implemented checks in pillar / checks in pillar × 10
security score = (C + I + A) / 30 × 10
```

Assets scoring below **5** are *exposed* and need mitigation; the threshold is configurable. If a custom category has no checks for a pillar, that pillar is treated as not applicable and the score is the mean of the remaining pillars.

**Risk (NIST SP 800-30, 2002, section 3.7, Table 3-6).** Likelihood is set per weakness, and impact is the asset's highest CIA impact (the high-water mark):

| Likelihood \ Impact | Low (10) | Medium (50) | High (100) |
|---|---|---|---|
| **High (1.0)**   | 10 Low | 50 Medium | 100 High |
| **Medium (0.5)** | 5 Low  | 25 Medium | 50 Medium |
| **Low (0.1)**    | 1 Low  | 5 Low     | 10 Low |

The risk scale is High > 50, Medium > 10, Low ≤ 10. Each level shows the corrective action recommended in NIST Table 3-7. When every applicable treatment is implemented, the risk becomes *Mitigated* and its residual likelihood defaults to Low, which matches NIST's definition of Low ("controls are in place to prevent, or at least significantly impede" exploitation). Analysts can override this.

[docs/methodology.md](docs/methodology.md) maps every dissertation requirement to the code that implements it.

## Quick start

### Docker (PostgreSQL)

```bash
export CUSTARD_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')"
export POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
docker compose up -d --build
docker compose exec web python manage.py createsuperuser
# open http://localhost:8000
```

The container applies migrations, prepares the cache table and loads the knowledge base on every start. All three steps are safe to repeat. The compose file is set up for evaluation on `http://localhost`. For production, put a TLS reverse proxy in front and remove the two local-HTTP lines.

### Local development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env              # sets CUSTARD_DEBUG=true
python manage.py migrate
python manage.py createcachetable
python manage.py load_catalog
python manage.py createsuperuser
python manage.py seed_demo --password 'choose-a-demo-password'   # optional demo data
python manage.py runserver
```

Run the tests with `python manage.py test`, and lint with `ruff check .`.

## Configuration

All settings come from environment variables (or a local `.env`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `CUSTARD_SECRET_KEY` | (required) | Django secret key. Startup fails without it unless `CUSTARD_DEBUG=true`. |
| `CUSTARD_DEBUG` | `false` | Development mode. Never enable in production. |
| `CUSTARD_ALLOWED_HOSTS` | localhost in debug | Comma-separated host names. |
| `CUSTARD_CSRF_TRUSTED_ORIGINS` | | e.g. `https://custard.example.com` |
| `DATABASE_URL` | `sqlite:///db.sqlite3` | `postgres://user:pass@host:5432/db` recommended for production. |
| `CUSTARD_EXPOSURE_THRESHOLD` | `5.0` | Score below which an asset counts as exposed. |
| `CUSTARD_ORGANISATION_NAME` | `Your organisation` | Shown in the UI and reports. |
| `CUSTARD_PRIVATE_STORAGE_ROOT` | `./var/private` | Where generated reports are stored (never web-served). |
| `CUSTARD_ADMIN_URL` | `admin/` | Move the admin site to a less guessable path. |
| `CUSTARD_BEHIND_TLS_PROXY` | `false` | Trust `X-Forwarded-Proto` from your reverse proxy. |
| `CUSTARD_TRUST_X_FORWARDED_FOR` | `false` | Use `X-Forwarded-For` for audit IPs and throttling (trusted proxy only). |
| `CUSTARD_LOGIN_MAX_ATTEMPTS` / `CUSTARD_LOGIN_LOCKOUT_SECONDS` | `5` / `900` | Failed sign-in lockout per username and IP. |
| `CUSTARD_SESSION_AGE_SECONDS` | `28800` | Session lifetime (8 hours). |
| `CUSTARD_HSTS_SECONDS`, `CUSTARD_SSL_REDIRECT` | 1 year, `true` | HTTPS enforcement when DEBUG is off. |
| `CUSTARD_TIME_ZONE` | `Europe/London` | Display time zone. |

## Roles

Assign users to a group in the admin site. The groups are created and kept in sync on every `migrate` (or with `manage.py sync_roles`).

| Capability | Viewer | Security Analyst | Administrator |
|------------|:-:|:-:|:-:|
| View dashboard, assets, risks, dependency map, reports | ✓ | ✓ | ✓ |
| Download reports and CSV exports | ✓ | ✓ | ✓ |
| Register, edit, assess and import assets | | ✓ | ✓ |
| Manage risks and treatments | | ✓ | ✓ |
| Add categories, checklist items and risk mappings | | ✓ | ✓ |
| Generate reports | | ✓ | ✓ |
| Formally accept risks | | | ✓ |
| Audit log, users, admin site, delete records | | | ✓ |

## API

Read-only JSON at `/api/v1/` (`summary/`, `assets/`, `assets/<id>/`, `risks/`), paginated with `limit` and `offset`. Authenticate with a browser session or a token:

```bash
python manage.py create_api_token analyst "SIEM integration" --days 90
curl -H "Authorization: Bearer cst_…" https://custard.example.com/api/v1/risks/?level=HIGH
```

Only a SHA-256 hash of each token is stored. Tokens expire, can be revoked in the admin site, and carry their user's permissions.

## Security design

- **Server-side scoring:** the score is never trusted from the browser.
- **Access control:** every application page requires authentication and a model permission (only sign-in and `/healthz` are public).
- **Strict security headers:** Content-Security-Policy with `script-src 'self'` and no inline code, `nosniff`, `X-Frame-Options: DENY`, HSTS, secure cookies and `Cache-Control: no-store` on authenticated pages.
- **Private reports:** reports are stored outside web-served directories and downloaded through a permission-checked view.
- **Brute-force protection:** sign-in throttling, a 12-character minimum password, and POST-only logout.
- **Audit trail:** an append-only log of sign-ins, changes, assessments, risk acceptances, exports and report generation.
- **Safe exports:** CSV exports are protected against spreadsheet formula injection, and all text in the PDF and SVG output is escaped.
- **Minimal dependencies:** no third-party JavaScript and no CDN. Charts and the dependency map are rendered on the server as SVG.
- **CI checks:** CI runs `pip-audit`, `bandit`, `ruff`, `check --deploy` and tests against Django 4.2 and 5.2 on SQLite and PostgreSQL. Dependabot keeps dependencies current.

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Changes from the 2023 prototype

The rewrite keeps the prototype's research content: all 290 checklist items, 116 category risk mappings and 268 mitigations, migrated into `custard/catalog/data/catalog.json`. It fixes the following:

| Prototype issue | Fix |
|-----------------|-----|
| Report download (`/protected_media/<path>`) had no authentication and allowed path traversal | Removed; reports are private and permission-checked |
| Asset list, dashboard, dependency view and report generation had no login check | Every view requires login and a role permission |
| Score was sent by the browser and stored as-is; the stored formula (checked/total) differed from the dissertation's (C+I+A)/30×10 | Dissertation formula, computed on the server |
| Opening the dependency page inserted duplicate vulnerability and treatment rows each time | Risks and treatments are persistent records created once |
| "Firewall" vs "Firewalls" naming mismatch meant firewalls never received risks | Single normalised catalog |
| Comma-splitting broke "Secure protocols (e.g., SSH, SFTP)" into three items | Structured data |
| Users could not add asset categories (dissertation test case 6 failed) | Custom categories with their own checklists and risk mappings |
| Hard-coded secret key and debug defaults; `requirements.txt` was a global `pip freeze` | Environment-driven settings, minimal pinned dependencies |
| GoJS (commercial licence) and Chart.js loaded from CDNs | Server-rendered SVG |

## Limitations and roadmap

- **Not yet automated:** likelihoods and mitigations come from the curated knowledge base. They are not yet updated from live threat-intelligence or CVE feeds (dissertation future work).
- **Framework mappings left empty:** ISO/IEC 27001 and CIS references have fields on checklist items, mitigations and vulnerabilities but are not pre-populated. Mapping them is a review task for each organisation.
- **Single tenancy:** one organisation per deployment.
- **Planned:** SSO (OIDC/SAML), threat-feed integration, ML-assisted categorisation and predictive risk analysis, and IoT asset coverage, as proposed in dissertation section 6.2.

## Citation

> Seid, A. A. (2023). *CuSTaRD – A Cyber Support Tool for Risk Decisions*. MSc dissertation, University of Manchester.

See [CITATION.cff](CITATION.cff). Licensed under the MIT License.
