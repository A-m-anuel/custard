# Security policy

## Reporting a vulnerability

Please do not open a public issue. Report vulnerabilities privately through
[GitHub security advisories](https://github.com/A-m-anuel/custard/security/advisories/new).
You will get an acknowledgement within five working days.

## Deployment checklist

- Set a long random `CUSTARD_SECRET_KEY`; keep `CUSTARD_DEBUG` off.
- Serve over HTTPS behind a reverse proxy; set `CUSTARD_BEHIND_TLS_PROXY=true` and `CUSTARD_ALLOWED_HOSTS`.
- Use PostgreSQL; back up the database **and** `CUSTARD_PRIVATE_STORAGE_ROOT` (generated reports).
- Move the admin site with `CUSTARD_ADMIN_URL` and restrict it at the proxy if possible.
- Give users the least-privileged role; review API tokens and the audit log regularly.
- Run `python manage.py check --deploy` after configuration changes.
