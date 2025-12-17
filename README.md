# Secure REST API (FastAPI)

Security-focused REST API built with FastAPI and SQLAlchemy, demonstrating authentication, authorization, and defensive controls against common web threats.

## Features
- JWT-based authentication
- Role-Based Access Control (RBAC)
- Admin-only endpoints
- Audit logging (JSONL)
- Brute-force protection:
  - IP-based rate limiting
  - Per-user account lockout
- Secure password hashing (Argon2)
- Automated tests (pytest)

## Tech stack used
- FastAPI
- SQLAlchemy + SQLite
- JWT (python-jose)
- Argon2 (password hashing)
- Pytest

## Endpoints
- `POST /auth/register`
- `POST /auth/login`
- `GET /users/me`
- `GET /admin/users` (admin only)
- `GET /health`

## Security notes
- Login responses do not disclose account existence
- Failed authentication attempts are rate-limited and audited
- Repeated failures trigger temporary account lockout
- Admin actions are logged for traceability

## Tests
```bash
pytest -q
```
## Threat model

- Credential stuffing → rate limiting + lockout

- Privilege escalation → RBAC

- Token forgery → signed JWTs

- Insider misuse → audit logging
