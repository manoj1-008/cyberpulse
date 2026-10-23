# CyberGuard Pulse

CyberGuard Pulse is an MVP security-posture SaaS for small teams. It includes tenant-scoped accounts, verified asset registration, passive HTTP security-header checks, TLS certificate expiry checks, evidence-backed findings, remediation status, audit events, and deployment scaffolding.

> **Security scope:** Checks are deliberately limited to HTTPS hostnames that the signed-in user has proven control over using a DNS TXT challenge. The MVP does not perform port scans, exploitation, brute force, or arbitrary-target scanning. Findings are observations, not a guarantee that an asset is secure.

## Stack
- Frontend: React + TypeScript + Vite
- API: Python + FastAPI
- Database: SQLAlchemy (SQLite for local development; PostgreSQL in production)
- Authentication: Argon2 password hashing + signed bearer tokens
- Deployment: Docker, Render blueprint, Vercel frontend configuration

## Local development

### API
```bash
cd backend
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```
Open the Vite URL shown in the terminal. Set `VITE_API_URL=http://127.0.0.1:8000`.

### Docker
```bash
docker compose up --build
```

## Upload to the supplied GitHub repository (Windows PowerShell)
1. Extract the ZIP to a folder.
2. Open PowerShell in the extracted `cyberguard-pulse` root folder.
3. Run `Set-ExecutionPolicy -Scope Process Bypass` if your current PowerShell policy blocks local scripts (this changes policy only for that shell), then run `./push-to-github.ps1`.
4. Authenticate with Git Credential Manager if prompted. The script refuses to replace an unrelated `origin` remote and embeds no access token.

The connected GitHub integration may have read-only permissions even when your personal account has push access. If direct upload from ChatGPT is blocked, this script uses your own authenticated Git client instead.

## Production deployment (manual approval required)
1. Create a private GitHub repository and push this project.
2. Deploy `backend/` as a Docker web service using `render.yaml` or a compatible host. Configure `DATABASE_URL` with a managed PostgreSQL connection URL, `JWT_SECRET` with a random secret of at least 32 bytes, and `APP_ORIGINS` with the exact deployed frontend origin. `APP_ENV=production` rejects SQLite and the development signing key.
3. Deploy `frontend/` to Vercel and set `VITE_API_URL` to the deployed API origin.
4. Set the frontend origin in `APP_ORIGINS`. Configure HTTPS and a persistent managed database.
5. Verify health endpoint, registration/login, tenant isolation, asset TXT verification, and a test HTTPS assessment before inviting customers.

Do not use SQLite on ephemeral production filesystems. Do not commit `.env` files or credentials. The current configuration is an MVP and has not been deployed or independently security-audited. The GitHub Actions workflow is included but has not run until the code is pushed.

## Asset verification
Create an asset in the app. The API gives a TXT record name/value. Add that record to the DNS zone you control and click Verify. The check is only enabled after successful DNS verification. DNS propagation can take time.

## Test
```bash
cd backend
pip install -r requirements.txt
pytest
```

## MVP limitations
- Single-password login; no email verification, password reset, MFA, billing, or SSO yet.
- No background queue or scheduled reassessment.
- Passive HTTPS checks only; redirects are disabled.
- DNS TXT verification is the authorization gate, but production use should add rate limits, abuse monitoring, an egress allowlist/denylist, and independent penetration testing.
- TLS checks use Python's standard TLS stack; results depend on the deployment environment.
