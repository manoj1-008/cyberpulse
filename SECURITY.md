# Security Notes

CyberGuard Pulse is an early MVP, not an independently audited production security product.

## Safe assessment boundaries
- Add only domains you own or are explicitly authorized to assess.
- The app requires a per-asset DNS TXT ownership proof before it can make an HTTPS request.
- Current checks are passive HTTPS response-header observations only; no port scanning, brute force, exploit attempts, or automated remediation is included.
- A missing header is evidence of a configuration observation, not proof that the application is exploitable.

## Required before real customer data
- Use managed PostgreSQL, a strong random `JWT_SECRET` (32+ bytes), HTTPS, and the exact frontend origin in `APP_ORIGINS`.
- Add request rate limits and abuse monitoring for registration, verification, and assessment endpoints.
- Add outbound network egress controls and DNS-pinning/rebinding mitigations before allowing external targets in production. DNS ownership verification alone is not a complete SSRF defense.
- Add email verification, secure account recovery, MFA, secret rotation, backups, and database migrations.
- Review logs and audit data for personal information, define retention, and test backup restoration.
- Run dependency scanning, a threat model, automated security tests, and an independent penetration test before charging customers.

## Reporting
Do not run assessments against third-party systems without explicit permission. Report suspected product vulnerabilities privately to the maintainer rather than publishing secrets or customer data.
