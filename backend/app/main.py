import hashlib, secrets, socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import dns.resolver
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select
from .config import settings
from .db import Base, engine, get_db
from .models import User, Asset, Finding, AuditEvent
from .schemas import Credentials, TokenResponse, AssetCreate, StatusUpdate
from .security import hash_password, verify_password, make_token, current_user
from .checks import check_https_asset

Base.metadata.create_all(bind=engine)
app = FastAPI(title="CyberGuard Pulse API", version="0.1.0", description="Tenant-scoped security posture MVP. Assess only assets you own or are authorized to assess.")
origins = [x.strip() for x in settings.app_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET","POST","PATCH","DELETE"], allow_headers=["Authorization","Content-Type"])

def audit(db, user, action, detail=""):
    db.add(AuditEvent(owner_id=user.id, action=action, detail=detail[:500]))
    db.commit()

def validate_hostname(hostname: str):
    hostname = hostname.lower().rstrip(".")
    if len(hostname) > 253 or "." not in hostname or hostname in {"localhost", "example.com", "test"}:
        raise HTTPException(status_code=422, detail="Enter a public fully qualified domain name you control.")
    if hostname.replace(".", "").isdigit():
        raise HTTPException(status_code=422, detail="IP addresses are not supported; use a verified hostname.")
    try:
        labels = hostname.split(".")
        if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
            raise ValueError()
        # Resolve and reject private, loopback, link-local, multicast, and reserved addresses.
        import ipaddress
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        ips = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not ips or any(not ip.is_global for ip in ips):
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=422, detail="Hostname must resolve publicly; private and reserved destinations are blocked.")
    return hostname

@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberguard-pulse-api", "mode": "mvp"}

@app.post("/auth/register", response_model=TokenResponse, status_code=201)
def register(data: Credentials, db: Session = Depends(get_db)):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = User(email=email, password_hash=hash_password(data.password))
    db.add(user); db.commit(); db.refresh(user)
    audit(db, user, "account.registered")
    return {"access_token": make_token(user.id)}

@app.post("/auth/login", response_model=TokenResponse)
def login(data: Credentials, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return {"access_token": make_token(user.id)}

@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at.isoformat()}

@app.get("/assets")
def list_assets(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(Asset).where(Asset.owner_id == user.id).order_by(Asset.id.desc())).all()
    return [{"id": a.id, "hostname": a.hostname, "verified": a.verified, "created_at": a.created_at.isoformat()} for a in rows]

@app.post("/assets", status_code=201)
def create_asset(data: AssetCreate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    hostname = validate_hostname(data.hostname)
    existing = db.scalar(select(Asset).where(Asset.owner_id == user.id, Asset.hostname == hostname))
    if existing:
        raise HTTPException(status_code=409, detail="This hostname is already registered in your workspace.")
    token = secrets.token_urlsafe(24)
    asset = Asset(owner_id=user.id, hostname=hostname, verification_token=token)
    db.add(asset); db.commit(); db.refresh(asset)
    audit(db, user, "asset.created", hostname)
    return {"id": asset.id, "hostname": asset.hostname, "verified": False, "verification_name": f"_cyberguard-verification.{hostname}", "verification_value": f"cyberguard-pulse={token}"}

@app.post("/assets/{asset_id}/verify")
def verify_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    asset = db.scalar(select(Asset).where(Asset.id == asset_id, Asset.owner_id == user.id))
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    try:
        answers = dns.resolver.resolve(f"_cyberguard-verification.{asset.hostname}", "TXT", lifetime=5)
        expected = f"cyberguard-pulse={asset.verification_token}"
        found = any(expected in "".join(part.decode() if isinstance(part, bytes) else str(part) for part in r.strings) for r in answers)
    except Exception:
        found = False
    if not found:
        raise HTTPException(status_code=400, detail="Verification TXT record not found. Check the DNS record and retry.")
    asset.verified = True
    db.commit()
    audit(db, user, "asset.verified", asset.hostname)
    return {"verified": True, "hostname": asset.hostname}

@app.post("/assets/{asset_id}/assess")
def assess_asset(asset_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    asset = db.scalar(select(Asset).where(Asset.id == asset_id, Asset.owner_id == user.id))
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found.")
    if not asset.verified:
        raise HTTPException(status_code=403, detail="Complete DNS ownership verification before assessment.")
    # Revalidate DNS immediately before outbound connection to reduce rebinding risk.
    validate_hostname(asset.hostname)
    observations = check_https_asset(asset.hostname)
    created = []
    for item in observations:
        finding = Finding(owner_id=user.id, asset_id=asset.id, title=item["title"], severity=item["severity"], evidence=item["evidence"], recommendation=item["recommendation"])
        db.add(finding); created.append(finding)
    asset.last_checked_at = datetime.now(timezone.utc)
    db.commit()
    for finding in created: db.refresh(finding)
    audit(db, user, "asset.assessed", f"{asset.hostname}; findings={len(created)}")
    return {"hostname": asset.hostname, "checked_at": asset.last_checked_at.isoformat(), "findings_created": len(created), "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in created], "scope": "Passive HTTPS response-header checks only; no port scanning or exploitation."}

@app.get("/findings")
def list_findings(db: Session = Depends(get_db), user: User = Depends(current_user), status: str | None = None):
    query = select(Finding).where(Finding.owner_id == user.id).order_by(Finding.observed_at.desc())
    if status in {"open","in_progress","resolved"}:
        query = query.where(Finding.status == status)
    rows = db.scalars(query).all()
    return [{"id": f.id, "asset_id": f.asset_id, "title": f.title, "severity": f.severity, "status": f.status, "evidence": f.evidence, "recommendation": f.recommendation, "observed_at": f.observed_at.isoformat()} for f in rows]

@app.patch("/findings/{finding_id}")
def update_finding(finding_id: int, data: StatusUpdate, db: Session = Depends(get_db), user: User = Depends(current_user)):
    finding = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.owner_id == user.id))
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding.status = data.status
    db.commit()
    audit(db, user, "finding.status_changed", f"finding={finding_id}; status={data.status}")
    return {"id": finding.id, "status": finding.status}

@app.get("/audit")
def audit_log(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.scalars(select(AuditEvent).where(AuditEvent.owner_id == user.id).order_by(AuditEvent.created_at.desc()).limit(100)).all()
    return [{"id": e.id, "action": e.action, "detail": e.detail, "created_at": e.created_at.isoformat()} for e in rows]
