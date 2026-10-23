import os
os.environ["DATABASE_URL"] = "sqlite:///./test_cyberguard.db"
os.environ["JWT_SECRET"] = "test-secret-long-enough-for-unit-tests-123456"
os.environ["ASSET_VERIFICATION_SECRET"] = "test-verification-secret-long-enough-123"
os.environ["APP_ORIGINS"] = "http://localhost:5173"
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, engine, SessionLocal
from app.models import User, Asset, Finding
from sqlalchemy import select
import pytest

@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

client = TestClient(app)

def signup(email):
    return client.post("/auth/register", json={"email": email, "password": "A-strong-test-password-123"}).json()["access_token"]

def test_health():
    assert client.get("/health").json()["status"] == "ok"

def test_register_and_me():
    token = signup("one@example.org")
    r = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "one@example.org"

def test_duplicate_registration_rejected():
    signup("dupe@example.org")
    assert client.post("/auth/register", json={"email": "dupe@example.org", "password": "A-strong-test-password-123"}).status_code == 409

def test_auth_required():
    assert client.get("/assets").status_code == 401

def test_tenant_isolation_for_findings():
    token1 = signup("tenant1@example.org")
    token2 = signup("tenant2@example.org")
    h1 = {"Authorization": f"Bearer {token1}"}
    h2 = {"Authorization": f"Bearer {token2}"}
    # Seed a finding owned by tenant 1, then confirm tenant 2 cannot read or modify it.
    with SessionLocal() as db:
        user1 = db.scalar(select(User).where(User.email == "tenant1@example.org"))
        asset = Asset(owner_id=user1.id, hostname="sample-owned.example.org", verification_token="unused", verified=False)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        finding = Finding(owner_id=user1.id, asset_id=asset.id, title="Sample finding", severity="Low", evidence="Test evidence", recommendation="Test fix")
        db.add(finding)
        db.commit()
        db.refresh(finding)
        finding_id = finding.id
    assert len(client.get("/findings", headers=h1).json()) == 1
    assert client.get("/findings", headers=h2).json() == []
    assert client.patch(f"/findings/{finding_id}", json={"status":"resolved"}, headers=h2).status_code == 404
    audit2 = client.get("/audit", headers=h2).json()
    assert len(audit2) == 1
    assert audit2[0]["action"] == "account.registered"

def test_status_validation():
    token = signup("status@example.org")
    r = client.patch("/findings/999", json={"status":"pwned"}, headers={"Authorization":f"Bearer {token}"})
    assert r.status_code == 422
