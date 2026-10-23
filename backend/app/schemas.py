from pydantic import BaseModel, EmailStr, Field, ConfigDict

class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AssetCreate(BaseModel):
    hostname: str = Field(min_length=3, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")

class AssetOut(BaseModel):
    id: int
    hostname: str
    verified: bool
    verification_name: str
    verification_value: str
    model_config = ConfigDict(from_attributes=True)

class FindingOut(BaseModel):
    id: int
    asset_id: int
    title: str
    severity: str
    status: str
    evidence: str
    recommendation: str
    observed_at: str

class StatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|resolved)$")
