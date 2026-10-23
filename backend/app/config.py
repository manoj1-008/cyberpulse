from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./cyberguard.db"
    jwt_secret: str = "development-only-change-this-secret-before-deploying"
    app_origins: str = "http://localhost:5173"
    token_ttl_minutes: int = 720
    app_env: str = "development"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

if settings.app_env.lower() == "production":
    if len(settings.jwt_secret.encode("utf-8")) < 32 or settings.jwt_secret.startswith("development-only"):
        raise RuntimeError("JWT_SECRET must be a random secret of at least 32 bytes in production.")
    if settings.database_url.startswith("sqlite"):
        raise RuntimeError("Production must use a managed PostgreSQL database, not SQLite.")
