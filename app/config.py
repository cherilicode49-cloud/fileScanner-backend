import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    APP_NAME: str = "FileScanner"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api"

    # Database
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/filescanner_db"

    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    ASYNC_SCAN_ENABLED: bool = False

    # ClamAV
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310
    CLAMAV_SOCKET_TIMEOUT: int = 15
    CLAMAV_REQUIRED: bool = True

    # Limits
    MAX_FILE_SIZE_MB: int = 100
    MAX_ZIP_EXTRACT_SIZE_MB: int = 500
    MAX_ZIP_FILES: int = 1000
    MAX_NESTED_ZIP_DEPTH: int = 3

    # URL Scanner
    URL_SCAN_TIMEOUT: int = 10
    URL_MAX_REDIRECTS: int = 5
    URL_MAX_CONTENT_SIZE_MB: int = 5

    # Directories
    UPLOAD_DIRECTORY: str = "uploads"
    TEMP_DIRECTORY: str = "temp"
    REPORT_DIRECTORY: str = "reports"
    YARA_RULES_DIRECTORY: str = "yara_rules"
    LOG_DIRECTORY: str = "logs"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024

    @property
    def max_zip_extract_bytes(self) -> int:
        return self.MAX_ZIP_EXTRACT_SIZE_MB * 1024 * 1024

    @property
    def max_url_content_bytes(self) -> int:
        return self.URL_MAX_CONTENT_SIZE_MB * 1024 * 1024

    @property
    def upload_path(self) -> Path:
        p = BASE_DIR / self.UPLOAD_DIRECTORY
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def temp_path(self) -> Path:
        p = BASE_DIR / self.TEMP_DIRECTORY
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def report_path(self) -> Path:
        p = BASE_DIR / self.REPORT_DIRECTORY
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def yara_rules_path(self) -> Path:
        p = BASE_DIR / self.YARA_RULES_DIRECTORY
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def log_path(self) -> Path:
        p = BASE_DIR / self.LOG_DIRECTORY
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()

