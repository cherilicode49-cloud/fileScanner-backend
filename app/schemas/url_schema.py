from pydantic import BaseModel, HttpUrl, field_validator
import re


class URLScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("URL cannot be empty")
        v = v.strip()
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")
        return v

