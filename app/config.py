from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")

    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY")
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")

    request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "12"))


settings = Settings()