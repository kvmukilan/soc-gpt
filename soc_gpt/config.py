from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ES_URL: str = "http://localhost:9200"
    ES_INDEX: str = "soc-gpt-logs"
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2:3b"
    LOG_LEVEL: str = "INFO"

settings = Settings()
