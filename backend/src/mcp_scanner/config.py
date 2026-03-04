from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/mcp_scanner"
    openrouter_api_key: str = ""
    openrouter_model: str = "google/gemini-3.1-pro-preview"
    llm_judge_enabled: bool = True
    scan_timeout_seconds: int = 300
    max_repo_size_mb: int = 500
    cors_origins: list[str] = ["http://localhost:5173"]
    huggingface_api_token: str = ""
    ml_classifier_enabled: bool = False
    ml_classifier_timeout: float = 15.0
    api_key: str = ""

    model_config = {"env_prefix": "MCP_SCANNER_", "env_file": ".env"}


settings = Settings()
