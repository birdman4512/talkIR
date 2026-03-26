from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    es_host: str = "https://elasticsearch:9200"
    es_user: str = "elastic"
    es_password: str = ""
    es_ca_cert_path: str = "/certs/ca/ca.crt"

    ollama_host: str = "http://ollama:11434"
    ollama_model: str = "llama3.2:3b"

    anthropic_api_key: str = ""
    openai_api_key: str = ""

    jwt_secret: str = ""


settings = Settings()
