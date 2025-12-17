from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    ENV: str = Field(
        default="dev",
        validation_alias=AliasChoices("ENV", "env"),
    )

    DATABASE_URL: str = Field(
        default="sqlite:///./secure_rest_api.db",
        validation_alias=AliasChoices("DATABASE_URL", "database_url"),
    )

    CORS_ALLOW_ORIGINS: str = Field(
        default="http://localhost:3000,http://127.0.0.1:3000",
        validation_alias=AliasChoices("CORS_ALLOW_ORIGINS", "cors_allow_origins"),
    )

    SECRET_KEY: str = Field(
        default="CHANGE_ME_IN_PROD",
        validation_alias=AliasChoices("SECRET_KEY", "secret_key"),
    )

    ALGORITHM: str = Field(
        default="HS256",
        validation_alias=AliasChoices("ALGORITHM", "algorithm"),
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        validation_alias=AliasChoices("ACCESS_TOKEN_EXPIRE_MINUTES", "access_token_expire_minutes"),
    )


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()
