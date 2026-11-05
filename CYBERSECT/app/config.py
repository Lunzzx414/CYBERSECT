from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    API_KEY: str = Field(
        validation_alias="AIR_DS_API_KEY",
    )
    ALERT_API_URL: str = Field(
        default="http://127.0.0.1:8012/api/v1/alert",
        validation_alias="AIR_DS_ALERT_API_URL",
    )
    DATA_DIR: Path = Field(default=DEFAULT_DATA_DIR, validation_alias="AIR_DS_DATA_DIR")
    SQLITE_DATABASE_PATH: Optional[Path] = None
    GEOLITE2_CITY_DB_PATH: Optional[Path] = Field(
        default=None,
        validation_alias="AIR_DS_GEOLITE2_CITY_DB_PATH",
    )
    GEOLOCATION_PROVIDER: Literal["maxmind", "ipwhois"] = Field(
        default="maxmind",
        validation_alias="AIR_DS_GEOLOCATION_PROVIDER",
    )

settings = Settings()
