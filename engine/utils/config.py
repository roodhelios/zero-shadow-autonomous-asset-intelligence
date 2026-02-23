import os
from dotenv import load_dotenv

load_dotenv()

def env(key: str, default: str | None = None) -> str:
    val = os.getenv(key, default)
    if val is None:
        raise RuntimeError(f"Missing required env var: {key}")
    return val

DB = {
    "host": env("DB_HOST", "localhost"),
    "port": int(env("DB_PORT", "5432")),
    "name": env("DB_NAME", "zeroshadow"),
    "user": env("DB_USER", "zeroshadow"),
    "password": env("DB_PASSWORD", "zeroshadow"),
}