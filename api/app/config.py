import os
from typing import List


class Settings:
    def __init__(self) -> None:
        self.environment = os.getenv("ENV", "development")

        # Auth
        self.guardian_api_key = os.getenv("GUARDIAN_API_KEY", "")
        self.guardian_api_keys = self._split_env_list(os.getenv("GUARDIAN_API_KEYS", ""))

        # Gemini
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

        # Supabase
        self.supabase_url = os.getenv("SUPABASE_URL", "")
        self.supabase_anon_key = os.getenv("SUPABASE_ANON_KEY", "")
        self.supabase_service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    @staticmethod
    def _split_env_list(value: str) -> List[str]:
        return [v for v in value.split(",") if v]


settings = Settings()


