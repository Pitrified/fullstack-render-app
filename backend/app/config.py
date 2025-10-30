"""
Environment configuration management for secure logging
"""

import os
from typing import List, Optional

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class AppConfig:
    """Centralized application configuration with environment detection"""

    def __init__(self):
        self.environment = os.getenv("ENVIRONMENT", "production").lower()
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.database_url = os.getenv("DATABASE_URL")
        self.session_secret = os.getenv("SESSION_SECRET")

        # Normalize database URL for async usage
        if self.database_url and self.database_url.startswith("postgresql://"):
            self.database_url = self.database_url.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            )

    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.environment in ["development", "dev"]

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.environment not in ["development", "dev", "test", "testing"]

    def is_testing(self) -> bool:
        """Check if running in test environment"""
        return self.environment in ["test", "testing"]

    def get_safe_database_info(self) -> str:
        """Get safe database connection information for logging"""
        if not self.database_url:
            return "No database URL configured"

        try:
            import re

            # Extract safe connection info without credentials
            pattern = r"postgresql\+?[^:]*://([^:]+):[^@]+@([^/]+)/(\w+)"
            match = re.match(pattern, self.database_url, re.IGNORECASE)
            if match:
                user, host, database = match.groups()
                return f"Database: {database} | Host: {host} | User: {user}"
            else:
                return "Database connection configured"
        except Exception:
            return "Database connection configured"

    def validate_production_config(self) -> List[str]:
        """Validate that production configuration is complete and secure"""
        errors = []

        if self.is_production():
            # Check required environment variables
            if not self.database_url:
                errors.append("DATABASE_URL not configured for production")

            if not self.session_secret:
                errors.append("SESSION_SECRET not configured for production")

            # Check for insecure configurations
            if self.log_level == "DEBUG":
                errors.append("DEBUG logging should not be enabled in production")

            # Validate database URL format
            if self.database_url and not self.database_url.startswith(
                ("postgresql", "sqlite")
            ):
                errors.append("Invalid database URL format")

        return errors

    def get_logging_config(self) -> dict:
        """Get environment-specific logging configuration"""
        if self.is_development():
            return {
                "level": "DEBUG",
                "database_echo": True,
                "show_connection_details": True,
                "redaction_enabled": False,
                "format": "detailed",
            }
        elif self.is_testing():
            return {
                "level": "WARNING",
                "database_echo": False,
                "show_connection_details": False,
                "redaction_enabled": True,
                "format": "simple",
            }
        else:  # production
            return {
                "level": self.log_level,
                "database_echo": False,
                "show_connection_details": False,
                "redaction_enabled": True,
                "format": "structured",
            }


# Global configuration instance
_app_config: Optional[AppConfig] = None


def get_app_config() -> AppConfig:
    """Get the global application configuration instance"""
    global _app_config
    if _app_config is None:
        _app_config = AppConfig()
    return _app_config
