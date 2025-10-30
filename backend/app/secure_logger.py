"""
Secure logging infrastructure with environment detection and redaction capabilities
"""

import logging
import os
import re
from typing import Dict, List, Optional


class SecureFormatter(logging.Formatter):
    """Custom formatter that redacts sensitive information"""

    def __init__(self, fmt=None, datefmt=None, redaction_patterns=None):
        super().__init__(fmt, datefmt)
        self.redaction_patterns = redaction_patterns or {}
        # Compile patterns for better performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.redaction_patterns.items()
        }

    def format(self, record):
        """Format the log record with sensitive data redaction"""
        # Get the original formatted message
        original_message = super().format(record)

        # Apply redaction patterns
        return self.redact_patterns(original_message)

    def redact_patterns(self, message: str) -> str:
        """Apply redaction patterns to a message"""
        try:
            for pattern_name, compiled_pattern in self.compiled_patterns.items():
                if pattern_name == "database_url":
                    # Special handling for database URLs to preserve useful info
                    message = compiled_pattern.sub(
                        lambda m: self._redact_database_url(m.group(0)), message
                    )
                else:
                    # Generic redaction for other patterns
                    message = compiled_pattern.sub("***", message)
            return message
        except Exception:
            # If redaction fails, return safe default
            return "[REDACTED - PROCESSING ERROR]"

    def _redact_database_url(self, url: str) -> str:
        """Redact database URL while preserving useful connection info"""
        try:
            # Pattern: postgresql://user:password@host:port/database
            pattern = r"postgresql\+?[^:]*://([^:]+):([^@]+)@([^/]+)/(\w+)"
            match = re.match(pattern, url, re.IGNORECASE)
            if match:
                user, password, host, database = match.groups()
                return f"postgresql://{user}:***@{host}/{database}"
            else:
                # Fallback for other database URL formats
                return re.sub(r"://[^:]+:[^@]+@", "://***:***@", url)
        except Exception:
            return "postgresql://***:***@***/***"


class SensitiveDataFilter(logging.Filter):
    """Logging filter that automatically redacts sensitive information"""

    def __init__(self, redaction_patterns: Dict[str, str]):
        super().__init__()
        self.redaction_patterns = redaction_patterns
        # Compile patterns for better performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in redaction_patterns.items()
        }

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log record by redacting sensitive information"""
        # Create a copy of the record to avoid modifying the original
        if hasattr(record, "msg") and record.msg:
            record.msg = self.redact_patterns(str(record.msg))

        # Also redact args if present
        if hasattr(record, "args") and record.args:
            redacted_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    redacted_args.append(self.redact_patterns(arg))
                else:
                    redacted_args.append(arg)
            record.args = tuple(redacted_args)

        return True

    def redact_patterns(self, message: str) -> str:
        """Apply redaction patterns to a message"""
        try:
            for pattern_name, compiled_pattern in self.compiled_patterns.items():
                if pattern_name == "database_url":
                    # Special handling for database URLs to preserve useful info
                    message = compiled_pattern.sub(
                        lambda m: self._redact_database_url(m.group(0)), message
                    )
                else:
                    # Generic redaction for other patterns
                    message = compiled_pattern.sub("***", message)
            return message
        except Exception:
            # If redaction fails, return safe default
            return "[REDACTED - PROCESSING ERROR]"

    def _redact_database_url(self, url: str) -> str:
        """Redact database URL while preserving useful connection info"""
        try:
            # Pattern: postgresql://user:password@host:port/database
            pattern = r"postgresql\+?[^:]*://([^:]+):([^@]+)@([^/]+)/(\w+)"
            match = re.match(pattern, url, re.IGNORECASE)
            if match:
                user, password, host, database = match.groups()
                return f"postgresql://{user}:***@{host}/{database}"
            else:
                # Fallback for other database URL formats
                return re.sub(r"://[^:]+:[^@]+@", "://***:***@", url)
        except Exception:
            return "postgresql://***:***@***/***"


class SecureLoggerManager:
    """Central logging manager with environment-aware security filtering"""

    # Comprehensive redaction patterns for sensitive information
    SENSITIVE_PATTERNS = {
        "database_url": r"postgresql\+?[^:]*://[^:]+:[^@]+@[^/]+/\w+",
        "password": r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        "token": r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        "bearer_token": r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "secret": r'secret["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        "key": r'key["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        "api_key": r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        "session_id": r'session[_-]?id["\']?\s*[:=]\s*["\']?[^"\'\s]{16,}',
        "jwt": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email_in_url": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    }

    def __init__(self, environment: Optional[str] = None):
        """Initialize secure logger manager with environment detection"""
        self.environment = environment or os.getenv("ENVIRONMENT", "production").lower()
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self._loggers: Dict[str, logging.Logger] = {}
        self._filter = None
        self._formatter = None

        # Initialize redaction components for production environments
        if self.is_production():
            self._filter = SensitiveDataFilter(self.SENSITIVE_PATTERNS)
            self._formatter = SecureFormatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                redaction_patterns=self.SENSITIVE_PATTERNS,
            )

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.environment not in ["development", "dev", "test", "testing"]

    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.environment in ["development", "dev"]

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with secure configuration"""
        if name in self._loggers:
            return self._loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, self.log_level, logging.INFO))

        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        # Create new handler with appropriate configuration
        handler = logging.StreamHandler()

        # Set formatter based on environment
        if self.is_production() and self._formatter:
            # Use secure formatter for production
            handler.setFormatter(self._formatter)
        else:
            # Use standard formatter for development
            if self.is_development():
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
                )
            else:
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            handler.setFormatter(formatter)

        # Add sensitive data filter for production (as backup)
        if self._filter:
            handler.addFilter(self._filter)

        logger.addHandler(handler)
        logger.propagate = False  # Prevent duplicate logging

        self._loggers[name] = logger
        return logger

    def configure_database_logging(self, engine) -> None:
        """Configure database engine logging with security considerations"""
        if hasattr(engine, "echo"):
            # Only enable SQL echo in development
            engine.echo = self.is_development()

        # Configure SQLAlchemy loggers
        sqlalchemy_logger = self.get_logger("sqlalchemy.engine")
        sqlalchemy_pool_logger = self.get_logger("sqlalchemy.pool")

        if self.is_production():
            # Reduce SQLAlchemy logging in production
            sqlalchemy_logger.setLevel(logging.WARNING)
            sqlalchemy_pool_logger.setLevel(logging.WARNING)
        else:
            # Allow detailed logging in development
            sqlalchemy_logger.setLevel(logging.INFO)
            sqlalchemy_pool_logger.setLevel(logging.INFO)

    def redact_sensitive_info(self, message: str) -> str:
        """Manually redact sensitive information from a message"""
        if self._formatter:
            return self._formatter.redact_patterns(message)
        elif self._filter:
            return self._filter.redact_patterns(message)
        return message

    def get_safe_database_info(self, database_url: str) -> str:
        """Get safe database connection information for logging"""
        if not database_url:
            return "No database URL configured"

        try:
            # Extract safe connection info
            pattern = r"postgresql\+?[^:]*://([^:]+):[^@]+@([^/]+)/(\w+)"
            match = re.match(pattern, database_url, re.IGNORECASE)
            if match:
                user, host, database = match.groups()
                return f"Database: {database} | Host: {host} | User: {user}"
            else:
                return "Database connection configured"
        except Exception:
            return "Database connection configured"

    def validate_production_config(self) -> List[str]:
        """Validate that production configuration is secure"""
        errors = []

        if self.is_production():
            # Check required environment variables
            required_vars = ["DATABASE_URL", "SESSION_SECRET"]
            for var in required_vars:
                if not os.getenv(var):
                    errors.append(f"{var} not configured for production")

            # Check that sensitive info isn't in plain text logs
            if self.log_level == "DEBUG":
                errors.append("DEBUG logging enabled in production")

            # Verify redaction is enabled
            if not self._filter and not self._formatter:
                errors.append("Sensitive data redaction not enabled")

        return errors


# Global instance for easy access
_secure_logger_manager: Optional[SecureLoggerManager] = None


def get_secure_logger_manager() -> SecureLoggerManager:
    """Get the global secure logger manager instance"""
    global _secure_logger_manager
    if _secure_logger_manager is None:
        _secure_logger_manager = SecureLoggerManager()
    return _secure_logger_manager


def get_secure_logger(name: str) -> logging.Logger:
    """Convenience function to get a secure logger"""
    return get_secure_logger_manager().get_logger(name)
