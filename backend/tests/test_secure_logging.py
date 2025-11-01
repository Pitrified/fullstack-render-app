"""
Comprehensive unit tests for secure logging infrastructure
"""

import logging
import os
import re
from unittest.mock import MagicMock, patch

import pytest
from app.config import AppConfig, get_app_config
from app.secure_logger import (
    SecureFormatter,
    SecureLoggerManager,
    SensitiveDataFilter,
    get_secure_logger,
    get_secure_logger_manager,
)


class TestSecureLoggerManager:
    """Test SecureLoggerManager redaction patterns and environment detection"""

    def test_environment_detection_production(self):
        """Test production environment detection"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            assert manager.is_production() is True
            assert manager.is_development() is False

    def test_environment_detection_development(self):
        """Test development environment detection"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            manager = SecureLoggerManager("development")
            assert manager.is_production() is False
            assert manager.is_development() is True

    def test_environment_detection_default_production(self):
        """Test that default environment is production"""
        manager = SecureLoggerManager()
        # Should default to production for security
        assert manager.is_production() is True

    def test_redaction_patterns_database_url(self):
        """Test database URL redaction patterns"""
        manager = SecureLoggerManager("production")

        # Test standard PostgreSQL URL
        message = "Connecting to postgresql://user:secret123@localhost:5432/mydb"
        redacted = manager.redact_sensitive_info(message)
        assert "secret123" not in redacted
        assert "postgresql://user:***@localhost:5432/mydb" in redacted

    def test_redaction_patterns_bearer_token(self):
        """Test bearer token redaction"""
        manager = SecureLoggerManager("production")

        message = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
        )
        redacted = manager.redact_sensitive_info(message)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature" not in redacted
        assert "***" in redacted

    def test_redaction_patterns_password(self):
        """Test password redaction patterns"""
        manager = SecureLoggerManager("production")

        test_cases = [
            'password="secret123"',
            "password: secret123",
            "password=secret123",
            'password: "secret123"',
        ]

        for test_case in test_cases:
            redacted = manager.redact_sensitive_info(test_case)
            assert "secret123" not in redacted
            assert "***" in redacted

    def test_redaction_patterns_api_key(self):
        """Test API key redaction patterns"""
        manager = SecureLoggerManager("production")

        test_cases = [
            "api_key=abc123def456",
            "api-key: abc123def456",
            'apikey="abc123def456"',
        ]

        for test_case in test_cases:
            redacted = manager.redact_sensitive_info(test_case)
            assert "abc123def456" not in redacted
            assert "***" in redacted

    def test_redaction_patterns_jwt_token(self):
        """Test JWT token redaction"""
        manager = SecureLoggerManager("production")

        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        message = f"Token: {jwt_token}"
        redacted = manager.redact_sensitive_info(message)
        assert jwt_token not in redacted
        assert "***" in redacted

    def test_redaction_patterns_credit_card(self):
        """Test credit card number redaction"""
        manager = SecureLoggerManager("production")

        test_cases = [
            "4532 1234 5678 9012",
            "4532-1234-5678-9012",
            "4532123456789012",
        ]

        for test_case in test_cases:
            message = f"Payment card: {test_case}"
            redacted = manager.redact_sensitive_info(message)
            assert test_case not in redacted
            assert "***" in redacted

    def test_redaction_patterns_ssn(self):
        """Test SSN redaction"""
        manager = SecureLoggerManager("production")

        message = "SSN: 123-45-6789"
        redacted = manager.redact_sensitive_info(message)
        assert "123-45-6789" not in redacted
        assert "***" in redacted

    def test_no_redaction_in_development(self):
        """Test that redaction is disabled in development"""
        manager = SecureLoggerManager("development")

        message = "Database: postgresql://user:secret@localhost/db"
        # In development, no redaction should occur
        result = manager.redact_sensitive_info(message)
        # Since no formatter/filter is set in development, message should be unchanged
        assert result == message

    def test_logger_creation_and_configuration(self):
        """Test logger creation with proper configuration"""
        manager = SecureLoggerManager("production")
        logger = manager.get_logger("test_logger")

        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger"
        assert len(logger.handlers) > 0
        assert logger.propagate is False

    def test_logger_caching(self):
        """Test that loggers are cached and reused"""
        manager = SecureLoggerManager("production")
        logger1 = manager.get_logger("test_logger")
        logger2 = manager.get_logger("test_logger")

        assert logger1 is logger2

    def test_database_logging_configuration(self):
        """Test database logging configuration"""
        manager = SecureLoggerManager("production")

        # Mock engine
        mock_engine = MagicMock()
        mock_engine.echo = True

        manager.configure_database_logging(mock_engine)

        # In production, echo should be disabled
        assert mock_engine.echo is False

    def test_database_logging_configuration_development(self):
        """Test database logging configuration in development"""
        manager = SecureLoggerManager("development")

        # Mock engine
        mock_engine = MagicMock()
        mock_engine.echo = False

        manager.configure_database_logging(mock_engine)

        # In development, echo should be enabled
        assert mock_engine.echo is True

    def test_safe_database_info_extraction(self):
        """Test safe database info extraction"""
        manager = SecureLoggerManager("production")

        database_url = "postgresql://user:secret@localhost:5432/mydb"
        safe_info = manager.get_safe_database_info(database_url)

        assert "secret" not in safe_info
        assert "user" in safe_info
        assert "localhost" in safe_info
        assert "mydb" in safe_info

    def test_production_config_validation(self):
        """Test production configuration validation"""
        manager = SecureLoggerManager("production")

        with patch.dict(os.environ, {"DATABASE_URL": "", "SESSION_SECRET": ""}):
            errors = manager.validate_production_config()
            assert len(errors) > 0
            assert any("DATABASE_URL" in error for error in errors)
            assert any("SESSION_SECRET" in error for error in errors)

    def test_production_config_validation_debug_logging(self):
        """Test that DEBUG logging is flagged in production"""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            manager = SecureLoggerManager("production")
            errors = manager.validate_production_config()
            assert any("DEBUG logging" in error for error in errors)


class TestSensitiveDataFilter:
    """Test SensitiveDataFilter class"""

    def test_filter_initialization(self):
        """Test filter initialization with patterns"""
        patterns = {"password": r"password=\w+"}
        filter_obj = SensitiveDataFilter(patterns)

        assert filter_obj.redaction_patterns == patterns
        assert len(filter_obj.compiled_patterns) == 1

    def test_filter_log_record_message(self):
        """Test filtering of log record message"""
        patterns = {"password": r"password=\w+"}
        filter_obj = SensitiveDataFilter(patterns)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login with password=secret123",
            args=(),
            exc_info=None,
        )

        result = filter_obj.filter(record)
        assert result is True
        assert "secret123" not in record.msg
        assert "***" in record.msg

    def test_filter_log_record_args(self):
        """Test filtering of log record args"""
        patterns = {"token": r"token=\w+"}
        filter_obj = SensitiveDataFilter(patterns)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authentication failed for %s",
            args=("token=abc123",),
            exc_info=None,
        )

        result = filter_obj.filter(record)
        assert result is True
        assert "abc123" not in record.args[0]
        assert "***" in record.args[0]

    def test_database_url_special_handling(self):
        """Test special handling of database URLs"""
        patterns = {"database_url": r"postgresql://[^:]+:[^@]+@[^/]+/\w+"}
        filter_obj = SensitiveDataFilter(patterns)

        message = "postgresql://user:secret@localhost:5432/mydb"
        redacted = filter_obj.redact_patterns(message)

        assert "secret" not in redacted
        assert "postgresql://user:***@localhost:5432/mydb" in redacted

    def test_redaction_error_handling(self):
        """Test error handling in redaction"""
        # Create a filter with an invalid regex pattern
        patterns = {"invalid": r"["}  # Invalid regex

        # This should raise an exception during initialization due to invalid regex
        with pytest.raises(re.error):
            filter_obj = SensitiveDataFilter(patterns)


class TestSecureFormatter:
    """Test SecureFormatter class"""

    def test_formatter_initialization(self):
        """Test formatter initialization"""
        patterns = {"password": r"password=\w+"}
        formatter = SecureFormatter(redaction_patterns=patterns)

        assert formatter.redaction_patterns == patterns
        assert len(formatter.compiled_patterns) == 1

    def test_formatter_redaction(self):
        """Test formatter redaction during formatting"""
        patterns = {"password": r"password=\w+"}
        formatter = SecureFormatter(fmt="%(message)s", redaction_patterns=patterns)

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User login with password=secret123",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        assert "secret123" not in formatted
        assert "***" in formatted

    def test_formatter_database_url_redaction(self):
        """Test formatter database URL redaction"""
        patterns = {"database_url": r"postgresql://[^:]+:[^@]+@[^/]+/\w+"}
        formatter = SecureFormatter(redaction_patterns=patterns)

        message = "Connecting to postgresql://user:secret@localhost:5432/mydb"
        redacted = formatter.redact_patterns(message)

        assert "secret" not in redacted
        assert "postgresql://user:***@localhost:5432/mydb" in redacted

    def test_formatter_error_handling(self):
        """Test formatter error handling"""
        patterns = {"test": r"test=\w+"}
        formatter = SecureFormatter(redaction_patterns=patterns)

        # Test that redact_patterns handles errors gracefully
        # Create a message that will cause redaction to fail
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )

        # Mock the redact_patterns method to raise an exception
        with patch.object(
            formatter, "redact_patterns", side_effect=Exception("Test error")
        ):
            formatted = formatter.format(record)
            assert "[REDACTED - PROCESSING ERROR]" in formatted


class TestAppConfig:
    """Test AppConfig environment-specific configuration and validation methods"""

    def test_config_initialization_defaults(self):
        """Test config initialization with defaults"""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            assert config.environment == "production"
            assert config.log_level == "INFO"

    def test_config_initialization_from_env(self):
        """Test config initialization from environment variables"""
        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "development",
                "LOG_LEVEL": "DEBUG",
                "DATABASE_URL": "postgresql://user:pass@localhost/db",
                "SESSION_SECRET": "secret123",
            },
        ):
            config = AppConfig()
            assert config.environment == "development"
            assert config.log_level == "DEBUG"
            assert config.database_url.startswith("postgresql+asyncpg://")
            assert config.session_secret == "secret123"

    def test_environment_detection_methods(self):
        """Test environment detection methods"""
        # Test development
        config = AppConfig()
        config.environment = "development"
        assert config.is_development() is True
        assert config.is_production() is False
        assert config.is_testing() is False

        # Test production
        config.environment = "production"
        assert config.is_development() is False
        assert config.is_production() is True
        assert config.is_testing() is False

        # Test testing
        config.environment = "test"
        assert config.is_development() is False
        assert config.is_production() is False
        assert config.is_testing() is True

    def test_safe_database_info_extraction(self):
        """Test safe database info extraction"""
        config = AppConfig()
        config.database_url = "postgresql://user:secret@localhost:5432/mydb"

        safe_info = config.get_safe_database_info()
        assert "secret" not in safe_info
        assert "user" in safe_info
        assert "localhost" in safe_info
        assert "mydb" in safe_info

    def test_safe_database_info_no_url(self):
        """Test safe database info when no URL is configured"""
        config = AppConfig()
        config.database_url = None

        safe_info = config.get_safe_database_info()
        assert safe_info == "No database URL configured"

    def test_production_config_validation_success(self):
        """Test successful production config validation"""
        config = AppConfig()
        config.environment = "production"
        config.database_url = "postgresql://user:pass@localhost/db"
        config.session_secret = "secret123"
        config.log_level = "INFO"

        errors = config.validate_production_config()
        assert len(errors) == 0

    def test_production_config_validation_missing_database(self):
        """Test production config validation with missing database URL"""
        config = AppConfig()
        config.environment = "production"
        config.database_url = None
        config.session_secret = "secret123"

        errors = config.validate_production_config()
        assert any("DATABASE_URL" in error for error in errors)

    def test_production_config_validation_missing_session_secret(self):
        """Test production config validation with missing session secret"""
        config = AppConfig()
        config.environment = "production"
        config.database_url = "postgresql://user:pass@localhost/db"
        config.session_secret = None

        errors = config.validate_production_config()
        assert any("SESSION_SECRET" in error for error in errors)

    def test_production_config_validation_debug_logging(self):
        """Test production config validation flags DEBUG logging"""
        config = AppConfig()
        config.environment = "production"
        config.database_url = "postgresql://user:pass@localhost/db"
        config.session_secret = "secret123"
        config.log_level = "DEBUG"

        errors = config.validate_production_config()
        assert any("DEBUG logging" in error for error in errors)

    def test_production_config_validation_invalid_database_url(self):
        """Test production config validation with invalid database URL"""
        config = AppConfig()
        config.environment = "production"
        config.database_url = "invalid://url"
        config.session_secret = "secret123"

        errors = config.validate_production_config()
        assert any("Invalid database URL" in error for error in errors)

    def test_development_config_no_validation(self):
        """Test that development config doesn't trigger validation errors"""
        config = AppConfig()
        config.environment = "development"
        config.database_url = None
        config.session_secret = None
        config.log_level = "DEBUG"

        errors = config.validate_production_config()
        assert len(errors) == 0

    def test_logging_config_development(self):
        """Test logging configuration for development"""
        config = AppConfig()
        config.environment = "development"

        logging_config = config.get_logging_config()
        assert logging_config["level"] == "DEBUG"
        assert logging_config["database_echo"] is True
        assert logging_config["show_connection_details"] is True
        assert logging_config["redaction_enabled"] is False

    def test_logging_config_production(self):
        """Test logging configuration for production"""
        config = AppConfig()
        config.environment = "production"
        config.log_level = "INFO"

        logging_config = config.get_logging_config()
        assert logging_config["level"] == "INFO"
        assert logging_config["database_echo"] is False
        assert logging_config["show_connection_details"] is False
        assert logging_config["redaction_enabled"] is True

    def test_logging_config_testing(self):
        """Test logging configuration for testing"""
        config = AppConfig()
        config.environment = "test"

        logging_config = config.get_logging_config()
        assert logging_config["level"] == "WARNING"
        assert logging_config["database_echo"] is False
        assert logging_config["redaction_enabled"] is True


class TestGlobalFunctions:
    """Test global convenience functions"""

    def test_get_secure_logger_function(self):
        """Test get_secure_logger convenience function"""
        logger = get_secure_logger("test_module")

        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"

    def test_get_secure_logger_manager_singleton(self):
        """Test that get_secure_logger_manager returns singleton"""
        manager1 = get_secure_logger_manager()
        manager2 = get_secure_logger_manager()

        assert manager1 is manager2

    def test_get_app_config_singleton(self):
        """Test that get_app_config returns singleton"""
        config1 = get_app_config()
        config2 = get_app_config()

        assert config1 is config2


class TestEdgeCasesAndErrorHandling:
    """Test edge cases in redaction patterns and error handling"""

    def test_malformed_database_urls(self):
        """Test redaction of malformed database URLs"""
        manager = SecureLoggerManager("production")

        test_cases = [
            "postgresql://user@localhost/db",  # No password
            "postgresql://:password@localhost/db",  # No user
            "postgresql://localhost/db",  # No credentials
            "postgresql://user:pass@/db",  # No host
            "postgresql://user:pass@localhost",  # No database
            "not-a-url",  # Not a URL at all
        ]

        for test_case in test_cases:
            message = f"Database: {test_case}"
            redacted = manager.redact_sensitive_info(message)
            # Should not crash and should return some form of redacted content
            assert isinstance(redacted, str)
            assert len(redacted) > 0

    def test_special_characters_in_patterns(self):
        """Test redaction patterns with special characters"""
        manager = SecureLoggerManager("production")

        test_cases = [
            'password="p@ssw0rd!"',
            "token=abc-123_def.456",
            "secret: $ecr3t#123",
            "api_key=key+with/special=chars",
        ]

        for test_case in test_cases:
            redacted = manager.redact_sensitive_info(test_case)
            # Should redact the sensitive part
            assert "***" in redacted
            # Should not contain the original sensitive value
            sensitive_value = test_case.split("=")[-1].split(":")[-1].strip('"')
            assert sensitive_value not in redacted

    def test_multiple_patterns_in_single_message(self):
        """Test redaction when multiple patterns exist in one message"""
        manager = SecureLoggerManager("production")

        message = (
            "Connecting to postgresql://user:dbpass@localhost/db "
            "with api_key=abc123 and session_token=xyz789"
        )

        redacted = manager.redact_sensitive_info(message)
        assert "dbpass" not in redacted
        assert "abc123" not in redacted
        assert "xyz789" not in redacted
        assert "***" in redacted

    def test_empty_and_none_messages(self):
        """Test handling of empty and None messages"""
        manager = SecureLoggerManager("production")

        # Test empty string
        assert manager.redact_sensitive_info("") == ""

        # Test None (should be handled gracefully)
        try:
            result = manager.redact_sensitive_info(None)
            # Should either return None or handle gracefully
            assert result is None or isinstance(result, str)
        except (TypeError, AttributeError):
            # This is acceptable behavior for None input
            pass

    def test_very_long_messages(self):
        """Test redaction performance with very long messages"""
        manager = SecureLoggerManager("production")

        # Create a long message with sensitive data
        long_message = (
            "Normal log data " * 1000 + " password=secret123 " + "More data " * 1000
        )

        redacted = manager.redact_sensitive_info(long_message)
        assert "secret123" not in redacted
        assert "***" in redacted
        assert len(redacted) > 0

    def test_nested_sensitive_patterns(self):
        """Test handling of nested or overlapping sensitive patterns"""
        manager = SecureLoggerManager("production")

        # Message with overlapping patterns
        message = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbiI6InNlY3JldCJ9.signature"

        redacted = manager.redact_sensitive_info(message)
        # Should redact the JWT token
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
        assert "***" in redacted

    def test_case_insensitive_redaction(self):
        """Test that redaction patterns work case-insensitively"""
        manager = SecureLoggerManager("production")

        test_cases = [
            "PASSWORD=secret123",
            "Password=secret123",
            "password=secret123",
            "TOKEN=abc123",
            "Token=abc123",
            "token=abc123",
        ]

        for test_case in test_cases:
            redacted = manager.redact_sensitive_info(test_case)
            assert "secret123" not in redacted or "abc123" not in redacted
            assert "***" in redacted

    def test_unicode_and_encoding_handling(self):
        """Test handling of unicode characters and different encodings"""
        manager = SecureLoggerManager("production")

        # Test with unicode characters
        message = "password=sëcrét123 with ñoñ-ascii chars"
        redacted = manager.redact_sensitive_info(message)
        assert "sëcrét123" not in redacted
        assert "***" in redacted
        assert "ñoñ-ascii" in redacted  # Non-sensitive unicode should remain

    def test_regex_injection_protection(self):
        """Test protection against regex injection attacks"""
        manager = SecureLoggerManager("production")

        # Message that could potentially break regex patterns
        malicious_message = "password=secret.*?admin token=.*"

        redacted = manager.redact_sensitive_info(malicious_message)
        # Should handle gracefully without breaking
        assert isinstance(redacted, str)
        assert len(redacted) > 0
