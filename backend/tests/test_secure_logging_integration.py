"""
Test secure logging integration with authentication system
"""

import os
from unittest.mock import patch

from app.auth import logger as auth_logger
from app.secure_logger import SecureLoggerManager, get_secure_logger
from app.security_logger import security_logger


class TestSecureLoggingIntegration:
    """Test that secure logging is properly integrated with authentication system"""

    def test_auth_module_uses_secure_logger(self):
        """Test that auth module is using secure logger"""
        # Verify that auth logger is properly configured
        assert hasattr(auth_logger, "handlers")
        assert len(auth_logger.handlers) > 0
        assert auth_logger.name == "app.auth"

    def test_security_logger_uses_secure_logger(self):
        """Test that security logger is using secure logger manager"""
        # Verify that security logger is properly configured
        assert hasattr(security_logger, "handlers")
        assert len(security_logger.handlers) > 0
        assert security_logger.name == "security"

    def test_sensitive_information_redaction_functionality(self):
        """Test that sensitive information redaction works correctly"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")

            # Test database URL redaction
            message = (
                "Database connection: postgresql://user:secret123@localhost:5432/mydb"
            )
            redacted = manager.redact_sensitive_info(message)
            assert "secret123" not in redacted
            assert "***" in redacted

            # Test bearer token redaction
            message = "Bearer token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
            redacted = manager.redact_sensitive_info(message)
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature" not in redacted
            assert "***" in redacted

    def test_production_environment_security(self):
        """Test that production environment has proper security settings"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")

            # Verify environment detection
            assert manager.is_production() is True
            assert manager.is_development() is False

            # Verify redaction is enabled
            assert manager._filter is not None
            assert manager._formatter is not None

    def test_get_secure_logger_function(self):
        """Test that get_secure_logger function works correctly"""
        test_logger = get_secure_logger("test_module")

        # Verify it returns a proper logger
        assert hasattr(test_logger, "info")
        assert hasattr(test_logger, "error")
        assert hasattr(test_logger, "warning")
        assert test_logger.name == "test_module"
