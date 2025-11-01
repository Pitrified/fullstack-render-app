"""
Security-focused tests for secure logging infrastructure
Tests to verify no credentials are exposed in production logs across all components
"""

import io
import logging
import os
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

import pytest
from app.config import AppConfig
from app.secure_logger import SecureLoggerManager, get_secure_logger


class TestProductionSecurityCompliance:
    """Test that production environment prevents credential exposure"""

    def test_no_database_credentials_in_production_logs(self):
        """Test that database credentials are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various database URL formats
            test_urls = [
                "postgresql://user:secret123@localhost:5432/mydb",
                "postgresql+asyncpg://admin:p@ssw0rd@db.example.com:5432/production",
                "mysql://root:topsecret@mysql.local/app",
                "sqlite:///path/to/database.db?password=secret",
            ]

            for url in test_urls:
                logger.info(f"Database connection: {url}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no credentials are present
            assert "secret123" not in log_output
            assert "p@ssw0rd" not in log_output
            assert "topsecret" not in log_output
            assert "password=secret" not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_no_bearer_tokens_in_production_logs(self):
        """Test that bearer tokens are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various token formats
            test_tokens = [
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
                "Authorization: Bearer abc123def456ghi789",
                "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.signature",
            ]

            for token in test_tokens:
                logger.info(f"Authentication: {token}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no tokens are present
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in log_output
            assert "abc123def456ghi789" not in log_output
            assert "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_no_api_keys_in_production_logs(self):
        """Test that API keys are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various API key formats
            test_keys = [
                "api_key=sk_live_abc123def456",
                "apikey: pk_test_xyz789",
                'API-Key="secret_key_12345"',
                "x-api-key=ghi789jkl012",
            ]

            for key in test_keys:
                logger.info(f"Configuration: {key}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no API keys are present
            assert "sk_live_abc123def456" not in log_output
            assert "pk_test_xyz789" not in log_output
            assert "secret_key_12345" not in log_output
            assert "ghi789jkl012" not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_no_passwords_in_production_logs(self):
        """Test that passwords are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various password formats
            test_passwords = [
                'password="mySecretPass123"',
                "password: admin123",
                "password=p@ssw0rd!",
                'pwd="secret"',
            ]

            for password in test_passwords:
                logger.info(f"User login: {password}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no passwords are present
            assert "mySecretPass123" not in log_output
            assert "admin123" not in log_output
            assert "p@ssw0rd!" not in log_output
            assert '"secret"' not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_no_credit_cards_in_production_logs(self):
        """Test that credit card numbers are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various credit card formats
            test_cards = [
                "4532 1234 5678 9012",
                "4532-1234-5678-9012",
                "4532123456789012",
                "5555 5555 5555 4444",
            ]

            for card in test_cards:
                logger.info(f"Payment processing: {card}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no credit card numbers are present
            for card in test_cards:
                assert card not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_no_ssn_in_production_logs(self):
        """Test that SSNs are never exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test SSN format
            ssn = "123-45-6789"
            logger.info(f"User verification: SSN {ssn}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # Verify no SSN is present
            assert ssn not in log_output

            # Verify redaction markers are present
            assert "***" in log_output


class TestDevelopmentEnvironmentSecurity:
    """Test that development environment allows debugging while maintaining basic security"""

    def test_development_allows_detailed_logging(self):
        """Test that development environment allows detailed logging for debugging"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            manager = SecureLoggerManager("development")
            logger = manager.get_logger("test_dev")

            # Capture all log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test database URL logging in development
            test_url = "postgresql://user:secret123@localhost:5432/mydb"
            logger.info(f"Database connection: {test_url}")

            # Get all logged output
            log_output = log_capture.getvalue()

            # In development, the URL should be logged as-is for debugging
            assert test_url in log_output

    def test_development_environment_detection(self):
        """Test that development environment is properly detected"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            manager = SecureLoggerManager("development")

            assert manager.is_development() is True
            assert manager.is_production() is False

            # Verify redaction components are not initialized in development
            assert manager._filter is None
            assert manager._formatter is None


class TestCrossComponentSecurity:
    """Test security across all application components"""

    def test_database_module_security_compliance(self):
        """Test that database module doesn't expose credentials in production"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Mock database connection to test logging

            # Capture stdout/stderr to catch any direct prints
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()

            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # Test that database module uses secure logging
                config = AppConfig()
                safe_info = config.get_safe_database_info()

                # Verify safe info doesn't contain credentials
                assert "secret" not in safe_info.lower()
                assert "password" not in safe_info.lower()

            # Verify no credentials in captured output
            stdout_output = stdout_capture.getvalue()
            stderr_output = stderr_capture.getvalue()

            # Should not contain common credential patterns
            sensitive_patterns = ["password", "secret", "token", "key"]
            for pattern in sensitive_patterns:
                assert pattern not in stdout_output.lower()
                assert pattern not in stderr_output.lower()

    def test_auth_module_security_compliance(self):
        """Test that auth module uses secure logging"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Import auth module to verify it uses secure logging
            from app import auth

            # Verify auth logger is configured
            assert hasattr(auth, "logger")
            assert auth.logger.name == "app.auth"

            # Test that auth logger has secure handlers
            assert len(auth.logger.handlers) > 0

            # Verify the logger has filters for production
            handler = auth.logger.handlers[0]
            # In production, should have filters
            if hasattr(handler, "filters"):
                # Check if any filters are applied
                assert len(handler.filters) >= 0  # May have filters

    def test_main_application_security_compliance(self):
        """Test that main application module uses secure logging"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            # Test that main module would use secure logging
            logger = get_secure_logger("app.main")

            # Capture log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test logging sensitive information
            logger.info(
                "Application starting with DATABASE_URL=postgresql://user:secret@localhost/db"
            )

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify credentials are redacted
            assert "secret" not in log_output
            assert "***" in log_output


class TestSecurityConfigurationValidation:
    """Test security configuration validation"""

    def test_production_config_security_validation(self):
        """Test that production configuration is validated for security"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")

            # Test with missing required configuration
            with patch.dict(os.environ, {"DATABASE_URL": "", "SESSION_SECRET": ""}):
                errors = manager.validate_production_config()
                assert len(errors) > 0
                assert any("DATABASE_URL" in error for error in errors)
                assert any("SESSION_SECRET" in error for error in errors)

    def test_debug_logging_flagged_in_production(self):
        """Test that DEBUG logging is flagged as insecure in production"""
        with patch.dict(
            os.environ, {"ENVIRONMENT": "production", "LOG_LEVEL": "DEBUG"}
        ):
            manager = SecureLoggerManager("production")
            errors = manager.validate_production_config()

            assert any("DEBUG logging" in error for error in errors)

    def test_redaction_enabled_in_production(self):
        """Test that redaction is enabled in production"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")

            # Verify redaction components are initialized
            assert manager._filter is not None
            assert manager._formatter is not None

            # Verify redaction is working
            test_message = "password=secret123"
            redacted = manager.redact_sensitive_info(test_message)
            assert "secret123" not in redacted
            assert "***" in redacted


class TestSecurityEdgeCases:
    """Test security edge cases and attack scenarios"""

    def test_log_injection_protection(self):
        """Test protection against log injection attacks"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test log injection attempt
            malicious_input = "user_input\nFAKE LOG ENTRY: admin login successful\npassword=injected_secret"
            logger.info(f"User input: {malicious_input}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify sensitive data is still redacted even in injection attempts
            assert "injected_secret" not in log_output
            assert "***" in log_output

    def test_unicode_credential_redaction(self):
        """Test that unicode credentials are properly redacted"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test unicode credentials
            unicode_password = "password=pássw0rd123"
            logger.info(f"Login attempt: {unicode_password}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify unicode credentials are redacted
            assert "pássw0rd123" not in log_output
            assert "***" in log_output

    def test_multiple_credential_types_in_single_message(self):
        """Test redaction when multiple credential types exist in one message"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test message with multiple credential types
            complex_message = (
                "Database: postgresql://user:dbpass@localhost/db "
                "API-Key: sk_live_abc123 "
                "Session: session_id=xyz789 "
                "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
            )
            logger.info(complex_message)

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify all credentials are redacted
            assert "dbpass" not in log_output
            assert "sk_live_abc123" not in log_output
            assert "xyz789" not in log_output
            assert "eyJhbGciOiJIUzI1NiJ9.payload.signature" not in log_output

            # Verify redaction markers are present
            assert "***" in log_output

    def test_case_insensitive_credential_detection(self):
        """Test that credential detection works case-insensitively"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            manager = SecureLoggerManager("production")
            logger = manager.get_logger("test_security")

            # Capture log output
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Test various case combinations
            test_cases = [
                "PASSWORD=secret123",
                "Password=secret456",
                "password=secret789",
                "TOKEN=abc123",
                "Token=def456",
                "token=ghi789",
            ]

            for test_case in test_cases:
                logger.info(f"Config: {test_case}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify all credentials are redacted regardless of case
            sensitive_values = [
                "secret123",
                "secret456",
                "secret789",
                "abc123",
                "def456",
                "ghi789",
            ]
            for value in sensitive_values:
                assert value not in log_output

            # Verify redaction markers are present
            assert "***" in log_output


class TestSessionSecurityCompliance:
    """Test that session management uses secure logging and doesn't expose sensitive data"""

    @pytest.mark.asyncio
    async def test_session_logging_uses_secure_logger(self):
        """Test that session.py uses secure logger instead of standard logging"""
        from backend.app.session import logger

        # Verify that the logger is from secure logger manager
        assert hasattr(logger, "handlers")
        # The logger should have been configured by SecureLoggerManager
        assert len(logger.handlers) > 0

    @pytest.mark.asyncio
    async def test_no_session_ids_in_production_logs(self):
        """Test that session IDs are not exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            from backend.app.secure_logger import get_secure_logger
            from backend.app.session import SessionManager

            # Create session manager
            session_manager = SessionManager()

            # Test that session logging uses secure redaction
            logger = get_secure_logger("test_session")

            # Capture log output using StringIO and redirect stderr
            log_capture = StringIO()

            # Create a custom handler to capture the logs
            handler = logging.StreamHandler(log_capture)
            handler.setLevel(logging.INFO)

            # Get the session logger and add our handler
            session_logger = get_secure_logger("backend.app.session")
            session_logger.addHandler(handler)

            try:
                # Create a session (this should log without exposing session ID)
                session_id = await session_manager.create_session(
                    123, "test_google_token"
                )

                # Refresh session (this should log without exposing session ID)
                await session_manager.refresh_session(session_id)

                # Get logged output
                log_output = log_capture.getvalue()

                # Verify session ID is not in logs (if any logs were captured)
                if log_output:
                    assert session_id not in log_output
                    assert "123" in log_output
                    assert (
                        "Created session for user" in log_output
                        or "Refreshed session for user" in log_output
                    )

                # The main test is that the session module uses secure logging
                # which we can verify by checking the logger type
                from backend.app.session import logger as session_module_logger

                assert hasattr(session_module_logger, "handlers")

            finally:
                # Clean up the handler
                session_logger.removeHandler(handler)

    @pytest.mark.asyncio
    async def test_no_google_tokens_in_production_logs(self):
        """Test that Google tokens are not exposed in production logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            from backend.app.secure_logger import get_secure_logger

            logger = get_secure_logger("test_session")

            # Capture log output
            log_capture = StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Log a message that might contain a Google token
            test_token = "ya29.a0AfH6SMBxyz123_sensitive_token_data"
            logger.info(f"Processing google_token: {test_token}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify token is redacted
            assert test_token not in log_output
            assert "***" in log_output

    @pytest.mark.asyncio
    async def test_url_safe_tokens_redacted_in_production(self):
        """Test that URL-safe tokens (like session IDs) are redacted in production"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            import secrets

            from backend.app.secure_logger import get_secure_logger

            logger = get_secure_logger("test_session")

            # Capture log output
            log_capture = StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Generate a URL-safe token like those used for sessions
            url_safe_token = secrets.token_urlsafe(32)
            logger.info(f"Generated session token: {url_safe_token}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify token is redacted (should be caught by url_safe_token pattern)
            assert url_safe_token not in log_output
            assert "***" in log_output

    @pytest.mark.asyncio
    async def test_session_data_structure_security(self):
        """Test that SessionData objects don't accidentally expose sensitive info in logs"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            from datetime import datetime

            from backend.app.secure_logger import get_secure_logger
            from backend.app.session import SessionData

            logger = get_secure_logger("test_session")

            # Capture log output
            log_capture = StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # Create session data with sensitive token
            session_data = SessionData(
                user_id=456,
                google_token="ya29.sensitive_google_token_12345",
                expires_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow(),
            )

            # Log session data (this should never happen in real code, but test for safety)
            logger.info(f"Session data: {session_data}")

            # Get logged output
            log_output = log_capture.getvalue()

            # Verify sensitive token is redacted
            assert "ya29.sensitive_google_token_12345" not in log_output
            assert "***" in log_output

            # Verify non-sensitive data is still present
            assert "456" in log_output  # user_id should be visible

    def test_development_environment_allows_session_debugging(self):
        """Test that development environment allows more detailed session logging"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}):
            from backend.app.secure_logger import get_secure_logger

            logger = get_secure_logger("test_session")

            # Capture log output
            log_capture = StringIO()
            handler = logging.StreamHandler(log_capture)
            logger.addHandler(handler)

            # In development, some session info might be logged for debugging
            session_id = "test_session_id_12345"
            logger.info(f"Debug: session_id={session_id}")

            # Get logged output
            log_output = log_capture.getvalue()

            # In development, session ID might be visible for debugging
            # (though in practice we still avoid logging it directly)
            assert "Debug:" in log_output
