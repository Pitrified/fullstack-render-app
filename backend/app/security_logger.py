"""
Security logging utilities for authentication events
"""

import logging
from typing import Optional

from fastapi import Request

# Configure security logger
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

# Create handler if not exists
if not security_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - SECURITY - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)


def log_authentication_attempt(
    request: Request,
    success: bool,
    user_id: Optional[int] = None,
    reason: Optional[str] = None,
):
    """Log authentication attempts without exposing sensitive data"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    if success:
        security_logger.info(
            f"Authentication successful - IP: {client_ip} - User: {user_id or 'unknown'}"
        )
    else:
        security_logger.warning(
            f"Authentication failed - IP: {client_ip} - Reason: {reason or 'invalid_credentials'} - UA: {user_agent[:100]}"
        )


def log_session_event(
    request: Request,
    event_type: str,
    user_id: Optional[int] = None,
    session_id: Optional[str] = None,
):
    """Log session events without exposing sensitive data"""
    client_ip = request.client.host if request.client else "unknown"

    # Only log first 8 characters of session ID for security
    safe_session_id = session_id[:8] + "..." if session_id else "unknown"

    security_logger.info(
        f"Session {event_type} - IP: {client_ip} - User: {user_id or 'unknown'} - Session: {safe_session_id}"
    )


def log_security_violation(
    request: Request, violation_type: str, details: Optional[str] = None
):
    """Log security violations without exposing sensitive data"""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    security_logger.error(
        f"Security violation - Type: {violation_type} - IP: {client_ip} - UA: {user_agent[:100]} - Details: {details or 'none'}"
    )
