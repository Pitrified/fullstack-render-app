"""
Rate limiting utilities for authentication endpoints
"""

import time
from collections import defaultdict, deque
from typing import Dict

from fastapi import HTTPException, Request

from .security_logger import log_security_violation


class RateLimiter:
    """Simple in-memory rate limiter"""

    def __init__(self):
        # Store request timestamps for each IP
        self.requests: Dict[str, deque] = defaultdict(deque)

    def is_allowed(
        self, client_ip: str, max_requests: int, window_seconds: int
    ) -> bool:
        """Check if request is allowed based on rate limits"""
        now = time.time()
        window_start = now - window_seconds

        # Clean old requests outside the window
        while self.requests[client_ip] and self.requests[client_ip][0] < window_start:
            self.requests[client_ip].popleft()

        # Check if under the limit
        if len(self.requests[client_ip]) < max_requests:
            self.requests[client_ip].append(now)
            return True

        return False

    def cleanup_old_entries(self, max_age_seconds: int = 3600):
        """Clean up old entries to prevent memory leaks"""
        cutoff_time = time.time() - max_age_seconds

        # Remove IPs with no recent requests
        ips_to_remove = []
        for ip, requests in self.requests.items():
            # Remove old requests
            while requests and requests[0] < cutoff_time:
                requests.popleft()

            # If no requests left, mark IP for removal
            if not requests:
                ips_to_remove.append(ip)

        # Remove empty IP entries
        for ip in ips_to_remove:
            del self.requests[ip]


# Global rate limiter instance
rate_limiter = RateLimiter()


def check_rate_limit(
    request: Request,
    max_requests: int = 5,
    window_seconds: int = 60,
    endpoint_name: str = "authentication",
) -> None:
    """
    Check rate limit for a request and raise HTTPException if exceeded

    Args:
        request: FastAPI request object
        max_requests: Maximum number of requests allowed
        window_seconds: Time window in seconds
        endpoint_name: Name of endpoint for logging
    """
    client_ip = request.client.host if request.client else "unknown"

    if not rate_limiter.is_allowed(client_ip, max_requests, window_seconds):
        # Log rate limit violation
        log_security_violation(
            request,
            "rate_limit_exceeded",
            f"Endpoint: {endpoint_name}, Limit: {max_requests}/{window_seconds}s",
        )

        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(window_seconds)},
        )


def check_auth_rate_limit(request: Request) -> None:
    """Rate limit for authentication endpoints (5 requests per minute)"""
    check_rate_limit(request, max_requests=5, window_seconds=60, endpoint_name="auth")


def check_login_rate_limit(request: Request) -> None:
    """Stricter rate limit for login attempts (3 requests per minute)"""
    check_rate_limit(request, max_requests=3, window_seconds=60, endpoint_name="login")


def check_refresh_rate_limit(request: Request) -> None:
    """Rate limit for session refresh (10 requests per minute)"""
    check_rate_limit(
        request, max_requests=10, window_seconds=60, endpoint_name="refresh"
    )
