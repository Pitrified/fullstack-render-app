import pytest
from app.rate_limiter import rate_limiter
from app.session import session_manager


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter before each test"""
    rate_limiter.requests.clear()
    yield
    rate_limiter.requests.clear()


@pytest.fixture(autouse=True)
def reset_session_manager():
    """Reset session manager before each test"""
    session_manager.sessions.clear()
    yield
    session_manager.sessions.clear()
