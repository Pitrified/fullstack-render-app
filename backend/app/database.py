from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from .config import get_app_config
from .secure_logger import get_secure_logger_manager

# Initialize configuration and secure logging
config = get_app_config()
logger_manager = get_secure_logger_manager()
logger = logger_manager.get_logger(__name__)

# Get database URL from configuration
DATABASE_URL = config.database_url

if not DATABASE_URL:
    logger.error("DATABASE_URL not configured")
    raise ValueError("DATABASE_URL environment variable is required")

# Log database connection information securely
if config.is_development():
    # In development, show safe connection details for debugging
    safe_info = config.get_safe_database_info()
    logger.info(f"Database configured: {safe_info}")
    logger.debug(
        f"Full database URL: {logger_manager.redact_sensitive_info(DATABASE_URL)}"
    )
else:
    # In production, only log that connection is established
    logger.info("Database connection established")

# Create engine with environment-aware echo configuration
# Only enable SQL echo in development for debugging
engine = create_async_engine(
    DATABASE_URL,
    echo=config.is_development(),  # Only echo SQL queries in development
)

# Configure database logging through secure logger manager
logger_manager.configure_database_logging(engine)

SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db():
    async with SessionLocal() as session:
        yield session
