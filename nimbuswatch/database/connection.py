"""Database connection and session factory for SQLite SQLAlchemy."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from nimbuswatch.config import settings

# SQLite connection args for multithreaded FastAPI requests
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

_db_initialized = False

def init_db():
    """Initialize database tables."""
    global _db_initialized
    from nimbuswatch.database import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _db_initialized = True

def get_db():
    """FastAPI dependency for database sessions."""
    global _db_initialized
    if not _db_initialized:
        init_db()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

