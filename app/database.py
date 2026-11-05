import logging
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.exc import OperationalError
from app.config import settings

logger = logging.getLogger(__name__)

db_url = settings.DATABASE_URL

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

connect_args = {}
if "sqlite" in db_url:
    connect_args = {"check_same_thread": False}

try:
    engine = create_engine(
        db_url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args
    )
    # Test connection
    with engine.connect() as conn:
        pass
except (OperationalError, Exception) as e:
    logger.warning(
        "Could not connect to configured database (%s): %s. Falling back to local SQLite (filescanner.db) for local development.",
        db_url,
        e
    )
    fallback_url = "sqlite:///./filescanner.db"
    engine = create_engine(
        fallback_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
