"""
PhishGuard AI - Database Setup
Configures SQLAlchemy engine, session maker, base model, and initialization.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from backend.app.core.config import settings

# If SQLite, ensure connect_args allows multi-threading
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass


def auto_migrate_schema(engine_instance, base_instance):
    """
    Ensures that any newly added columns in SQLAlchemy models
    are automatically created in the existing database tables (e.g., SQLite).
    """
    import logging
    from sqlalchemy import inspect, text

    logger = logging.getLogger("phishguard.database")
    try:
        insp = inspect(engine_instance)
        with engine_instance.begin() as conn:
            for table_name, table in base_instance.metadata.tables.items():
                if insp.has_table(table_name):
                    existing_cols = {c["name"] for c in insp.get_columns(table_name)}
                    for column in table.columns:
                        if column.name not in existing_cols:
                            col_type = column.type.compile(engine_instance.dialect)
                            stmt = text(f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}")
                            logger.info(f"Auto-migrated database: added column '{column.name}' ({col_type}) to table '{table_name}'")
                            conn.execute(stmt)
    except Exception as e:
        logger.warning(f"Auto-migration check notice: {e}")


def init_db():
    """Initializes the database schema and performs automatic schema synchronization."""
    Base.metadata.create_all(bind=engine)
    auto_migrate_schema(engine, Base)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
