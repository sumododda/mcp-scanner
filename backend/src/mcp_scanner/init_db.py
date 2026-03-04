"""Create all database tables from SQLAlchemy models.

Replaces Alembic migrations — run once on fresh databases.
"""

import asyncio

from sqlalchemy.ext.asyncio import create_async_engine

from mcp_scanner.config import settings
from mcp_scanner.models import Base  # noqa: F401 — registers all models


async def init_db() -> None:
    engine = create_async_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(init_db())
