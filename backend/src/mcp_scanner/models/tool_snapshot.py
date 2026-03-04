import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mcp_scanner.models.base import Base


class ToolSnapshot(Base):
    __tablename__ = "tool_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"))
    server_name: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    definition_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_definition: Mapped[dict] = mapped_column(JSONB, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    scan = relationship("Scan", back_populates="tool_snapshots")

    @staticmethod
    def compute_hash(server_name: str, tool_name: str, definition: dict) -> str:
        content = json.dumps(
            {"server": server_name, "tool": tool_name, "definition": definition},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()
