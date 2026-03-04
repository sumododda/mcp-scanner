import enum
import uuid

from sqlalchemy import Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mcp_scanner.models.base import Base, TimestampMixin


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(TimestampMixin, Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    mcp_config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    repo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_hash: Mapped[str | None] = mapped_column(String(40), nullable=True)
    overall_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(1), nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    server_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    code_graph: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_snapshots = relationship("ToolSnapshot", back_populates="scan", cascade="all, delete-orphan")
    sboms = relationship("Sbom", back_populates="scan", cascade="all, delete-orphan")
