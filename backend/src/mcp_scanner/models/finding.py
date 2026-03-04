import enum
import uuid

from sqlalchemy import Enum, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mcp_scanner.models.base import Base, TimestampMixin


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 15, "medium": 5, "low": 1}[self.value]


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id"))
    checker: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="")
    cwe_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_file: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dismissed_as: Mapped[str | None] = mapped_column(Text, nullable=True)
    dismissed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")
