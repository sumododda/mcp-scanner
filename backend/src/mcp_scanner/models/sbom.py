import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mcp_scanner.models.base import Base, TimestampMixin


class Sbom(TimestampMixin, Base):
    __tablename__ = "sboms"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False,
    )
    server_name: Mapped[str] = mapped_column(Text, nullable=False)
    package_name: Mapped[str] = mapped_column(Text, nullable=False)
    package_version: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(
        String(20), nullable=False, default="cyclonedx",
    )
    sbom_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    dependency_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=0,
    )
    vulnerability_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=0,
    )
    license_summary: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, default=None,
    )
    vulnerabilities: Mapped[list | None] = mapped_column(
        JSONB, nullable=True, default=None,
    )

    scan = relationship("Scan", back_populates="sboms")

    def __init__(self, **kwargs):
        kwargs.setdefault("format", "cyclonedx")
        super().__init__(**kwargs)
