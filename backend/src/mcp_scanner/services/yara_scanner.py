"""YARA-based pattern scanner for MCP tool analysis."""

import logging
from dataclasses import dataclass, field
from importlib.resources import files as pkg_files
from pathlib import Path

import yara

logger = logging.getLogger(__name__)


@dataclass
class YaraMatch:
    """A single YARA rule match."""

    rule_name: str
    category: str
    severity: str
    description: str
    matched_strings: list[str] = field(default_factory=list)
    cwe_id: str = ""


class YaraScanner:
    """Compiles and caches YARA rules, scans text for matches."""

    def __init__(self, rules_dir: Path | None = None):
        self._rules_dir = rules_dir or Path(str(pkg_files("mcp_scanner") / "data" / "yara_rules"))
        self._compiled: yara.Rules | None = None

    def _compile(self) -> yara.Rules:
        """Lazy-compile all .yar files from the rules directory."""
        if self._compiled is not None:
            return self._compiled

        rule_files = sorted(self._rules_dir.glob("*.yar"))
        if not rule_files:
            raise FileNotFoundError(f"No .yar files found in {self._rules_dir}")

        filepaths = {f.stem: str(f) for f in rule_files}
        logger.info("Compiling %d YARA rule files: %s", len(filepaths), list(filepaths.keys()))
        self._compiled = yara.compile(filepaths=filepaths)
        return self._compiled

    def scan_text(self, text: str) -> list[YaraMatch]:
        """Scan a text string against all compiled YARA rules."""
        rules = self._compile()
        matches = rules.match(data=text)
        results: list[YaraMatch] = []

        for match in matches:
            meta = match.meta
            matched_strings = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    try:
                        decoded = instance.matched_data.decode("utf-8", errors="replace")
                    except AttributeError:
                        decoded = str(instance.matched_data)
                    matched_strings.append(decoded)

            results.append(
                YaraMatch(
                    rule_name=match.rule,
                    category=meta.get("category", "unknown"),
                    severity=meta.get("severity", "MEDIUM"),
                    description=meta.get("description", match.rule),
                    matched_strings=matched_strings,
                    cwe_id=meta.get("cwe", ""),
                )
            )

        return results


# Module-level singleton for reuse across checker invocations
_scanner: YaraScanner | None = None


def get_yara_scanner() -> YaraScanner:
    """Return (and lazily create) the module-level YaraScanner singleton."""
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner()
    return _scanner
