"""Pluggable manifest file parsers for SBOM generation.

Supports 4 ecosystems (npm, Python, Go, Rust) with proper PURL handling
via packageurl-python. Each parser returns a ParseResult or None.

Lockfiles are preferred over plain manifests for richer dependency data.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from packageurl import PackageURL

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ParsedComponent:
    """A single resolved package with PURL."""

    name: str
    version: str
    purl: PackageURL
    ecosystem: str  # npm, pypi, golang, cargo


@dataclass
class ParseResult:
    """Aggregated parse output from one or more manifest files."""

    components: list[ParsedComponent] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)
    main_name: str = ""
    main_version: str = ""
    ecosystem: str = ""


# ---------------------------------------------------------------------------
# PURL helpers
# ---------------------------------------------------------------------------


def _npm_purl(name: str, version: str) -> PackageURL:
    """Build a PURL for an npm package, handling scoped packages."""
    if name.startswith("@") and "/" in name:
        namespace, pkg_name = name.split("/", 1)
        return PackageURL(type="npm", namespace=namespace, name=pkg_name, version=version)
    return PackageURL(type="npm", name=name, version=version)


def _go_purl(module_path: str, version: str) -> PackageURL:
    """Build a PURL for a Go module, splitting namespace at last '/'."""
    if "/" in module_path:
        last_slash = module_path.rfind("/")
        namespace = module_path[:last_slash]
        name = module_path[last_slash + 1:]
    else:
        namespace = None
        name = module_path
    return PackageURL(type="golang", namespace=namespace, name=name, version=version)


def _pypi_purl(name: str, version: str) -> PackageURL:
    """Build a PURL for a PyPI package."""
    if version:
        return PackageURL(type="pypi", name=name, version=version)
    return PackageURL(type="pypi", name=name)


def _cargo_purl(name: str, version: str) -> PackageURL:
    """Build a PURL for a Cargo crate."""
    return PackageURL(type="cargo", name=name, version=version)


# ---------------------------------------------------------------------------
# npm ecosystem parsers
# ---------------------------------------------------------------------------


def parse_npm_lockfile(repo_path: Path) -> ParseResult | None:
    """Parse package-lock.json (v1/v2/v3) for the full transitive tree."""
    lock_path = repo_path / "package-lock.json"
    if not lock_path.is_file():
        return None

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return None

    components: list[ParsedComponent] = []
    dep_map: dict[str, list[str]] = defaultdict(list)
    seen: set[str] = set()

    main_name = data.get("name", repo_path.name)
    main_version = data.get("version", "0.0.0")

    packages = data.get("packages", {})
    if packages:
        # v2/v3 flat layout
        for path_key, pkg_info in packages.items():
            if not path_key:  # root entry
                continue
            name = (
                path_key.split("node_modules/")[-1]
                if "node_modules/" in path_key
                else path_key
            )
            ver = pkg_info.get("version", "")
            if not name or name in seen:
                continue
            seen.add(name)

            purl = _npm_purl(name, ver)
            components.append(ParsedComponent(name=name, version=ver, purl=purl, ecosystem="npm"))

            # Build dependency edges
            all_deps = {
                **pkg_info.get("dependencies", {}),
                **pkg_info.get("optionalDependencies", {}),
            }
            for dep_name in all_deps:
                dep_ver = ""
                for check_path, check_info in packages.items():
                    if check_path.endswith(f"node_modules/{dep_name}"):
                        dep_ver = check_info.get("version", "")
                        break
                dep_map[str(purl)].append(str(_npm_purl(dep_name, dep_ver)))
    else:
        # v1 nested layout
        def _walk_v1(deps: dict) -> None:
            for name, info in deps.items():
                ver = info.get("version", "")
                if name in seen:
                    continue
                seen.add(name)
                purl = _npm_purl(name, ver)
                components.append(ParsedComponent(name=name, version=ver, purl=purl, ecosystem="npm"))

                sub_deps = info.get("dependencies", {})
                if sub_deps:
                    for sub_name, sub_info in sub_deps.items():
                        dep_map[str(purl)].append(
                            str(_npm_purl(sub_name, sub_info.get("version", "")))
                        )
                    _walk_v1(sub_deps)
                for req_name in info.get("requires", {}):
                    dep_map[str(purl)].append(str(_npm_purl(req_name, "")))

        _walk_v1(data.get("dependencies", {}))

    return ParseResult(
        components=components,
        dependencies=dict(dep_map),
        main_name=main_name,
        main_version=main_version,
        ecosystem="npm",
    )


def parse_yarn_lock(repo_path: Path) -> ParseResult | None:
    """Parse yarn.lock v1 format."""
    lock_path = repo_path / "yarn.lock"
    if not lock_path.is_file():
        return None

    try:
        content = lock_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []
    seen: set[str] = set()

    # Match patterns like:
    #   express@^4.18.0:
    #     version "4.18.2"
    # Or scoped:
    #   "@types/node@^20.0.0":
    #     version "20.11.0"
    pattern = re.compile(
        r'^"?(@?[^@\s"]+)@[^:]+:?\s*\n\s+version\s+"([^"]+)"',
        re.MULTILINE,
    )
    for match in pattern.finditer(content):
        name = match.group(1)
        version = match.group(2)
        if name in seen:
            continue
        seen.add(name)
        purl = _npm_purl(name, version)
        components.append(ParsedComponent(name=name, version=version, purl=purl, ecosystem="npm"))

    # Try to get main name/version from package.json
    main_name, main_version = _read_npm_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="npm",
    )


def parse_pnpm_lock(repo_path: Path) -> ParseResult | None:
    """Parse pnpm-lock.yaml packages map.

    Uses PyYAML if available, falls back to regex parsing.
    """
    lock_path = repo_path / "pnpm-lock.yaml"
    if not lock_path.is_file():
        return None

    try:
        content = lock_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []
    seen: set[str] = set()

    # Try PyYAML first
    parsed = False
    try:
        import yaml

        data = yaml.safe_load(content)
        if data and isinstance(data.get("packages"), dict):
            for pkg_key in data["packages"]:
                name, version = _parse_pnpm_package_key(pkg_key)
                if name and name not in seen:
                    seen.add(name)
                    purl = _npm_purl(name, version)
                    components.append(
                        ParsedComponent(name=name, version=version, purl=purl, ecosystem="npm")
                    )
            parsed = True
    except ImportError:
        pass
    except Exception:
        logger.debug("PyYAML failed for pnpm-lock.yaml, falling back to regex")

    if not parsed:
        # Regex fallback: match lines like "  /express@4.18.2:" or "  /@types/node@20.11.0:"
        pattern = re.compile(r"^\s+/(@?[^@\s]+)@([^:\s]+):", re.MULTILINE)
        for match in pattern.finditer(content):
            name = match.group(1)
            version = match.group(2)
            if name not in seen:
                seen.add(name)
                purl = _npm_purl(name, version)
                components.append(
                    ParsedComponent(name=name, version=version, purl=purl, ecosystem="npm")
                )

    main_name, main_version = _read_npm_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="npm",
    )


def _parse_pnpm_package_key(key: str) -> tuple[str, str]:
    """Parse a pnpm package key like '/express@4.18.2' or '/@types/node@20.11.0'.

    Returns (name, version) tuple.
    """
    key = key.lstrip("/")
    # Handle scoped: @types/node@20.11.0
    if key.startswith("@"):
        # Find the second @ which separates name from version
        at_idx = key.index("@", 1)
        return key[:at_idx], key[at_idx + 1:]
    # Regular: express@4.18.2
    if "@" in key:
        at_idx = key.index("@")
        return key[:at_idx], key[at_idx + 1:]
    return key, ""


def parse_package_json(repo_path: Path) -> ParseResult | None:
    """Parse package.json for direct deps + devDeps (fallback parser)."""
    pkg_path = repo_path / "package.json"
    if not pkg_path.is_file():
        return None

    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return None

    components: list[ParsedComponent] = []
    main_name = data.get("name", repo_path.name)
    main_version = data.get("version", "0.0.0")

    all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for dep_name, dep_ver_spec in all_deps.items():
        # Strip semver range prefixes
        ver = re.sub(r"^[\^~>=<]+", "", dep_ver_spec).strip()
        purl = _npm_purl(dep_name, ver)
        components.append(ParsedComponent(name=dep_name, version=ver, purl=purl, ecosystem="npm"))

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="npm",
    )


def _read_npm_main(repo_path: Path) -> tuple[str, str]:
    """Read main name/version from package.json if present."""
    pkg_path = repo_path / "package.json"
    if pkg_path.is_file():
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
            return data.get("name", repo_path.name), data.get("version", "0.0.0")
        except (json.JSONDecodeError, OSError):
            pass
    return repo_path.name, "0.0.0"


# ---------------------------------------------------------------------------
# Python ecosystem parsers
# ---------------------------------------------------------------------------


def parse_poetry_lock(repo_path: Path) -> ParseResult | None:
    """Parse poetry.lock [[package]] blocks (TOML format)."""
    lock_path = repo_path / "poetry.lock"
    if not lock_path.is_file():
        return None

    try:
        content = lock_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []

    # poetry.lock uses TOML with [[package]] array of tables
    try:
        data = tomllib.loads(content)
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name:
                purl = _pypi_purl(name, version)
                components.append(
                    ParsedComponent(name=name, version=version, purl=purl, ecosystem="pypi")
                )
    except Exception:
        # Fallback to regex if TOML parsing fails
        pattern = re.compile(
            r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"'
        )
        for match in pattern.finditer(content):
            name, version = match.group(1), match.group(2)
            purl = _pypi_purl(name, version)
            components.append(
                ParsedComponent(name=name, version=version, purl=purl, ecosystem="pypi")
            )

    if not components:
        return None

    # Try to read main name from pyproject.toml
    main_name, main_version = _read_python_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="pypi",
    )


def parse_requirements_txt(repo_path: Path) -> ParseResult | None:
    """Parse requirements.txt — pinned/unpinned/comments/flags."""
    req_path = repo_path / "requirements.txt"
    if not req_path.is_file():
        return None

    try:
        content = req_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match package name and optional version spec
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~]+\s*(.+))?", line)
        if match:
            name = match.group(1)
            ver = (match.group(2) or "").strip()
            purl = _pypi_purl(name, ver)
            components.append(
                ParsedComponent(name=name, version=ver, purl=purl, ecosystem="pypi")
            )

    if not components:
        return None

    main_name, main_version = _read_python_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="pypi",
    )


def parse_pyproject_toml(repo_path: Path) -> ParseResult | None:
    """Parse pyproject.toml [project.dependencies]."""
    toml_path = repo_path / "pyproject.toml"
    if not toml_path.is_file():
        return None

    try:
        data = tomllib.loads(toml_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    project = data.get("project", {})
    main_name = project.get("name", repo_path.name)
    main_version = project.get("version", "0.0.0")

    components: list[ParsedComponent] = []
    deps = project.get("dependencies", [])

    for dep_spec in deps:
        # Parse "requests>=2.31.0" or "pydantic==2.5.0" or "click~=8.1"
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(?:[=<>!~]+\s*(.+))?", dep_spec)
        if match:
            name = match.group(1)
            ver = (match.group(2) or "").strip()
            purl = _pypi_purl(name, ver)
            components.append(
                ParsedComponent(name=name, version=ver, purl=purl, ecosystem="pypi")
            )

    if not components:
        return None

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="pypi",
    )


def _read_python_main(repo_path: Path) -> tuple[str, str]:
    """Read main name/version from pyproject.toml if present."""
    toml_path = repo_path / "pyproject.toml"
    if toml_path.is_file():
        try:
            data = tomllib.loads(toml_path.read_text(encoding="utf-8", errors="ignore"))
            project = data.get("project", {})
            return project.get("name", repo_path.name), project.get("version", "0.0.0")
        except (OSError, tomllib.TOMLDecodeError):
            pass
    return repo_path.name, "0.0.0"


# ---------------------------------------------------------------------------
# Go ecosystem parsers
# ---------------------------------------------------------------------------


def parse_go_sum(repo_path: Path) -> ParseResult | None:
    """Parse go.sum — deduplicate /go.mod and h1: hash entries."""
    go_sum_path = repo_path / "go.sum"
    if not go_sum_path.is_file():
        return None

    try:
        content = go_sum_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []
    seen: set[str] = set()

    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        module = parts[0]
        ver_raw = parts[1]
        # Strip /go.mod suffix from version
        ver = ver_raw.split("/")[0]
        key = f"{module}@{ver}"
        if key in seen:
            continue
        seen.add(key)

        purl = _go_purl(module, ver)
        components.append(
            ParsedComponent(name=module, version=ver, purl=purl, ecosystem="golang")
        )

    if not components:
        return None

    main_name, main_version = _read_go_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="golang",
    )


def parse_go_mod(repo_path: Path) -> ParseResult | None:
    """Parse go.mod require block + module name (fallback parser)."""
    go_mod_path = repo_path / "go.mod"
    if not go_mod_path.is_file():
        return None

    try:
        content = go_mod_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    # Extract module name
    main_name = repo_path.name
    mod_match = re.search(r"^module\s+(\S+)", content, re.MULTILINE)
    if mod_match:
        main_name = mod_match.group(1)

    components: list[ParsedComponent] = []
    seen: set[str] = set()

    # Match require lines: both single and block form
    # Single: require github.com/foo/bar v1.2.3
    # Block:  require (\n\tgithub.com/foo/bar v1.2.3\n)
    for match in re.finditer(r"^\s+(\S+)\s+(v\S+)", content, re.MULTILINE):
        module = match.group(1)
        ver = match.group(2)
        if module in seen:
            continue
        seen.add(module)
        purl = _go_purl(module, ver)
        components.append(
            ParsedComponent(name=module, version=ver, purl=purl, ecosystem="golang")
        )

    if not components:
        return None

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version="",
        ecosystem="golang",
    )


def _read_go_main(repo_path: Path) -> tuple[str, str]:
    """Read main module name from go.mod if present."""
    go_mod_path = repo_path / "go.mod"
    if go_mod_path.is_file():
        try:
            content = go_mod_path.read_text(encoding="utf-8", errors="ignore")
            mod_match = re.search(r"^module\s+(\S+)", content, re.MULTILINE)
            if mod_match:
                return mod_match.group(1), ""
        except OSError:
            pass
    return repo_path.name, ""


# ---------------------------------------------------------------------------
# Rust ecosystem parsers
# ---------------------------------------------------------------------------


def parse_cargo_lock(repo_path: Path) -> ParseResult | None:
    """Parse Cargo.lock [[package]] blocks."""
    lock_path = repo_path / "Cargo.lock"
    if not lock_path.is_file():
        return None

    try:
        content = lock_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    components: list[ParsedComponent] = []

    # Cargo.lock is valid TOML
    try:
        data = tomllib.loads(content)
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            if name:
                purl = _cargo_purl(name, version)
                components.append(
                    ParsedComponent(name=name, version=version, purl=purl, ecosystem="cargo")
                )
    except Exception:
        # Fallback to regex
        pattern = re.compile(
            r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"'
        )
        for match in pattern.finditer(content):
            name, version = match.group(1), match.group(2)
            purl = _cargo_purl(name, version)
            components.append(
                ParsedComponent(name=name, version=version, purl=purl, ecosystem="cargo")
            )

    if not components:
        return None

    main_name, main_version = _read_cargo_main(repo_path)

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="cargo",
    )


def parse_cargo_toml(repo_path: Path) -> ParseResult | None:
    """Parse Cargo.toml [dependencies] — simple string and table formats."""
    toml_path = repo_path / "Cargo.toml"
    if not toml_path.is_file():
        return None

    try:
        data = tomllib.loads(toml_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    package = data.get("package", {})
    main_name = package.get("name", repo_path.name)
    main_version = package.get("version", "0.0.0")

    components: list[ParsedComponent] = []

    # Collect from [dependencies] and [dev-dependencies]
    for section in ("dependencies", "dev-dependencies"):
        deps = data.get(section, {})
        for dep_name, dep_spec in deps.items():
            if isinstance(dep_spec, str):
                ver = dep_spec
            elif isinstance(dep_spec, dict):
                ver = dep_spec.get("version", "")
            else:
                ver = str(dep_spec)
            purl = _cargo_purl(dep_name, ver)
            components.append(
                ParsedComponent(name=dep_name, version=ver, purl=purl, ecosystem="cargo")
            )

    if not components:
        return None

    return ParseResult(
        components=components,
        dependencies={},
        main_name=main_name,
        main_version=main_version,
        ecosystem="cargo",
    )


def _read_cargo_main(repo_path: Path) -> tuple[str, str]:
    """Read main crate name/version from Cargo.toml if present."""
    toml_path = repo_path / "Cargo.toml"
    if toml_path.is_file():
        try:
            data = tomllib.loads(toml_path.read_text(encoding="utf-8", errors="ignore"))
            package = data.get("package", {})
            return package.get("name", repo_path.name), package.get("version", "0.0.0")
        except (OSError, tomllib.TOMLDecodeError):
            pass
    return repo_path.name, "0.0.0"


# ---------------------------------------------------------------------------
# Aggregation functions
# ---------------------------------------------------------------------------

# All supported manifest filenames
_SUPPORTED_MANIFESTS = [
    # npm
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "package.json",
    # Python
    "poetry.lock",
    "requirements.txt",
    "pyproject.toml",
    # Go
    "go.sum",
    "go.mod",
    # Rust
    "Cargo.lock",
    "Cargo.toml",
]


def detect_manifests(repo_path: Path) -> list[Path]:
    """Find all supported manifest files in the repo root."""
    found: list[Path] = []
    for name in _SUPPORTED_MANIFESTS:
        p = repo_path / name
        if p.is_file():
            found.append(p)
    return found


# Parser registry: (parser_fn, ecosystem, is_lockfile)
# Ordered by ecosystem and lockfile preference (lockfiles first)
_PARSER_REGISTRY: list[tuple] = [
    # npm: lockfiles first, then fallback
    (parse_npm_lockfile, "npm", True),
    (parse_yarn_lock, "npm", True),
    (parse_pnpm_lock, "npm", True),
    (parse_package_json, "npm", False),
    # Python: lockfiles first
    (parse_poetry_lock, "pypi", True),
    (parse_requirements_txt, "pypi", False),
    (parse_pyproject_toml, "pypi", False),
    # Go: lockfiles first
    (parse_go_sum, "golang", True),
    (parse_go_mod, "golang", False),
    # Rust: lockfiles first
    (parse_cargo_lock, "cargo", True),
    (parse_cargo_toml, "cargo", False),
]


def parse_all(repo_path: Path) -> ParseResult:
    """Run all parsers with lockfile preference, deduplicate by PURL.

    For each ecosystem, if a lockfile parser succeeds, skip fallback parsers.
    Merges results from all ecosystems into a single ParseResult.
    """
    merged = ParseResult()
    seen_purls: set[str] = set()
    parsed_ecosystems: set[str] = set()

    for parser_fn, ecosystem, is_lockfile in _PARSER_REGISTRY:
        # If we already have lockfile data for this ecosystem, skip fallbacks
        if ecosystem in parsed_ecosystems and not is_lockfile:
            continue

        result = parser_fn(repo_path)
        if result is None:
            continue

        # Mark this ecosystem as having lockfile data
        if is_lockfile:
            parsed_ecosystems.add(ecosystem)

        # Set main name/version from first successful result
        if not merged.main_name and result.main_name:
            merged.main_name = result.main_name
            merged.main_version = result.main_version

        # Set ecosystem if not yet set
        if not merged.ecosystem and result.ecosystem:
            merged.ecosystem = result.ecosystem

        # Deduplicate components by PURL string
        for comp in result.components:
            purl_str = str(comp.purl)
            if purl_str not in seen_purls:
                seen_purls.add(purl_str)
                merged.components.append(comp)

        # Merge dependency edges
        merged.dependencies.update(result.dependencies)

    return merged
