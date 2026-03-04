FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root
WORKDIR /app

# System deps for native Python packages (WeasyPrint, yara-python, tree-sitter)
RUN apk add --no-cache \
    build-base \
    pango-dev \
    cairo-dev \
    gdk-pixbuf-dev \
    fontconfig-dev \
    harfbuzz-dev \
    glib-dev \
    git \
    yara-dev

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
COPY src/ src/
RUN uv pip install --system "." && \
    pip install --no-cache-dir semgrep

# ── Runtime stage ──
FROM cgr.dev/chainguard/python:latest-dev

USER root
WORKDIR /app

# Runtime-only native libs + tools needed by the scanner
RUN apk add --no-cache \
    pango \
    cairo \
    gdk-pixbuf \
    fontconfig \
    harfbuzz \
    glib \
    font-noto \
    git \
    nodejs \
    npm \
    curl \
    yara

# Copy installed Python packages from builder (system site-packages + scripts)
COPY --from=builder /usr/lib/python3.14/site-packages/ /usr/lib/python3.14/site-packages/
COPY --from=builder /usr/bin/uvicorn /usr/bin/uvicorn
COPY --from=builder /usr/bin/semgrep /usr/bin/semgrep

COPY pyproject.toml .
COPY src/ src/
COPY entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

# Install the package in editable mode so mcp_scanner is importable
RUN pip install --no-cache-dir -e "."

USER nonroot
EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "mcp_scanner.main:app", "--host", "0.0.0.0", "--port", "8000"]
