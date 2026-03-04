import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mcp_scanner.api.auth import require_api_key
from mcp_scanner.api.report_routes import router as report_router
from mcp_scanner.api.routes import router
from mcp_scanner.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)

app = FastAPI(title="MCP Security Scanner", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, dependencies=[Depends(require_api_key)])
app.include_router(report_router, dependencies=[Depends(require_api_key)])


@app.get("/health")
async def health():
    return {"status": "ok"}
