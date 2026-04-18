from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.config import settings
from app.routers import assessments, assets, reports, firewall, auth


def _run_migrations() -> None:
    """Apply any pending Alembic migrations on startup.

    This ensures the DB schema is always up-to-date regardless of how the
    service is launched (e.g. if the startCommand in render.yaml is missing
    the `alembic upgrade head` step, or the service was configured manually).
    """
    from alembic.config import Config
    from alembic import command
    import os

    alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    alembic_cfg.set_main_option("script_location", os.path.join(os.path.dirname(__file__), "..", "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(alembic_cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _run_migrations()
    yield


app = FastAPI(
    title="PCI DSS Scoping Tool API",
    description="Helps FSIs confirm PCI DSS scope per v4.0 Requirement 12.3",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all handler so unhandled exceptions return a proper JSON 500 response.

    We also inject CORS headers here directly, because in some Starlette
    versions ServerErrorMiddleware can intercept the response before
    CORSMiddleware has a chance to add the Allow-Origin header, causing
    the browser to block the error response as a CORS violation.
    """
    origin = request.headers.get("origin", "")
    headers: dict[str, str] = {}
    if origin in settings.cors_origins_list:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
        headers=headers,
    )

app.include_router(assessments.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(firewall.router, prefix="/api")
app.include_router(auth.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
