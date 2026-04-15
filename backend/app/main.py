from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routers import assessments, assets, reports, firewall

app = FastAPI(
    title="PCI DSS Scoping Tool API",
    description="Helps FSIs confirm PCI DSS scope per v4.0 Requirement 12.3",
    version="0.1.0",
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
    Catch-all handler so unhandled exceptions return a proper JSON 500 response
    that travels through CORSMiddleware (instead of being swallowed by
    Starlette's ServerErrorMiddleware which sends the response directly,
    bypassing CORS header injection).
    """
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

app.include_router(assessments.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(firewall.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
