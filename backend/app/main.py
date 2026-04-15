from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

app.include_router(assessments.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(firewall.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
