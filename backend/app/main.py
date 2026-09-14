from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router, get_current_user
from app.api.events import router as events_router
from app.api.stats import router as stats_router
from app.api.ingest import router as ingest_router
from app.api.devices import router as devices_router
from app.api.mappings import router as mappings_router
from app.api.exports import router as exports_router
from app.api.process import router as process_router
from app.api.scanner import router as scanner_router
from app.storage.database import initialize_database

app = FastAPI(
    title="ULPF — Universal Log Processing Framework",
    description="Local-first universal telemetry ingestion and normalization platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/health")
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "ulpf-api",
        "version": "2.0.0",
    }


# Production canonical routers
app.include_router(auth_router)
app.include_router(ingest_router, dependencies=[Depends(get_current_user)])
app.include_router(devices_router, dependencies=[Depends(get_current_user)])
app.include_router(events_router, dependencies=[Depends(get_current_user)])
app.include_router(mappings_router, dependencies=[Depends(get_current_user)])
app.include_router(exports_router, dependencies=[Depends(get_current_user)])
app.include_router(stats_router, dependencies=[Depends(get_current_user)])

# Compatibility aliases
app.include_router(process_router, dependencies=[Depends(get_current_user)])
app.include_router(scanner_router, dependencies=[Depends(get_current_user)])