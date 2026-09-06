from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.events import router as events_router
from app.api.stats import router as stats_router
from app.api.process import router as process_router
from app.storage.database import initialize_database
from app.api.mappings import router as mappings_router
from app.api.scanner import router as scanner_router

app = FastAPI(
    title="ULPF API",
    description="Universal Log Pre-processing Framework API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    initialize_database()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ulpf-api",
    }


app.include_router(events_router)
app.include_router(stats_router)
app.include_router(process_router)
app.include_router(mappings_router)
app.include_router(scanner_router)