from fastapi import FastAPI
from .db import init_db, insert_event
from .models import SecurityEvent, EventResponse
from .detection import detect_for_source

app = FastAPI(
    title="AI-Powered SOC Dashboard API",
    version="1.0.0",
    description="Local academic prototype for security event ingestion, detection, correlation and risk scoring."
)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def root():
    return {"project": "AI-Powered SOC Dashboard", "version": "V1", "status": "running"}

@app.post("/events", response_model=EventResponse)
def ingest_event(event: SecurityEvent):
    event_id = insert_event(event.model_dump())
    result = detect_for_source(event.source_ip)
    return EventResponse(event_id=event_id, message="Security event ingested and analyzed", **result)

@app.get("/health")
def health():
    return {"status": "ok"}
