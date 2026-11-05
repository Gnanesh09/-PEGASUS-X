import json, os
from typing import Literal
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .store import init_store, get_events, get_rounds, clear_events
from .engine import SimulationEngine
from .config import GROQ_API_KEY, POSTGRES_DSN, POSTGRES_TEST_DSN, ENABLE_LAB_TESTS
from .lab_tests import check_lab_connection, lab_configuration

app = FastAPI(title="PEGASUS-X", version="1.1.0",
              description="Local multi-agent cyber defense research lab")
engine = SimulationEngine()
BASE = os.path.dirname(os.path.dirname(__file__))
app.mount("/assets", StaticFiles(directory=os.path.join(BASE, "frontend")), name="assets")

@app.on_event("startup")
def startup():
    init_store()

@app.get("/")
def home():
    return FileResponse(os.path.join(BASE, "frontend", "index.html"))

class StartRequest(BaseModel):
    max_rounds: int = Field(default=4, ge=1, le=100)
    interval: int = Field(default=3, ge=1, le=60)
    mode: Literal["simulation", "real_lab"] = "simulation"

@app.get("/api/health")
def health():
    lab_ok, lab_message = lab_configuration()
    return {"ok": True, "product": "PEGASUS-X", "groq_configured": bool(GROQ_API_KEY),
            "postgres_configured": bool(POSTGRES_DSN and POSTGRES_TEST_DSN),
            "live_lab_enabled": lab_ok, "live_lab_message": lab_message,
            "graph_status": engine.graph_status}

@app.get("/api/status")
def status():
    return engine.status()

@app.post("/api/start")
def start(req: StartRequest):
    ok, message = engine.start(req.max_rounds, req.interval, req.mode)
    if not ok and req.mode == "real_lab":
        raise HTTPException(status_code=400, detail=message)
    return {"started": ok, "message": message}

@app.post("/api/stop")
def stop():
    engine.stop()
    return {"stopping": True}

@app.get("/api/events")
def events(limit: int = 100):
    from .store import get_events
    return get_events(max(1, min(limit, 500)))

@app.get("/api/rounds")
def rounds():
    return get_rounds()

@app.get("/api/report/latest")
def latest_report():
    if not engine.last_report:
        return {"report": None}
    try:
        return {"report": json.loads(engine.last_report)}
    except Exception:
        return {"report": engine.last_report}

@app.post("/api/reset")
def reset():
    if engine.running:
        return {"ok": False, "message": "Stop the simulation before resetting."}
    clear_events()
    engine.last_report = None
    engine.round_no = 0
    return {"ok": True}

@app.get("/api/lab-check")
def lab_check():
    return check_lab_connection()
