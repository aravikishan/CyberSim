"""CyberSim -- Cybersecurity Attack Scenario Simulator.

FastAPI application entry point.  Start with:
    uvicorn app:app --host 0.0.0.0 --port 8002 --reload
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import config
from models.database import SessionLocal, init_db
from models.schemas import Asset, AttackScenario, ThreatActor, Vulnerability
from routes.api import router as api_router
from routes.views import router as views_router


# v1.0.1 - Updated for clarity
def _seed_database() -> None:
    """Load seed data if the database is empty."""
    db = SessionLocal()
    try:
        if db.query(Vulnerability).count() > 0:
            return

        seed_path = config.SEED_DATA_PATH
        if not os.path.exists(seed_path):
            return

        with open(seed_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for item in data.get("vulnerabilities", []):
            db.add(Vulnerability(**item))

        for item in data.get("threat_actors", []):
            db.add(ThreatActor(**item))

        for item in data.get("assets", []):
            db.add(Asset(**item))

        db.commit()

        # Add scenarios after other entities exist
        for item in data.get("scenarios", []):
            db.add(AttackScenario(**item))
        db.commit()

    except Exception as exc:
        db.rollback()
        print(f"[CyberSim] Seed data error: {exc}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Startup / shutdown lifecycle."""
    init_db()
    _seed_database()
    yield


app = FastAPI(
    title=config.APP_NAME,
    description=config.APP_DESCRIPTION,
    version=config.APP_VERSION,
    lifespan=lifespan,
)

# Static files
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Routers
app.include_router(api_router)
app.include_router(views_router)
