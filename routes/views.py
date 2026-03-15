"""HTML-serving routes for CyberSim using Jinja2Templates."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from models.database import get_db
from models.schemas import Asset, AttackScenario, ThreatActor, Vulnerability
from services.simulator import get_kill_chain

router = APIRouter(tags=["views"])
templates = Jinja2Templates(directory="templates")


@router.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    """Security dashboard home page."""
    vulns = db.query(Vulnerability).all()
    scenarios = db.query(AttackScenario).all()
    assets = db.query(Asset).all()
    actors_count = db.query(ThreatActor).count()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    for v in vulns:
        sev = v.severity.upper() if v.severity else "MEDIUM"
        if sev in severity_counts:
            severity_counts[sev] += 1

    avg_cvss = 0.0
    if vulns:
        avg_cvss = round(sum(v.cvss_score for v in vulns) / len(vulns), 2)

    top_assets = sorted(assets, key=lambda a: a.risk_score, reverse=True)[:5]

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_vulns": len(vulns),
        "total_scenarios": len(scenarios),
        "total_assets": len(assets),
        "total_actors": actors_count,
        "severity_counts": severity_counts,
        "avg_cvss": avg_cvss,
        "top_assets": top_assets,
        "recent_vulns": vulns[:10],
    })


@router.get("/vulnerabilities")
def vulnerabilities_page(
    request: Request,
    severity: str = "",
    search: str = "",
    db: Session = Depends(get_db),
):
    """Vulnerability browser page."""
    q = db.query(Vulnerability)
    if severity:
        q = q.filter(Vulnerability.severity == severity.upper())
    if search:
        pattern = f"%{search}%"
        q = q.filter(
            Vulnerability.title.ilike(pattern)
            | Vulnerability.cve_id.ilike(pattern)
        )
    vulns = q.order_by(Vulnerability.cvss_score.desc()).all()

    return templates.TemplateResponse("vulnerabilities.html", {
        "request": request,
        "vulnerabilities": vulns,
        "current_severity": severity,
        "current_search": search,
    })


@router.get("/scenarios")
def scenarios_page(request: Request, db: Session = Depends(get_db)):
    """Attack scenario builder page."""
    scenarios = db.query(AttackScenario).all()
    vulns = db.query(Vulnerability).all()
    assets = db.query(Asset).all()
    actors = db.query(ThreatActor).all()
    kill_chain = get_kill_chain()

    return templates.TemplateResponse("scenarios.html", {
        "request": request,
        "scenarios": scenarios,
        "vulnerabilities": vulns,
        "assets": assets,
        "threat_actors": actors,
        "kill_chain": kill_chain,
    })


@router.get("/assets")
def assets_page(request: Request, db: Session = Depends(get_db)):
    """Asset inventory page."""
    assets = db.query(Asset).order_by(Asset.risk_score.desc()).all()
    return templates.TemplateResponse("assets.html", {
        "request": request,
        "assets": assets,
    })


@router.get("/about")
def about_page(request: Request):
    """About page."""
    return templates.TemplateResponse("about.html", {
        "request": request,
    })
