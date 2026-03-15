"""REST API endpoints for CyberSim."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from models.database import get_db
from models.schemas import (
    Asset,
    AssetCreate,
    AssetRead,
    AttackScenario,
    AttackScenarioCreate,
    AttackScenarioRead,
    CVSSRequest,
    CVSSResponse,
    DashboardStats,
    ThreatActor,
    ThreatActorCreate,
    ThreatActorRead,
    Vulnerability,
    VulnerabilityCreate,
    VulnerabilityRead,
)
from services.cvss import calculate_base_score
from services.simulator import (
    calculate_risk_score,
    get_kill_chain,
    get_techniques_for_stage,
    simulate_attack,
)

router = APIRouter(prefix="/api", tags=["api"])


# ── Dashboard ──────────────────────────────────────────────────────────────


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return aggregate statistics for the security dashboard."""
    vulns = db.query(Vulnerability).all()
    scenarios = db.query(AttackScenario).all()
    assets = db.query(Asset).all()
    actors = db.query(ThreatActor).count()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_cvss = 0.0
    for v in vulns:
        sev = v.severity.upper() if v.severity else "MEDIUM"
        if sev in severity_counts:
            severity_counts[sev] += 1
        total_cvss += v.cvss_score or 0.0

    stages_count = {}
    for sc in scenarios:
        stage = sc.kill_chain_stage or "Unknown"
        stages_count[stage] = stages_count.get(stage, 0) + 1

    sorted_assets = sorted(assets, key=lambda a: a.risk_score, reverse=True)
    top_risky = [
        {"name": a.name, "risk_score": a.risk_score, "criticality": a.criticality}
        for a in sorted_assets[:5]
    ]

    avg_cvss = round(total_cvss / len(vulns), 2) if vulns else 0.0
    total_risk = sum(a.risk_score for a in assets)
    avg_risk = round(total_risk / len(assets), 1) if assets else 0.0

    return DashboardStats(
        total_vulnerabilities=len(vulns),
        total_scenarios=len(scenarios),
        total_assets=len(assets),
        total_threat_actors=actors,
        critical_vulns=severity_counts["CRITICAL"],
        high_vulns=severity_counts["HIGH"],
        medium_vulns=severity_counts["MEDIUM"],
        low_vulns=severity_counts["LOW"],
        avg_cvss=avg_cvss,
        avg_risk_score=avg_risk,
        scenarios_by_stage=stages_count,
        top_risky_assets=top_risky,
    )


# ── Vulnerabilities ───────────────────────────────────────────────────────


@router.get("/vulnerabilities", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List vulnerabilities with optional filters."""
    q = db.query(Vulnerability)
    if severity:
        q = q.filter(Vulnerability.severity == severity.upper())
    if search:
        pattern = f"%{search}%"
        q = q.filter(
            Vulnerability.title.ilike(pattern)
            | Vulnerability.cve_id.ilike(pattern)
            | Vulnerability.description.ilike(pattern)
        )
    return q.order_by(Vulnerability.cvss_score.desc()).offset(skip).limit(limit).all()


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityRead)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Get a single vulnerability by ID."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.post("/vulnerabilities", response_model=VulnerabilityRead, status_code=201)
def create_vulnerability(data: VulnerabilityCreate, db: Session = Depends(get_db)):
    """Create a new vulnerability entry."""
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id == data.cve_id).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"CVE {data.cve_id} already exists")
    vuln = Vulnerability(**data.model_dump())
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


@router.put("/vulnerabilities/{vuln_id}", response_model=VulnerabilityRead)
def update_vulnerability(vuln_id: int, data: VulnerabilityCreate, db: Session = Depends(get_db)):
    """Update an existing vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    for key, value in data.model_dump().items():
        setattr(vuln, key, value)
    db.commit()
    db.refresh(vuln)
    return vuln


@router.delete("/vulnerabilities/{vuln_id}")
def delete_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    """Delete a vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    db.delete(vuln)
    db.commit()
    return {"detail": "Deleted"}


# ── Attack Scenarios ───────────────────────────────────────────────────────


@router.get("/scenarios", response_model=list[AttackScenarioRead])
def list_scenarios(
    stage: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List attack scenarios with optional filters."""
    q = db.query(AttackScenario)
    if stage:
        q = q.filter(AttackScenario.kill_chain_stage == stage)
    if severity:
        q = q.filter(AttackScenario.severity == severity.upper())
    return q.offset(skip).limit(limit).all()


@router.get("/scenarios/{scenario_id}", response_model=AttackScenarioRead)
def get_scenario(scenario_id: int, db: Session = Depends(get_db)):
    """Get a single scenario by ID."""
    sc = db.query(AttackScenario).filter(AttackScenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return sc


@router.post("/scenarios", response_model=AttackScenarioRead, status_code=201)
def create_scenario(data: AttackScenarioCreate, db: Session = Depends(get_db)):
    """Create a new attack scenario."""
    sc = AttackScenario(**data.model_dump())
    db.add(sc)
    db.commit()
    db.refresh(sc)
    return sc


@router.put("/scenarios/{scenario_id}", response_model=AttackScenarioRead)
def update_scenario(scenario_id: int, data: AttackScenarioCreate, db: Session = Depends(get_db)):
    """Update an existing scenario."""
    sc = db.query(AttackScenario).filter(AttackScenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    for key, value in data.model_dump().items():
        setattr(sc, key, value)
    db.commit()
    db.refresh(sc)
    return sc


@router.delete("/scenarios/{scenario_id}")
def delete_scenario(scenario_id: int, db: Session = Depends(get_db)):
    """Delete a scenario."""
    sc = db.query(AttackScenario).filter(AttackScenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")
    db.delete(sc)
    db.commit()
    return {"detail": "Deleted"}


# ── Assets ─────────────────────────────────────────────────────────────────


@router.get("/assets", response_model=list[AssetRead])
def list_assets(
    asset_type: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List assets with optional filters."""
    q = db.query(Asset)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    if environment:
        q = q.filter(Asset.environment == environment)
    return q.order_by(Asset.risk_score.desc()).offset(skip).limit(limit).all()


@router.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get a single asset by ID."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/assets", response_model=AssetRead, status_code=201)
def create_asset(data: AssetCreate, db: Session = Depends(get_db)):
    """Create a new asset."""
    asset = Asset(**data.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.put("/assets/{asset_id}", response_model=AssetRead)
def update_asset(asset_id: int, data: AssetCreate, db: Session = Depends(get_db)):
    """Update an existing asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for key, value in data.model_dump().items():
        setattr(asset, key, value)
    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    """Delete an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    return {"detail": "Deleted"}


# ── Threat Actors ──────────────────────────────────────────────────────────


@router.get("/threat-actors", response_model=list[ThreatActorRead])
def list_threat_actors(
    actor_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """List threat actors."""
    q = db.query(ThreatActor)
    if actor_type:
        q = q.filter(ThreatActor.actor_type == actor_type)
    return q.offset(skip).limit(limit).all()


@router.post("/threat-actors", response_model=ThreatActorRead, status_code=201)
def create_threat_actor(data: ThreatActorCreate, db: Session = Depends(get_db)):
    """Create a new threat actor profile."""
    actor = ThreatActor(**data.model_dump())
    db.add(actor)
    db.commit()
    db.refresh(actor)
    return actor


@router.delete("/threat-actors/{actor_id}")
def delete_threat_actor(actor_id: int, db: Session = Depends(get_db)):
    """Delete a threat actor."""
    actor = db.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    db.delete(actor)
    db.commit()
    return {"detail": "Deleted"}


# ── CVSS Calculator ───────────────────────────────────────────────────────


@router.post("/cvss/calculate", response_model=CVSSResponse)
def cvss_calculate(data: CVSSRequest):
    """Calculate CVSS v3.1 base score from metrics."""
    result = calculate_base_score(
        av=data.attack_vector,
        ac=data.attack_complexity,
        pr=data.privileges_required,
        ui=data.user_interaction,
        s=data.scope,
        c=data.confidentiality,
        i=data.integrity,
        a=data.availability,
    )
    return CVSSResponse(**result)


# ── Kill Chain / Simulation ────────────────────────────────────────────────


@router.get("/kill-chain")
def get_kill_chain_stages():
    """Return the full kill chain definition with techniques."""
    return get_kill_chain()


@router.get("/kill-chain/{stage}/techniques")
def get_stage_techniques(stage: str):
    """Return techniques for a specific kill chain stage."""
    techniques = get_techniques_for_stage(stage)
    if not techniques:
        raise HTTPException(status_code=404, detail=f"Stage '{stage}' not found")
    return techniques


@router.post("/simulate")
def run_simulation(
    stages: list[str],
    techniques: list[str] = [],
    target_criticality: str = "Medium",
    attacker_sophistication: str = "Medium",
):
    """Run an attack simulation through specified kill chain stages."""
    result = simulate_attack(
        stages=stages,
        techniques=techniques,
        target_asset_criticality=target_criticality,
        attacker_sophistication=attacker_sophistication,
    )
    return result


@router.get("/risk-score")
def compute_risk_score(
    cvss_score: float = Query(..., ge=0, le=10),
    exposure: str = Query("External"),
    asset_criticality: str = Query("High"),
):
    """Calculate composite risk score."""
    score = calculate_risk_score(cvss_score, exposure, asset_criticality)
    return {"risk_score": score, "cvss_score": cvss_score, "exposure": exposure, "criticality": asset_criticality}
