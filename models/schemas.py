"""SQLAlchemy ORM models and Pydantic schemas for CyberSim."""

from __future__ import annotations

import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from models.database import Base


# ── SQLAlchemy ORM Models ──────────────────────────────────────────────────


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM")
    cvss_score = Column(Float, nullable=False, default=0.0)
    cvss_vector = Column(String(100), nullable=True)
    affected_product = Column(String(255), nullable=True)
    affected_vendor = Column(String(255), nullable=True)
    published_date = Column(String(20), nullable=True)
    status = Column(String(20), nullable=False, default="Open")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    scenarios = relationship(
        "AttackScenario", back_populates="vulnerability", cascade="all, delete-orphan"
    )


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    alias = Column(String(255), nullable=True)
    actor_type = Column(String(50), nullable=False, default="Unknown")
    origin_country = Column(String(100), nullable=True)
    sophistication = Column(String(50), nullable=False, default="Medium")
    motivation = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    first_seen = Column(String(20), nullable=True)
    last_active = Column(String(20), nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    scenarios = relationship(
        "AttackScenario", back_populates="threat_actor", cascade="all, delete-orphan"
    )


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    asset_type = Column(String(50), nullable=False, default="Server")
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_info = Column(String(100), nullable=True)
    environment = Column(String(50), nullable=False, default="Production")
    owner = Column(String(100), nullable=True)
    criticality = Column(String(20), nullable=False, default="Medium")
    risk_score = Column(Float, nullable=False, default=0.0)
    status = Column(String(20), nullable=False, default="Active")
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    scenarios = relationship(
        "AttackScenario", back_populates="target_asset", cascade="all, delete-orphan"
    )


class AttackScenario(Base):
    __tablename__ = "attack_scenarios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    kill_chain_stage = Column(String(50), nullable=False, default="Reconnaissance")
    technique = Column(String(255), nullable=True)
    mitre_id = Column(String(20), nullable=True)
    severity = Column(String(20), nullable=False, default="MEDIUM")
    likelihood = Column(String(20), nullable=False, default="Medium")
    impact = Column(String(20), nullable=False, default="Medium")
    status = Column(String(20), nullable=False, default="Draft")
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)
    threat_actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    target_asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    vulnerability = relationship("Vulnerability", back_populates="scenarios")
    threat_actor = relationship("ThreatActor", back_populates="scenarios")
    target_asset = relationship("Asset", back_populates="scenarios")


# ── Pydantic Schemas ───────────────────────────────────────────────────────


class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=20)
    title: str = Field(..., min_length=1, max_length=255)
    description: str
    severity: str = "MEDIUM"
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    affected_product: Optional[str] = None
    affected_vendor: Optional[str] = None
    published_date: Optional[str] = None
    status: str = "Open"


class VulnerabilityRead(BaseModel):
    id: int
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    affected_product: Optional[str]
    affected_vendor: Optional[str]
    published_date: Optional[str]
    status: str

    model_config = {"from_attributes": True}


class ThreatActorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    alias: Optional[str] = None
    actor_type: str = "Unknown"
    origin_country: Optional[str] = None
    sophistication: str = "Medium"
    motivation: Optional[str] = None
    description: Optional[str] = None
    first_seen: Optional[str] = None
    last_active: Optional[str] = None


class ThreatActorRead(BaseModel):
    id: int
    name: str
    alias: Optional[str]
    actor_type: str
    origin_country: Optional[str]
    sophistication: str
    motivation: Optional[str]
    description: Optional[str]
    first_seen: Optional[str]
    last_active: Optional[str]

    model_config = {"from_attributes": True}


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    asset_type: str = "Server"
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    environment: str = "Production"
    owner: Optional[str] = None
    criticality: str = "Medium"
    risk_score: float = Field(0.0, ge=0.0, le=100.0)
    status: str = "Active"


class AssetRead(BaseModel):
    id: int
    name: str
    asset_type: str
    ip_address: Optional[str]
    hostname: Optional[str]
    os_info: Optional[str]
    environment: str
    owner: Optional[str]
    criticality: str
    risk_score: float
    status: str

    model_config = {"from_attributes": True}


class AttackScenarioCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    kill_chain_stage: str = "Reconnaissance"
    technique: Optional[str] = None
    mitre_id: Optional[str] = None
    severity: str = "MEDIUM"
    likelihood: str = "Medium"
    impact: str = "Medium"
    status: str = "Draft"
    vulnerability_id: Optional[int] = None
    threat_actor_id: Optional[int] = None
    target_asset_id: Optional[int] = None


class AttackScenarioRead(BaseModel):
    id: int
    name: str
    description: Optional[str]
    kill_chain_stage: str
    technique: Optional[str]
    mitre_id: Optional[str]
    severity: str
    likelihood: str
    impact: str
    status: str
    vulnerability_id: Optional[int]
    threat_actor_id: Optional[int]
    target_asset_id: Optional[int]

    model_config = {"from_attributes": True}


class CVSSRequest(BaseModel):
    """CVSS v3.1 base metric input."""
    attack_vector: str = Field("N", description="AV: N, A, L, P")
    attack_complexity: str = Field("L", description="AC: L, H")
    privileges_required: str = Field("N", description="PR: N, L, H")
    user_interaction: str = Field("N", description="UI: N, R")
    scope: str = Field("U", description="S: U, C")
    confidentiality: str = Field("H", description="C: N, L, H")
    integrity: str = Field("H", description="I: N, L, H")
    availability: str = Field("H", description="A: N, L, H")


class CVSSResponse(BaseModel):
    score: float
    severity: str
    vector_string: str
    breakdown: dict


class DashboardStats(BaseModel):
    total_vulnerabilities: int
    total_scenarios: int
    total_assets: int
    total_threat_actors: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int
    avg_cvss: float
    avg_risk_score: float
    scenarios_by_stage: dict
    top_risky_assets: list
