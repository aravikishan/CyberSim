"""Model and schema tests for CyberSim."""

import pytest
from pydantic import ValidationError

from models.schemas import (
    Asset,
    AttackScenario,
    ThreatActor,
    Vulnerability,
    VulnerabilityCreate,
    AssetCreate,
    CVSSRequest,
)


class TestVulnerabilityModel:
    def test_create_vulnerability_record(self, db_session):
        vuln = Vulnerability(
            cve_id="CVE-2024-9999",
            title="Test Model Vuln",
            description="Testing ORM creation.",
            severity="CRITICAL",
            cvss_score=9.8,
        )
        db_session.add(vuln)
        db_session.commit()
        assert vuln.id is not None
        assert vuln.cve_id == "CVE-2024-9999"

    def test_vulnerability_create_schema_validation(self):
        schema = VulnerabilityCreate(
            cve_id="CVE-2024-1000",
            title="Schema Test",
            description="Valid schema.",
        )
        assert schema.severity == "MEDIUM"
        assert schema.cvss_score == 0.0

    def test_vulnerability_create_invalid_score(self):
        with pytest.raises(ValidationError):
            VulnerabilityCreate(
                cve_id="CVE-2024-BAD",
                title="Bad Score",
                description="Score too high.",
                cvss_score=15.0,
            )


class TestAssetModel:
    def test_create_asset_record(self, db_session):
        asset = Asset(
            name="DB Server",
            asset_type="Database",
            environment="Production",
            criticality="Critical",
            risk_score=85.0,
        )
        db_session.add(asset)
        db_session.commit()
        assert asset.id is not None

    def test_asset_create_schema_defaults(self):
        schema = AssetCreate(name="Test Asset")
        assert schema.asset_type == "Server"
        assert schema.environment == "Production"
        assert schema.criticality == "Medium"


class TestCVSSRequestSchema:
    def test_cvss_request_defaults(self):
        req = CVSSRequest()
        assert req.attack_vector == "N"
        assert req.scope == "U"
