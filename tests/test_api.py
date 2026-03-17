"""API endpoint tests for CyberSim."""

import pytest


class TestVulnerabilityAPI:
    def test_list_vulnerabilities_empty(self, client):
        resp = client.get("/api/vulnerabilities")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_vulnerability(self, client):
        payload = {
            "cve_id": "CVE-2024-0001",
            "title": "Test Vulnerability",
            "description": "A test vulnerability for unit testing.",
            "severity": "HIGH",
            "cvss_score": 7.5,
        }
        resp = client.post("/api/vulnerabilities", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-0001"
        assert data["cvss_score"] == 7.5
        assert data["severity"] == "HIGH"

    def test_get_vulnerability_not_found(self, client):
        resp = client.get("/api/vulnerabilities/999")
        assert resp.status_code == 404

    def test_create_duplicate_cve(self, client):
        payload = {
            "cve_id": "CVE-2024-0002",
            "title": "Dup Test",
            "description": "First entry.",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
        }
        client.post("/api/vulnerabilities", json=payload)
        resp = client.post("/api/vulnerabilities", json=payload)
        assert resp.status_code == 409

    def test_delete_vulnerability(self, client):
        payload = {
            "cve_id": "CVE-2024-0003",
            "title": "To Delete",
            "description": "Will be deleted.",
            "severity": "LOW",
            "cvss_score": 2.0,
        }
        create_resp = client.post("/api/vulnerabilities", json=payload)
        vuln_id = create_resp.json()["id"]
        del_resp = client.delete(f"/api/vulnerabilities/{vuln_id}")
        assert del_resp.status_code == 200


class TestScenarioAPI:
    def test_create_scenario(self, client):
        payload = {
            "name": "Phishing Campaign",
            "kill_chain_stage": "Delivery",
            "technique": "Spearphishing Attachment",
            "mitre_id": "T1566.001",
            "severity": "HIGH",
        }
        resp = client.post("/api/scenarios", json=payload)
        assert resp.status_code == 201
        assert resp.json()["name"] == "Phishing Campaign"

    def test_list_scenarios(self, client):
        resp = client.get("/api/scenarios")
        assert resp.status_code == 200


class TestAssetAPI:
    def test_create_asset(self, client):
        payload = {
            "name": "Web Server 01",
            "asset_type": "Server",
            "ip_address": "10.0.1.50",
            "environment": "Production",
            "criticality": "High",
        }
        resp = client.post("/api/assets", json=payload)
        assert resp.status_code == 201
        assert resp.json()["name"] == "Web Server 01"

    def test_list_assets(self, client):
        resp = client.get("/api/assets")
        assert resp.status_code == 200


class TestCVSSAPI:
    def test_cvss_calculate(self, client):
        payload = {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        }
        resp = client.post("/api/cvss/calculate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 9.8
        assert data["severity"] == "CRITICAL"


class TestKillChainAPI:
    def test_get_kill_chain(self, client):
        resp = client.get("/api/kill-chain")
        assert resp.status_code == 200
        stages = resp.json()
        assert len(stages) == 7
        assert stages[0]["stage"] == "Reconnaissance"


class TestDashboardAPI:
    def test_dashboard_empty(self, client):
        resp = client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vulnerabilities"] == 0
        assert data["avg_cvss"] == 0.0
