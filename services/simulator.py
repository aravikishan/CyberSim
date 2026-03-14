"""Attack scenario simulation engine.

Provides the logic for building and evaluating attack scenarios
using the Cyber Kill Chain model and MITRE ATT&CK techniques.
"""

from __future__ import annotations

import random
from typing import Any, Optional

from services.cvss import calculate_base_score, severity_rating


# ── Kill Chain Stages ──────────────────────────────────────────────────────

KILL_CHAIN = [
    {
        "stage": "Reconnaissance",
        "description": "Adversary identifies and selects targets, gathers information.",
        "techniques": [
            {"id": "T1595", "name": "Active Scanning", "description": "Scanning IP blocks to identify live hosts and services."},
            {"id": "T1592", "name": "Gather Victim Host Info", "description": "Collect details about victim host configurations."},
            {"id": "T1589", "name": "Gather Victim Identity Info", "description": "Collect credentials, email addresses, employee names."},
            {"id": "T1590", "name": "Gather Victim Network Info", "description": "Discover network topology, DNS, and domain info."},
            {"id": "T1593", "name": "Search Open Websites/Domains", "description": "Harvest data from public websites and social media."},
        ],
    },
    {
        "stage": "Weaponization",
        "description": "Adversary creates malicious payload tailored to the target.",
        "techniques": [
            {"id": "T1587.001", "name": "Develop Malware", "description": "Custom malware development for the campaign."},
            {"id": "T1587.003", "name": "Develop Digital Certificates", "description": "Create code-signing certificates for legitimacy."},
            {"id": "T1588.002", "name": "Obtain Tool", "description": "Acquire offensive tools (Cobalt Strike, Metasploit)."},
            {"id": "T1585", "name": "Establish Accounts", "description": "Create fake social media/email accounts for phishing."},
        ],
    },
    {
        "stage": "Delivery",
        "description": "Adversary transmits the weapon to the target environment.",
        "techniques": [
            {"id": "T1566.001", "name": "Spearphishing Attachment", "description": "Targeted email with malicious attachment."},
            {"id": "T1566.002", "name": "Spearphishing Link", "description": "Email with link to adversary-controlled site."},
            {"id": "T1189", "name": "Drive-by Compromise", "description": "Compromise visited websites to exploit browser vulns."},
            {"id": "T1195", "name": "Supply Chain Compromise", "description": "Manipulate software supply chain for delivery."},
            {"id": "T1091", "name": "Removable Media", "description": "Spread via USB drives or other removable media."},
        ],
    },
    {
        "stage": "Exploitation",
        "description": "Adversary exploits a vulnerability to gain access.",
        "techniques": [
            {"id": "T1203", "name": "Exploitation for Client Execution", "description": "Exploit software vulnerability in client app."},
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "description": "Exploit vulnerability to gain elevated privileges."},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "description": "Target web apps, databases, or standard services."},
            {"id": "T1210", "name": "Exploitation of Remote Services", "description": "Exploit remote services like SMB, RDP."},
        ],
    },
    {
        "stage": "Installation",
        "description": "Adversary installs persistent access mechanism on target.",
        "techniques": [
            {"id": "T1543", "name": "Create System Service", "description": "Install malware as a system service for persistence."},
            {"id": "T1547", "name": "Boot/Logon Autostart", "description": "Add entries to startup for automatic execution."},
            {"id": "T1053", "name": "Scheduled Task/Job", "description": "Use task scheduler for persistent execution."},
            {"id": "T1136", "name": "Create Account", "description": "Create backdoor user accounts for access."},
            {"id": "T1505", "name": "Server Software Component", "description": "Install web shell or IIS module for persistence."},
        ],
    },
    {
        "stage": "Command & Control",
        "description": "Adversary establishes communication channel with compromised system.",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol", "description": "Use HTTP/HTTPS/DNS for C2 communication."},
            {"id": "T1573", "name": "Encrypted Channel", "description": "Encrypt C2 traffic to evade detection."},
            {"id": "T1572", "name": "Protocol Tunneling", "description": "Tunnel C2 inside legitimate protocols."},
            {"id": "T1090", "name": "Proxy", "description": "Route C2 traffic through proxy infrastructure."},
            {"id": "T1102", "name": "Web Service", "description": "Use legitimate web services (Dropbox, GitHub) for C2."},
        ],
    },
    {
        "stage": "Actions on Objectives",
        "description": "Adversary accomplishes their mission goals.",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "description": "Steal data over the existing C2 channel."},
            {"id": "T1486", "name": "Data Encrypted for Impact", "description": "Ransomware - encrypt data for extortion."},
            {"id": "T1565", "name": "Data Manipulation", "description": "Modify data to affect business processes."},
            {"id": "T1499", "name": "Endpoint Denial of Service", "description": "Overload systems to disrupt availability."},
            {"id": "T1529", "name": "System Shutdown/Reboot", "description": "Shut down systems for destructive impact."},
        ],
    },
]


def get_kill_chain() -> list[dict[str, Any]]:
    """Return the full kill chain definition with techniques."""
    return KILL_CHAIN


def get_techniques_for_stage(stage: str) -> list[dict[str, str]]:
    """Return techniques available for a given kill chain stage."""
    for entry in KILL_CHAIN:
        if entry["stage"].lower() == stage.lower():
            return entry["techniques"]
    return []


def calculate_risk_score(
    cvss_score: float,
    exposure: str = "External",
    asset_criticality: str = "High",
) -> float:
    """Calculate a composite risk score (0-100) from multiple factors.

    Parameters
    ----------
    cvss_score : float
        CVSS base score (0-10)
    exposure : str
        Network exposure: External, Internal, Isolated
    asset_criticality : str
        Asset value: Critical, High, Medium, Low
    """
    exposure_map = {
        "External": 1.0,
        "Internal": 0.6,
        "Isolated": 0.3,
    }
    criticality_map = {
        "Critical": 1.0,
        "High": 0.8,
        "Medium": 0.5,
        "Low": 0.2,
    }

    vuln_factor = (cvss_score / 10.0) * 40
    exposure_factor = exposure_map.get(exposure, 0.5) * 30
    criticality_factor = criticality_map.get(asset_criticality, 0.5) * 30

    return round(min(vuln_factor + exposure_factor + criticality_factor, 100.0), 1)


def simulate_attack(
    stages: list[str],
    techniques: list[str],
    target_asset_criticality: str = "Medium",
    attacker_sophistication: str = "Medium",
) -> dict[str, Any]:
    """Simulate an attack through kill chain stages.

    Returns a result dict with success probability, timeline, and recommendations.
    """
    sophistication_modifier = {
        "Nation-State": 0.9,
        "Advanced": 0.75,
        "Medium": 0.5,
        "Low": 0.3,
        "Script Kiddie": 0.15,
    }

    criticality_modifier = {
        "Critical": 0.3,
        "High": 0.5,
        "Medium": 0.7,
        "Low": 0.85,
    }

    base_success = sophistication_modifier.get(attacker_sophistication, 0.5)
    defense_factor = criticality_modifier.get(target_asset_criticality, 0.7)

    timeline = []
    cumulative_probability = 1.0

    for idx, stage in enumerate(stages):
        stage_success = base_success * (0.9 ** idx)
        stage_success *= (1 - defense_factor * 0.3)

        stage_success = max(0.05, min(0.95, stage_success))
        cumulative_probability *= stage_success

        random.seed(hash(f"{stage}-{idx}"))
        hours = random.randint(1, 72) * (idx + 1)

        timeline.append({
            "stage": stage,
            "success_probability": round(stage_success * 100, 1),
            "estimated_hours": hours,
            "techniques_used": [t for t in techniques if t],
        })

    mitigations = _generate_mitigations(stages)

    overall_success = round(cumulative_probability * 100, 2)
    risk_level = "CRITICAL" if overall_success > 60 else                  "HIGH" if overall_success > 40 else                  "MEDIUM" if overall_success > 20 else "LOW"

    return {
        "overall_success_probability": overall_success,
        "risk_level": risk_level,
        "timeline": timeline,
        "total_estimated_hours": sum(t["estimated_hours"] for t in timeline),
        "mitigations": mitigations,
        "stages_count": len(stages),
    }


def _generate_mitigations(stages: list[str]) -> list[dict[str, str]]:
    """Generate recommended mitigations based on kill chain stages."""
    mitigation_map = {
        "Reconnaissance": {
            "control": "Network Monitoring",
            "description": "Deploy network IDS/IPS to detect scanning activity.",
            "priority": "Medium",
        },
        "Weaponization": {
            "control": "Threat Intelligence",
            "description": "Subscribe to threat feeds and monitor for new malware samples.",
            "priority": "Medium",
        },
        "Delivery": {
            "control": "Email Security Gateway",
            "description": "Implement advanced email filtering with sandboxing for attachments.",
            "priority": "High",
        },
        "Exploitation": {
            "control": "Patch Management",
            "description": "Maintain aggressive patching cadence, prioritize CVSS 7+ vulnerabilities.",
            "priority": "Critical",
        },
        "Installation": {
            "control": "Endpoint Protection",
            "description": "Deploy EDR with application whitelisting and behavioral analysis.",
            "priority": "High",
        },
        "Command & Control": {
            "control": "Network Segmentation",
            "description": "Implement micro-segmentation and monitor egress traffic for anomalies.",
            "priority": "High",
        },
        "Actions on Objectives": {
            "control": "Data Loss Prevention",
            "description": "Deploy DLP controls and maintain offline backups with tested recovery.",
            "priority": "Critical",
        },
    }

    mitigations = []
    for stage in stages:
        if stage in mitigation_map:
            mitigations.append(mitigation_map[stage])
    return mitigations
