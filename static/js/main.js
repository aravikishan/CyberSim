/* ====================================================================
   CyberSim -- Client-side JavaScript
   CVSS calculator, severity charts, attack simulation, CRUD helpers
   ==================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    initSeverityChart();
    initCVSSCalculator();
    initTogglePanels();
    initScenarioForm();
    initAssetForm();
    initDeleteHandlers();
    initSimulation();
});

/* ── Severity Distribution Chart ─────────────────────────────────────── */

function initSeverityChart() {
    const container = document.getElementById('severity-chart');
    if (!container) return;

    const critical = parseInt(container.dataset.critical || '0', 10);
    const high = parseInt(container.dataset.high || '0', 10);
    const medium = parseInt(container.dataset.medium || '0', 10);
    const low = parseInt(container.dataset.low || '0', 10);

    const maxVal = Math.max(critical, high, medium, low, 1);

    const data = [
        { label: 'Critical', value: critical, color: '#ff1744' },
        { label: 'High', value: high, color: '#ff6d00' },
        { label: 'Medium', value: medium, color: '#ffab00' },
        { label: 'Low', value: low, color: '#00c853' },
    ];

    container.innerHTML = '';
    data.forEach(item => {
        const group = document.createElement('div');
        group.className = 'chart-bar-group';

        const valueEl = document.createElement('div');
        valueEl.className = 'chart-bar-value';
        valueEl.textContent = item.value;
        valueEl.style.color = item.color;

        const bar = document.createElement('div');
        bar.className = 'chart-bar';
        bar.style.backgroundColor = item.color;
        bar.style.height = Math.max((item.value / maxVal) * 150, 4) + 'px';

        const labelEl = document.createElement('div');
        labelEl.className = 'chart-bar-label';
        labelEl.textContent = item.label;
        labelEl.style.color = item.color;

        group.appendChild(valueEl);
        group.appendChild(bar);
        group.appendChild(labelEl);
        container.appendChild(group);
    });
}

/* ── CVSS v3.1 Calculator (client-side mirror) ──────────────────────── */

const CVSS_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const CVSS_AC = { L: 0.77, H: 0.44 };
const CVSS_PR_U = { N: 0.85, L: 0.62, H: 0.27 };
const CVSS_PR_C = { N: 0.85, L: 0.68, H: 0.50 };
const CVSS_UI = { N: 0.85, R: 0.62 };
const CVSS_CIA = { H: 0.56, L: 0.22, N: 0.00 };

function roundUp(val) {
    return Math.ceil(val * 10) / 10;
}

function calcCVSS(metrics) {
    const av = CVSS_AV[metrics.AV] || 0.85;
    const ac = CVSS_AC[metrics.AC] || 0.77;
    const scopeChanged = metrics.S === 'C';
    const prMap = scopeChanged ? CVSS_PR_C : CVSS_PR_U;
    const pr = prMap[metrics.PR] || 0.85;
    const ui = CVSS_UI[metrics.UI] || 0.85;
    const c = CVSS_CIA[metrics.C] || 0.56;
    const i = CVSS_CIA[metrics.I] || 0.56;
    const a = CVSS_CIA[metrics.A] || 0.56;

    const exploitability = 8.22 * av * ac * pr * ui;
    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);

    let impact;
    if (scopeChanged) {
        impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    } else {
        impact = 6.42 * iscBase;
    }

    let score;
    if (impact <= 0) {
        score = 0.0;
    } else if (scopeChanged) {
        score = roundUp(Math.min(1.08 * (impact + exploitability), 10.0));
    } else {
        score = roundUp(Math.min(impact + exploitability, 10.0));
    }

    return score;
}

function getSeverity(score) {
    if (score === 0) return 'NONE';
    if (score <= 3.9) return 'LOW';
    if (score <= 6.9) return 'MEDIUM';
    if (score <= 8.9) return 'HIGH';
    return 'CRITICAL';
}

function initCVSSCalculator() {
    const calc = document.getElementById('cvss-calculator');
    if (!calc) return;

    const metrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };

    calc.querySelectorAll('.metric-buttons').forEach(group => {
        const metric = group.dataset.metric;
        group.querySelectorAll('.metric-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                group.querySelectorAll('.metric-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                metrics[metric] = btn.dataset.value;
                updateCVSSDisplay(metrics);
            });
        });
    });

    updateCVSSDisplay(metrics);
}

function updateCVSSDisplay(metrics) {
    const score = calcCVSS(metrics);
    const severity = getSeverity(score);
    const vector = `CVSS:3.1/AV:${metrics.AV}/AC:${metrics.AC}/PR:${metrics.PR}/UI:${metrics.UI}/S:${metrics.S}/C:${metrics.C}/I:${metrics.I}/A:${metrics.A}`;

    const scoreEl = document.getElementById('cvss-score');
    const sevEl = document.getElementById('cvss-severity');
    const vecEl = document.getElementById('cvss-vector');

    if (scoreEl) scoreEl.textContent = score.toFixed(1);
    if (sevEl) {
        sevEl.textContent = severity;
        sevEl.className = 'severity-badge severity-' + severity.toLowerCase();
    }
    if (vecEl) vecEl.textContent = vector;
}

/* ── Toggle Panels ───────────────────────────────────────────────────── */

function initTogglePanels() {
    document.querySelectorAll('.toggle-panel').forEach(toggle => {
        toggle.addEventListener('click', () => {
            const targetId = toggle.dataset.target;
            const target = document.getElementById(targetId);
            if (!target) return;
            const icon = toggle.querySelector('.toggle-icon');
            if (target.classList.contains('collapsed')) {
                target.classList.remove('collapsed');
                if (icon) icon.textContent = '-';
            } else {
                target.classList.add('collapsed');
                if (icon) icon.textContent = '+';
            }
        });
    });
}

/* ── Scenario Form ───────────────────────────────────────────────────── */

function initScenarioForm() {
    const form = document.getElementById('scenario-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = {
            name: document.getElementById('sc-name').value,
            description: document.getElementById('sc-desc').value,
            kill_chain_stage: document.getElementById('sc-stage').value,
            technique: document.getElementById('sc-technique').value,
            mitre_id: document.getElementById('sc-mitre').value,
            severity: document.getElementById('sc-severity').value,
            likelihood: document.getElementById('sc-likelihood').value,
            vulnerability_id: parseInt(document.getElementById('sc-vuln').value) || null,
            target_asset_id: parseInt(document.getElementById('sc-asset').value) || null,
            threat_actor_id: parseInt(document.getElementById('sc-actor').value) || null,
        };

        try {
            const resp = await fetch('/api/scenarios', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (resp.ok) {
                window.location.reload();
            } else {
                const err = await resp.json();
                alert('Error: ' + (err.detail || 'Unknown error'));
            }
        } catch (ex) {
            alert('Network error: ' + ex.message);
        }
    });
}

/* ── Asset Form ──────────────────────────────────────────────────────── */

function initAssetForm() {
    const form = document.getElementById('asset-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = {
            name: document.getElementById('asset-name').value,
            asset_type: document.getElementById('asset-type').value,
            ip_address: document.getElementById('asset-ip').value || null,
            hostname: document.getElementById('asset-hostname').value || null,
            os_info: document.getElementById('asset-os').value || null,
            environment: document.getElementById('asset-env').value,
            owner: document.getElementById('asset-owner').value || null,
            criticality: document.getElementById('asset-criticality').value,
        };

        try {
            const resp = await fetch('/api/assets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (resp.ok) {
                window.location.reload();
            } else {
                const err = await resp.json();
                alert('Error: ' + (err.detail || 'Unknown error'));
            }
        } catch (ex) {
            alert('Network error: ' + ex.message);
        }
    });
}

/* ── Delete Handlers ─────────────────────────────────────────────────── */

function initDeleteHandlers() {
    document.querySelectorAll('.delete-scenario').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!confirm('Delete this scenario?')) return;
            const id = btn.dataset.id;
            const resp = await fetch(`/api/scenarios/${id}`, { method: 'DELETE' });
            if (resp.ok) window.location.reload();
        });
    });

    document.querySelectorAll('.delete-asset').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!confirm('Delete this asset?')) return;
            const id = btn.dataset.id;
            const resp = await fetch(`/api/assets/${id}`, { method: 'DELETE' });
            if (resp.ok) window.location.reload();
        });
    });
}

/* ── Attack Simulation ───────────────────────────────────────────────── */

function initSimulation() {
    const btn = document.getElementById('run-simulation');
    if (!btn) return;

    btn.addEventListener('click', async () => {
        const stageCheckboxes = document.querySelectorAll('#sim-stages input[type="checkbox"]:checked');
        const stages = Array.from(stageCheckboxes).map(cb => cb.value);
        const sophistication = document.getElementById('sim-sophistication').value;
        const criticality = document.getElementById('sim-criticality').value;

        if (stages.length === 0) {
            alert('Select at least one kill chain stage.');
            return;
        }

        try {
            const params = new URLSearchParams();
            stages.forEach(s => params.append('stages', s));
            params.set('attacker_sophistication', sophistication);
            params.set('target_criticality', criticality);

            const resp = await fetch('/api/simulate?' + params.toString(), { method: 'POST' });
            if (!resp.ok) {
                alert('Simulation failed');
                return;
            }
            const data = await resp.json();
            displaySimResults(data);
        } catch (ex) {
            alert('Error: ' + ex.message);
        }
    });
}

function displaySimResults(data) {
    const container = document.getElementById('sim-results');
    if (!container) return;
    container.classList.remove('hidden');

    const riskColors = {
        CRITICAL: '#ff1744',
        HIGH: '#ff6d00',
        MEDIUM: '#ffab00',
        LOW: '#00c853',
    };

    const color = riskColors[data.risk_level] || '#00ff41';

    let html = `
        <div class="sim-overall">
            <div class="sim-prob" style="color: ${color}">${data.overall_success_probability}%</div>
            <div>
                <div style="font-size:0.9rem;color:var(--text-secondary)">Overall Attack Success Probability</div>
                <div><span class="severity-badge" style="background:${color};color:#000">${data.risk_level}</span></div>
            </div>
            <div style="margin-left:auto;text-align:right;font-family:var(--font-mono);font-size:0.85rem;color:var(--text-secondary)">
                Est. ${data.total_estimated_hours}h total
            </div>
        </div>
        <h4 style="color:var(--neon-green);font-family:var(--font-mono);margin-bottom:0.75rem">Stage Timeline</h4>
        <div class="sim-timeline">
    `;

    data.timeline.forEach(stage => {
        const stageColor = stage.success_probability > 60 ? '#ff1744' :
                           stage.success_probability > 40 ? '#ff6d00' :
                           stage.success_probability > 20 ? '#ffab00' : '#00c853';
        html += `
            <div class="sim-stage-card">
                <div class="sim-stage-name">${stage.stage}</div>
                <div class="sim-stage-prob" style="color:${stageColor}">${stage.success_probability}%</div>
                <div style="font-size:0.7rem;color:var(--text-muted)">~${stage.estimated_hours}h</div>
            </div>
        `;
    });

    html += '</div>';

    if (data.mitigations && data.mitigations.length > 0) {
        html += '<h4 style="color:var(--neon-green);font-family:var(--font-mono);margin:1rem 0 0.75rem">Recommended Mitigations</h4>';
        html += '<div style="display:flex;flex-direction:column;gap:0.5rem">';
        data.mitigations.forEach(m => {
            const prioColor = m.priority === 'Critical' ? '#ff1744' :
                              m.priority === 'High' ? '#ff6d00' : '#ffab00';
            html += `
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.5rem;background:var(--bg-panel);border-radius:4px;border:1px solid var(--border-color)">
                    <span class="severity-badge" style="background:${prioColor};color:#fff;min-width:60px;text-align:center">${m.priority}</span>
                    <div>
                        <strong style="color:var(--text-primary)">${m.control}</strong>
                        <div style="font-size:0.8rem;color:var(--text-secondary)">${m.description}</div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
    }

    container.innerHTML = html;
}
