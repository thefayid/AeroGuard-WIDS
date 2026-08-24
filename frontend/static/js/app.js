let ws = null;
let reconnectTimer = null;
let isMuted = false;
let discoveredAPs = new Map();
let currentCriticalAlert = null;

document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initCharts(); 
    loadInterfaces();
    setupEventListeners();
    fetchSettings();
    fetchWIPSStatus();
    pollHealth();    
    // Core polling loops
    setInterval(pollHealth, 2000);
    setInterval(pollLiveNetworks, 5000);
    setInterval(pollLiveClients, 5000);
    
    // WIPS status loop
    setInterval(fetchWIPSStatus, 5000);
    initWebSocket();
    
    // We are now connected to a real Linux backend, so no mock data is needed.
    // startMockDataGenerator();

    initTheme();
});

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        document.getElementById('theme-icon-moon').style.display = 'none';
        document.getElementById('theme-icon-sun').style.display = 'block';
    }
}

function initClock() {
    setInterval(() => {
        const now = new Date();
        document.getElementById('live-clock').innerText = now.toISOString().substr(11, 8) + ' UTC';
    }, 1000);
}

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws/stream`);
    
    ws.onopen = () => {
        const ind = document.getElementById('status-indicator');
        ind.classList.remove('bg-red-500', 'bg-amber-500');
        ind.classList.add('bg-primary');
        
        setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, 15000);
    };

    ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'telemetry') handleTelemetry(msg.data);
            if (msg.type === 'alert') handleAlert(msg.data);
        } catch (e) {
            console.error('WS parse error', e);
        }
    };

    ws.onclose = () => {
        const ind = document.getElementById('status-indicator');
        ind.classList.remove('bg-primary', 'bg-amber-500');
        ind.classList.add('bg-red-500');
        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(initWebSocket, 3000);
    };
}

function handleTelemetry(data) {
    if(typeof updateTelemetryChart === 'function') updateTelemetryChart(data);
    // radar-ap-count is now updated via renderTable
}

function showToast(title, body, type = 'blue') {
    const container = document.getElementById('alert-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = 'toast';
    const icons = {
        red:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>',
        orange: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        blue:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'
    };
    el.innerHTML = `
        <div class="toast-icon ${type}">
            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24">${icons[type] || icons.blue}</svg>
        </div>
        <div>
            <div class="toast-title">${title}</div>
            <div class="toast-body">${body}</div>
        </div>`;
    container.prepend(el);
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, 4000);
}

function triggerCriticalModal(alert) {
    currentCriticalAlert = alert;
    document.getElementById('critical-modal').classList.remove('hidden');
    document.getElementById('modal-ssid').textContent = alert.metadata.ssid || 'N/A';
    document.getElementById('modal-bssid').textContent = alert.metadata.bssid || 'N/A';
    document.getElementById('modal-channel').textContent = alert.metadata.channel || 'N/A';
    document.getElementById('modal-rssi').textContent = alert.metadata.rssi ? alert.metadata.rssi + ' dBm' : 'N/A';
    const factorsDiv = document.getElementById('modal-factors');
    factorsDiv.innerHTML = '';
    if (alert.metadata.factors) {
        alert.metadata.factors.forEach(f => {
            const row = document.createElement('div');
            row.className = 'factor-row';
            row.textContent = f;
            factorsDiv.appendChild(row);
        });
    }
}

function handleAlert(alert) {
    if (!isMuted) {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator();
            osc.connect(ctx.destination);
            osc.frequency.value = alert.metadata.severity === 'CRITICAL' ? 880 : 440;
            osc.start();
            setTimeout(() => osc.stop(), 120);
        } catch(e) {}
    }
    if (alert.metadata.severity === 'CRITICAL') triggerCriticalModal(alert);

    const container = document.getElementById('alert-container');
    const el = document.createElement('div');
    const isCrit = alert.metadata.severity === 'CRITICAL';
    const isInfo = !alert.metadata.severity || alert.metadata.severity === 'INFO';
    const iconType = isCrit ? 'red' : isInfo ? 'blue' : 'orange';
    const iconSvg = isCrit
        ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>'
        : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>';

    el.className = 'toast';
    el.innerHTML = `
        <div class="toast-icon ${iconType}">
            <svg width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24">${iconSvg}</svg>
        </div>
        <div>
            <div class="toast-title">${alert.title}</div>
            <div class="toast-body">${alert.description}</div>
        </div>`;
    container.prepend(el);

    setTimeout(() => {
        el.classList.add('out');
        setTimeout(() => el.remove(), 300);
    }, 6000);

    if (alert.metadata.bssid && alert.metadata.ssid) {
        discoveredAPs.set(alert.metadata.bssid, alert.metadata);
        renderTable();
    }
}

function scoreCell(score, isCrit, isWarn) {
    const fillCls = isCrit ? 'red' : isWarn ? 'orange' : 'muted';
    const lblCls  = isCrit ? 'red' : isWarn ? 'orange' : '';
    return `<div class="score-inline"><div class="score-bar"><div class="score-fill ${fillCls}" style="width:${score}%"></div></div><span class="score-label ${lblCls}">${score}</span></div>`;
}

function renderTable() {
    const tbodyLegit = document.getElementById('network-tbody');
    const tbodyThreats = document.getElementById('threats-tbody');
    if (!tbodyLegit || !tbodyThreats) return;
    
    tbodyLegit.innerHTML = '';
    tbodyThreats.innerHTML = '';
    const aps = Array.from(discoveredAPs.values()).sort((a, b) => (b.score || 0) - (a.score || 0));
    const cutoff = parseInt(document.getElementById('slide-cutoff')?.value || 70);

    let threatCount = 0;
    aps.forEach(ap => {
        const row = document.createElement('tr');
        const isCrit = ap.score >= cutoff;
        const isWarn = ap.score >= 40 && !isCrit;
        const score = ap.score || 0;
        const sigCls = (ap.rssi || -100) > -65 ? 'accent' : 'dim';

        if (isCrit) {
            threatCount++;
            row.className = 'threat-row';
            row.innerHTML = `
                <td style="font-weight:600">${ap.ssid || '—'}</td>
                <td class="mono">${ap.bssid}</td>
                <td class="center dim">${ap.channel || '—'}</td>
                <td class="center ${sigCls}" style="font-family:var(--font-mono);font-size:11px">${ap.rssi ? ap.rssi + ' dBm' : '—'}</td>
                <td class="right">${scoreCell(score, true, false)}</td>
            `;
            row.onclick = () => openTargetDetails(ap.bssid);
            tbodyThreats.appendChild(row);
        } else {
            row.innerHTML = `
                <td style="font-weight:500">${ap.ssid || '—'}</td>
                <td class="mono">${ap.bssid}</td>
                <td class="dim" style="font-size:11px;max-width:80px;overflow:hidden;text-overflow:ellipsis">${ap.vendor || 'Unknown'}</td>
                <td class="center dim">${ap.channel || '—'}</td>
                <td class="center ${sigCls}" style="font-family:var(--font-mono);font-size:11px">${ap.rssi ? ap.rssi + ' dBm' : '—'}</td>
                <td class="center dim" style="font-size:11px">${ap.security || 'WPA2'}</td>
                <td class="right">${scoreCell(score, false, isWarn)}</td>
            `;
            tbodyLegit.appendChild(row);
        }
    });

    // Update all counters
    ['hdr-ap-count','radar-ap-count','kpi-endpoints'].forEach(id => { const el = document.getElementById(id); if(el) el.textContent = aps.length; });
    ['hdr-threat-count','radar-threat-count','kpi-threats'].forEach(id => { const el = document.getElementById(id); if(el) el.textContent = threatCount; });

    const dot = document.getElementById('threat-indicator-dot');
    const badge = document.getElementById('threat-count-badge');
    const emptyState = document.getElementById('threats-empty');
    if (dot) dot.className = 'threat-dot' + (threatCount > 0 ? ' active' : '');
    if (badge) { badge.textContent = threatCount; badge.className = 'count-chip' + (threatCount > 0 ? ' red' : ''); }
    if (emptyState) emptyState.style.display = threatCount === 0 ? 'flex' : 'none';
    
    // Also update radar UI
    if (typeof updateRadar === 'function') updateRadar();
}

async function loadInterfaces() {
    try {
        const res = await fetch('/api/interfaces');
        const data = await res.json();
        const select = document.getElementById('interface-select');
        select.innerHTML = '<option value="" disabled selected>Select Interface...</option>';
        data.forEach(iface => {
            const opt = document.createElement('option');
            opt.value = iface.name;
            opt.innerText = `${iface.name} [${iface.mode.toUpperCase()}]`;
            select.appendChild(opt);
            if(iface.mode === 'monitor') {
                document.getElementById('active-iface').innerText = iface.name;
            }
        });
    } catch(e) {
        document.getElementById('interface-select').innerHTML = '<option>Offline</option>';
    }
}

async function pollHealth() {
    try {
        const res = await fetch('/api/health');
        const data = await res.json();
        document.getElementById('stat-cpu').innerText = `${data.cpu_usage_percent}%`;
        document.getElementById('stat-ram').innerText = `${data.memory_usage_percent}%`;
        const snifferEl = document.getElementById('stat-sniffer');
        snifferEl.innerText = data.sniffer_active ? 'Active' : 'Idle';
        snifferEl.className = data.sniffer_active ? 'text-primary font-medium' : 'text-amber-500 font-medium';
        snifferEl.className = data.sniffer_active ? 'text-primary font-medium' : 'text-amber-500 font-medium';
    } catch(e) {}
}

async function pollLiveNetworks() {
    try {
        const res = await fetch('/api/live');
        const liveData = await res.json();
        let changed = false;
        
        // Remove APs that are no longer in liveData
        for (const [bssid, data] of discoveredAPs.entries()) {
            if (!liveData[bssid]) {
                discoveredAPs.delete(bssid);
                changed = true;
            }
        }
        
        // Add or update live APs
        for (const [bssid, data] of Object.entries(liveData)) {
            if (!discoveredAPs.has(bssid)) {
                changed = true;
                discoveredAPs.set(bssid, {
                    ssid: data.ssid,
                    bssid: bssid,
                    vendor: data.vendor,
                    channel: data.channel,
                    rssi: data.rssi,
                    security: data.security,
                    score: data.score || 0
                });
            } else {
                const existing = discoveredAPs.get(bssid);
                if (existing.rssi !== data.rssi || existing.score !== (data.score || 0)) {
                    existing.rssi = data.rssi;
                    existing.score = data.score || 0;
                    changed = true;
                }
            }
        }
        
        if (changed) {
            renderTable();
        }
    } catch(e) {
        console.error('Failed to fetch live networks', e);
    }
}

async function pollLiveClients() {
    try {
        const res = await fetch('/api/clients');
        const data = await res.json();
        const tbody = document.getElementById('clients-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        if (data.clients.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="center dim" style="padding: 24px;">No stations detected</td></tr>';
            return;
        }
        
        // Sort by most recently seen
        data.clients.sort((a, b) => b.last_seen - a.last_seen);
        
        data.clients.forEach(client => {
            const row = document.createElement('tr');
            const sigCls = client.rssi > -65 ? 'accent' : 'dim';
            const timeAgo = Math.round((Date.now()/1000) - client.last_seen);
            
            row.innerHTML = `
                <td class="mono">${client.mac}</td>
                <td class="mono">${client.bssid}</td>
                <td class="dim" style="font-size:11px;max-width:150px;overflow:hidden;text-overflow:ellipsis">${client.probed_ssids.length > 0 ? client.probed_ssids.join(', ') : '—'}</td>
                <td class="center ${sigCls}" style="font-family:var(--font-mono);font-size:11px">${client.rssi !== -100 ? client.rssi + ' dBm' : '—'}</td>
                <td class="center dim" style="font-size:11px">${timeAgo}s ago</td>
            `;
            tbody.appendChild(row);
        });
    } catch(e) {
        console.error('Failed to fetch live clients', e);
    }
}

async function fetchSettings() {
    try {
        const res = await fetch('/api/settings');
        const data = await res.json();
        document.getElementById('slide-deauth').value = data.deauth_threshold;
        document.getElementById('val-deauth').innerText = data.deauth_threshold;
        document.getElementById('slide-rssi').value = data.rssi_variance_tolerance;
        document.getElementById('val-rssi').innerText = data.rssi_variance_tolerance;
        document.getElementById('slide-cutoff').value = data.critical_cutoff;
        document.getElementById('val-cutoff').innerText = data.critical_cutoff;
    } catch(e) {}
}

function updateSettings() {
    const payload = {
        deauth_threshold: parseInt(document.getElementById('slide-deauth').value),
        rssi_variance_tolerance: parseInt(document.getElementById('slide-rssi').value),
        critical_cutoff: parseInt(document.getElementById('slide-cutoff').value)
    };
    fetch('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
}

async function fetchWIPSStatus() {
    try {
        const res = await fetch('/api/countermeasures');
        const data = await res.json();
        const toggle = document.getElementById('toggle-wips');
        if (toggle && document.activeElement !== toggle) toggle.checked = data.enabled;

        const dot = document.getElementById('wips-dot');
        const label = document.getElementById('wips-label');
        const kpiMode = document.getElementById('kpi-deauths');
        if (dot) dot.className = 'wips-pill-dot' + (data.enabled ? ' on' : '');
        if (label) label.textContent = data.enabled ? 'WIPS Active' : 'WIPS Offline';
        if (kpiMode) kpiMode.textContent = data.demo_mode ? 'Demo' : 'Live';

        if (document.activeElement.id !== 'slide-wips-threshold') {
            document.getElementById('slide-wips-threshold').value = data.config.threshold;
            document.getElementById('val-wips-threshold').innerText = data.config.threshold;
        }
        if (document.activeElement.id !== 'slide-wips-burst') {
            document.getElementById('slide-wips-burst').value = data.config.burst;
            document.getElementById('val-wips-burst').innerText = data.config.burst;
        }
        if (document.activeElement.id !== 'slide-wips-interval') {
            document.getElementById('slide-wips-interval').value = data.config.attack_interval;
            document.getElementById('val-wips-interval').innerText = data.config.attack_interval;
        }
    } catch(e) {
        console.error('Failed to fetch WIPS status', e);
    }
}

function updateWIPSConfig() {
    const payload = {
        threshold: parseInt(document.getElementById('slide-wips-threshold').value),
        burst: parseInt(document.getElementById('slide-wips-burst').value),
        attack_interval: parseFloat(document.getElementById('slide-wips-interval').value)
    };
    fetch('/api/countermeasures/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
}

function setupEventListeners() {
    const muteBtn = document.getElementById('btn-mute');
    muteBtn.addEventListener('click', () => {
        isMuted = !isMuted;
        muteBtn.textContent = isMuted ? 'Unmute Alerts' : 'Mute Alerts';
        muteBtn.style.color = isMuted ? 'var(--red)' : '';
        muteBtn.style.borderColor = isMuted ? 'rgba(255,59,48,0.4)' : '';
    });

    document.getElementById('btn-theme').addEventListener('click', () => {
        const root = document.documentElement;
        const current = root.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        
        root.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        
        document.getElementById('theme-icon-moon').style.display = next === 'dark' ? 'none' : 'block';
        document.getElementById('theme-icon-sun').style.display = next === 'dark' ? 'block' : 'none';
        
        // Let the charts know they should redraw their grid lines (optional, but good for polish)
        if (typeof updateTelemetryChart === 'function' && window.telemetryChart) {
            window.telemetryChart.update();
        }
    });

    const views = ['dashboard', 'forensics', 'radar'];
    
    views.forEach(view => {
        const btn = document.getElementById(`btn-view-${view}`);
        if(btn) {
            btn.addEventListener('click', () => {
                views.forEach(v => {
                    document.getElementById(`view-${v}`).classList.add('hidden');
                    document.getElementById(`btn-view-${v}`).classList.remove('active-view');
                });
                
                document.getElementById(`view-${view}`).classList.remove('hidden');
                btn.classList.add('active-view');
                
                if (view === 'forensics') fetchForensics();
                if (view === 'radar') updateRadar();
            });
        }
    });

    ['slide-deauth', 'slide-rssi', 'slide-cutoff'].forEach(id => {
        const el = document.getElementById(id);
        el.addEventListener('input', (e) => {
            document.getElementById(`val-${id.split('-')[1]}`).innerText = e.target.value;
        });
        el.addEventListener('change', updateSettings);
    });
    
    document.getElementById('btn-monitor').addEventListener('click', async () => {
        const iface = document.getElementById('interface-select').value;
        if (!iface) { showToast('No Interface Selected', 'Select an interface first.', 'orange'); return; }
        const btn = document.getElementById('btn-monitor');
        btn.textContent = 'Setting...';
        btn.disabled = true;
        try {
            const res = await fetch(`/api/interfaces/${iface}/monitor`, {method: 'POST'});
            const data = await res.json();
            if (data.status === 'success') {
                document.getElementById('active-iface').textContent = data.interface;
                loadInterfaces();
                showToast('Monitor Mode Active', `Interface ${data.interface} set to monitor mode.`, 'blue');
            } else {
                showToast('Mode Switch Failed', data.message || 'Could not set monitor mode.', 'orange');
            }
        } catch(e) {
            showToast('Error', 'Request failed.', 'orange');
        } finally {
            btn.textContent = 'Monitor';
            btn.disabled = false;
        }
    });
    
    document.getElementById('btn-managed').addEventListener('click', async () => {
        const iface = document.getElementById('interface-select').value;
        if (!iface) { showToast('No Interface Selected', 'Select an interface first.', 'orange'); return; }
        const btn = document.getElementById('btn-managed');
        btn.textContent = 'Setting...';
        btn.disabled = true;
        try {
            const res = await fetch(`/api/interfaces/${iface}/managed`, {method: 'POST'});
            const data = await res.json();
            if (data.status === 'success') {
                document.getElementById('active-iface').textContent = 'NONE';
                loadInterfaces();
                showToast('Managed Mode', `Interface set back to managed mode.`, 'blue');
            } else {
                showToast('Mode Switch Failed', data.message || 'Could not set managed mode.', 'orange');
            }
        } catch(e) {
            showToast('Error', 'Request failed.', 'orange');
        } finally {
            btn.textContent = 'Managed';
            btn.disabled = false;
        }
    });

    document.getElementById('interface-select').addEventListener('change', async (e) => {
        const iface = e.target.value;
        if (iface) {
            document.getElementById('active-iface').textContent = iface;
            await fetch(`/api/interfaces/${iface}/select`, {method: 'POST'});
        }
    });
    
    document.getElementById('btn-baseline').addEventListener('click', async () => {
        const iface = document.getElementById('interface-select').value;
        if (!iface) { showToast('No Interface Selected', 'Select an interface first.', 'orange'); return; }
        
        // Ensure the sniffer is started on the selected interface before scanning
        await fetch(`/api/interfaces/${iface}/select`, {method: 'POST'});

        const res = await fetch('/api/baseline/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({duration: 180})
        });
        if(res.ok) {
            document.getElementById('baseline-status').classList.remove('hidden');
            let t = 180;
            const intv = setInterval(() => {
                t--;
                document.getElementById('baseline-timer').innerText = t;
                if(t <= 0) {
                    clearInterval(intv);
                    document.getElementById('baseline-status').classList.add('hidden');
                    fetch('/api/baseline/save', {method: 'POST'});
                }
            }, 1000);
        }
    });

    // WIPS Settings Event Listeners
    ['slide-wips-threshold', 'slide-wips-burst', 'slide-wips-interval'].forEach(id => {
        const el = document.getElementById(id);
        el.addEventListener('input', (e) => {
            document.getElementById(`val-${id.split('-')[1]}-${id.split('-')[2]}`).innerText = e.target.value;
        });
        el.addEventListener('change', updateWIPSConfig);
    });

    document.getElementById('toggle-wips').addEventListener('change', async (e) => {
        const currentlyEnabled = e.target.checked;
        await fetch('/api/countermeasures/enable', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled: currentlyEnabled})
        });
        fetchWIPSStatus();
    });

    // Modal Actions
    document.getElementById('btn-trigger-wips').addEventListener('click', async () => {
        if (!currentCriticalAlert || !currentCriticalAlert.metadata.bssid) return;
        const payload = {
            ssid: currentCriticalAlert.metadata.ssid || 'Unknown',
            bssid: currentCriticalAlert.metadata.bssid || 'Unknown',
            score: currentCriticalAlert.metadata.score || 100
        };
        await triggerWIPSAttack(payload, 'btn-trigger-wips');
    });

    ['btn-ack-alert', 'btn-ack-alert-2'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', () => {
            document.getElementById('critical-modal').classList.add('hidden');
            currentCriticalAlert = null;
        });
    });

    document.getElementById('btn-download-pcap').addEventListener('click', () => {
        if (!currentCriticalAlert || !currentCriticalAlert.metadata.bssid) return;
        const bssid = currentCriticalAlert.metadata.bssid.replace(/:/g, '');
        window.open(`/api/reports/pcap/${bssid}`, '_blank');
    });

    // Target Inspection Modal Actions
    document.getElementById('btn-close-target').addEventListener('click', () => {
        document.getElementById('target-modal').classList.add('hidden');
        currentTargetBssid = null;
    });

    document.getElementById('btn-target-attack').addEventListener('click', async () => {
        if (!currentTargetBssid) return;
        const ap = discoveredAPs.get(currentTargetBssid);
        if (!ap) return;
        
        const payload = {
            ssid: ap.ssid || 'Unknown',
            bssid: ap.bssid,
            score: ap.score || 100
        };
        await triggerWIPSAttack(payload, 'btn-target-attack');
    });

    document.getElementById('btn-export-forensics').addEventListener('click', async () => {
        if (!currentCriticalAlert) return;
        
        const payload = {
            ssid: currentCriticalAlert.metadata.ssid || 'Unknown',
            bssid: currentCriticalAlert.metadata.bssid || 'Unknown',
            factors: currentCriticalAlert.metadata.factors || [],
            score: currentCriticalAlert.metadata.score || 0,
            timestamp: currentCriticalAlert.timestamp || (Date.now() / 1000)
        };
        
        const res = await fetch('/api/reports/export', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `incident_report_${payload.bssid.replace(/:/g, '')}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }
    });

    document.getElementById('btn-download-pcap').addEventListener('click', () => {
        if (!currentCriticalAlert || !currentCriticalAlert.metadata.bssid) return;
        const bssid = currentCriticalAlert.metadata.bssid.replace(/:/g, '');
        window.open(`/api/reports/pcap/${bssid}`, '_blank');
    });
}

function drawRadar() {
    const canvas = document.getElementById('radar-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    
    const cw = canvas.width;
    const ch = canvas.height;
    const cx = cw / 2;
    const cy = ch / 2;
    
    ctx.clearRect(0, 0, cw, ch);
    
    const aps = Array.from(discoveredAPs.values());
    aps.forEach(ap => {
        const hash = ap.bssid.split(':').reduce((acc, val) => acc + parseInt(val, 16), 0);
        const angle = (hash % 360) * (Math.PI / 180);
        
        const r = ap.rssi || -90;
        const distRatio = Math.max(0, Math.min(1, (r + 100) / 70)); 
        const distance = cx - 5 - ((1 - distRatio) * (cx - 15));
        
        const x = cx + distance * Math.cos(angle);
        const y = cy + distance * Math.sin(angle);
        
        ctx.beginPath();
        ctx.arc(x, y, 2.5, 0, Math.PI * 2);
        
        const cutoff = parseInt(document.getElementById('slide-cutoff').value);
        if (ap.score >= cutoff) {
            ctx.fillStyle = '#ef4444'; // red-500
            ctx.shadowColor = 'rgba(239, 68, 68, 0.8)';
        } else if (ap.score >= 40) {
            ctx.fillStyle = '#f59e0b'; // amber-500
            ctx.shadowColor = 'rgba(245, 158, 11, 0.8)';
        } else {
            ctx.fillStyle = '#0284c7'; // primary blue
            ctx.shadowColor = 'rgba(2, 132, 199, 0.8)';
        }
        
        ctx.shadowBlur = 6;
        ctx.fill();
    });
}

setInterval(drawRadar, 50);

let currentTargetBssid = null;

function openTargetDetails(bssid) {
    const ap = discoveredAPs.get(bssid);
    if (!ap) return;
    currentTargetBssid = bssid;
    document.getElementById('target-ssid').textContent = ap.ssid || 'UNKNOWN';
    document.getElementById('target-bssid').textContent = ap.bssid;
    document.getElementById('target-rssi').textContent = ap.rssi ? `${ap.rssi} dBm` : '—';
    document.getElementById('target-score').textContent = `${ap.score || 0}/100`;
    const factorsDiv = document.getElementById('target-factors');
    factorsDiv.innerHTML = '';
    const factors = ap.factors || (ap.metadata ? ap.metadata.factors : null);
    if (factors && factors.length > 0) {
        factors.forEach(f => {
            const row = document.createElement('div');
            row.className = 'factor-row';
            row.textContent = f;
            factorsDiv.appendChild(row);
        });
    } else {
        const row = document.createElement('div');
        row.className = 'factor-row';
        row.textContent = 'No anomaly factors recorded.';
        row.style.opacity = '0.5';
        factorsDiv.appendChild(row);
    }
    document.getElementById('target-modal').classList.remove('hidden');

    // Fetch and render compromised clients
    const clientsDiv = document.getElementById('target-clients');
    const clientsCount = document.getElementById('target-clients-count');
    clientsDiv.innerHTML = '<div class="empty-state" style="padding: 12px 0;">Loading...</div>';
    clientsCount.textContent = '0';
    
    fetch(`/api/threats/${bssid}/clients`)
        .then(r => r.json())
        .then(data => {
            if (data.status === 'success' && data.clients && data.clients.length > 0) {
                clientsDiv.innerHTML = '';
                clientsCount.textContent = data.clients.length;
                data.clients.forEach(mac => {
                    const row = document.createElement('div');
                    row.className = 'factor-row';
                    row.style.fontFamily = 'var(--font-mono)';
                    row.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px"><path d="M5 12.55a11 11 0 0114.08 0"/><path d="M1.42 9a16 16 0 0121.16 0"/><path d="M8.53 16.11a6 6 0 016.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg> ${mac.toUpperCase()}`;
                    clientsDiv.appendChild(row);
                });
            } else {
                clientsDiv.innerHTML = '<div class="empty-state" style="padding: 12px 0;">No clients detected yet.</div>';
                clientsCount.textContent = '0';
            }
        })
        .catch(err => {
            clientsDiv.innerHTML = '<div class="empty-state" style="padding: 12px 0;">Failed to load.</div>';
        });
}

async function triggerWIPSAttack(payload, btnId) {
    // Read the selected attack mode
    let deauthBroadcast = false;
    let deauthClients = true;
    const modeInputs = document.getElementsByName('attack-mode');
    if (modeInputs && modeInputs.length > 0) {
        for (const input of modeInputs) {
            if (input.checked && input.value === 'broadcast') {
                deauthBroadcast = true;
                break;
            }
        }
    }

    // Configure the attack mode on the backend
    await fetch('/api/countermeasures/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            deauth_broadcast: deauthBroadcast,
            deauth_clients: deauthClients
        })
    });
    // Force global WIPS engine ON so the attack actually executes
    await fetch('/api/countermeasures/enable', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: true})
    });
    
    // Visually update the toggle switch immediately
    const toggle = document.getElementById('toggle-wips');
    if (toggle) toggle.checked = true;

    const res = await fetch('/api/countermeasures/trigger', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
    });
    
    const btn = document.getElementById(btnId);
    if (btn) {
        const origText = btn.innerHTML;
        btn.innerHTML = 'FIRING...';
        btn.classList.add('animate-pulse');
        setTimeout(() => {
            btn.innerHTML = origText;
            btn.classList.remove('animate-pulse');
        }, 1000);
    }
    
    if (res.ok) {
        const modeDesc = deauthBroadcast ? "Full BSSID Takedown (Broadcast)" : "Targeted Client Containment";
        handleAlert({
            title: "WIPS COUNTERMEASURE DEPLOYED",
            description: `Active countermeasures engaged against ${payload.ssid} (${payload.bssid}). Mode: ${modeDesc}.`,
            metadata: { bssid: payload.bssid, severity: "WARNING" }
        });
        
        // Hide the modal after triggering
        document.getElementById('target-modal').classList.add('hidden');
        currentTargetBssid = null;
    }
}

function startMockDataGenerator() {
    console.log("Started Mock Data Generator for Demonstration");
    
    // 1. Initial Mock APs (Legitimate)
    const mockMacs = ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "11:22:33:44:55:66", "00:11:22:33:44:55"];
    
    mockMacs.forEach((mac, i) => {
        discoveredAPs.set(mac, {
            ssid: i < 2 ? "Corp-Net" : "Guest-WiFi",
            bssid: mac,
            vendor: i < 2 ? "Cisco" : "Aruba",
            channel: i === 0 ? 1 : i === 1 ? 6 : 11,
            rssi: -60 - (i * 5),
            security: "WPA2",
            score: Math.floor(Math.random() * 10),
            factors: []
        });
    });
    renderTable();

    // 2. Simulate Telemetry 
    setInterval(() => {
        const pkts = Math.floor(Math.random() * 500) + 100;
        document.getElementById('telemetry-pkts').innerText = pkts;
        if(typeof updateTelemetryChart === 'function') {
            updateTelemetryChart({ total_packets: pkts });
        }
    }, 1000);

    // 3. Simulate an Evil Twin Attack periodically
    setTimeout(() => {
        const maliciousBssid = "AA:BB:CC:DD:EE:99";
        const spoofedScore = 85;
        const alertData = {
            title: "CRITICAL EVIL TWIN ATTACK IN PROGRESS",
            description: "Threat Score: 85/100. Vectors: W1: Unknown BSSID, W5: Security Downgrade",
            metadata: {
                ssid: "Corp-Net",
                bssid: maliciousBssid,
                vendor: "UNKNOWN",
                channel: 6,
                rssi: -45, /* Very strong signal, typical of evil twin */
                security: "Open",
                score: spoofedScore,
                factors: ["W1: Unknown BSSID", "W5: Security Downgrade", "W4: RSSI Delta Spike"],
                severity: "CRITICAL"
            },
            timestamp: Date.now() / 1000
        };
        handleAlert(alertData);
    }, 5000);
    
    // Simulate roaming/signal fluctuations
    setInterval(() => {
        discoveredAPs.forEach(ap => {
            if (ap.score < 50) {
                ap.rssi += (Math.random() > 0.5 ? 1 : -1) * Math.floor(Math.random() * 3);
                ap.rssi = Math.min(-30, Math.max(-95, ap.rssi));
            }
        });
        renderTable();
    }, 2000);
}

// UI Utilities
function toggleFullscreen(cardId) {
    const card = document.getElementById(cardId);
    if (!card) return;
    card.classList.toggle('fullscreen');
}

async function fetchForensics() {
    try {
        const res = await fetch('/api/forensics/logs');
        const data = await res.json();
        if (data.status === 'success') {
            const tbody = document.getElementById('forensics-tbody');
            tbody.innerHTML = '';
            data.logs.forEach(log => {
                const tr = document.createElement('tr');
                const date = new Date(log.timestamp * 1000).toLocaleString();
                let scoreClass = log.score >= 70 ? 'red' : 'orange';
                tr.innerHTML = `
                    <td class="mono" style="font-size:12px">${date}</td>
                    <td style="font-weight:600">${log.title}</td>
                    <td style="font-size:12px; color:var(--label-2); max-width: 300px;">${log.description}</td>
                    <td class="mono">${log.bssid}</td>
                    <td class="r ${scoreClass}"><b>${log.score}</b>/100</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch(e) {
        console.error('Failed to fetch forensics', e);
    }
}

// Radar Logic
function calculateDistance(rssi, freqMHz = 2412) {
    // FSPL formula: Distance = 10 ^ ((27.55 - (20 * log10(freq)) + |rssi|) / 20)
    const exp = (27.55 - (20 * Math.log10(freqMHz)) + Math.abs(rssi)) / 20.0;
    return Math.pow(10, exp);
}

function updateRadar() {
    const container = document.getElementById('radar-dots');
    if (!container) return;
    
    // Check if radar view is active
    if (document.getElementById('view-radar').classList.contains('hidden')) return;
    
    container.innerHTML = '';
    
    // Max radius of radar is 250px (500x500 container). Max distance ~100m.
    const maxRadiusPx = 240; // padding
    const maxDistM = 100;
    
    discoveredAPs.forEach(ap => {
        const distM = calculateDistance(ap.rssi);
        // Clamp distance
        const clampedDist = Math.min(distM, maxDistM);
        
        // Calculate pixel radius
        const rPx = (clampedDist / maxDistM) * maxRadiusPx;
        
        // Use BSSID to generate a stable random angle between 0 and 2PI
        let hash = 0;
        for(let i=0; i<ap.bssid.length; i++) hash = ap.bssid.charCodeAt(i) + ((hash << 5) - hash);
        const angle = Math.abs(hash) % (Math.PI * 2);
        
        // Calculate x, y relative to center (250, 250)
        const x = 250 + (rPx * Math.cos(angle));
        const y = 250 + (rPx * Math.sin(angle));
        
        const dot = document.createElement('div');
        dot.className = \`radar-dot \${ap.score >= 40 ? 'rogue' : 'legit'}\`;
        dot.style.left = \`\${x}px\`;
        dot.style.top = \`\${y}px\`;
        
        // Tooltip
        const tooltip = document.createElement('div');
        tooltip.className = 'radar-tooltip hidden';
        tooltip.innerHTML = \`
            <strong>\${ap.ssid}</strong><br>
            <span style="color:var(--label-2)">\${ap.bssid}</span><br>
            <span style="color:var(--label-2)">RSSI:</span> \${ap.rssi} dBm (~\${distM.toFixed(1)}m)<br>
            <span style="color:var(--label-2)">Score:</span> <span class="\${ap.score >= 40 ? 'red' : 'green'}">\${ap.score}/100</span>
        \`;
        
        dot.addEventListener('mouseenter', () => tooltip.classList.remove('hidden'));
        dot.addEventListener('mouseleave', () => tooltip.classList.add('hidden'));
        
        dot.appendChild(tooltip);
        container.appendChild(dot);
    });
}
