let packetChart;
let throughputChart;
const maxDataPoints = 60;

function initCharts() {
    const ctxPackets = document.getElementById('telemetry-chart');
    const ctxThroughput = document.getElementById('secondary-chart');
    if (!ctxPackets || !ctxThroughput) return;

    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 1000, easing: 'linear' },
        interaction: { mode: 'index', intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: '#ffffff',
                titleColor: '#1d1d1f',
                bodyColor: '#6e6e73',
                borderColor: '#d2d2d7',
                borderWidth: 1,
                padding: 8,
                titleFont: { family: '-apple-system, BlinkMacSystemFont, sans-serif', size: 11, weight: '600' },
                bodyFont: { family: 'SF Mono, Menlo, monospace', size: 11 }
            }
        }
    };

    packetChart = new Chart(ctxPackets, {
        type: 'line',
        data: {
            labels: Array(maxDataPoints).fill(''),
            datasets: [
                {
                    label: 'Mgmt (Pkts/s)',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#007aff', // Blue
                    backgroundColor: 'rgba(0,122,255,0.1)',
                    borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0
                },
                {
                    label: 'Ctrl (Pkts/s)',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#af52de', // Purple
                    backgroundColor: 'rgba(175,82,222,0.1)',
                    borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0
                },
                {
                    label: 'Data (Pkts/s)',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#34c759', // Green
                    backgroundColor: 'rgba(52,199,89,0.1)',
                    borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0
                },
                {
                    label: 'Deauths/s',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#ff3b30', // Red
                    backgroundColor: 'transparent',
                    borderWidth: 2.5, tension: 0, fill: false, pointRadius: 0
                }
            ]
        },
        options: {
            ...commonOptions,
            scales: {
                x: { display: false },
                y: {
                    display: true,
                    grid: { color: 'rgba(0,0,0,0.05)', drawBorder: false },
                    ticks: { color: '#aeaeb2', font: { family: 'SF Mono, Menlo, monospace', size: 10 }, maxTicksLimit: 4, beginAtZero: true },
                    border: { display: false }
                }
            }
        }
    });

    throughputChart = new Chart(ctxThroughput, {
        type: 'line',
        data: {
            labels: Array(maxDataPoints).fill(''),
            datasets: [
                {
                    label: 'Throughput (Bytes/s)',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#5ac8fa', // Light Blue
                    backgroundColor: 'rgba(90,200,250,0.2)',
                    borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0,
                    yAxisID: 'y'
                },
                {
                    label: 'Threat Score',
                    data: Array(maxDataPoints).fill(0),
                    borderColor: '#ff9500', // Orange
                    backgroundColor: 'transparent',
                    borderWidth: 2, tension: 0.2, fill: false, pointRadius: 0,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            ...commonOptions,
            scales: {
                x: { display: false },
                y: {
                    type: 'linear', display: true, position: 'left',
                    grid: { color: 'rgba(0,0,0,0.05)', drawBorder: false },
                    ticks: { color: '#aeaeb2', font: { family: 'SF Mono, Menlo, monospace', size: 10 }, maxTicksLimit: 4, beginAtZero: true },
                    border: { display: false }
                },
                y1: {
                    type: 'linear', display: true, position: 'right',
                    grid: { drawOnChartArea: false },
                    ticks: { color: '#ff9500', font: { family: 'SF Mono, Menlo, monospace', size: 10 }, max: 100, beginAtZero: true },
                    border: { display: false }
                }
            }
        }
    });
}

let lastStats = { total: 0, mgmt: 0, ctrl: 0, data: 0, deauth: 0, bytes: 0 };

function updateTelemetryChart(telemetry) {
    if (!packetChart || !throughputChart) return;

    const rates = {
        total: Math.max(0, telemetry.total_packets - lastStats.total),
        mgmt: Math.max(0, telemetry.mgmt_packets - lastStats.mgmt),
        ctrl: Math.max(0, telemetry.ctrl_packets - lastStats.ctrl),
        data: Math.max(0, telemetry.data_packets - lastStats.data),
        deauth: Math.max(0, telemetry.deauth_packets - lastStats.deauth),
        bytes: Math.max(0, telemetry.total_bytes - lastStats.bytes)
    };

    // If it's the first data point, don't spike the rate.
    if (lastStats.total === 0 && telemetry.total_packets > 0) {
        rates.total = 0; rates.mgmt = 0; rates.ctrl = 0; rates.data = 0; rates.deauth = 0; rates.bytes = 0;
    }

    lastStats = {
        total: telemetry.total_packets,
        mgmt: telemetry.mgmt_packets,
        ctrl: telemetry.ctrl_packets,
        data: telemetry.data_packets,
        deauth: telemetry.deauth_packets,
        bytes: telemetry.total_bytes
    };

    // Update Packet Chart
    packetChart.data.datasets[0].data.push(rates.mgmt);
    packetChart.data.datasets[0].data.shift();
    packetChart.data.datasets[1].data.push(rates.ctrl);
    packetChart.data.datasets[1].data.shift();
    packetChart.data.datasets[2].data.push(rates.data);
    packetChart.data.datasets[2].data.shift();
    packetChart.data.datasets[3].data.push(rates.deauth);
    packetChart.data.datasets[3].data.shift();
    packetChart.update();

    // Update Throughput Chart
    throughputChart.data.datasets[0].data.push(rates.bytes);
    throughputChart.data.datasets[0].data.shift();
    throughputChart.data.datasets[1].data.push(telemetry.max_threat_score || 0);
    throughputChart.data.datasets[1].data.shift();
    throughputChart.update();

    // Update KPIs (Total packets/s)
    ['telemetry-pkts', 'kpi-pkts'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = rates.total;
    });
}
