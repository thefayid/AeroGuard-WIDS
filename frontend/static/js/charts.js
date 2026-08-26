let telemetryChart;
const maxDataPoints = 60;

function initCharts() {
    const ctx = document.getElementById('telemetry-chart');
    if (!ctx) return;

    telemetryChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(maxDataPoints).fill(''),
            datasets: [{
                label: 'Packets/s',
                data: Array(maxDataPoints).fill(0),
                borderColor: '#007aff',
                backgroundColor: 'rgba(0,122,255,0.06)',
                borderWidth: 1.5,
                tension: 0.4,
                fill: true,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { 
                duration: 1000,
                easing: 'linear'
            },
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: { display: false },
                y: {
                    display: true,
                    grid: { color: 'rgba(0,0,0,0.05)', drawBorder: false },
                    ticks: {
                        color: '#aeaeb2',
                        font: { family: 'SF Mono, Menlo, monospace', size: 10 },
                        maxTicksLimit: 4
                    },
                    border: { display: false },
                    beginAtZero: true
                }
            },
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
        }
    });
}

let lastTotal = 0;
function updateTelemetryChart(telemetry) {
    if (!telemetryChart) return;

    const currentTotal = telemetry.total_packets;
    let rate = 0;
    if (lastTotal > 0 && currentTotal >= lastTotal) {
        rate = currentTotal - lastTotal;
    }
    lastTotal = currentTotal;

    telemetryChart.data.datasets[0].data.push(rate);
    telemetryChart.data.datasets[0].data.shift();
    telemetryChart.update();

    // Update all packet/s displays
    ['telemetry-pkts', 'kpi-pkts'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = rate;
    });
}
