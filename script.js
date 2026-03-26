const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const BASE_URL = isLocal ? 'http://localhost:3000' : '';
const API_URL = `${BASE_URL}/api/scan-url`;
const FILE_API_URL = `${BASE_URL}/api/scan-file`;

// Simple state management for history (usually would be backend DB)
let activityHistory = JSON.parse(localStorage.getItem('cypherx_history')) || [];
let totalScanned = parseInt(localStorage.getItem('cypherx_total')) || 2451;
let totalThreats = parseInt(localStorage.getItem('cypherx_threats')) || 142;

function saveHistory() {
    localStorage.setItem('cypherx_history', JSON.stringify(activityHistory));
    localStorage.setItem('cypherx_total', totalScanned);
    localStorage.setItem('cypherx_threats', totalThreats);
}

function addToHistory(url, score, status, source) {
    const entry = {
        date: new Date().toLocaleString(),
        url: url,
        score: score,
        status: status,
        source: source
    };
    activityHistory.unshift(entry);
    if(activityHistory.length > 50) activityHistory.pop();
    
    totalScanned++;
    if(status !== 'SAFE') totalThreats++;
    saveHistory();
    updateWidget(url, status);
}

// Widget logic
const widget = document.getElementById('floating-widget');
const widgetPanel = document.getElementById('widget-panel');
const closeWidget = document.getElementById('close-widget');
const widgetUrl = document.getElementById('widget-last-url');

if(widget && widgetPanel) {
    widget.addEventListener('click', () => {
        widgetPanel.classList.toggle('show');
    });
    closeWidget.addEventListener('click', () => {
        widgetPanel.classList.remove('show');
    });
}

function updateWidget(url, status) {
    if(widgetUrl) {
        widgetUrl.textContent = `${url} (${status})`;
        let color = status === 'SAFE' ? '#00ff88' : (status === 'SUSPICIOUS' ? '#ffb800' : '#ff3366');
        widgetUrl.style.color = color;
    }
}

// Global initialization
document.addEventListener('DOMContentLoaded', () => {
    if(activityHistory.length > 0) {
        updateWidget(activityHistory[0].url, activityHistory[0].status);
    }
    
    // Populate activity table if exists
    const tb = document.getElementById('activity-table-body');
    if(tb) {
        activityHistory.forEach(item => {
            const tr = document.createElement('tr');
            let statusColor = item.status === 'SAFE' ? 'safe-text' : (item.status === 'SUSPICIOUS' ? 'warning-text' : 'danger-text');
            tr.innerHTML = `
                <td>${item.date}</td>
                <td style="max-width:300px; word-break:break-all;">${item.url}</td>
                <td>${item.score}/100</td>
                <td class="${statusColor}" style="font-weight:bold;">${item.status}</td>
                <td>${item.source}</td>
            `;
            tb.appendChild(tr);
        });
    }

    // Populate dashboard scan list
    const dl = document.getElementById('dashboard-scan-list');
    if(dl) {
        activityHistory.slice(0, 5).forEach(item => {
            const li = document.createElement('li');
            li.className = 'scan-item';
            let icon = item.status === 'SAFE' ? 'fa-shield-check safe-text' : (item.status === 'SUSPICIOUS' ? 'fa-exclamation-triangle warning-text' : 'fa-skull-crossbones danger-text');
            li.innerHTML = `
                <div class="scan-url"><i class="fas ${icon}"></i> ${item.url}</div>
                <div class="scan-score">${item.score}%</div>
            `;
            dl.appendChild(li);
        });

        // Update counters
        document.getElementById('total-scanned').textContent = totalScanned;
        document.getElementById('total-threats').textContent = totalThreats;
        
        // Update Risk Meter based on recent threats (Mock logic)
        let recentRisk = activityHistory.length > 0 ? activityHistory[0].score : 25;
        document.getElementById('global-risk-score').textContent = recentRisk;
        
        let dial = document.getElementById('risk-dial');
        if(dial) dial.style.strokeDasharray = `${recentRisk}, 100`;
        
        let label = document.querySelector('.risk-label');
        if(recentRisk > 70) {
            dial.style.stroke = 'var(--danger)';
            label.textContent = 'DANGER';
            label.className = 'risk-label danger-text';
        } else if (recentRisk > 30) {
            dial.style.stroke = 'var(--warning)';
            label.textContent = 'ELEVATED';
            label.className = 'risk-label warning-text';
        }
    }
});

// Generic risk popup
function triggerWarningPopup(score, reasons) {
    if (score > 60) {
        // Fallback to simple alert to keep readability as requested
        setTimeout(() => {
            alert(`CYPHERX SECURITY WARNING!\n\nRisk Score: ${score}/100\nThreats Detected:\n- ${reasons.join('\n- ')}`);
        }, 300);
    }
}

// URL Scanner API Wrap
async function fetchUrlSafety(url, source) {
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url, source })
        });
        const data = await response.json();
        const score = data.riskScore !== undefined ? data.riskScore : 0;
        addToHistory(url, score, data.status, source);
        return data;
    } catch(err) {
        return { status: 'ERROR', reasons: ['Failed to contact threat server.'], riskScore: 0 };
    }
}

// 1. Standard URL Scanner
const urlScanForm = document.getElementById('url-scan-form');
if (urlScanForm) {
    urlScanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('url-input').value;
        const loader = document.getElementById('url-loader');
        const card = document.getElementById('url-result-card');
        
        card.style.display = 'none';
        loader.style.display = 'block';

        const data = await fetchUrlSafety(urlInput, 'Manual URL');
        
        loader.style.display = 'none';
        updateResultCard('url', data.status, data.reasons.join(', '), data.riskScore);
        card.style.display = 'block';

        triggerWarningPopup(data.riskScore, data.reasons);
    });
}

// 2. Monitor Simulation
const mtForm = document.getElementById('monitor-form');
if(mtForm) {
    mtForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = document.getElementById('monitor-input').value;
        const loader = document.getElementById('monitor-loader');
        const modal = document.getElementById('monitor-intercept-modal');
        
        loader.style.display = 'block';
        mtForm.style.display = 'none';
        
        const data = await fetchUrlSafety(url, 'Live Monitor Intercept');
        
        setTimeout(() => {
            loader.style.display = 'none';
            if(data.status !== 'SAFE' && data.riskScore > 30) { // Catch suspicious and dangerous
                modal.style.display = 'block';
                document.getElementById('monitor-score-val').textContent = data.riskScore;
                document.getElementById('monitor-status-val').textContent = data.status;
                document.getElementById('monitor-reason-val').textContent = data.reasons.join(', ');
                
                if(data.status === 'DANGEROUS') {
                    document.getElementById('monitor-modal-icon').className = 'fas fa-skull-crossbones pulse';
                    document.getElementById('monitor-modal-icon').style.color = 'var(--danger)';
                } else {
                    document.getElementById('monitor-modal-icon').className = 'fas fa-exclamation-triangle pulse';
                    document.getElementById('monitor-modal-icon').style.color = 'var(--warning)';
                }
                
                document.getElementById('btn-go-back').onclick = () => {
                    modal.style.display = 'none';
                    mtForm.style.display = 'block';
                    document.getElementById('monitor-input').value = '';
                };
                
                document.getElementById('btn-proceed').onclick = () => {
                    window.open(url.startsWith('http') ? url : 'http://' + url, '_blank');
                    modal.style.display = 'none';
                    mtForm.style.display = 'block';
                }
            } else {
                // If safe, just open it
                mtForm.style.display = 'block';
                document.getElementById('monitor-input').value = '';
                window.open(url.startsWith('http') ? url : 'http://' + url, '_blank');
            }
        }, 1200);
    });
}

// 3. File Scan Simulation (on Dashboard)
const fileInput = document.getElementById('file-input');
const fileBtn = document.getElementById('scan-file-btn');
if(fileInput && fileBtn) {
    fileInput.addEventListener('change', function() {
        if(this.files.length > 0) {
            document.getElementById('selected-filename').textContent = this.files[0].name;
            fileBtn.style.display = 'inline-flex';
            document.getElementById('file-result-card').style.display = 'none';
        }
    });

    fileBtn.addEventListener('click', async () => {
        const file = fileInput.files[0];
        if(!file) return;

        fileBtn.style.display = 'none';
        document.getElementById('file-loader').style.display = 'block';
        
        let prog = 0;
        let pB = document.getElementById('file-progress');
        let iv = setInterval(() => {
            prog += Math.random() * 15;
            if(prog > 90) prog = 90;
            pB.style.width = prog + '%';
        }, 200);

        try {
            const resp = await fetch(FILE_API_URL, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ filename: file.name })
            });
            const data = await resp.json();
            
            clearInterval(iv);
            pB.style.width = '100%';
            
            addToHistory(file.name, data.riskScore, data.status, 'File Scanner');

            setTimeout(() => {
                document.getElementById('file-loader').style.display = 'none';
                updateResultCard('file', data.status, data.reasons.join(', '), data.riskScore);
                document.getElementById('file-result-card').style.display = 'block';
                
                document.getElementById('file-score-val').textContent = data.riskScore;
                let fill = document.getElementById('file-risk-fill');
                fill.style.width = data.riskScore + '%';
                if(data.riskScore > 70) fill.style.background = 'var(--danger)';
                else if(data.riskScore > 30) fill.style.background = 'var(--warning)';
                else fill.style.background = 'var(--safe)';

                triggerWarningPopup(data.riskScore, data.reasons);
                
            }, 500);
        } catch(e) {
            clearInterval(iv);
            document.getElementById('file-loader').style.display = 'none';
        }
    });
}

// 4. QR Scanner Logic
const qrInput = document.getElementById('qr-input');
const qrPreviewContainer = document.getElementById('preview-container');
const qrPreviewImg = document.getElementById('qr-preview');
const scanQrBtn = document.getElementById('scan-qr-btn');

if (qrInput && typeof ZXing !== 'undefined') {
    qrInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            const file = this.files[0];
            const reader = new FileReader();
            reader.onload = function(e) {
                qrPreviewImg.src = e.target.result;
                qrPreviewContainer.style.display = 'block';
                scanQrBtn.style.display = 'inline-flex';
                document.getElementById('qr-error-msg').style.display = 'none';
                document.getElementById('qr-decoded-text').style.display = 'none';
                document.getElementById('qr-result-card').style.display = 'none';
            }
            reader.readAsDataURL(file);
        }
    });

    scanQrBtn.addEventListener('click', async () => {
        document.getElementById('qr-error-msg').style.display = 'none';
        
        try {
            const codeReader = new ZXing.BrowserQRCodeReader();
            const result = await codeReader.decodeFromImageElement(qrPreviewImg);
            const url = result.text;
            
            document.getElementById('extracted-url').textContent = url;
            document.getElementById('qr-decoded-text').style.display = 'block';

            document.getElementById('qr-loader').style.display = 'block';
            document.getElementById('qr-result-card').style.display = 'none';
            
            const data = await fetchUrlSafety(url, 'QR Decoder');
            
            document.getElementById('qr-loader').style.display = 'none';
            updateResultCard('qr', data.status, data.reasons.join(', '), data.riskScore);
            document.getElementById('qr-result-card').style.display = 'block';

            triggerWarningPopup(data.riskScore, data.reasons);
            
        } catch (err) {
            document.getElementById('qr-error-msg').style.display = 'block';
            document.getElementById('qr-error-msg').textContent = "Failed to detect valid payload.";
        }
    });
}

// Refactored UI updater
function updateResultCard(prefix, status, reason, score) {
    const card = document.getElementById(`${prefix}-result-card`);
    const icon = document.getElementById(`${prefix}-result-icon`);
    const sText = document.getElementById(`${prefix}-result-status`);
    const rText = document.getElementById(`${prefix}-result-reason`);

    card.className = 'result-card';
    icon.className = 'fas result-icon';
    
    sText.innerHTML = `${status} <span style="font-size:1rem; color:#fff;">(Risk: ${score}/100)</span>`;
    rText.textContent = reason;

    if (status === 'SAFE') {
        card.classList.add('safe');
        icon.classList.add('fa-shield-check');
    } else if (status === 'SUSPICIOUS') {
        card.classList.add('suspicious');
        icon.classList.add('fa-exclamation-triangle');
    } else {
        card.classList.add('dangerous');
        icon.classList.add('fa-skull-crossbones');
    }
}
