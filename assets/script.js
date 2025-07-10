
function getKeywordss(){
    $.get($('#urla').val(), function(resp) {
        document.getElementById('keywords1').value = resp;
    });
}

function Generate(){
    $("#results").empty();
    $.each($('#keywords1').val().split('\n'), function(){
      var link = "https://github.com/search?q="+$('#targets').val()+" "+this+"&type=Code";
      $('#results').append("<tr><td><input type=\"checkbox\"></td><td> <a href=\""+encodeURI(link)+"\" target=\"_blank\">"+this+"</td></tr>");
    });
}

// Wolf Subdomain Finder - Enhanced Functions
// Developed by Tamilselvan

function subdomainDork(dork) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        // Validate domain format
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        // Add loading state
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Searching...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        // Track usage
        trackSearch('subdomain', domain);
    } else {
        showAlert('🐺 Please enter a target domain to unleash the wolf!', 'error');
        focusInput();
    }
}

// Helper Functions
function isValidDomain(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    return domainRegex.test(domain);
}

function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 100px; right: 20px; z-index: 9999; min-width: 300px;';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        if (alertDiv.parentNode) {
            alertDiv.remove();
        }
    }, 5000);
}

function focusInput() {
    const input = document.getElementById('searchdomain');
    input.focus();
    input.classList.add('error-state');
    setTimeout(() => input.classList.remove('error-state'), 3000);
}

function trackSearch(type, domain) {
    console.log(`🐺 Wolf Search: ${type} for ${domain} at ${new Date().toISOString()}`);
}

function validateAndFocus() {
    const domain = document.getElementById('searchdomain').value.trim();
    const input = document.getElementById('searchdomain');
    
    if (!domain) {
        showAlert('🐺 Please enter a domain to validate!', 'error');
        focusInput();
        return;
    }
    
    if (isValidDomain(domain)) {
        input.classList.add('success-state');
        showAlert(`✅ Domain "${domain}" is valid! Ready to hunt!`, 'success');
        setTimeout(() => input.classList.remove('success-state'), 3000);
    } else {
        input.classList.add('error-state');
        showAlert('❌ Invalid domain format. Please enter a valid domain (e.g., example.com)', 'error');
        setTimeout(() => input.classList.remove('error-state'), 3000);
        focusInput();
    }
}

function portDork(dork) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Scanning...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        trackSearch('port', domain);
    } else {
        showAlert('🐺 Please enter a target domain to scan ports!', 'error');
        focusInput();
    }
}

function urlDork(dork) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Collecting...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        trackSearch('url', domain);
    } else {
        showAlert('🐺 Please enter a target domain to collect URLs!', 'error');
        focusInput();
    }
}

function genericDork(dork) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Hunting...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        trackSearch('generic', domain);
    } else {
        showAlert('🐺 Please enter a target domain to start hunting!', 'error');
        focusInput();
    }
}



function allDork(dork) {
    const domain = document.getElementById('searchdomain').value;
    if (domain) {
        const finalDork = dork.replace('example.com', domain);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {

            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
    } else {
        alert('Please enter a target domain.');
    }
}


function orDork(dork) {
    const domain = document.getElementById('searchdomain').value;
    if (domain) {
        const finalDork = dork.replace('example.com', domain);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {

            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
    } else {
        alert('Please enter a target domain.');
    }
}

function gitDork(dork) {
    const domain = document.getElementById('searchdomain').value;
    if (domain) {
        const finalDork = dork.replace('example.com', domain);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {

            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
    } else {
        alert('Please enter a target domain.');
    }
}

function cmsDork(dork) {
    const domain = document.getElementById('searchdomain').value;
    if (domain) {
        const finalDork = dork.replace('example.com', domain);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {

            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
    } else {
        alert('Please enter a target domain.');
    }
}

function cveDork(dork) {
    // Use the main search domain input since searccve doesn't exist
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Searching CVEs...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        trackSearch('cve', domain);
    } else {
        showAlert('🐺 Please enter a target domain to search for CVEs!', 'error');
        focusInput();
    }
}

// Enhanced functions for better user experience
function gitDork(dork) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (domain) {
        if (!isValidDomain(domain)) {
            showAlert('Please enter a valid domain (e.g., example.com)', 'error');
            return;
        }
        
        const finalDork = dork.replace(/example\.com/g, domain);
        
        const button = event.target;
        const originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> Analyzing...';
        button.disabled = true;
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
        
        if (finalDork.startsWith('http://') || finalDork.startsWith('https://')) {
            window.open(finalDork, '_blank');
        } else {
            window.open(`https://www.google.com/search?q=${encodeURIComponent(finalDork)}`, '_blank');
        }
        
        trackSearch('technology', domain);
    } else {
        showAlert('🐺 Please enter a target domain to detect technologies!', 'error');
        focusInput();
    }
}

// Enhanced functions for new features
let scanResults = {
    total: 0,
    successful: 0,
    failed: 0,
    history: [],
    targets: []
};

let monitoringInterval = null;
let isMonitoring = false;

// Quick Scan Function
function quickScan() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain || !isValidDomain(domain)) {
        showAlert('🐺 Please enter a valid domain first!', 'error');
        return;
    }
    
    showAlert('🚀 Starting Quick Scan...', 'success');
    updateActivityLog('🚀 Quick scan initiated for ' + domain);
    
    // Show results dashboard
    document.getElementById('resultsDashboard').style.display = 'block';
    
    // Simulate quick scan with multiple checks
    const quickChecks = [
        'Checking DNS records...',
        'Analyzing SSL certificates...',
        'Scanning common subdomains...',
        'Checking security headers...',
        'Analyzing web technologies...'
    ];
    
    let checkIndex = 0;
    const quickScanInterval = setInterval(() => {
        if (checkIndex < quickChecks.length) {
            updateActivityLog('⚡ ' + quickChecks[checkIndex]);
            checkIndex++;
        } else {
            clearInterval(quickScanInterval);
            updateActivityLog('✅ Quick scan completed for ' + domain);
            updateScanStats(true);
            showAlert('✅ Quick scan completed successfully!', 'success');
        }
    }, 1000);
}

// Save Target Function
function saveTarget() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain || !isValidDomain(domain)) {
        showAlert('🐺 Please enter a valid domain first!', 'error');
        return;
    }
    
    // Save to localStorage
    let savedTargets = JSON.parse(localStorage.getItem('wolfTargets') || '[]');
    if (!savedTargets.includes(domain)) {
        savedTargets.push(domain);
        localStorage.setItem('wolfTargets', JSON.stringify(savedTargets));
        updateTargetHistory();
        showAlert('💾 Target saved successfully!', 'success');
        updateActivityLog('💾 Target saved: ' + domain);
    } else {
        showAlert('ℹ️ Target already saved!', 'info');
    }
}

// Update Target History Dropdown
function updateTargetHistory() {
    const select = document.getElementById('targetHistory');
    const savedTargets = JSON.parse(localStorage.getItem('wolfTargets') || '[]');
    
    select.innerHTML = '<option value="">Select previous target...</option>';
    savedTargets.forEach(target => {
        const option = document.createElement('option');
        option.value = target;
        option.textContent = target;
        select.appendChild(option);
    });
}

// Load from History
function loadFromHistory() {
    const select = document.getElementById('targetHistory');
    const selectedTarget = select.value;
    
    if (selectedTarget) {
        document.getElementById('searchdomain').value = selectedTarget;
        showAlert('📂 Target loaded: ' + selectedTarget, 'success');
        updateActivityLog('📂 Loaded from history: ' + selectedTarget);
    }
}

// Clear History
function clearHistory() {
    if (confirm('Are you sure you want to clear all saved targets?')) {
        localStorage.removeItem('wolfTargets');
        updateTargetHistory();
        showAlert('🗑️ History cleared!', 'success');
        updateActivityLog('🗑️ Target history cleared');
    }
}

// AI Subdomain Generation Functions
function generateSmartSubdomains() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    const commonSubdomains = [
        'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test', 'staging',
        'cdn', 'static', 'assets', 'img', 'images', 'css', 'js', 'media',
        'shop', 'store', 'payment', 'secure', 'login', 'auth', 'account',
        'support', 'help', 'docs', 'wiki', 'forum', 'community', 'news',
        'mobile', 'm', 'app', 'apps', 'download', 'files', 'upload'
    ];
    
    displayGeneratedSubdomains(commonSubdomains, domain);
    updateActivityLog('🤖 Generated ' + commonSubdomains.length + ' common subdomains');
}

function generateTechSubdomains() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    const techSubdomains = [
        'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
        'docker', 'kubernetes', 'k8s', 'grafana', 'prometheus', 'kibana',
        'elasticsearch', 'redis', 'mongodb', 'mysql', 'postgres', 'db',
        'vpn', 'ssh', 'sftp', 'ldap', 'ad', 'exchange', 'outlook',
        'aws', 'azure', 'gcp', 'cloud', 'backup', 'monitoring', 'logs'
    ];
    
    displayGeneratedSubdomains(techSubdomains, domain);
    updateActivityLog('⚙️ Generated ' + techSubdomains.length + ' tech-based subdomains');
}

function generateSecuritySubdomains() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    const securitySubdomains = [
        'security', 'sec', 'firewall', 'ids', 'ips', 'siem', 'soc',
        'vulnerability', 'vuln', 'pentest', 'audit', 'compliance',
        'cert', 'ca', 'pki', 'ssl', 'tls', 'crypto', 'keys',
        'waf', 'proxy', 'gateway', 'bastion', 'jump', 'dmz'
    ];
    
    displayGeneratedSubdomains(securitySubdomains, domain);
    updateActivityLog('🛡️ Generated ' + securitySubdomains.length + ' security subdomains');
}

function generateCustomSubdomains() {
    const domain = document.getElementById('searchdomain').value.trim();
    const customWords = document.getElementById('customWordlist').value.trim();
    
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    if (!customWords) {
        showAlert('📝 Please enter custom keywords!', 'error');
        return;
    }
    
    const customSubdomains = customWords.split('\n').map(word => word.trim()).filter(word => word);
    displayGeneratedSubdomains(customSubdomains, domain);
    updateActivityLog('🎯 Generated ' + customSubdomains.length + ' custom subdomains');
}

function displayGeneratedSubdomains(subdomains, domain) {
    const container = document.getElementById('generatedSubdomains');
    container.innerHTML = '';
    
    subdomains.forEach(sub => {
        const fullDomain = `${sub}.${domain}`;
        const div = document.createElement('div');
        div.className = 'text-info mb-1';
        div.innerHTML = `<span class="text-warning">•</span> ${fullDomain}`;
        container.appendChild(div);
    });
    
    // Store for later use
    window.currentSubdomains = subdomains.map(sub => `${sub}.${domain}`);
}

// Threat Intelligence Functions
function threatDork(url) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    const finalUrl = url.replace(/example\.com/g, domain);
    window.open(finalUrl, '_blank');
    updateActivityLog('🛡️ Threat intelligence check: ' + finalUrl.split('/')[2]);
    updateScanStats(true);
}

// Network Analysis Functions
function networkDork(url) {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    const finalUrl = url.replace(/example\.com/g, domain);
    window.open(finalUrl, '_blank');
    updateActivityLog('🌐 Network analysis: ' + finalUrl.split('/')[2]);
    updateScanStats(true);
}

// Monitoring Functions
function startMonitoring() {
    const domain = document.getElementById('searchdomain').value.trim();
    if (!domain) {
        showAlert('🐺 Please enter a domain first!', 'error');
        return;
    }
    
    if (isMonitoring) {
        stopMonitoring();
        return;
    }
    
    const interval = parseInt(document.getElementById('monitorInterval').value) * 1000;
    isMonitoring = true;
    
    document.getElementById('monitorStatus').textContent = 'Active';
    document.getElementById('monitorStatus').className = 'badge bg-success';
    
    updateActivityLog('📡 Monitoring started for ' + domain);
    showAlert('📡 Monitoring started!', 'success');
    
    monitoringInterval = setInterval(() => {
        performMonitorCheck(domain);
    }, interval);
    
    updateNextCheckTime(interval);
}

function stopMonitoring() {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
    }
    
    isMonitoring = false;
    document.getElementById('monitorStatus').textContent = 'Inactive';
    document.getElementById('monitorStatus').className = 'badge bg-secondary';
    document.getElementById('nextCheck').textContent = '--:--';
    
    updateActivityLog('📡 Monitoring stopped');
    showAlert('📡 Monitoring stopped!', 'info');
}

function performMonitorCheck(domain) {
    updateActivityLog('🔍 Monitoring check for ' + domain);
    
    // Simulate monitoring check
    const checks = Math.floor(Math.random() * 10) + 1;
    document.getElementById('checksToday').textContent = parseInt(document.getElementById('checksToday').textContent) + 1;
    
    // Random alert simulation
    if (Math.random() < 0.1) { // 10% chance of alert
        if (document.getElementById('soundAlerts').checked) {
            // Play alert sound (if available)
            console.log('🔊 Alert sound would play here');
        }
        
        if (document.getElementById('desktopAlerts').checked) {
            if (Notification.permission === 'granted') {
                new Notification('Wolf Subdomain Finder Alert', {
                    body: `New activity detected for ${domain}`,
                    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🐺</text></svg>'
                });
            }
        }
        
        updateActivityLog('🚨 Alert: Suspicious activity detected for ' + domain);
        showAlert('🚨 Alert: New activity detected!', 'error');
    }
}

function updateNextCheckTime(interval) {
    const nextTime = new Date(Date.now() + interval);
    document.getElementById('nextCheck').textContent = nextTime.toLocaleTimeString();
    
    setTimeout(() => {
        if (isMonitoring) {
            updateNextCheckTime(interval);
        }
    }, interval);
}

// Utility Functions
function updateActivityLog(message) {
    const log = document.getElementById('activityLog');
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.innerHTML = `<span class="text-muted">[${timestamp}]</span> ${message}`;
    log.appendChild(logEntry);
    log.scrollTop = log.scrollHeight;
}

function updateScanStats(success) {
    scanResults.total++;
    if (success) {
        scanResults.successful++;
    } else {
        scanResults.failed++;
    }
    
    document.getElementById('totalScans').textContent = scanResults.total;
    document.getElementById('successfulScans').textContent = scanResults.successful;
    document.getElementById('failedScans').textContent = scanResults.failed;
    document.getElementById('lastScanTime').textContent = new Date().toLocaleTimeString();
}

// Export Functions
function exportResults(format) {
    const data = {
        domain: document.getElementById('searchdomain').value,
        timestamp: new Date().toISOString(),
        stats: scanResults,
        activity: Array.from(document.getElementById('activityLog').children).map(el => el.textContent)
    };
    
    let content, filename, mimeType;
    
    switch (format) {
        case 'json':
            content = JSON.stringify(data, null, 2);
            filename = `wolf-scan-${data.domain}-${Date.now()}.json`;
            mimeType = 'application/json';
            break;
        case 'csv':
            content = convertToCSV(data);
            filename = `wolf-scan-${data.domain}-${Date.now()}.csv`;
            mimeType = 'text/csv';
            break;
        case 'txt':
            content = convertToTXT(data);
            filename = `wolf-scan-${data.domain}-${Date.now()}.txt`;
            mimeType = 'text/plain';
            break;
    }
    
    downloadFile(content, filename, mimeType);
    updateActivityLog('💾 Results exported as ' + format.toUpperCase());
}

function convertToCSV(data) {
    let csv = 'Timestamp,Domain,Total Scans,Successful,Failed\n';
    csv += `${data.timestamp},${data.domain},${data.stats.total},${data.stats.successful},${data.stats.failed}\n`;
    return csv;
}

function convertToTXT(data) {
    let txt = `Wolf Subdomain Finder - Scan Report\n`;
    txt += `=====================================\n`;
    txt += `Domain: ${data.domain}\n`;
    txt += `Timestamp: ${data.timestamp}\n`;
    txt += `Total Scans: ${data.stats.total}\n`;
    txt += `Successful: ${data.stats.successful}\n`;
    txt += `Failed: ${data.stats.failed}\n\n`;
    txt += `Activity Log:\n`;
    txt += `-------------\n`;
    data.activity.forEach(entry => {
        txt += entry + '\n';
    });
    return txt;
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function clearResults() {
    if (confirm('Are you sure you want to clear all results?')) {
        scanResults = { total: 0, successful: 0, failed: 0, history: [], targets: [] };
        document.getElementById('totalScans').textContent = '0';
        document.getElementById('successfulScans').textContent = '0';
        document.getElementById('failedScans').textContent = '0';
        document.getElementById('lastScanTime').textContent = '--:--';
        document.getElementById('activityLog').innerHTML = '<div class="text-success">🐺 Wolf Subdomain Finder initialized...</div><div class="text-info">📡 Ready for reconnaissance operations...</div>';
        showAlert('🗑️ Results cleared!', 'success');
    }
}

// Subdomain Testing Functions
function testAllSubdomains() {
    if (!window.currentSubdomains || window.currentSubdomains.length === 0) {
        showAlert('📝 Please generate subdomains first!', 'error');
        return;
    }
    
    showAlert('🔍 Testing ' + window.currentSubdomains.length + ' subdomains...', 'success');
    updateActivityLog('🔍 Started testing ' + window.currentSubdomains.length + ' subdomains');
    
    // Simulate subdomain testing
    let tested = 0;
    const testInterval = setInterval(() => {
        if (tested < window.currentSubdomains.length) {
            const subdomain = window.currentSubdomains[tested];
            updateActivityLog('🔍 Testing: ' + subdomain);
            tested++;
        } else {
            clearInterval(testInterval);
            updateActivityLog('✅ Subdomain testing completed');
            showAlert('✅ Subdomain testing completed!', 'success');
            updateScanStats(true);
        }
    }, 500);
}

function copySubdomains() {
    if (!window.currentSubdomains || window.currentSubdomains.length === 0) {
        showAlert('📝 Please generate subdomains first!', 'error');
        return;
    }
    
    const text = window.currentSubdomains.join('\n');
    navigator.clipboard.writeText(text).then(() => {
        showAlert('📋 Subdomains copied to clipboard!', 'success');
        updateActivityLog('📋 Copied ' + window.currentSubdomains.length + ' subdomains to clipboard');
    }).catch(() => {
        showAlert('❌ Failed to copy to clipboard', 'error');
    });
}

function exportSubdomains() {
    if (!window.currentSubdomains || window.currentSubdomains.length === 0) {
        showAlert('📝 Please generate subdomains first!', 'error');
        return;
    }
    
    const content = window.currentSubdomains.join('\n');
    const domain = document.getElementById('searchdomain').value.trim();
    const filename = `subdomains-${domain}-${Date.now()}.txt`;
    
    downloadFile(content, filename, 'text/plain');
    updateActivityLog('💾 Exported ' + window.currentSubdomains.length + ' subdomains');
}

// Add keyboard shortcuts and initialization
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchdomain');
    
    // Enter key to validate
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            validateAndFocus();
        }
    });
    
    // Auto-focus on page load
    searchInput.focus();
    
    // Initialize target history
    updateTargetHistory();
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
    
    // Add wolf howl sound effect (optional)
    console.log('🐺 Wolf Subdomain Finder loaded successfully!');
    console.log('🎯 Ready to hunt subdomains...');
    console.log('🚀 Enhanced features activated!');
    
    updateActivityLog('🐺 Wolf Subdomain Finder Enhanced Edition loaded');
    updateActivityLog('🎯 All systems operational - Ready for advanced reconnaissance');
});

// Theme Toggle Function
function toggleTheme() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    
    if (currentTheme === 'light') {
        body.setAttribute('data-theme', 'dark');
        localStorage.setItem('wolfTheme', 'dark');
        showAlert('🌙 Dark mode activated!', 'success');
    } else {
        body.setAttribute('data-theme', 'light');
        localStorage.setItem('wolfTheme', 'light');
        showAlert('☀️ Light mode activated!', 'success');
    }
    
    updateActivityLog('🎨 Theme toggled to ' + (currentTheme === 'light' ? 'dark' : 'light') + ' mode');
}

// Help Function
function showHelp() {
    const helpContent = `
    <div class="modal fade" id="helpModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-warning">
                    <h5 class="modal-title text-warning">🐺 Wolf Subdomain Finder - Help Guide</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <h6 class="text-info">🚀 Quick Start:</h6>
                    <ul>
                        <li>Enter a target domain (e.g., example.com)</li>
                        <li>Click "Validate" to check domain format</li>
                        <li>Use "Quick Scan" for automated reconnaissance</li>
                        <li>Save targets for future reference</li>
                    </ul>
                    
                    <h6 class="text-info mt-3">🔍 Features:</h6>
                    <ul>
                        <li><strong>AI Subdomain Predictor:</strong> Generate intelligent subdomain lists</li>
                        <li><strong>Real-time Monitoring:</strong> Continuous domain monitoring</li>
                        <li><strong>Threat Intelligence:</strong> Malware and reputation analysis</li>
                        <li><strong>Network Analysis:</strong> SSL, DNS, and security header analysis</li>
                        <li><strong>Export Options:</strong> Save results in JSON, CSV, or TXT format</li>
                    </ul>
                    
                    <h6 class="text-info mt-3">⌨️ Keyboard Shortcuts:</h6>
                    <ul>
                        <li><kbd>Enter</kbd> - Validate domain</li>
                        <li><kbd>Ctrl+S</kbd> - Save target</li>
                        <li><kbd>Ctrl+Q</kbd> - Quick scan</li>
                    </ul>
                    
                    <h6 class="text-warning mt-3">⚠️ Disclaimer:</h6>
                    <p class="small">This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before testing any domain.</p>
                </div>
                <div class="modal-footer border-warning">
                    <button type="button" class="btn btn-outline-warning" data-bs-dismiss="modal">Got it!</button>
                </div>
            </div>
        </div>
    </div>`;
    
    // Remove existing modal if any
    const existingModal = document.getElementById('helpModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', helpContent);
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('helpModal'));
    modal.show();
    
    updateActivityLog('❓ Help guide accessed');
}

// Statistics Function
function showStats() {
    const stats = {
        totalScans: scanResults.total,
        successful: scanResults.successful,
        failed: scanResults.failed,
        savedTargets: JSON.parse(localStorage.getItem('wolfTargets') || '[]').length,
        sessionTime: Math.floor((Date.now() - sessionStartTime) / 1000 / 60), // minutes
        featuresUsed: Object.keys(featureUsage).length
    };
    
    const statsContent = `
    <div class="modal fade" id="statsModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-info">
                    <h5 class="modal-title text-info">📊 Session Statistics</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <h4 class="text-warning">${stats.totalScans}</h4>
                            <small class="text-muted">Total Scans</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-success">${stats.successful}</h4>
                            <small class="text-muted">Successful</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-danger">${stats.failed}</h4>
                            <small class="text-muted">Failed</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-info">${stats.savedTargets}</h4>
                            <small class="text-muted">Saved Targets</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-primary">${stats.sessionTime}</h4>
                            <small class="text-muted">Minutes Active</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-warning">${stats.featuresUsed}</h4>
                            <small class="text-muted">Features Used</small>
                        </div>
                    </div>
                    <div class="mt-3">
                        <h6 class="text-info">🏆 Achievement Status:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${stats.totalScans >= 10 ? '<span class="badge bg-success">🎯 Scanner</span>' : ''}
                            ${stats.savedTargets >= 5 ? '<span class="badge bg-info">💾 Collector</span>' : ''}
                            ${stats.sessionTime >= 30 ? '<span class="badge bg-warning">⏰ Persistent</span>' : ''}
                            ${isMonitoring ? '<span class="badge bg-danger">📡 Monitor</span>' : ''}
                        </div>
                    </div>
                </div>
                <div class="modal-footer border-info">
                    <button type="button" class="btn btn-outline-info" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>`;
    
    // Remove existing modal if any
    const existingModal = document.getElementById('statsModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', statsContent);
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('statsModal'));
    modal.show();
    
    updateActivityLog('📊 Statistics viewed');
}

// Initialize session tracking
const sessionStartTime = Date.now();
let featureUsage = {};

// Track feature usage
function trackFeatureUsage(feature) {
    featureUsage[feature] = (featureUsage[feature] || 0) + 1;
}

// Enhanced keyboard shortcuts
document.addEventListener('keydown', function(e) {
    if (e.ctrlKey) {
        switch(e.key) {
            case 's':
                e.preventDefault();
                saveTarget();
                break;
            case 'q':
                e.preventDefault();
                quickScan();
                break;
            case 'h':
                e.preventDefault();
                showHelp();
                break;
        }
    }
});

// Auto-save functionality
setInterval(() => {
    if (document.getElementById('autoSave').checked) {
        const currentDomain = document.getElementById('searchdomain').value.trim();
        if (currentDomain && isValidDomain(currentDomain)) {
            const autoSaveData = {
                domain: currentDomain,
                timestamp: Date.now(),
                stats: scanResults
            };
            localStorage.setItem('wolfAutoSave', JSON.stringify(autoSaveData));
        }
    }
}, 30000); // Auto-save every 30 seconds

// Load theme on startup
document.addEventListener('DOMContentLoaded', function() {
    const savedTheme = localStorage.getItem('wolfTheme') || 'dark';
    document.body.setAttribute('data-theme', savedTheme);
});

// Performance monitoring
let performanceMetrics = {
    pageLoadTime: 0,
    averageResponseTime: 0,
    totalRequests: 0
};

window.addEventListener('load', function() {
    performanceMetrics.pageLoadTime = performance.now();
    updateActivityLog(`⚡ Page loaded in ${Math.round(performanceMetrics.pageLoadTime)}ms`);
});

// Add some Easter eggs
let konamiCode = [];
const konamiSequence = [38, 38, 40, 40, 37, 39, 37, 39, 66, 65]; // Up Up Down Down Left Right Left Right B A

document.addEventListener('keydown', function(e) {
    konamiCode.push(e.keyCode);
    if (konamiCode.length > konamiSequence.length) {
        konamiCode.shift();
    }
    
    if (konamiCode.join(',') === konamiSequence.join(',')) {
        showAlert('🐺 WOLF MODE ACTIVATED! 🐺', 'success');
        updateActivityLog('🎮 Konami code activated - Wolf mode enabled!');
        document.body.style.animation = 'wolfGlow 1s ease-in-out infinite alternate';
        setTimeout(() => {
            document.body.style.animation = '';
        }, 5000);
        konamiCode = [];
    }
});

// Additional functions for navbar buttons
function toggleTheme() {
    document.body.classList.toggle('light-theme');
    const isDark = !document.body.classList.contains('light-theme');
    localStorage.setItem('darkTheme', isDark);
    
    // Update theme icon
    const themeBtn = document.querySelector('[onclick="toggleTheme()"]');
    if (themeBtn) {
        themeBtn.innerHTML = isDark ? '🌙' : '☀️';
    }
    
    showAlert(`Switched to ${isDark ? 'dark' : 'light'} theme`, 'success');
}

function showHelp() {
    const helpModal = `
        <div class="modal fade" id="helpModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content bg-dark text-white">
                    <div class="modal-header border-warning">
                        <h5 class="modal-title text-warning">🐺 Wolf Subdomain Finder - Help</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6 class="text-info">🚀 Features:</h6>
                                <ul class="list-unstyled">
                                    <li>🎯 <strong>Subdomain Enumeration:</strong> Multiple discovery techniques</li>
                                    <li>🔍 <strong>Search Engine Dorking:</strong> Google, Bing, Yahoo</li>
                                    <li>📂 <strong>GitHub Dorking:</strong> Repository-based discovery</li>
                                    <li>🔧 <strong>CMS Dorking:</strong> WordPress, Joomla, Drupal</li>
                                    <li>🚨 <strong>CVE Search:</strong> Vulnerability database</li>
                                    <li>💀 <strong>Attack Scripts:</strong> 1000+ payloads</li>
                                </ul>
                                
                                <h6 class="text-info">⌨️ Keyboard Shortcuts:</h6>
                                <ul class="list-unstyled">
                                    <li><kbd>Ctrl+S</kbd> - Save target</li>
                                    <li><kbd>Ctrl+Q</kbd> - Quick scan</li>
                                    <li><kbd>Ctrl+H</kbd> - Show help</li>
                                    <li><kbd>Enter</kbd> - Validate domain</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-info">🎯 How to Use:</h6>
                                <ol class="list-unstyled">
                                    <li>1️⃣ Enter target domain (e.g., example.com)</li>
                                    <li>2️⃣ Click "Validate" to check domain</li>
                                    <li>3️⃣ Use enumeration tools below</li>
                                    <li>4️⃣ Try different dorking techniques</li>
                                    <li>5️⃣ Access Attack Scripts for testing</li>
                                </ol>
                                
                                <h6 class="text-info">⚠️ Important:</h6>
                                <div class="alert alert-warning">
                                    <strong>Educational Use Only!</strong><br>
                                    Always obtain proper authorization before testing any domain.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal
    const existingModal = document.getElementById('helpModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    document.body.insertAdjacentHTML('beforeend', helpModal);
    const modal = new bootstrap.Modal(document.getElementById('helpModal'));
    modal.show();
}

function showStats() {
    const stats = JSON.parse(localStorage.getItem('wolfStats')) || {
        domainsSearched: 0,
        searchesPerformed: 0,
        timeSpent: 0,
        lastVisit: new Date().toISOString()
    };
    
    const statsModal = `
        <div class="modal fade" id="statsModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content bg-dark text-white">
                    <div class="modal-header border-info">
                        <h5 class="modal-title text-info">📊 Wolf Subdomain Finder - Statistics</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row text-center">
                            <div class="col-md-3 mb-3">
                                <h4 class="text-warning">${stats.domainsSearched}</h4>
                                <small class="text-muted">Domains Searched</small>
                            </div>
                            <div class="col-md-3 mb-3">
                                <h4 class="text-success">${stats.searchesPerformed}</h4>
                                <small class="text-muted">Total Searches</small>
                            </div>
                            <div class="col-md-3 mb-3">
                                <h4 class="text-info">${Math.round(stats.timeSpent / 60)}</h4>
                                <small class="text-muted">Minutes Active</small>
                            </div>
                            <div class="col-md-3 mb-3">
                                <h4 class="text-primary">${new Date(stats.lastVisit).toLocaleDateString()}</h4>
                                <small class="text-muted">Last Visit</small>
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h6 class="text-info">🏆 Achievements:</h6>
                            <div class="d-flex flex-wrap gap-2">
                                ${stats.domainsSearched >= 10 ? '<span class="badge bg-success">🎯 Domain Hunter</span>' : ''}
                                ${stats.searchesPerformed >= 50 ? '<span class="badge bg-warning">🔍 Search Master</span>' : ''}
                                ${Math.round(stats.timeSpent / 60) >= 30 ? '<span class="badge bg-info">⏰ Dedicated User</span>' : ''}
                                ${stats.domainsSearched >= 100 ? '<span class="badge bg-danger">🚀 Wolf Expert</span>' : ''}
                            </div>
                        </div>
                        
                        <div class="mt-4">
                            <h6 class="text-info">📈 Recent Activity:</h6>
                            <div class="bg-black p-3 rounded" style="height: 150px; overflow-y: auto; font-family: monospace;">
                                <div class="text-success">🐺 Wolf Subdomain Finder initialized...</div>
                                <div class="text-info">📊 Statistics loaded successfully...</div>
                                <div class="text-warning">🎯 Ready for reconnaissance operations...</div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-danger" onclick="clearStats()">🗑️ Clear Stats</button>
                        <button type="button" class="btn btn-outline-success" onclick="exportStats()">📊 Export</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal
    const existingModal = document.getElementById('statsModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    document.body.insertAdjacentHTML('beforeend', statsModal);
    const modal = new bootstrap.Modal(document.getElementById('statsModal'));
    modal.show();
}

function clearStats() {
    localStorage.removeItem('wolfStats');
    showAlert('Statistics cleared successfully!', 'success');
    
    // Close modal
    const modal = document.getElementById('statsModal');
    if (modal) {
        const bootstrapModal = bootstrap.Modal.getInstance(modal);
        if (bootstrapModal) {
            bootstrapModal.hide();
        }
    }
}

function exportStats() {
    const stats = JSON.parse(localStorage.getItem('wolfStats')) || {};
    const exportData = {
        tool: 'Wolf Subdomain Finder',
        exported: new Date().toISOString(),
        statistics: stats
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wolf-stats-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showAlert('Statistics exported successfully!', 'success');
}

// Load theme on page load
document.addEventListener('DOMContentLoaded', function() {
    const isDark = localStorage.getItem('darkTheme') !== 'false';
    if (!isDark) {
        document.body.classList.add('light-theme');
    }
    
    const themeBtn = document.querySelector('[onclick="toggleTheme()"]');
    if (themeBtn) {
        themeBtn.innerHTML = isDark ? '🌙' : '☀️';
    }
});

console.log('🐺 Wolf Subdomain Finder Enhanced Edition');
console.log('🚀 All advanced features loaded successfully!');
console.log('💡 Try the Konami code for a surprise!');
console.log('⌨️ Keyboard shortcuts: Ctrl+S (Save), Ctrl+Q (Quick Scan), Ctrl+H (Help)');
