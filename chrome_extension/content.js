// Cerberus Chrome Extension - Content Script

class CerberusContentScript {
    constructor() {
        this.isInjected = false;
        this.warningShown = false;
        this.settings = {};
        
        this.init();
    }

    async init() {
        await this.loadSettings();
        this.setupPageMonitoring();
        this.checkCurrentPage();
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.sync.get([
                'realTimeProtection',
                'phishingProtection',
                'malwareBlocking'
            ]);

            this.settings = {
                realTimeProtection: result.realTimeProtection ?? true,
                phishingProtection: result.phishingProtection ?? true,
                malwareBlocking: result.malwareBlocking ?? true
            };
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    }

    setupPageMonitoring() {
        if (!this.settings.realTimeProtection) return;

        // Monitor for suspicious page changes
        this.observePageChanges();
        
        // Monitor for suspicious form submissions
        this.monitorForms();
        
        // Monitor for suspicious downloads
        this.monitorDownloads();
        
        // Monitor for suspicious redirects
        this.monitorRedirects();
    }

    observePageChanges() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    this.checkForSuspiciousContent(mutation.addedNodes);
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    checkForSuspiciousContent(nodes) {
        if (!this.settings.phishingProtection) return;

        nodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
                // Check for suspicious iframe injections
                const iframes = node.querySelectorAll ? node.querySelectorAll('iframe') : [];
                iframes.forEach(iframe => {
                    if (this.isSuspiciousIframe(iframe)) {
                        this.handleSuspiciousElement(iframe, 'Suspicious iframe detected');
                    }
                });

                // Check for suspicious form elements
                const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
                forms.forEach(form => {
                    if (this.isSuspiciousForm(form)) {
                        this.handleSuspiciousElement(form, 'Suspicious form detected');
                    }
                });

                // Check for suspicious scripts
                const scripts = node.querySelectorAll ? node.querySelectorAll('script') : [];
                scripts.forEach(script => {
                    if (this.isSuspiciousScript(script)) {
                        this.handleSuspiciousElement(script, 'Suspicious script detected');
                    }
                });
            }
        });
    }

    isSuspiciousIframe(iframe) {
        const src = iframe.src || '';
        const suspiciousPatterns = [
            /data:text\/html/i,
            /javascript:/i,
            /vbscript:/i,
            /about:blank/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(src)) ||
               iframe.style.display === 'none' ||
               iframe.style.visibility === 'hidden' ||
               iframe.width === '0' ||
               iframe.height === '0';
    }

    isSuspiciousForm(form) {
        const action = form.action || '';
        const method = form.method || '';
        
        // Check for forms posting to suspicious URLs
        const suspiciousPatterns = [
            /data:/i,
            /javascript:/i,
            /vbscript:/i
        ];

        if (suspiciousPatterns.some(pattern => pattern.test(action))) {
            return true;
        }

        // Check for password fields in suspicious contexts
        const passwordFields = form.querySelectorAll('input[type="password"]');
        const emailFields = form.querySelectorAll('input[type="email"]');
        
        if (passwordFields.length > 0 && emailFields.length > 0) {
            // This might be a phishing form - check if it's on a legitimate domain
            return this.isPotentialPhishingForm(form);
        }

        return false;
    }

    isPotentialPhishingForm(form) {
        // Check if the form is trying to mimic a legitimate service
        const formText = form.textContent.toLowerCase();
        const legitimateServices = [
            'google', 'facebook', 'twitter', 'microsoft', 'apple',
            'amazon', 'paypal', 'bank', 'login', 'signin'
        ];

        const foundServices = legitimateServices.filter(service => 
            formText.includes(service)
        );

        if (foundServices.length > 0) {
            // Check if we're actually on the legitimate domain
            const hostname = window.location.hostname.toLowerCase();
            return !foundServices.some(service => hostname.includes(service));
        }

        return false;
    }

    isSuspiciousScript(script) {
        const src = script.src || '';
        const content = script.textContent || '';

        // Check for suspicious script sources
        const suspiciousPatterns = [
            /data:/i,
            /javascript:/i,
            /vbscript:/i
        ];

        if (suspiciousPatterns.some(pattern => pattern.test(src))) {
            return true;
        }

        // Check for suspicious script content
        const maliciousPatterns = [
            /eval\s*\(/i,
            /document\.write\s*\(/i,
            /setTimeout\s*\(\s*['"][\w\s]*eval/i,
            /fromCharCode/i,
            /unescape/i,
            /String\.fromCharCode/i
        ];

        return maliciousPatterns.some(pattern => pattern.test(content));
    }

    monitorForms() {
        document.addEventListener('submit', (event) => {
            if (!this.settings.phishingProtection) return;

            const form = event.target;
            if (this.isSuspiciousForm(form)) {
                event.preventDefault();
                this.showPhishingWarning('Suspicious form submission blocked');
            }
        }, true);
    }

    monitorDownloads() {
        document.addEventListener('click', (event) => {
            const target = event.target;
            
            if (target.tagName === 'A' && target.href) {
                const href = target.href.toLowerCase();
                const suspiciousExtensions = [
                    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
                    '.jar', '.vbs', '.js', '.jse', '.wsf', '.wsh'
                ];

                if (suspiciousExtensions.some(ext => href.includes(ext))) {
                    if (this.settings.malwareBlocking) {
                        event.preventDefault();
                        this.showDownloadWarning(target.href);
                    }
                }
            }
        }, true);
    }

    monitorRedirects() {
        // Monitor for suspicious redirects
        let redirectCount = 0;
        const maxRedirects = 3;

        const originalPushState = history.pushState;
        const originalReplaceState = history.replaceState;

        history.pushState = function(...args) {
            redirectCount++;
            if (redirectCount > maxRedirects) {
                console.warn('Cerberus: Excessive redirects detected');
            }
            return originalPushState.apply(this, args);
        };

        history.replaceState = function(...args) {
            redirectCount++;
            if (redirectCount > maxRedirects) {
                console.warn('Cerberus: Excessive redirects detected');
            }
            return originalReplaceState.apply(this, args);
        };
    }

    async checkCurrentPage() {
        if (!this.settings.realTimeProtection) return;

        try {
            // Get threat status from background script
            const response = await chrome.runtime.sendMessage({
                type: 'getThreatStatus',
                hostname: window.location.hostname
            });

            if (response.success && response.status.isThreat) {
                this.handleThreatDetection(response.status.result);
            }
        } catch (error) {
            console.error('Error checking page status:', error);
        }
    }

    handleSuspiciousElement(element, message) {
        console.warn('Cerberus:', message, element);
        
        // Add visual indicator
        this.addSuspiciousElementWarning(element);
        
        // Optionally disable the element
        if (this.settings.malwareBlocking) {
            element.style.display = 'none';
            element.disabled = true;
        }
    }

    addSuspiciousElementWarning(element) {
        // Create warning overlay
        const warning = document.createElement('div');
        warning.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 71, 87, 0.9);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, sans-serif;
            font-size: 12px;
            font-weight: bold;
            z-index: 999999;
            pointer-events: none;
        `;
        warning.textContent = '⚠️ BLOCKED BY CERBERUS';

        // Position relative to element
        const rect = element.getBoundingClientRect();
        if (rect.width > 20 && rect.height > 20) {
            element.style.position = 'relative';
            element.appendChild(warning);
        }
    }

    showPhishingWarning(message) {
        if (this.warningShown) return;
        this.warningShown = true;

        const warningDiv = document.createElement('div');
        warningDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 300px;
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            z-index: 999999;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 14px;
            animation: slideIn 0.3s ease-out;
        `;

        warningDiv.innerHTML = `
            <style>
                @keyframes slideIn {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
            </style>
            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 24px; margin-right: 10px;">🛡️</div>
                <div style="font-weight: bold;">Cerberus Protection</div>
            </div>
            <div style="margin-bottom: 15px;">${message}</div>
            <button onclick="this.parentElement.remove()" style="
                background: white;
                color: #333;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
                font-weight: bold;
            ">Dismiss</button>
        `;

        document.body.appendChild(warningDiv);

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (warningDiv.parentElement) {
                warningDiv.remove();
            }
            this.warningShown = false;
        }, 10000);
    }

    showDownloadWarning(url) {
        const warningDiv = document.createElement('div');
        warningDiv.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 400px;
            background: white;
            border: 3px solid #ff6b6b;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            z-index: 999999;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow: hidden;
        `;

        warningDiv.innerHTML = `
            <div style="background: linear-gradient(135deg, #ff6b6b, #ee5a24); color: white; padding: 20px; text-align: center;">
                <div style="font-size: 48px; margin-bottom: 10px;">⚠️</div>
                <h2 style="margin: 0; font-size: 20px;">Download Blocked</h2>
            </div>
            <div style="padding: 20px;">
                <p style="margin: 0 0 15px 0; color: #333;">
                    This download has been blocked because it may contain malware or be from an untrusted source.
                </p>
                <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 20px; word-break: break-all; font-size: 12px; color: #666;">
                    ${url}
                </div>
                <div style="display: flex; gap: 10px; justify-content: center;">
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
                        background: #6c757d;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 5px;
                        cursor: pointer;
                        font-weight: bold;
                    ">Cancel</button>
                    <button onclick="window.open('${url}'); this.parentElement.parentElement.parentElement.remove();" style="
                        background: #dc3545;
                        color: white;
                        border: none;
                        padding: 10px 20px;
                        border-radius: 5px;
                        cursor: pointer;
                        font-weight: bold;
                    ">Download Anyway</button>
                </div>
            </div>
        `;

        document.body.appendChild(warningDiv);
    }

    handleThreatDetection(result) {
        if (this.settings.malwareBlocking) {
            this.blockPage(result);
        } else {
            this.showThreatWarning(result);
        }
    }

    blockPage(result) {
        // Replace page content with warning
        document.documentElement.innerHTML = `
            <html>
            <head>
                <title>Site Blocked - Cerberus</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="
                margin: 0;
                padding: 0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #ff6b6b, #ee5a24);
                color: white;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            ">
                <div style="
                    max-width: 600px;
                    text-align: center;
                    padding: 40px;
                    background: rgba(0, 0, 0, 0.2);
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                ">
                    <div style="font-size: 72px; margin-bottom: 20px;">🛡️</div>
                    <h1 style="font-size: 32px; margin-bottom: 20px;">Site Blocked by Cerberus</h1>
                    <p style="font-size: 18px; margin-bottom: 30px;">
                        This website has been identified as potentially malicious and has been blocked for your protection.
                    </p>
                    <div style="
                        background: rgba(255, 255, 255, 0.1);
                        padding: 20px;
                        border-radius: 10px;
                        margin-bottom: 30px;
                    ">
                        <h3>Site: ${window.location.hostname}</h3>
                        <p>Threat Score: ${result.threat_score || 0}/100</p>
                        ${result.malware_type ? `<p>Threat Type: ${result.malware_type}</p>` : ''}
                    </div>
                    <div style="display: flex; gap: 20px; justify-content: center; flex-wrap: wrap;">
                        <button onclick="history.back()" style="
                            padding: 12px 24px;
                            background: white;
                            color: #333;
                            border: none;
                            border-radius: 6px;
                            font-size: 16px;
                            cursor: pointer;
                            font-weight: 600;
                        ">Go Back</button>
                        <button onclick="window.close()" style="
                            padding: 12px 24px;
                            background: transparent;
                            color: white;
                            border: 2px solid white;
                            border-radius: 6px;
                            font-size: 16px;
                            cursor: pointer;
                            font-weight: 600;
                        ">Close Tab</button>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    showThreatWarning(result) {
        this.showPhishingWarning(
            `Potential threat detected on this site. Threat score: ${result.threat_score || 0}/100`
        );
    }
}

// Initialize content script when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new CerberusContentScript();
    });
} else {
    new CerberusContentScript();
}