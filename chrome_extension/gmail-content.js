// Cerberus Gmail Extension - Basic Attachment Scanner

class GmailAttachmentScanner {
    constructor() {
        this.API_BASE = 'http://localhost:5000';
        this.scannedAttachments = new Set();
        this.isEnabled = true;
        
        this.init();
    }

    async init() {
        console.log('🛡️ Cerberus Gmail Scanner initialized');
        
        if (this.isEnabled) {
            this.waitForGmailLoad();
            this.setupMessageListener();
        }
    }

    waitForGmailLoad() {
        // Wait for Gmail to fully load
        const checkGmailLoaded = () => {
            if (this.isGmailLoaded()) {
                this.startScanning();
            } else {
                setTimeout(checkGmailLoaded, 2000);
            }
        };
        
        checkGmailLoaded();
    }

    isGmailLoaded() {
        // Check if Gmail interface is loaded
        return document.querySelector('[data-thread-id]') !== null ||
               document.querySelector('.ii.gt') !== null ||
               document.querySelector('[role="main"]') !== null ||
               document.querySelector('.bGI') !== null || // Modern Gmail thread container
               document.querySelector('.aAA') !== null;  // Modern Gmail main container
    }

    startScanning() {
        console.log('🔍 Starting Gmail attachment scanning');
        
        // Monitor for new emails and attachments
        this.observeAttachments();
        
        // Scan existing attachments
        this.scanExistingAttachments();
        
        // Add status indicator
        this.addStatusIndicator();
    }

    observeAttachments() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.findAndScanAttachments(node);
                        }
                    });
                }
            });
        });

        // Observe the main Gmail container
        const gmailContainer = document.querySelector('[role="main"]') || document.body;
        observer.observe(gmailContainer, {
            childList: true,
            subtree: true
        });
    }

    scanExistingAttachments() {
        console.log('📎 Scanning existing attachments');
        this.findAndScanAttachments(document);
    }

    findAndScanAttachments(container) {
        // Gmail attachment selectors - updated for modern Gmail UI
        const attachmentSelectors = [
            '.aZo',                    // Attachment card
            '[role="button"][data-tooltip*="Download"]', // Download button
            '.aQy',                    // Attachment container
            '[href*="view=att"]',    // Attachment download links
            '.aYv',                    // Attachment preview
            '.aZn',                    // Attachment tile
            '.aQw',                    // Attachment download area
            '.aPv',                    // Attachment icon area
            '[data-message-id] .aZo',  // Attachment within message
            '[data-tooltip*="attachment"]', // Generic attachment tooltip
            '.BqLmrf',                // New Gmail attachment container
            '.aVY',                   // Attachment icon
            '.aYp',                   // Attachment name container
            '[data-message-id] [role="button"]', // Attachment buttons in messages
            '.bAs',                   // Modern Gmail attachment container
            '.bAt',                   // Modern Gmail attachment name
            '.bAu',                   // Modern Gmail attachment size
            '[data-item-type="attachment"]' // Data attribute for attachments
        ];

        attachmentSelectors.forEach(selector => {
            const attachments = container.querySelectorAll ? 
                container.querySelectorAll(selector) : [];
            
            attachments.forEach(attachment => {
                this.processAttachment(attachment);
            });
        });
        
        // Also check for file links that might be attachments
        this.checkForFileLinks(container);
    }

    checkForFileLinks(container) {
        // Look for links that might be file attachments
        const fileLinkSelectors = [
            'a[href*="view=att"]',
            'a[href*="disp=attd"]',
            'a[download]',
            'a[href*=".pdf"]',
            'a[href*=".doc"]',
            'a[href*=".xls"]',
            'a[href*=".zip"]',
            'a[href*=".rar"]',
            'a[href*=".ppt"]',
            'a[href*=".txt"]',
            'a[href*=".jpg"]',
            'a[href*=".png"]',
            'a[href*=".gif"]',
            'a[href*=".mp3"]',
            'a[href*=".mp4"]'
        ];
        
        fileLinkSelectors.forEach(selector => {
            const links = container.querySelectorAll ? 
                container.querySelectorAll(selector) : [];
            
            links.forEach(link => {
                // Create a mock attachment element for processing
                const fileName = this.extractFileNameFromLink(link);
                if (fileName) {
                    const mockAttachment = {
                        textContent: fileName,
                        title: fileName,
                        dataset: {}
                    };
                    this.processAttachment(mockAttachment);
                }
            });
        });
    }

    extractFileNameFromLink(linkElement) {
        // Try to extract filename from link
        let fileName = '';
        
        // Check link text
        if (linkElement.textContent) {
            fileName = linkElement.textContent.trim();
        }
        
        // Check title attribute
        if (!fileName && linkElement.title) {
            fileName = linkElement.title.trim();
        }
        
        // Check href for filename parameter
        if (!fileName && linkElement.href) {
            try {
                const url = new URL(linkElement.href);
                fileName = url.searchParams.get('filename') || 
                          url.searchParams.get('name') ||
                          url.pathname.split('/').pop() ||
                          '';
            } catch (e) {
                // Invalid URL, try to extract from href
                const hrefParts = linkElement.href.split('/');
                if (hrefParts.length > 0) {
                    fileName = hrefParts[hrefParts.length - 1];
                }
            }
        }
        
        // Validate it looks like a filename
        if (fileName && fileName.includes('.')) {
            // Remove any query parameters or fragments
            fileName = fileName.split('?')[0].split('#')[0];
            return fileName;
        }
        
        return null;
    }

    extractAttachmentInfo(element) {
        // Try to extract attachment name
        let name = '';
        let size = '';
        
        // Multiple ways to get filename - improved for modern Gmail
        const nameSelectors = [
            '.aZp', 
            '.aQJ', 
            '[title]', 
            'span',
            '.aYy',
            '.aYz',
            '.aYx',
            '.BqLmrf .aYp', // New Gmail attachment name
            '.bAt',         // Modern Gmail attachment name
            '.bAu'          // Modern Gmail attachment size
        ];
        
        // Try to get name from data attributes first
        if (element.dataset && element.dataset.filename) {
            name = element.dataset.filename;
        } else if (element.dataset && element.dataset.name) {
            name = element.dataset.name;
        }
        
        // If no name from data attributes, try selectors
        if (!name || !name.includes('.')) {
            for (const selector of nameSelectors) {
                const nameEl = element.querySelector(selector) || element;
                if (nameEl && nameEl.textContent) {
                    name = nameEl.textContent.trim();
                    if (name && name.includes('.')) break;
                }
            }
        }
        
        // Get title attribute as fallback
        if ((!name || !name.includes('.')) && element.title) {
            name = element.title;
        }
        
        // For mock attachments from links
        if ((!name || !name.includes('.')) && element.textContent) {
            name = element.textContent;
        }
        
        // Get size if available
        const sizeElement = element.querySelector('.SaH9Ve, .aQG, .aYv, .BqLmrf .aYv, .bAu');
        if (sizeElement) {
            size = sizeElement.textContent || '';
        }

        // Skip if no valid filename found
        if (!name || !name.includes('.')) {
            return null;
        }

        const extension = name.split('.').pop()?.toLowerCase();
        const id = `${name}_${Date.now()}`;

        return {
            id,
            name: name.trim(),
            size: size.trim(),
            extension,
            element
        };
    }

    async processAttachment(attachmentElement) {
        try {
            const attachmentInfo = this.extractAttachmentInfo(attachmentElement);
            
            if (!attachmentInfo || this.scannedAttachments.has(attachmentInfo.id)) {
                return;
            }

            console.log('📎 Scanning attachment:', attachmentInfo.name);
            this.scannedAttachments.add(attachmentInfo.id);

            // Add scanning indicator
            this.showScanningIndicator(attachmentElement);

            // Analyze the attachment
            const analysis = await this.analyzeAttachment(attachmentInfo);
            
            // Show results
            this.displayResults(attachmentElement, analysis);

        } catch (error) {
            console.error('Error processing attachment:', error);
            this.showError(attachmentElement, 'Scan failed');
        }
    }

    async analyzeAttachment(attachmentInfo) {
        try {
            // Send to background script for analysis
            const response = await chrome.runtime.sendMessage({
                type: 'analyzeAttachment',
                data: attachmentInfo
            });

            if (response && response.success) {
                return response.result;
            } else {
                throw new Error('Analysis failed');
            }
        } catch (error) {
            console.error('Analysis error:', error);
            return {
                filename: attachmentInfo.name,
                is_malware: false,
                risk_score: 0,
                error: error.message
            };
        }
    }

    showScanningIndicator(element) {
        // Remove any existing scanning indicators first
        const existingIndicator = element.querySelector('.cerberus-scanning');
        if (existingIndicator) {
            existingIndicator.remove();
        }
        
        const indicator = document.createElement('div');
        indicator.className = 'cerberus-scanning';
        indicator.style.cssText = `
            display: inline-block;
            margin-left: 8px;
            padding: 2px 6px;
            background: #667eea;
            color: white;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        `;
        indicator.textContent = '🔍 Scanning...';
        
        element.appendChild(indicator);
    }

    displayResults(element, analysis) {
        // Remove scanning indicator
        const scanningEl = element.querySelector('.cerberus-scanning');
        if (scanningEl) scanningEl.remove();
        
        // Remove any existing result indicators first to prevent duplicates
        const existingResults = element.querySelectorAll('.cerberus-result');
        existingResults.forEach(result => result.remove());

        // Create result indicator
        const result = document.createElement('div');
        result.className = 'cerberus-result';
        
        let bgColor, textColor, icon, text;
        
        if (analysis.is_malware || analysis.risk_score > 70) {
            bgColor = '#ff4757';
            textColor = 'white';
            icon = '⚠️';
            text = 'THREAT DETECTED';
        } else if (analysis.risk_score > 40) {
            bgColor = '#ffa502';
            textColor = 'white';
            icon = '⚠️';
            text = 'SUSPICIOUS';
        } else {
            bgColor = '#2ed573';
            textColor = 'white';
            icon = '✅';
            text = 'SAFE';
        }
        
        result.style.cssText = `
            display: inline-block;
            margin-left: 8px;
            padding: 3px 8px;
            background: ${bgColor};
            color: ${textColor};
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            cursor: pointer;
        `;
        
        result.innerHTML = `${icon} ${text}`;
        
        // Add detailed tooltip
        result.title = `Cerberus Scan Results:\n` +
                      `File: ${analysis.filename}\n` +
                      `Risk Score: ${analysis.risk_score}/100\n` +
                      `Threat Type: ${analysis.threat_type || 'None'}\n` +
                      `Confidence: ${Math.round((analysis.confidence || 0) * 100)}%`;
        
        // Click to show detailed results
        result.addEventListener('click', () => {
            this.showDetailedResults(analysis);
        });
        
        element.appendChild(result);
        
        console.log('📊 Analysis complete:', analysis);
        
        // Update Gmail stats in background
        chrome.runtime.sendMessage({
            type: 'updateGmailStats',
            data: {
                type: 'attachment_scanned',
                threat: analysis.is_malware,
                suspicious: analysis.risk_score > 50
            }
        });
    }

    showDetailedResults(analysis) {
        const modal = document.createElement('div');
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
        `;
        
        const content = document.createElement('div');
        content.style.cssText = `
            background: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
            font-family: 'Segoe UI', Arial, sans-serif;
        `;
        
        const statusColor = analysis.is_malware ? '#ff4757' : analysis.risk_score > 40 ? '#ffa502' : '#2ed573';
        
        content.innerHTML = `
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: ${statusColor}; margin: 0;">🛡️ Cerberus Scan Results</h2>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>File:</strong> ${analysis.filename}
            </div>
            <div style="margin-bottom: 15px;">
                <strong>Risk Score:</strong> <span style="color: ${statusColor}; font-weight: bold;">${analysis.risk_score}/100</span>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>Threat Type:</strong> ${analysis.threat_type || 'None detected'}
            </div>
            <div style="margin-bottom: 15px;">
                <strong>Confidence:</strong> ${Math.round((analysis.confidence || 0) * 100)}%
            </div>
            ${analysis.recommendations ? `
                <div style="margin-bottom: 20px;">
                    <strong>Recommendations:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        ${analysis.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            <div style="text-align: center;">
                <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                        style="background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer;">
                    Close
                </button>
            </div>
        `;
        
        modal.appendChild(content);
        document.body.appendChild(modal);
        
        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
            }
        });
    }

    showError(element, message) {
        const scanningEl = element.querySelector('.cerberus-scanning');
        if (scanningEl) scanningEl.remove();
        
        // Remove any existing error indicators first
        const existingErrors = element.querySelectorAll('.cerberus-error');
        existingErrors.forEach(error => error.remove());

        const error = document.createElement('div');
        error.className = 'cerberus-error';
        error.style.cssText = `
            display: inline-block;
            margin-left: 8px;
            padding: 2px 6px;
            background: #ff6b6b;
            color: white;
            border-radius: 4px;
            font-size: 11px;
        `;
        error.textContent = `❌ ${message}`;
        element.appendChild(error);
    }

    addStatusIndicator() {
        // Check if already added
        if (document.querySelector('.cerberus-status')) return;
        
        const indicator = document.createElement('div');
        indicator.className = 'cerberus-status';
        indicator.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: bold;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        indicator.innerHTML = '🛡️ Cerberus Active';
        
        document.body.appendChild(indicator);
        
        // Auto-hide after 3 seconds
        setTimeout(() => {
            if (indicator.parentElement) {
                indicator.style.opacity = '0.3';
            }
        }, 3000);
    }
    
    clearAllIndicators() {
        // Remove all cerberus indicators from the page
        const indicators = document.querySelectorAll('.cerberus-scanning, .cerberus-result, .cerberus-error');
        indicators.forEach(indicator => indicator.remove());
        
        // Clear the scanned attachments set
        this.scannedAttachments.clear();
        
        console.log('Cleared all Cerberus indicators');
    }

    // Message listener for popup commands
    setupMessageListener() {
        // Remove existing listener if any
        if (this.messageListener) {
            chrome.runtime.onMessage.removeListener(this.messageListener);
        }
        
        // Store reference to listener
        this.messageListener = (message, sender, sendResponse) => {
            console.log('Gmail content script received message:', message);
            
            if (message.type === 'rescanAttachments') {
                console.log('Rescan attachments requested');
                // Clear all existing indicators before rescanning
                this.clearAllIndicators();
                this.scannedAttachments.clear();
                this.scanExistingAttachments();
                sendResponse({ success: true, message: 'Rescan initiated' });
                return true; // Keep message channel open for async response
            } else if (message.type === 'testMessage') {
                console.log('Test message received');
                sendResponse({ success: true, message: 'Test message received by Gmail content script' });
                return true; // Keep message channel open for async response
            } else if (message.type === 'ping') {
                console.log('Ping received, responding');
                sendResponse({ success: true, message: 'Pong from Gmail content script' });
                return true; // Keep message channel open for async response
            }
            
            // For other messages, send a response to avoid errors
            sendResponse({ success: false, error: 'Unknown message type: ' + message.type });
            return true;
        };
        
        chrome.runtime.onMessage.addListener(this.messageListener);
        console.log('Message listener set up for Gmail content script');
        
        // Send a ready message to background script
        chrome.runtime.sendMessage({type: 'gmailContentScriptReady'}, (response) => {
            if (chrome.runtime.lastError) {
                console.log('Could not send ready message to background:', chrome.runtime.lastError);
            } else {
                console.log('Sent ready message to background:', response);
            }
        });
    }
}

// Initialize Gmail scanner
function initializeGmailScanner() {
    // Check if we're actually on Gmail
    if (window.location.hostname.includes('mail.google.com')) {
        // Add a small delay to ensure Gmail is fully loaded
        setTimeout(() => {
            if (!window.cerberusGmailScanner) {
                window.cerberusGmailScanner = new GmailAttachmentScanner();
                console.log('Cerberus Gmail scanner initialized');
            }
        }, 3000);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeGmailScanner);
} else {
    initializeGmailScanner();
}

// Also initialize after a delay to handle Gmail's dynamic loading
setTimeout(() => {
    if (window.location.hostname.includes('mail.google.com') && !window.cerberusGmailScanner) {
        window.cerberusGmailScanner = new GmailAttachmentScanner();
        console.log('Cerberus Gmail scanner initialized (delayed)');
    }
}, 8000);

// Listen for Gmail navigation events
window.addEventListener('load', () => {
    // Set up a MutationObserver to detect Gmail navigation
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Check if Gmail UI elements are added
                        if (node.querySelector('[role="main"]') || node.querySelector('.aAA')) {
                            // Re-initialize scanner if needed
                            if (window.location.hostname.includes('mail.google.com') && !window.cerberusGmailScanner) {
                                window.cerberusGmailScanner = new GmailAttachmentScanner();
                                console.log('Cerberus Gmail scanner re-initialized');
                            }
                        }
                    }
                });
            }
        });
    });
    
    // Observe the document body for changes
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});