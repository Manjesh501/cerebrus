// Cerberus Chrome Extension - Background Service Worker

// Global variables for service worker
let serverUrl = 'http://localhost:5000';
let settings = {};
let threatCache = new Map();
let scanQueue = [];
let isProcessingQueue = false;

// Initialize when service worker starts
self.addEventListener('install', () => {
    console.log('Cerberus service worker installed');
    loadSettings();
});

self.addEventListener('activate', () => {
    console.log('Cerberus service worker activated');
    setupEventListeners();
    startPeriodicTasks();
});

async function loadSettings() {
    try {
        const result = await chrome.storage.sync.get([
            'realTimeProtection',
            'malwareBlocking',
            'phishingProtection',
            'downloadScanning',
            'threatNotifications',
            'serverUrl',
            'gmailProtection',
            'attachmentAnalysis',
            'emailLinkScanning',
            'phishingDetection'
        ]);

        settings = {
            realTimeProtection: result.realTimeProtection ?? true,
            malwareBlocking: result.malwareBlocking ?? true,
            phishingProtection: result.phishingProtection ?? true,
            downloadScanning: result.downloadScanning ?? false,
            threatNotifications: result.threatNotifications ?? true,
            serverUrl: result.serverUrl ?? 'http://localhost:5000',
            gmailProtection: result.gmailProtection ?? true,
            attachmentAnalysis: result.attachmentAnalysis ?? true,
            emailLinkScanning: result.emailLinkScanning ?? true,
            phishingDetection: result.phishingDetection ?? true
        };

        serverUrl = settings.serverUrl;
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

function setupEventListeners() {
    // Tab updates
    if (chrome.tabs && chrome.tabs.onUpdated) {
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            if (changeInfo.status === 'complete' && tab.url) {
                handleTabUpdate(tab);
            }
        });
    }

    // Downloads
    if (chrome.downloads && chrome.downloads.onCreated) {
        chrome.downloads.onCreated.addListener((downloadItem) => {
            if (settings.downloadScanning) {
                handleDownload(downloadItem);
            }
        });
    }

    // Settings changes
    if (chrome.storage && chrome.storage.onChanged) {
        chrome.storage.onChanged.addListener((changes, areaName) => {
            if (areaName === 'sync') {
                loadSettings();
            }
        });
    }

    // Extension messages
    if (chrome.runtime && chrome.runtime.onMessage) {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
    }

    // Alarm for periodic tasks
    if (chrome.alarms && chrome.alarms.onAlarm) {
        chrome.alarms.onAlarm.addListener((alarm) => {
            if (alarm.name === 'periodicScan') {
                performPeriodicTasks();
            }
        });
    }
}

function startPeriodicTasks() {
    // Create alarm for periodic threat intelligence updates
    if (chrome.alarms && chrome.alarms.create) {
        chrome.alarms.create('periodicScan', {
            delayInMinutes: 1,
            periodInMinutes: 30 // Every 30 minutes
        });
    }
}

async function handleTabUpdate(tab) {
    if (!settings.realTimeProtection) return;

    try {
        const url = new URL(tab.url);
        const hostname = url.hostname;

        // Update tab icon based on known threats
        updateTabIcon(tab.id, hostname);

    } catch (error) {
        console.error('Error handling tab update:', error);
    }
}

async function handleDownload(downloadItem) {
    if (!settings.downloadScanning) return;

    try {
        const filename = downloadItem.filename;
        const fileExt = filename.split('.').pop().toLowerCase();
        
        // Check for potentially dangerous file types
        const dangerousExts = ['exe', 'msi', 'scr', 'bat', 'cmd', 'com', 'pif', 'jar'];
        
        if (dangerousExts.includes(fileExt)) {
            // Show notification about potentially dangerous download
            showNotification('Cerberus: Potentially dangerous file downloaded', 
                           `Downloaded file: ${filename} - Please scan before opening`);
        }

    } catch (error) {
        console.error('Error handling download:', error);
    }
}

async function handleMessage(message, sender, sendResponse) {
    console.log('Background received message:', message.type, message);
    
    try {
        switch (message.type) {
            case 'scanUrl':
                const result = await scanUrl(message.url);
                sendResponse({ success: true, result });
                break;

            case 'analyzeAttachment':
                const analysisResult = await analyzeAttachment(message.data);
                sendResponse({ success: true, result: analysisResult });
                break;

            case 'updateGmailStats':
                await updateGmailStats(message.data);
                sendResponse({ success: true });
                break;

            case 'scanEmailLinks':
                const linkResults = await scanEmailLinks(message.data);
                sendResponse({ success: true, results: linkResults });
                break;

            case 'detectPhishing':
                const phishingResults = await detectPhishing(message.data);
                sendResponse({ success: true, results: phishingResults });
                break;

            case 'rescanAttachments':
                // This message should be handled by the content script
                // Forward to active tab if it's Gmail
                const queryTabs = message.tabId ? 
                    new Promise(resolve => chrome.tabs.get(message.tabId, tab => resolve([tab]))) : 
                    new Promise(resolve => chrome.tabs.query({active: true, currentWindow: true}, resolve));
                
                queryTabs.then(tabs => {
                    console.log('RescanAttachments: Found tabs:', tabs);
                    if (tabs && tabs.length > 0 && tabs[0] && tabs[0].url && tabs[0].url.includes('mail.google.com')) {
                        console.log('Forwarding rescan message to Gmail tab:', tabs[0].id);
                        chrome.tabs.sendMessage(tabs[0].id, {type: 'rescanAttachments'}, function(response) {
                            if (chrome.runtime.lastError) {
                                console.error('Error forwarding message:', chrome.runtime.lastError);
                                // Try to re-initialize the content script
                                chrome.scripting.executeScript({
                                    target: { tabId: tabs[0].id },
                                    files: ['gmail-content.js']
                                }, () => {
                                    if (chrome.runtime.lastError) {
                                        console.error('Failed to inject content script:', chrome.runtime.lastError);
                                        sendResponse({ success: false, error: 'Content script not available: ' + chrome.runtime.lastError.message });
                                    } else {
                                        // Try sending message again after injection
                                        setTimeout(() => {
                                            chrome.tabs.sendMessage(tabs[0].id, {type: 'rescanAttachments'}, function(retryResponse) {
                                                if (chrome.runtime.lastError) {
                                                    console.error('Retry failed:', chrome.runtime.lastError);
                                                    sendResponse({ success: false, error: 'Retry failed: ' + chrome.runtime.lastError.message });
                                                } else {
                                                    console.log('Retry response received:', retryResponse);
                                                    sendResponse(retryResponse || { success: true });
                                                }
                                            });
                                        }, 1000);
                                    }
                                });
                            } else {
                                console.log('Rescan response received:', response);
                                sendResponse(response || { success: true });
                            }
                        });
                    } else {
                        console.log('Not on Gmail page, cannot rescan');
                        sendResponse({ success: false, error: 'Not on Gmail page' });
                    }
                }).catch(error => {
                    console.error('Error querying tabs:', error);
                    sendResponse({ success: false, error: 'Failed to query tabs: ' + error.message });
                });
                return true; // Keep message channel open for async response
                
            case 'test':
                console.log('Test message received in background');
                sendResponse({ success: true, message: 'Background script is working' });
                break;
                
            case 'gmailContentScriptReady':
                console.log('Gmail content script is ready');
                sendResponse({ success: true, message: 'Background acknowledged ready signal' });
                break;
                
            case 'resetStats':
                console.log('Reset stats requested');
                // Reset Gmail stats
                chrome.storage.local.set({
                    gmailStats: {
                        attachmentsScanned: 0,
                        threatsBlocked: 0,
                        suspiciousFound: 0,
                        totalEmails: 0,
                        lastScan: null
                    },
                    gmailHistory: [],
                    threatsDetected: 0
                }, function() {
                    if (chrome.runtime.lastError) {
                        console.error('Error resetting stats:', chrome.runtime.lastError);
                        sendResponse({ success: false, error: chrome.runtime.lastError.message });
                    } else {
                        console.log('Statistics reset successfully');
                        sendResponse({ success: true, message: 'Statistics reset successfully' });
                    }
                });
                return true; // Keep message channel open for async response
                
            default:
                console.warn('Unknown message type received:', message.type);
                sendResponse({ success: false, error: 'Unknown message type: ' + message.type });
        }
    } catch (error) {
        console.error('Error handling message:', error);
        sendResponse({ success: false, error: error.message });
    }
    return true; // Keep message channel open
}

async function scanUrl(url) {
    try {
        const response = await fetch(`${serverUrl}/api/scan-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        if (response.ok) {
            return await response.json();
        } else {
            throw new Error('Scan request failed');
        }
    } catch (error) {
        console.error('URL scan error:', error);
        throw error;
    }
}

async function analyzeAttachment(attachmentData) {
    try {
        // Extract filename, size, and type
        const filename = attachmentData.name || attachmentData.filename || 'unknown';
        const size = attachmentData.size || '0';
        const type = attachmentData.type || 'application/octet-stream';
        
        // Perform static analysis
        const staticAnalysis = performStaticAnalysis(filename, size, type);
        
        // Check against threat intelligence
        const threatCheck = await checkThreatIndicators(filename);
        
        // Combine results
        const analysis = {
            filename,
            size,
            type,
            is_malware: staticAnalysis.isHighRisk || threatCheck.isThreat,
            confidence: Math.max(staticAnalysis.confidence, threatCheck.confidence),
            risk_score: Math.max(staticAnalysis.riskScore, threatCheck.riskScore),
            threat_type: staticAnalysis.threatType || threatCheck.threatType || 'Unknown',
            recommendations: generateRecommendations(staticAnalysis, threatCheck)
        };

        // Update Gmail stats
        await updateGmailStats({
            type: 'attachment_scanned',
            filename: filename,
            threat: analysis.is_malware,
            suspicious: analysis.risk_score > 50,
            size: size,
            type: type
        });

        return analysis;
        
    } catch (error) {
        console.error('Attachment analysis error:', error);
        return {
            filename: attachmentData.name || attachmentData.filename || 'unknown',
            is_malware: false,
            confidence: 0,
            risk_score: 0,
            error: error.message
        };
    }
}

function performStaticAnalysis(filename, size, type) {
    const extension = filename.split('.').pop()?.toLowerCase();
    
    // High-risk file extensions
    const highRiskExts = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'msi', 'jar', 'app', 'dmg'];
    const mediumRiskExts = ['zip', 'rar', '7z', 'tar', 'gz', 'pdf', 'doc', 'docx', 'xls', 'xlsx'];
    
    let riskScore = 0;
    let isHighRisk = false;
    let threatType = 'Unknown';
    let confidence = 0;

    // Extension-based risk assessment
    if (highRiskExts.includes(extension)) {
        riskScore += 70;
        isHighRisk = true;
        threatType = 'Executable File';
        confidence = 0.8;
    } else if (mediumRiskExts.includes(extension)) {
        riskScore += 30;
        threatType = 'Document/Archive';
        confidence = 0.5;
    }

    // Suspicious filename patterns
    const suspiciousPatterns = [
        { pattern: /invoice.*\.(exe|scr|bat)$/i, risk: 95, type: 'Invoice Scam Malware' },
        { pattern: /payment.*\.(exe|scr|bat)$/i, risk: 95, type: 'Payment Scam Malware' },
        { pattern: /receipt.*\.(exe|scr|bat)$/i, risk: 90, type: 'Receipt Scam Malware' },
        { pattern: /document.*\.(exe|scr|bat)$/i, risk: 85, type: 'Document Masquerading Malware' }
    ];

    for (const pattern of suspiciousPatterns) {
        if (pattern.pattern.test(filename)) {
            riskScore = Math.max(riskScore, pattern.risk);
            isHighRisk = riskScore > 70;
            threatType = pattern.type;
            confidence = 0.9;
            break;
        }
    }

    return {
        riskScore: Math.min(riskScore, 100),
        isHighRisk,
        threatType,
        confidence,
        extension
    };
}

async function checkThreatIndicators(filename) {
    try {
        const lowerFilename = filename.toLowerCase();
        
        // Known malware filename patterns
        const knownMalwarePatterns = [
            'trojan', 'virus', 'malware', 'ransomware', 'keylogger'
        ];

        for (const pattern of knownMalwarePatterns) {
            if (lowerFilename.includes(pattern)) {
                return {
                    isThreat: true,
                    confidence: 0.7,
                    riskScore: 85,
                    threatType: 'Known Malware Pattern'
                };
            }
        }

        return {
            isThreat: false,
            confidence: 0,
            riskScore: 0,
            threatType: null
        };
        
    } catch (error) {
        console.error('Threat indicator check error:', error);
        return {
            isThreat: false,
            confidence: 0,
            riskScore: 0,
            threatType: null
        };
    }
}

function generateRecommendations(staticAnalysis, threatCheck) {
    const recommendations = [];

    if (staticAnalysis.isHighRisk || threatCheck.isThreat) {
        recommendations.push('⚠️ DO NOT download or open this attachment');
        recommendations.push('🛡️ This file appears to be malicious');
        recommendations.push('📧 Report this email as spam/phishing');
    } else if (staticAnalysis.riskScore > 50) {
        recommendations.push('⚠️ Exercise caution with this attachment');
        recommendations.push('🔍 Scan with antivirus before opening');
        recommendations.push('👤 Verify sender authenticity');
    } else {
        recommendations.push('✅ Attachment appears safe');
        recommendations.push('🔍 Still recommended to scan with antivirus');
    }

    return recommendations;
}

async function updateGmailStats(data) {
    try {
        const result = await chrome.storage.local.get(['gmailStats', 'gmailHistory']);
        const stats = result.gmailStats || {
            attachmentsScanned: 0,
            threatsBlocked: 0,
            suspiciousFound: 0,
            totalEmails: 0,
            lastScan: null
        };
        
        const history = result.gmailHistory || [];

        switch (data.type) {
            case 'attachment_scanned':
                stats.attachmentsScanned++;
                if (data.threat) stats.threatsBlocked++;
                if (data.suspicious) stats.suspiciousFound++;
                
                // Add to history
                history.unshift({
                    filename: data.filename || 'Unknown',
                    timestamp: Date.now(),
                    threat: data.threat,
                    suspicious: data.suspicious,
                    size: data.size || 'Unknown',
                    type: data.type || 'Unknown'
                });
                
                // Keep only last 50 entries
                if (history.length > 50) {
                    history.splice(50);
                }
                break;
            case 'email_processed':
                stats.totalEmails++;
                break;
        }

        stats.lastScan = Date.now();
        await chrome.storage.local.set({ 
            gmailStats: stats,
            gmailHistory: history
        });
        
    } catch (error) {
        console.error('Error updating Gmail stats:', error);
    }
}

async function scanEmailLinks(data) {
    try {
        const { links } = data;
        const results = [];

        for (const link of links) {
            try {
                const scanResult = await scanUrl(link.url);
                results.push({
                    url: link.url,
                    text: link.text,
                    is_malicious: scanResult.is_malware || scanResult.threat_score > 70,
                    threat_score: scanResult.threat_score,
                    scan_result: scanResult
                });
            } catch (error) {
                results.push({
                    url: link.url,
                    text: link.text,
                    is_malicious: false,
                    error: error.message
                });
            }
        }

        return results;
        
    } catch (error) {
        console.error('Email link scanning error:', error);
        return [];
    }
}

async function detectPhishing(data) {
    try {
        const { emailContent, senderInfo, subject } = data;
        const phishingIndicators = [];
        let riskScore = 0;

        // Check for suspicious keywords
        const suspiciousKeywords = [
            'urgent', 'verify account', 'suspended', 'click here immediately',
            'confirm identity', 'update payment'
        ];

        const content = (emailContent + ' ' + subject).toLowerCase();
        
        for (const keyword of suspiciousKeywords) {
            if (content.includes(keyword)) {
                phishingIndicators.push(`Suspicious keyword: ${keyword}`);
                riskScore += 15;
            }
        }

        return {
            is_phishing: riskScore > 50,
            risk_score: Math.min(riskScore, 100),
            indicators: phishingIndicators,
            confidence: riskScore > 70 ? 0.9 : riskScore > 30 ? 0.6 : 0.3
        };
        
    } catch (error) {
        console.error('Phishing detection error:', error);
        return {
            is_phishing: false,
            risk_score: 0,
            indicators: [],
            error: error.message
        };
    }
}

function updateTabIcon(tabId, hostname) {
    try {
        // Set default icon
        if (chrome.action && chrome.action.setIcon) {
            chrome.action.setIcon({
                tabId: tabId,
                path: 'icons/icon48.png'
            });
        }
    } catch (error) {
        console.error('Error updating tab icon:', error);
    }
}

function showNotification(title, message) {
    if (chrome.notifications && chrome.notifications.create) {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: title,
            message: message
        });
    }
}

function performPeriodicTasks() {
    console.log('Performing periodic threat intelligence updates');
    // Clear old cache entries
    const oneHour = 60 * 60 * 1000;
    const now = Date.now();
    
    for (const [key, value] of threatCache.entries()) {
        if (now - value.timestamp > oneHour) {
            threatCache.delete(key);
        }
    }
}

// Initialize the service worker
loadSettings();