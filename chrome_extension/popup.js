// Cerberus Chrome Extension - Simplified Gmail Protection

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Gmail Protection Status
    updateGmailProtectionStatus();
    
    // Load Gmail stats
    loadGmailStats();
    
    // Auto-refresh status every 10 seconds
    setInterval(updateGmailProtectionStatus, 10000);
    setInterval(loadGmailStats, 5000);
    
    // Test extension button
    document.getElementById('testExtension')?.addEventListener('click', testExtensionFunctionality);
    
    // View threats button
    document.getElementById('viewThreats')?.addEventListener('click', function() {
        chrome.tabs.create({url: 'http://localhost:5000/realtime'});
    });
    
    // Rescan attachments button
    const rescanBtn = document.getElementById('rescanAttachments');
    if (rescanBtn) {
        rescanBtn.addEventListener('click', rescanAttachments);
    }
    
    // Reset stats button
    const resetBtn = document.getElementById('resetStats');
    if (resetBtn) {
        resetBtn.addEventListener('click', resetStats);
    }
});

function updateGmailProtectionStatus() {
    const statusCard = document.getElementById('gmailProtectionStatus');
    const statusTitle = statusCard?.querySelector('.status-title');
    const statusDesc = statusCard?.querySelector('.status-desc');
    const threatCount = document.getElementById('threatCount');
    
    // Check if we're on Gmail
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentTab = tabs[0];
        const isGmail = currentTab && currentTab.url && currentTab.url.includes('mail.google.com');
        
        if (isGmail) {
            statusCard.className = 'status-card active';
            statusTitle.textContent = 'Gmail Protection Active';
            statusDesc.textContent = 'Monitoring email attachments';
        } else {
            statusCard.className = 'status-card inactive';
            statusTitle.textContent = 'Gmail Protection Ready';
            statusDesc.textContent = 'Navigate to Gmail to enable';
        }
    });
    
    // Get threat count from storage
    chrome.storage.local.get({threatsDetected: 0}, function(result) {
        if (threatCount) {
            threatCount.textContent = result.threatsDetected;
        }
    });
}

function loadGmailStats() {
    chrome.storage.local.get(['gmailStats'], function(result) {
        const stats = result.gmailStats || {
            attachmentsScanned: 0,
            threatsBlocked: 0,
            suspiciousFound: 0,
            totalEmails: 0,
            lastScan: null
        };
        
        // Update UI elements
        document.getElementById('attachmentsScanned').textContent = stats.attachmentsScanned;
        document.getElementById('highRiskAttachments').textContent = stats.threatsBlocked;
        
        // Update recent activity if there are threats
        if (stats.threatsBlocked > 0 || stats.suspiciousFound > 0) {
            updateRecentActivity(stats);
        }
    });
}

function updateRecentActivity(stats) {
    const recentActivity = document.getElementById('recentActivity');
    if (recentActivity) {
        recentActivity.innerHTML = `
            <div class="activity-item">
                <span class="activity-icon">⚠️</span>
                <div class="activity-info">
                    <div class="activity-title">Threats Blocked</div>
                    <div class="activity-desc">${stats.threatsBlocked} malicious attachments blocked</div>
                </div>
            </div>
            <div class="activity-item">
                <span class="activity-icon">🔍</span>
                <div class="activity-info">
                    <div class="activity-title">Suspicious Files</div>
                    <div class="activity-desc">${stats.suspiciousFound} suspicious attachments detected</div>
                </div>
            </div>
        `;
    }
}

function testExtensionFunctionality() {
    // Simulate attachment analysis for testing
    const testAttachment = {
        name: 'suspicious_document.pdf',
        size: 2048576, // 2MB
        type: 'application/pdf',
        url: 'test://example.com/file.pdf'
    };
    
    // Show analysis in progress
    showNotification('Testing extension...', 'info');
    
    // Simulate analysis delay
    setTimeout(() => {
        const analysisResult = analyzeAttachmentMetadata(testAttachment);
        
        if (analysisResult.isSuspicious) {
            showNotification(`Test Complete: Found ${analysisResult.issues.length} suspicious indicators`, 'warning');
            
            // Update threat count
            chrome.storage.local.get({threatsDetected: 0}, function(result) {
                const newCount = result.threatsDetected + 1;
                chrome.storage.local.set({threatsDetected: newCount});
                updateGmailProtectionStatus();
            });
        } else {
            showNotification('Test Complete: No threats detected', 'success');
        }
    }, 1500);
}

function rescanAttachments() {
    // First check if we're on Gmail
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs.length > 0 && tabs[0].url && tabs[0].url.includes('mail.google.com')) {
            // Send message to Gmail content script to rescan
            chrome.tabs.sendMessage(tabs[0].id, {
                type: 'rescanAttachments'
            }, function(response) {
                if (chrome.runtime.lastError) {
                    console.error('Messaging error:', chrome.runtime.lastError);
                    // Try alternative approach - send via background script
                    chrome.runtime.sendMessage({
                        type: 'rescanAttachments',
                        tabId: tabs[0].id
                    }, function(backgroundResponse) {
                        if (chrome.runtime.lastError) {
                            console.error('Background messaging error:', chrome.runtime.lastError);
                            showNotification('Error: ' + chrome.runtime.lastError.message, 'error');
                        } else if (backgroundResponse && backgroundResponse.success) {
                            showNotification('Rescan initiated successfully', 'success');
                        } else {
                            showNotification('Failed to initiate rescan', 'error');
                        }
                    });
                } else if (response && response.success) {
                    showNotification('Rescan initiated successfully', 'success');
                } else {
                    showNotification('Failed to initiate rescan', 'error');
                }
            });
        } else {
            // If not on Gmail, show option to open Gmail
            showNotification('Please open Gmail to rescan attachments', 'warning');
        }
    });
}

function resetStats() {
    // Confirm with user before resetting
    if (confirm('Are you sure you want to reset all threat statistics? This action cannot be undone.')) {
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
                showNotification('Error resetting stats: ' + chrome.runtime.lastError.message, 'error');
            } else {
                showNotification('Statistics reset successfully', 'success');
                // Refresh the display
                loadGmailStats();
                updateGmailProtectionStatus();
            }
        });
    }
}

function analyzeAttachmentMetadata(attachment) {
    const issues = [];
    const suspiciousExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js'];
    const suspiciousKeywords = ['invoice', 'urgent', 'payment', 'virus', 'trojan', 'crack', 'keygen'];
    
    // Check file extension
    const ext = attachment.name.toLowerCase().substring(attachment.name.lastIndexOf('.'));
    if (suspiciousExtensions.includes(ext)) {
        issues.push(`Dangerous file extension: ${ext}`);
    }
    
    // Check filename for suspicious keywords
    const filename = attachment.name.toLowerCase();
    suspiciousKeywords.forEach(keyword => {
        if (filename.includes(keyword)) {
            issues.push(`Suspicious keyword in filename: ${keyword}`);
        }
    });
    
    // Check file size (very small or very large files can be suspicious)
    if (attachment.size < 1024) {
        issues.push('Unusually small file size');
    } else if (attachment.size > 50 * 1024 * 1024) {
        issues.push('Unusually large file size');
    }
    
    return {
        isSuspicious: issues.length > 0,
        issues: issues,
        riskLevel: issues.length > 2 ? 'HIGH' : issues.length > 0 ? 'MEDIUM' : 'LOW'
    };
}

function showNotification(message, type = 'info') {
    console.log(`Showing notification [${type}]: ${message}`);
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    // Set background color based on type
    const colors = {
        info: '#667eea',
        success: '#28a745',
        warning: '#ffc107',
        error: '#dc3545'
    };
    notification.style.backgroundColor = colors[type] || colors.info;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 300);
        }
    }, 3000);
}