// Simplified popup for Gmail protection only
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the popup
    initializePopup();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load Gmail stats
    loadGmailStats();
});

function initializePopup() {
    console.log('Cerberus Gmail Shield popup initialized');
    updateCurrentTab();
}

function setupEventListeners() {
    // Test extension button
    const testBtn = document.getElementById('testExtension');
    if (testBtn) {
        testBtn.addEventListener('click', simulateThreatDetection);
    }
    
    // Settings button
    const settingsBtn = document.getElementById('openSettings');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', openSettings);
    }
}

async function updateCurrentTab() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            const url = new URL(tab.url);
            const isGmail = url.hostname.includes('mail.google.com');
            
            // Update status based on current site
            updateGmailStatus(isGmail);
        }
    } catch (error) {
        console.error('Error getting current tab:', error);
    }
}

function updateGmailStatus(isOnGmail) {
    const statusCard = document.querySelector('.status-card');
    const statusTitle = document.querySelector('.status-title');
    const statusDesc = document.querySelector('.status-desc');
    
    if (isOnGmail) {
        statusTitle.textContent = 'Gmail Protection Active';
        statusDesc.textContent = 'Scanning attachments in real-time';
        statusCard.style.borderLeftColor = '#4CAF50';
    } else {
        statusTitle.textContent = 'Gmail Protection Ready';
        statusDesc.textContent = 'Open Gmail to start protection';
        statusCard.style.borderLeftColor = '#ffc107';
    }
}

async function loadGmailStats() {
    try {
        const result = await chrome.storage.local.get(['gmailStats']);
        const stats = result.gmailStats || {
            attachmentsScanned: 0,
            threatsBlocked: 0
        };
        
        // Update counters
        document.getElementById('attachmentsScanned').textContent = stats.attachmentsScanned;
        document.getElementById('highRiskAttachments').textContent = stats.threatsBlocked;
        
        // Load recent activity
        loadRecentActivity(stats);
        
    } catch (error) {
        console.error('Error loading Gmail stats:', error);
    }
}

function loadRecentActivity(stats) {
    const activityContainer = document.getElementById('recentActivity');
    
    if (stats.recentThreats && stats.recentThreats.length > 0) {
        activityContainer.innerHTML = '';
        
        stats.recentThreats.slice(0, 3).forEach(threat => {
            const activityItem = createActivityItem(threat);
            activityContainer.appendChild(activityItem);
        });
    }
}

function createActivityItem(threat) {
    const item = document.createElement('div');
    item.className = 'activity-item';
    
    item.innerHTML = `
        <span class="activity-icon">🚨</span>
        <div class="activity-info">
            <div class="activity-title">${threat.filename}</div>
            <div class="activity-desc">Blocked • ${threat.threatType}</div>
        </div>
    `;
    
    return item;
}

async function simulateThreatDetection() {
    const testBtn = document.getElementById('testExtension');
    const recentActivity = document.getElementById('recentActivity');
    
    // Show loading state
    testBtn.innerHTML = '<span class="icon">⏳</span> Testing...';
    testBtn.disabled = true;
    
    // Simulate threat detection
    setTimeout(async () => {
        // Create fake threat detection
        const fakeDetection = {
            filename: 'malware_test.exe',
            threatType: 'Trojan (Simulated)',
            timestamp: Date.now()
        };
        
        // Update stats
        const result = await chrome.storage.local.get(['gmailStats']);
        const stats = result.gmailStats || {
            attachmentsScanned: 0,
            threatsBlocked: 0,
            recentThreats: []
        };
        
        stats.attachmentsScanned++;
        stats.threatsBlocked++;
        stats.recentThreats = stats.recentThreats || [];
        stats.recentThreats.unshift(fakeDetection);
        
        // Keep only last 5 threats
        if (stats.recentThreats.length > 5) {
            stats.recentThreats = stats.recentThreats.slice(0, 5);
        }
        
        await chrome.storage.local.set({ gmailStats: stats });
        
        // Update UI
        document.getElementById('attachmentsScanned').textContent = stats.attachmentsScanned;
        document.getElementById('highRiskAttachments').textContent = stats.threatsBlocked;
        
        // Show the detection
        recentActivity.innerHTML = '';
        const activityItem = createActivityItem(fakeDetection);
        recentActivity.appendChild(activityItem);
        
        // Reset button
        testBtn.innerHTML = '<span class="icon">✅</span> Test Completed';
        
        setTimeout(() => {
            testBtn.innerHTML = '<span class="icon">🧪</span> Test Extension';
            testBtn.disabled = false;
        }, 2000);
        
    }, 1500);
}

function openSettings() {
    // For now, just show an alert
    alert('Settings panel coming soon!\\n\\nCurrent features:\\n• Gmail attachment monitoring\\n• Real-time threat detection\\n• Malware pattern analysis');
}