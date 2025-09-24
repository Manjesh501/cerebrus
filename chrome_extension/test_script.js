// Test script for Cerberus Gmail Extension
console.log('Cerberus Gmail Extension Test Script Loaded');

// Function to test messaging between components
async function testMessaging() {
    console.log('Testing messaging between components...');
    
    // Test background script communication
    try {
        const backgroundResponse = await chrome.runtime.sendMessage({type: 'test'});
        console.log('Background script response:', backgroundResponse);
    } catch (error) {
        console.error('Background script communication failed:', error);
    }
    
    // Test content script communication (if on Gmail)
    if (window.location.hostname.includes('mail.google.com')) {
        try {
            const tabs = await new Promise(resolve => chrome.tabs.query({active: true, currentWindow: true}, resolve));
            if (tabs.length > 0) {
                const contentResponse = await new Promise(resolve => 
                    chrome.tabs.sendMessage(tabs[0].id, {type: 'testMessage'}, response => {
                        if (chrome.runtime.lastError) {
                            console.error('Content script error:', chrome.runtime.lastError);
                            resolve(null);
                        } else {
                            resolve(response);
                        }
                    })
                );
                console.log('Content script response:', contentResponse);
            }
        } catch (error) {
            console.error('Content script communication failed:', error);
        }
    }
}

// Function to simulate attachment detection
function simulateAttachmentDetection() {
    console.log('Simulating attachment detection...');
    
    // Create a mock attachment element
    const mockAttachment = document.createElement('div');
    mockAttachment.className = 'aZo'; // Gmail attachment class
    mockAttachment.innerHTML = '<div class="aYp">test_document.pdf</div><div class="aYv">1.2 MB</div>';
    
    // Add to page body for testing
    document.body.appendChild(mockAttachment);
    
    console.log('Mock attachment added to page');
    
    // Remove after 5 seconds
    setTimeout(() => {
        if (mockAttachment.parentElement) {
            mockAttachment.parentElement.removeChild(mockAttachment);
            console.log('Mock attachment removed');
        }
    }, 5000);
}

// Run tests when script loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Running Cerberus tests...');
    testMessaging();
    
    // Only simulate attachment detection on Gmail
    if (window.location.hostname.includes('mail.google.com')) {
        setTimeout(simulateAttachmentDetection, 2000);
    }
});

// Export functions for manual testing
window.CerberusTest = {
    testMessaging: testMessaging,
    simulateAttachmentDetection: simulateAttachmentDetection
};

console.log('Cerberus test functions available at window.CerberusTest');