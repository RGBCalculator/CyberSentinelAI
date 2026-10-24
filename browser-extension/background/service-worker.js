/**
 * CyberSentinel AI - Background Service Worker (Manifest V3)
 * Manages extension lifecycle, configuration defaults, and context menus.
 */

const DEFAULT_API_BASE = 'http://localhost:8000';

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[CyberSentinel AI] Extension installed/updated:', details.reason);
  
  // Initialize default configuration
  const current = await chrome.storage.local.get(['apiBaseUrl']);
  if (!current.apiBaseUrl) {
    await chrome.storage.local.set({
      apiBaseUrl: DEFAULT_API_BASE,
      installedAt: new Date().toISOString()
    });
  }

  // Create context menu for quick scanning
  try {
    chrome.contextMenus.create({
      id: 'cybersentinel-scan-link',
      title: 'Scan link with CyberSentinel AI',
      contexts: ['link']
    });
  } catch (err) {
    // Menu item may already exist on reload
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'cybersentinel-scan-link' && info.linkUrl) {
    // Save target for popup to inspect
    chrome.storage.local.set({ pendingScanUrl: info.linkUrl }, () => {
      chrome.action.openPopup().catch(() => {
        // Fallback if popup cannot be programmatically opened
      });
    });
  }
});
