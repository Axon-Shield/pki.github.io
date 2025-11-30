// Disable GA if embedded in iframe
if (window.self !== window.top) {
  window['ga-disable-G-5G3T3K4DWB'] = true; // Replace with your GA measurement ID
}

// Sync navigation with parent window (for iframe embedding)
if (window.parent !== window) {
    // Send current path on page load
    window.parent.postMessage({
      type: 'navigation',
      path: window.location.pathname
    }, 'https://axonshield.com');
  
    // Also send on any navigation (for SPA-style navigation in MkDocs Material)
    document.addEventListener('DOMContentLoaded', function() {
      const observer = new MutationObserver(function() {
        window.parent.postMessage({
          type: 'navigation',
          path: window.location.pathname
        }, 'https://axonshield.com');
      });
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }