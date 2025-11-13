/**
 * Asset Cache - Caches static assets in localStorage for faster subsequent loads
 */

class AssetCache {
    static CACHE_PREFIX = 'asset_cache_';
    static CACHE_VERSION = 'v2';
    static CACHE_EXPIRY_DAYS = 7;

    /**
     * Get cache key for a URL
     */
    static getCacheKey(url) {
        return `${this.CACHE_PREFIX}${this.CACHE_VERSION}_${url}`;
    }

    /**
     * Check if cached asset is expired
     */
    static isExpired(cachedData) {
        if (!cachedData?.timestamp) return true;
        const expiryDate = new Date(cachedData.timestamp);
        expiryDate.setDate(expiryDate.getDate() + this.CACHE_EXPIRY_DAYS);
        return new Date() > expiryDate;
    }

    /**
     * Load and cache a script
     */
    static async loadScript(url, options = {}) {
        const cacheKey = this.getCacheKey(url);
        const cached = localStorage.getItem(cacheKey);
        
        if (cached) {
            const parsed = JSON.parse(cached);
            if (!this.isExpired(parsed)) {
                this.injectScript(parsed.content, options);
                return;
            }
        }

        try {
            const response = await fetch(url);
            const content = await response.text();
            
            localStorage.setItem(cacheKey, JSON.stringify({
                content,
                timestamp: new Date().toISOString()
            }));
            
            this.injectScript(content, options);
        } catch (error) {
            console.error(`Failed to load script ${url}:`, error);
            // Fallback to regular script tag if caching fails
            const script = document.createElement('script');
            script.src = url;
            if (options) Object.assign(script, options);
            document.head.appendChild(script);
        }
    }

    /**
     * Load and cache a stylesheet
     */
    static async loadStyle(url) {
        const cacheKey = this.getCacheKey(url);
        const cached = localStorage.getItem(cacheKey);
        
        if (cached) {
            const parsed = JSON.parse(cached);
            if (!this.isExpired(parsed)) {
                this.injectStyle(parsed.content);
                return;
            }
        }

        try {
            const response = await fetch(url);
            const content = await response.text();
            
            localStorage.setItem(cacheKey, JSON.stringify({
                content,
                timestamp: new Date().toISOString()
            }));
            
            this.injectStyle(content);
        } catch (error) {
            console.error(`Failed to load stylesheet ${url}:`, error);
            // Fallback to regular link tag if caching fails
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = url;
            document.head.appendChild(link);
        }
    }

    /**
     * Inject script content into DOM
     */
    static injectScript(content, options) {
        const script = document.createElement('script');
        script.textContent = content;
        if (options) Object.assign(script, options);
        document.head.appendChild(script);
    }

    /**
     * Inject style content into DOM
     */
    static injectStyle(content) {
        const style = document.createElement('style');
        style.textContent = content;
        document.head.appendChild(style);
    }

    /**
     * Clear expired cache entries
     */
    static clearExpired() {
        Object.keys(localStorage)
            .filter(key => key.startsWith(this.CACHE_PREFIX))
            .forEach(key => {
                const cached = localStorage.getItem(key);
                try {
                    const parsed = JSON.parse(cached);
                    if (this.isExpired(parsed)) {
                        localStorage.removeItem(key);
                    }
                } catch {
                    localStorage.removeItem(key);
                }
            });
    }
}

// Initialize and clear expired cache on load
document.addEventListener('DOMContentLoaded', () => {
    AssetCache.clearExpired();
});

// Export for module usage if needed
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AssetCache;
}
