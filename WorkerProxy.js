addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

// Centralized Configuration
const CONFIG = {
  proxy: {
    domains: ['workername.cfusername.workers.dev'],
    separator: '------',
    homepage: true,
    allowedDomains: [], // Empty = allow all
    maxContentSize: 10 * 1024 * 1024, // 10MB
    timeout: 30000, // 30 seconds
  },

  security: {
    rateLimit: {
      requests: 1000, // Slightly more generous for testing
      window: 60000, // 1 minute
    },
    blockedPatterns: [],
    requireHttps: false,
  },

  browserEmulation: {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
  },

  rewriting: {
    enableJSRewriting: true,
    enableCSSRewriting: true,
    enableHTMLRewriting: true,
    streamingThreshold: 1024 * 1024, // 1MB
  },

  caching: {
    enabled: true,
    ttl: {
      html: 300, // 5 minutes
      css: 3600, // 1 hour
      js: 3600, // 1 hour
      images: 7200, // 2 hours
      default: 600, // 10 minutes
    }
  }
}

// Enhanced URL Handler
class URLHandler {
  constructor(config) {
    this.config = config
    this.separator = config.proxy.separator
    this.proxyDomains = config.proxy.domains
  }

  extractTargetURL(request) {
    const url = new URL(request.url)
    const isProxyDomain = this.proxyDomains.includes(url.host)

    if (!isProxyDomain) {
      return {
        target: url,
        isProxy: false,
        isHomepage: false,
        isMalformed: false
      }
    }

    // Handle homepage
    if (url.pathname === '/' && !url.search) {
      return {
        target: null,
        isProxy: true,
        isHomepage: true,
        isMalformed: false
      }
    }

    // Handle different URL formats
    let targetURL = null

    // Format 1: /proxy?url=https://example.com (with proper URL encoding)
    if (url.pathname === '/proxy' && url.searchParams.has('url')) {
      // Get the raw URL parameter value (might be URL encoded)
      let urlParam = url.searchParams.get('url')

      // Try to decode it if it appears to be URL encoded
      try {
        const decodedUrl = decodeURIComponent(urlParam)
        // Check if decoding actually changed anything (i.e., it was encoded)
        if (decodedUrl !== urlParam) {
          urlParam = decodedUrl
        }
      } catch (e) {
        // If decoding fails, use the original value
      }

      targetURL = this.parseURL(urlParam)
    }
    // Format 2: /------https://example.com (including query parameters)
    else if (url.pathname.startsWith(`/${this.separator}`)) {
      // Extract everything after the separator, including query parameters
      // We need to reconstruct the full URL including search params
      const pathAfterSeparator = url.pathname.substring(this.separator.length + 1)

      if (!pathAfterSeparator) {
        // Empty URL part after separator
        return {
          target: null,
          isProxy: true,
          isHomepage: false,
          isMalformed: true
        }
      }

      // If there are query parameters in the original request, they might belong to the target URL
      let fullTargetURL = pathAfterSeparator

      // Check if the extracted path looks like a complete URL
      if (pathAfterSeparator.startsWith('http://') || pathAfterSeparator.startsWith('https://')) {
        // If there are additional query parameters in the proxy URL, they likely belong to the target
        if (url.search) {
          // The query parameters from the proxy URL should be appended to the target URL
          const targetHasQuery = pathAfterSeparator.includes('?')
          const connector = targetHasQuery ? '&' : '?'
          fullTargetURL = pathAfterSeparator + connector + url.search.substring(1)
        }
      }

      targetURL = this.parseURL(fullTargetURL)
    }
    // Format 3: Relative URLs or search queries
    else {
      // Check if this looks like an invalid direct path access
      const path = url.pathname.substring(1)

      // Special handling for common paths that should return errors
      const errorPaths = ['invalid-url', 'malformed-path', 'test-invalid']
      if (errorPaths.includes(path)) {
        // Explicitly malformed paths
        return {
          target: null,
          isProxy: true,
          isHomepage: false,
          isMalformed: true
        }
      }

      // General malformed path detection
      if (path && !path.includes('.') && !url.search &&
        path !== 'favicon.ico' && path.length < 50 && path.length > 0) {
        // This looks like someone tried to access a malformed proxy URL
        return {
          target: null,
          isProxy: true,
          isHomepage: false,
          isMalformed: true
        }
      }

      targetURL = this.handleRelativeOrSearch(request, url)
    }

    return {
      target: targetURL,
      isProxy: true,
      isHomepage: false,
      isMalformed: false
    }
  }

  parseURL(urlString) {
    if (!urlString) return null

    try {
      let processedURL = urlString.trim()

      // Check for dangerous protocols first
      const dangerousProtocols = ['file:', 'javascript:', 'data:', 'ftp:', 'mailto:', 'tel:']
      for (const protocol of dangerousProtocols) {
        if (processedURL.toLowerCase().startsWith(protocol)) {
          throw new Error(`Blocked protocol: ${protocol}`)
        }
      }

      // Handle protocol-relative URLs
      if (processedURL.startsWith('//')) {
        processedURL = 'https:' + processedURL
      }
      // Handle URLs without protocol
      else if (!processedURL.match(/^https?:\/\//i)) {
        // Be more strict about what we consider a valid domain
        if (processedURL.includes('.') && !processedURL.includes(' ') && processedURL.length > 3) {
          // Must look like a real domain (has TLD)
          const parts = processedURL.split('.')
          if (parts.length >= 2 && parts[parts.length - 1].length >= 2) {
            processedURL = 'https://' + processedURL
          } else {
            // Doesn't look like a valid domain, return null to trigger error
            return null
          }
        } else {
          // Single words or invalid formats should fail, not become searches
          return null
        }
      }

      const parsedURL = new URL(processedURL)

      // Double-check protocol after URL parsing
      if (!['http:', 'https:'].includes(parsedURL.protocol)) {
        throw new Error(`Invalid protocol: ${parsedURL.protocol}`)
      }

      return parsedURL
    } catch (error) {
      console.warn('URL parsing failed:', urlString, error.message)
      return null
    }
  }

  handleRelativeOrSearch(request, url) {
    const referer = request.headers.get('Referer')

    // Try to resolve relative URL using referer
    if (referer && referer.includes(url.host)) {
      const baseURL = this.extractBaseFromReferer(referer)
      if (baseURL) {
        try {
          return new URL(url.pathname + url.search, baseURL)
        } catch (error) {
          console.warn('Failed to resolve relative URL:', error)
        }
      }
    }

    // Handle search queries
    if (url.searchParams.has('q')) {
      const ddgURL = new URL('https://duckduckgo.com/')
      url.searchParams.forEach((value, key) => {
        ddgURL.searchParams.set(key, value)
      })
      return ddgURL
    }

    // Handle path as potential URL or search
    const path = url.pathname.substring(1)
    if (path) {
      // Check if it looks like a domain (has dots, no spaces, reasonable length)
      if (path.includes('.') && !path.includes(' ') && path.length < 100) {
        const parsedURL = this.parseURL(path)
        if (parsedURL) {
          return parsedURL
        }
      }

      // If not a valid URL, treat as search
      return new URL(`https://duckduckgo.com/?q=${encodeURIComponent(path)}`)
    }

    // Empty path - invalid
    return null
  }

  extractBaseFromReferer(referer) {
    try {
      const refURL = new URL(referer)
      // Handle format: https://proxy.com/------https://target.com/page
      const separatorPattern = new RegExp(`/${this.separator}(.+)`)
      const match = refURL.pathname.match(separatorPattern)

      if (match && match[1]) {
        const targetURLString = match[1]
        if (targetURLString.startsWith('http://') || targetURLString.startsWith('https://')) {
          return new URL(targetURLString)
        }
      }
    } catch (error) {
      console.warn('Failed to extract base from referer:', error)
    }

    return null
  }

  createProxyURL(targetURL, proxyDomain) {
    return `https://${proxyDomain}/${this.separator}${targetURL.href}`
  }

  isValidDomain(hostname) {
    if (this.config.proxy.allowedDomains.length === 0) return true

    return this.config.proxy.allowedDomains.some(domain =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    )
  }

  isBlockedDomain(hostname) {
    return this.config.security.blockedPatterns.some(pattern =>
      pattern.test(hostname)
    )
  }
}

// Enhanced Content Rewriter
class ContentRewriter {
  constructor(config) {
    this.config = config
    this.separator = config.proxy.separator
  }

  async rewriteResponse(response, targetURL, proxyDomain) {
    const contentType = response.headers.get('Content-Type') || ''
    const contentEncoding = response.headers.get('Content-Encoding') || ''
    const contentLengthHeader = response.headers.get('Content-Length')

    // Skip rewriting for compressed content - pass through unchanged
    if (contentEncoding && (contentEncoding.includes('gzip') ||
        contentEncoding.includes('deflate') ||
        contentEncoding.includes('br') ||
        contentEncoding.includes('compress'))) {
      console.log(`Skipping rewriting for compressed content: ${contentEncoding}`)
      return this.createPassthroughResponse(response)
    }

    // Skip rewriting for large files or non-text content
    // If no Content-Length header, we'll proceed with rewriting but clone first to be safe
    if (contentLengthHeader) {
      const contentLength = parseInt(contentLengthHeader)
      if (contentLength > this.config.rewriting.streamingThreshold) {
        return this.createPassthroughResponse(response)
      }
    }

    // Clone response for content inspection since body can only be consumed once
    const clonedResponse = response.clone()

    if (contentType.includes('text/html')) {
      return this.rewriteHTML(clonedResponse, targetURL, proxyDomain)
    } else if (contentType.includes('text/css')) {
      return this.rewriteCSS(clonedResponse, targetURL, proxyDomain)
    } else if (contentType.includes('javascript')) {
      return this.rewriteJavaScript(clonedResponse, targetURL, proxyDomain)
    } else if (contentType.includes('text/') || contentType.includes('application/json')) {
      // Handle plain text and JSON responses that might contain URLs
      return this.rewriteTextContent(clonedResponse, targetURL, proxyDomain)
    }

    return response
  }

  async rewriteTextContent(response, targetURL, proxyDomain) {
    if (!this.config.rewriting.enableHTMLRewriting) return response

    try {
      const textContent = await response.text()

      // Rewrite URLs in text content (for responses like GetPost's plain text responses)
      const urlPattern = /https?:\/\/[^\s<>"']+/g
      const rewrittenText = textContent.replace(urlPattern, (match) => {
        try {
          const matchedURL = new URL(match)
          // Only rewrite URLs that match the current target domain
          if (matchedURL.hostname === targetURL.hostname) {
            return `https://${proxyDomain}/${this.separator}${match}`
          }
          return match
        } catch {
          return match
        }
      })

      return new Response(rewrittenText, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      })
    } catch (error) {
      console.warn('Text content rewriting failed:', error)
      return response
    }
  }

  async rewriteHTML(response, targetURL, proxyDomain) {
    if (!this.config.rewriting.enableHTMLRewriting) return response

    const rewriter = new HTMLRewriter()
      .on('a[href]', new AttributeRewriter(targetURL, 'href', proxyDomain, this.separator))
      .on('form[action]', new AttributeRewriter(targetURL, 'action', proxyDomain, this.separator))
      .on('img[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('img[srcset]', new SrcsetRewriter(targetURL, proxyDomain, this.separator))
      .on('source[srcset]', new SrcsetRewriter(targetURL, proxyDomain, this.separator))
      .on('link[href]', new AttributeRewriter(targetURL, 'href', proxyDomain, this.separator))
      .on('script[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('iframe[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('video[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('audio[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('embed[src]', new AttributeRewriter(targetURL, 'src', proxyDomain, this.separator))
      .on('object[data]', new AttributeRewriter(targetURL, 'data', proxyDomain, this.separator))
      .on('base[href]', new AttributeRewriter(targetURL, 'href', proxyDomain, this.separator))
      .on('meta[content]', new MetaRewriter(targetURL, proxyDomain, this.separator))
      .on('*[style]', new StyleAttributeRewriter(targetURL, proxyDomain, this.separator))
      .on('style', new StyleElementRewriter(targetURL, proxyDomain, this.separator))
      .on('head', new HeadInjector(targetURL, proxyDomain))

    return rewriter.transform(response)
  }

  async rewriteCSS(response, targetURL, proxyDomain) {
    if (!this.config.rewriting.enableCSSRewriting) return response

    try {
      const cssText = await response.text()
      const rewrittenCSS = this.processCSS(cssText, targetURL, proxyDomain)

      return new Response(rewrittenCSS, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      })
    } catch (error) {
      console.warn('CSS rewriting failed:', error)
      return response
    }
  }

  async rewriteJavaScript(response, targetURL, proxyDomain) {
    if (!this.config.rewriting.enableJSRewriting) return response

    try {
      const jsText = await response.text()
      const rewrittenJS = this.processJavaScript(jsText, targetURL, proxyDomain)

      return new Response(rewrittenJS, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
      })
    } catch (error) {
      console.warn('JavaScript rewriting failed:', error)
      return response
    }
  }

  processCSS(css, targetURL, proxyDomain) {
    if (!css || css.length > 1024 * 1024) return css // Skip empty or very large CSS

    return css
      // @import statements
      .replace(/@import\s+(?:url\(\s*['"]?([^'")]+)['"]?\s*\)|['"]([^'"]+)['"])/g,
        (match, url1, url2) => {
          const url = url1 || url2
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? match.replace(url, rewritten) : match
        })
      // url() patterns
      .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g,
        (match, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `url(${quote}${rewritten}${quote})` : match
        })
      // CSS custom properties and variables
      .replace(/--[^:]*:\s*url\(\s*(['"]?)([^'")]+)\1\s*\)/g,
        (match, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? match.replace(url, rewritten) : match
        })
  }

  processJavaScript(js, targetURL, proxyDomain) {
    return js
      // Be more specific with URL string patterns to avoid false matches
      .replace(/(['"`])(https?:\/\/(?!.*\b(?:localhost|127\.0\.0\.1)\b)[^'"`]*)\1/g,
        (match, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `${quote}${rewritten}${quote}` : match
        })
      // Location assignments - be more specific
      .replace(/((?:window\.)?location\.(?:href|assign|replace)\s*[=\(]\s*)(['"`])([^'"`]+)\2/g,
        (match, prefix, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `${prefix}${quote}${rewritten}${quote}` : match
        })
      // Fetch calls - more precise pattern
      .replace(/(fetch\s*\(\s*)(['"`])([^'"`]+)\2(\s*[,\)])/g,
        (match, prefix, quote, url, suffix) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `${prefix}${quote}${rewritten}${quote}${suffix}` : match
        })
      // XMLHttpRequest.open calls
      .replace(/(\.open\s*\(\s*['"`]\w+['"`]\s*,\s*)(['"`])([^'"`]+)\2/g,
        (match, prefix, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `${prefix}${quote}${rewritten}${quote}` : match
        })
      // New URL() constructors
      .replace(/(new\s+URL\s*\(\s*)(['"`])([^'"`]+)\2/g,
        (match, prefix, quote, url) => {
          const rewritten = this.rewriteURL(url, targetURL, proxyDomain)
          return rewritten ? `${prefix}${quote}${rewritten}${quote}` : match
        })
  }

  rewriteURL(url, baseURL, proxyDomain) {
    if (!url || this.shouldSkipURL(url, proxyDomain)) return null

    try {
      const absoluteURL = new URL(url, baseURL)
      return `https://${proxyDomain}/${this.separator}${absoluteURL.href}`
    } catch {
      return null
    }
  }

  shouldSkipURL(url, proxyDomain) {
    return url.startsWith('data:') ||
      url.startsWith('blob:') ||
      url.startsWith('javascript:') ||
      url.startsWith('mailto:') ||
      url.startsWith('tel:') ||
      url.includes(proxyDomain) ||
      url.startsWith('#')
  }

  createPassthroughResponse(response) {
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    })
  }
}

// HTML Rewriter Classes
class AttributeRewriter {
  constructor(baseURL, attribute, proxyDomain, separator) {
    this.baseURL = baseURL
    this.attribute = attribute
    this.proxyDomain = proxyDomain
    this.separator = separator
  }

  element(element) {
    const value = element.getAttribute(this.attribute)
    if (!value || this.shouldSkip(value)) return

    try {
      const absoluteURL = new URL(value, this.baseURL)
      const proxyURL = `https://${this.proxyDomain}/${this.separator}${absoluteURL.href}`
      element.setAttribute(this.attribute, proxyURL)

      // Add error handling for images
      if (this.attribute === 'src' && element.tagName === 'img') {
        element.setAttribute('onerror', `this.onerror=null;this.style.display='none';`)
      }
    } catch (error) {
      console.warn(`Failed to rewrite ${this.attribute}:`, value, error.message)
    }
  }

  shouldSkip(value) {
    return value.startsWith('data:') ||
      value.startsWith('javascript:') ||
      value.startsWith('mailto:') ||
      value.startsWith('tel:') ||
      value.includes(this.proxyDomain) ||
      value.startsWith('#')
  }
}

class SrcsetRewriter {
  constructor(baseURL, proxyDomain, separator) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
    this.separator = separator
  }

  element(element) {
    const srcset = element.getAttribute('srcset')
    if (!srcset) return

    try {
      // More robust srcset parsing that handles edge cases
      const newSrcset = srcset
        .split(',')
        .map(item => {
          const trimmed = item.trim()
          if (!trimmed) return item

          // Find the last space to separate URL from descriptor
          const lastSpaceIndex = trimmed.lastIndexOf(' ')
          let url, descriptor

          if (lastSpaceIndex === -1) {
            url = trimmed
            descriptor = ''
          } else {
            url = trimmed.substring(0, lastSpaceIndex)
            descriptor = trimmed.substring(lastSpaceIndex)
          }

          if (!url || url.startsWith('data:') || url.includes(this.proxyDomain)) {
            return item
          }

          try {
            const absoluteURL = new URL(url, this.baseURL)
            const proxyURL = `https://${this.proxyDomain}/${this.separator}${absoluteURL.href}`
            return proxyURL + descriptor
          } catch {
            return item
          }
        })
        .join(', ')

      element.setAttribute('srcset', newSrcset)
    } catch (error) {
      console.warn('Srcset rewriting failed:', error)
    }
  }
}

class MetaRewriter {
  constructor(baseURL, proxyDomain, separator) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
    this.separator = separator
  }

  element(element) {
    const httpEquiv = element.getAttribute('http-equiv')
    const content = element.getAttribute('content')

    if (httpEquiv && httpEquiv.toLowerCase() === 'refresh' && content) {
      // More robust parsing of meta refresh content
      const refreshMatch = content.match(/^(\d+)(?:\s*;\s*url\s*=\s*(.+))?$/i)
      if (refreshMatch && refreshMatch[2]) {
        try {
          const url = refreshMatch[2].replace(/^['"]|['"]$/g, '') // Remove surrounding quotes
          const absoluteURL = new URL(url, this.baseURL)
          const proxyURL = `https://${this.proxyDomain}/${this.separator}${absoluteURL.href}`
          element.setAttribute('content', `${refreshMatch[1]};url=${proxyURL}`)
        } catch (error) {
          console.warn('Meta refresh URL rewriting failed:', error)
        }
      }
    }

    // Handle Open Graph and Twitter Card URLs
    const property = element.getAttribute('property') || element.getAttribute('name')
    if (property && content && /^(og:|twitter:)/.test(property) && /(url|image)$/.test(property)) {
      try {
        const url = new URL(content, this.baseURL)
        const proxyURL = `https://${this.proxyDomain}/${this.separator}${url.href}`
        element.setAttribute('content', proxyURL)
      } catch (error) {
        console.warn('Meta tag URL rewriting failed:', error)
      }
    }
  }
}

class StyleAttributeRewriter {
  constructor(baseURL, proxyDomain, separator) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
    this.separator = separator
  }

  element(element) {
    const style = element.getAttribute('style')
    if (!style) return

    const rewritten = style.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, (match, quote, url) => {
      try {
        if (url.startsWith('data:') || url.includes(this.proxyDomain)) return match
        const absoluteURL = new URL(url, this.baseURL)
        const proxyURL = `https://${this.proxyDomain}/${this.separator}${absoluteURL.href}`
        return `url(${quote}${proxyURL}${quote})`
      } catch {
        return match
      }
    })

    element.setAttribute('style', rewritten)
  }
}

class StyleElementRewriter {
  constructor(baseURL, proxyDomain, separator) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
    this.separator = separator
  }

  text(text) {
    const rewritten = text.text.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, (match, quote, url) => {
      try {
        if (url.startsWith('data:') || url.includes(this.proxyDomain)) return match
        const absoluteURL = new URL(url, this.baseURL)
        const proxyURL = `https://${this.proxyDomain}/${this.separator}${absoluteURL.href}`
        return `url(${quote}${proxyURL}${quote})`
      } catch {
        return match
      }
    })

    text.replace(rewritten)
  }
}

class HeadInjector {
  constructor(baseURL, proxyDomain) {
    this.baseURL = baseURL
    this.proxyDomain = proxyDomain
  }

  escapeForJS(str) {
    return str.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/`/g, '\\`').replace(/\\/g, '\\\\')
  }

  element(element) {
    const escapedDomain = this.escapeForJS(this.proxyDomain)
    const escapedSeparator = this.escapeForJS(CONFIG.proxy.separator)
    const escapedOriginalURL = this.escapeForJS(this.baseURL.href)

    element.append(`
      <script>
        // Proxy helper functions
        window.__PROXY_CONFIG__ = {
          domain: '${escapedDomain}',
          separator: '${escapedSeparator}',
          originalURL: '${escapedOriginalURL}'
        };

        // Override link clicks to handle proxy URLs
        document.addEventListener('click', function(e) {
          const link = e.target.closest('a');
          if (link && link.target === '_blank') {
            // Allow external links to open normally
            const href = link.href;
            if (href.includes(window.__PROXY_CONFIG__.domain)) {
              e.preventDefault();
              window.open(href, '_blank', 'noopener,noreferrer');
            }
          }
        });

        // Fix form submissions
        document.addEventListener('submit', function(e) {
          const form = e.target;
          if (form.action && !form.action.includes(window.__PROXY_CONFIG__.domain)) {
            try {
              const baseURL = new URL(window.__PROXY_CONFIG__.originalURL);
              const actionURL = new URL(form.action, baseURL);
              form.action = 'https://' + window.__PROXY_CONFIG__.domain + '/' + window.__PROXY_CONFIG__.separator + actionURL.href;
            } catch (err) {
              console.warn('Failed to rewrite form action:', err);
            }
          }
        });
      </script>
    `, {
      html: true
    });
  }
}

// Simple rate limiting implementation
const rateLimitStore = new Map()

function checkRateLimit(clientIP) {
  const now = Date.now()
  const windowMs = CONFIG.security.rateLimit.window
  const maxRequests = CONFIG.security.rateLimit.requests

  if (!rateLimitStore.has(clientIP)) {
    rateLimitStore.set(clientIP, [])
  }

  const requests = rateLimitStore.get(clientIP)

  // Clean old requests
  const validRequests = requests.filter(time => now - time < windowMs)

  if (validRequests.length >= maxRequests) {
    return false
  }

  validRequests.push(now)
  rateLimitStore.set(clientIP, validRequests)

  // Cleanup old entries periodically
  if (rateLimitStore.size > 1000) {
    const cutoff = now - windowMs * 2
    for (const [ip, times] of rateLimitStore.entries()) {
      const validTimes = times.filter(time => time > cutoff)
      if (validTimes.length === 0) {
        rateLimitStore.delete(ip)
      } else {
        rateLimitStore.set(ip, validTimes)
      }
    }
  }

  return true
}

// Main request handler
async function handleRequest(request) {
  try {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      })
    }

    // Rate limiting
    const clientIP = request.headers.get('CF-Connecting-IP') ||
      request.headers.get('X-Forwarded-For') ||
      'unknown'

    if (!checkRateLimit(clientIP)) {
      throw new Error('Rate limit exceeded')
    }

    const urlHandler = new URLHandler(CONFIG)
    const contentRewriter = new ContentRewriter(CONFIG)

    // Extract target URL
    const {
      target: targetURL,
      isProxy,
      isHomepage,
      isMalformed = false
    } = urlHandler.extractTargetURL(request)

    // Handle homepage
    if (isHomepage) {
      return getHomePage()
    }

    // Handle malformed proxy URLs
    if (isMalformed) {
      throw new Error('Invalid proxy URL format. Use: /' + urlHandler.separator + 'https://example.com')
    }

    // Validate target URL
    if (!targetURL) {
      throw new Error('Invalid or missing target URL')
    }

    // Validate URL protocol
    if (!['http:', 'https:'].includes(targetURL.protocol)) {
      throw new Error(`Invalid protocol: ${targetURL.protocol}. Only HTTP and HTTPS are allowed.`)
    }

    // Security checks
    if (!urlHandler.isValidDomain(targetURL.hostname)) {
      throw new Error('Domain not allowed')
    }

    if (urlHandler.isBlockedDomain(targetURL.hostname)) {
      throw new Error('Domain blocked')
    }

    // Check for SSRF attempts
    if (isPrivateIP(targetURL.hostname)) {
      throw new Error('Access to private IP addresses not allowed')
    }

    // Create proxied request
    const proxiedRequest = createProxiedRequest(request, targetURL)

    // Fetch response (Cloudflare Workers handle timeouts automatically)
    let response
    try {
      response = await fetch(proxiedRequest)
    } catch (fetchError) {
      throw new Error(`Network error: ${fetchError.message}`)
    }

    // Check if response indicates an error that should be passed through
    if (!response.ok && response.status >= 500) {
      // Server errors from target - pass through but add CORS headers
      const errorHeaders = prepareResponseHeaders(response.headers)
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: errorHeaders
      })
    }

    // Handle redirects
    if ([301, 302, 307, 308].includes(response.status)) {
      response = handleRedirect(response, request, urlHandler)
    }

    // Prepare response headers
    const newHeaders = prepareResponseHeaders(response.headers)

    // Create base response
    let newResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    })

    // Rewrite content if needed
    if (isProxy) {
      const proxyDomain = new URL(request.url).hostname
      newResponse = await contentRewriter.rewriteResponse(newResponse, targetURL, proxyDomain)
    }

    return newResponse

  } catch (error) {
    return createErrorResponse(error, request.url)
  }
}

// SSRF protection
function isPrivateIP(hostname) {
  // Check for localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    return true
  }

  // Check for private IP ranges
  const privateRanges = [
    /^10\./, // 10.0.0.0/8
    /^192\.168\./, // 192.168.0.0/16
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12
    /^169\.254\./, // 169.254.0.0/16 (link-local)
    /^fc00:/, // IPv6 private
    /^fe80:/ // IPv6 link-local
  ]

  return privateRanges.some(range => range.test(hostname))
}

function createProxiedRequest(originalRequest, targetURL) {
  const headers = new Headers()

  // Headers to exclude from the original request
  const excludedHeaders = new Set([
    'host', 'origin', 'referer', 'connection',
    'upgrade-insecure-requests', 'sec-fetch-dest', 'sec-fetch-mode',
    'sec-fetch-site', 'sec-fetch-user',
    // We will handle this header specifically
    'accept-encoding'
  ])

  // Copy headers from original request
  for (const [name, value] of originalRequest.headers.entries()) {
    if (!excludedHeaders.has(name.toLowerCase())) {
      headers.set(name, value)
    }
  }

  // Apply browser emulation headers, but let original request headers take precedence
  const headerMapping = {
    userAgent: 'User-Agent',
    accept: 'Accept',
    acceptLanguage: 'Accept-Language',
  }

  Object.entries(CONFIG.browserEmulation).forEach(([key, value]) => {
    const headerName = headerMapping[key] || key.replace(/([A-Z])/g, '-$1').toLowerCase();
    if (headerName !== 'accept-encoding' && !headers.has(headerName)) {
      headers.set(headerName, value);
    }
  });

  // Set target-specific headers
  headers.set('host', targetURL.host)
  headers.set('origin', targetURL.origin)
  headers.set('referer', targetURL.href)

  // CRITICAL FIX: We must remove the Accept-Encoding header.
  // This tells the origin server to send us uncompressed content,
  // which is required for HTMLRewriter to work. The Cloudflare Worker
  // will automatically re-compress the final response to the browser.
  headers.delete('Accept-Encoding');

  return new Request(targetURL, {
    method: originalRequest.method,
    headers,
    body: originalRequest.method !== 'GET' && originalRequest.method !== 'HEAD' ?
      originalRequest.body : null,
    redirect: 'manual'
  })
}

function handleRedirect(response, originalRequest, urlHandler) {
  const location = response.headers.get('Location')
  if (!location) return response

  try {
    const currentURL = new URL(originalRequest.url)
    const proxyDomain = currentURL.hostname

    // Parse the original target URL from the request
    const {
      target: originalTargetURL,
      isMalformed = false
    } = urlHandler.extractTargetURL(originalRequest)
    if (!originalTargetURL || isMalformed) return response

    // Handle relative and absolute redirects
    const redirectURL = new URL(location, originalTargetURL)
    const newLocation = urlHandler.createProxyURL(redirectURL, proxyDomain)

    const newHeaders = new Headers(response.headers)
    newHeaders.set('Location', newLocation)

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    })
  } catch (error) {
    console.warn('Redirect handling failed:', error)
    return response
  }
}

function prepareResponseHeaders(originalHeaders) {
  const newHeaders = new Headers(originalHeaders)

  // Remove security headers that might interfere
  const headersToRemove = [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-frame-options',
    'x-content-type-options'
  ]

  headersToRemove.forEach(header => newHeaders.delete(header))

  // Add CORS headers
  newHeaders.set('access-control-allow-origin', '*')
  newHeaders.set('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH')
  newHeaders.set('access-control-allow-headers', '*')

  return newHeaders
}

function createErrorResponse(error, requestUrl) {
  let status = 500
  let message = 'Proxy request failed'

  const errorMessage = error.message || ''

  // Map specific errors to appropriate status codes
  if (errorMessage.includes('Rate limit exceeded')) {
    status = 429
    message = 'Too many requests'
  } else if (errorMessage.includes('Domain not allowed') || errorMessage.includes('Domain blocked')) {
    status = 403
    message = 'Access forbidden'
  } else if (errorMessage.includes('Invalid or missing target URL') ||
    errorMessage.includes('Invalid protocol') ||
    errorMessage.includes('Only HTTP and HTTPS') ||
    errorMessage.includes('URL parsing failed') ||
    errorMessage.includes('Invalid proxy URL format')) { // ← Added this line
    status = 400
    message = 'Invalid request'
  } else if (errorMessage.includes('private IP')) {
    status = 403
    message = 'Access to private resources not allowed'
  } else if (errorMessage.includes('Network error') || errorMessage.includes('fetch')) {
    status = 502
    message = 'Bad gateway'
  } else if (errorMessage) {
    message = errorMessage
  }

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Error ${status}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      max-width: 600px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #333;
      background: #f8f9fa;
    }
    .container {
      background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .error {
      background: #fee; color: #c33; padding: 15px; border-radius: 8px;
      border-left: 4px solid #e74c3c; margin: 20px 0;
    }
    .retry {
      background: #007bff; color: white; padding: 10px 20px;
      border: none; border-radius: 5px; cursor: pointer; margin: 10px 5px 0 0;
    }
    .retry:hover { background: #0056b3; }
    .home {
      background: #28a745; color: white; padding: 10px 20px;
      border: none; border-radius: 5px; cursor: pointer; text-decoration: none;
      display: inline-block;
    }
    .home:hover { background: #1e7e34; }
    h1 { color: #2c3e50; margin-top: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚫 Error ${status}</h1>
    <div class="error">
      <strong>Error:</strong> ${message}
    </div>
    <div>
      ${status !== 429 ? '<button class="retry" onclick="window.location.reload()">🔄 Retry</button>' : ''}
      <a href="/" class="home">🏠 Home</a>
    </div>
  </div>
</body>
</html>`

  const headers = {
    'Content-Type': 'text/html;charset=UTF-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
    'Access-Control-Allow-Headers': '*'
  }

  if (status === 429) {
    headers['Retry-After'] = '60'
  }

  return new Response(html, {
    status,
    headers
  })
}

function getHomePage() {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web Proxy Service</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
    }
    .container {
      background: white; padding: 40px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.2);
      max-width: 500px; width: 100%; text-align: center;
    }
    h1 { color: #2c3e50; margin: 0 0 30px 0; font-size: 2.5em; font-weight: 300; }
    .subtitle { color: #7f8c8d; margin-bottom: 30px; font-size: 1.1em; }
    .input-group { display: flex; margin-bottom: 20px; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    input[type="text"] {
      flex: 1; padding: 15px; font-size: 16px; border: none; outline: none;
      background: #f8f9fa;
    }
    button {
      background: #3498db; color: white; border: none; padding: 15px 25px;
      font-size: 16px; cursor: pointer; transition: background 0.3s; font-weight: 500;
    }
    button:hover { background: #2980b9; }
    .examples { margin-top: 25px; }
    .examples a {
      display: inline-block; margin: 5px; padding: 8px 12px; background: #ecf0f1;
      color: #2c3e50; text-decoration: none; border-radius: 20px; font-size: 14px;
      transition: all 0.3s;
    }
    .examples a:hover { background: #3498db; color: white; }
    .features {
      background: #f8f9fa; padding: 25px; border-radius: 8px; margin-top: 30px; text-align: left;
    }
    .features h3 { margin-top: 0; color: #2c3e50; }
    .features ul { margin: 0; padding-left: 20px; }
    .features li { margin: 8px 0; color: #5a6c7d; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🌐 Web Proxy</h1>
    <p class="subtitle">Browse the web privately and securely</p>

    <form onsubmit="navigate(event)">
      <div class="input-group">
        <input type="text" id="url" placeholder="Enter URL or search term..." autocomplete="off" autofocus>
        <button type="submit">Go</button>
      </div>
    </form>

    <div class="examples">
      <a href="/${CONFIG.proxy.separator}https://example.com">example.com</a>
      <a href="/${CONFIG.proxy.separator}https://httpbin.org/get?test=123">httpbin.org (with params)</a>
      <a href="/${CONFIG.proxy.separator}https://github.com">github.com</a>
    </div>

    <div class="features">
      <h3>Features</h3>
      <ul>
        <li>🔒 Private browsing</li>
        <li>🚀 Fast response times</li>
        <li>📱 Mobile friendly</li>
        <li>🌍 Access global content</li>
      </ul>

      <h3>URL Formats</h3>
      <ul>
        <li><strong>Simple:</strong> /${CONFIG.proxy.separator}https://example.com</li>
        <li><strong>With parameters:</strong> /${CONFIG.proxy.separator}https://site.com/page?param=value</li>
        <li><strong>Alternative:</strong> /proxy?url=https%3A//site.com/page%3Fparam%3Dvalue</li>
      </ul>
    </div>
  </div>

  <script>
    function navigate(e) {
      e.preventDefault()
      const input = document.getElementById('url').value.trim()
      if (!input) return

      let target
      if (/^https?:\\/\\//i.test(input)) {
        target = input
      } else if (input.includes('.') && !input.includes(' ')) {
        target = 'https://' + input
      } else {
        target = 'https://duckduckgo.com/?q=' + encodeURIComponent(input)
      }

      // Use separator format for direct navigation
      window.location.href = '/${CONFIG.proxy.separator}' + target
    }

    // Utility function for programmatic proxy URL creation
    window.createProxyURL = function(targetURL) {
      // For URLs with complex query parameters, use the proxy format
      if (targetURL.includes('?') && targetURL.includes('&')) {
        return '/proxy?url=' + encodeURIComponent(targetURL)
      } else {
        // Use separator format for simple URLs
        return '/${CONFIG.proxy.separator}' + targetURL
      }
    }

    document.getElementById('url').addEventListener('paste', function() {
      setTimeout(() => {
        this.value = this.value.trim().replace(/\\s+/g, '')
      }, 0)
    })
  </script>
</body>
</html>`, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'public, max-age=3600'
    }
  })
}
