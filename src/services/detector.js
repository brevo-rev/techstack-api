/**
 * Multi-method tech stack detection
 * Combines: HTML analysis, DNS records, HTTP headers, JavaScript analysis
 */

import { chromium } from 'playwright';
import * as cheerio from 'cheerio';
import dns from 'dns/promises';

// Detection signatures organized by category
import { SIGNATURES } from '../data/signatures.js';
import { calculateTechScore } from './scoring.js';

// Browser recycling - prevents memory bloat
let browserInstance = null;
let requestCount = 0;
const MAX_REQUESTS_PER_BROWSER = 50;

/**
 * Get or create browser instance with recycling
 */
async function getBrowser() {
  if (!browserInstance || requestCount >= MAX_REQUESTS_PER_BROWSER) {
    if (browserInstance) {
      console.log(`Recycling browser after ${requestCount} requests`);
      await browserInstance.close().catch(() => {});
    }
    browserInstance = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    });
    requestCount = 0;
  }
  requestCount++;
  return browserInstance;
}

/**
 * Cleanup browser on shutdown
 */
export async function closeBrowser() {
  if (browserInstance) {
    await browserInstance.close().catch(() => {});
    browserInstance = null;
  }
}

/**
 * Main detection function - runs all detection methods
 * @param {string} domain - Domain to detect
 * @param {object} options - Detection options
 * @param {boolean} options.fastMode - Skip browser, DNS-only (much faster)
 * @param {boolean} options.smartMode - DNS first, full scan if high score
 */
export async function detectTechStack(domain, options = {}) {
  const { fastMode = false, smartMode = false } = options;
  const url = `https://${domain}`;

  // Fast mode: DNS-only detection (500ms vs 15s)
  if (fastMode) {
    const dnsResults = await detectFromDNS(domain);
    const result = {
      esp: dnsResults.esp,
      crm: dnsResults.crm,
      cms: [],
      ecommerce: [],
      analytics: [],
      cdn: dnsResults.cdn,
      marketing: [],
      chat: [],
      ab_testing: [],
      tag_manager: [],
      payment: [],
      hosting: dnsResults.hosting,
      dns_records: dnsResults.raw,
      detection_methods: {
        dns: true,
        html: false,
        headers: false,
        javascript: false
      },
      mode: 'fast'
    };
    const scoring = calculateTechScore(result);
    return { ...scoring, ...result };
  }

  // Smart mode: DNS first, upgrade to full if score >= 15
  if (smartMode) {
    const dnsResults = await detectFromDNS(domain);
    const dnsOnlyResult = {
      esp: dnsResults.esp,
      crm: dnsResults.crm,
      cms: [],
      ecommerce: [],
      analytics: [],
      cdn: dnsResults.cdn,
      marketing: [],
      chat: [],
      ab_testing: [],
      tag_manager: [],
      payment: [],
      hosting: dnsResults.hosting,
      dns_records: dnsResults.raw,
      detection_methods: {
        dns: true,
        html: false,
        headers: false,
        javascript: false
      }
    };
    const dnsScoring = calculateTechScore(dnsOnlyResult);

    // If score >= 15 (high potential), do full browser scan
    if (dnsScoring.tech_score >= 15) {
      try {
        const browserResults = await detectFromBrowser(url);
        const fullResult = {
          esp: mergeDetections(dnsResults.esp, browserResults.esp),
          crm: mergeDetections(dnsResults.crm, browserResults.crm),
          cms: browserResults.cms,
          ecommerce: browserResults.ecommerce,
          analytics: browserResults.analytics,
          cdn: mergeDetections(dnsResults.cdn, browserResults.cdn),
          marketing: browserResults.marketing,
          chat: browserResults.chat,
          ab_testing: browserResults.ab_testing,
          tag_manager: browserResults.tag_manager,
          payment: browserResults.payment,
          hosting: dnsResults.hosting,
          dns_records: dnsResults.raw,
          detection_methods: {
            dns: true,
            html: true,
            headers: browserResults.headersChecked,
            javascript: browserResults.jsChecked
          },
          mode: 'smart-full',
          upgraded: true,
          upgrade_reason: `DNS score ${dnsScoring.tech_score} >= 15`
        };
        const fullScoring = calculateTechScore(fullResult);
        return { ...fullScoring, ...fullResult };
      } catch (err) {
        // Browser failed, return DNS results
        return { ...dnsScoring, ...dnsOnlyResult, mode: 'smart-dns', upgrade_failed: err.message };
      }
    }

    // Low score, skip browser
    return { ...dnsScoring, ...dnsOnlyResult, mode: 'smart-dns', skipped_browser: 'score < 15' };
  }

  try {
    // Run DNS checks in parallel with browser
    const [dnsResults, browserResults] = await Promise.all([
      detectFromDNS(domain),
      detectFromBrowser(url)
    ]);

    const result = {
      esp: mergeDetections(dnsResults.esp, browserResults.esp),
      crm: mergeDetections(dnsResults.crm, browserResults.crm),
      cms: browserResults.cms,
      ecommerce: browserResults.ecommerce,
      analytics: browserResults.analytics,
      cdn: mergeDetections(dnsResults.cdn, browserResults.cdn),
      marketing: browserResults.marketing,
      chat: browserResults.chat,
      ab_testing: browserResults.ab_testing,
      tag_manager: browserResults.tag_manager,
      payment: browserResults.payment,
      hosting: dnsResults.hosting,
      dns_records: dnsResults.raw,
      detection_methods: {
        dns: true,
        html: true,
        headers: browserResults.headersChecked,
        javascript: browserResults.jsChecked
      }
    };

    // Calculate tech stack score
    const scoring = calculateTechScore(result);
    return {
      ...scoring,
      ...result
    };
  } catch (err) {
    // If browser fails, try DNS-only detection
    console.error(`Browser detection failed for ${domain}: ${err.message}`);

    try {
      const dnsResults = await detectFromDNS(domain);
      const partialResult = {
        esp: dnsResults.esp,
        crm: dnsResults.crm,
        cms: [],
        ecommerce: [],
        analytics: [],
        cdn: dnsResults.cdn,
        marketing: [],
        chat: [],
        ab_testing: [],
        tag_manager: [],
        payment: [],
        hosting: dnsResults.hosting,
        dns_records: dnsResults.raw,
        detection_methods: {
          dns: true,
          html: false,
          headers: false,
          javascript: false
        },
        partial: true,
        error: `Browser detection failed: ${err.message}`
      };

      // Calculate tech stack score
      const scoring = calculateTechScore(partialResult);
      return {
        ...scoring,
        ...partialResult
      };
    } catch (dnsErr) {
      throw new Error(`All detection methods failed: ${err.message}`);
    }
  }
}

/**
 * DNS-based detection (MX, TXT, CNAME records)
 */
async function detectFromDNS(domain) {
  const results = {
    esp: [],
    crm: [],
    cdn: [],
    hosting: [],
    raw: {}
  };

  // Check MX records for ESP
  try {
    const mxRecords = await dns.resolveMx(domain);
    results.raw.mx = mxRecords.map(r => r.exchange);

    for (const mx of mxRecords) {
      const exchange = mx.exchange.toLowerCase();

      // ESP detection from MX records
      for (const [provider, patterns] of Object.entries(SIGNATURES.esp.mx)) {
        for (const pattern of patterns) {
          if (exchange.includes(pattern)) {
            if (!results.esp.find(e => e.name === provider)) {
              results.esp.push({ name: provider, confidence: 'high', source: 'mx' });
            }
          }
        }
      }
    }
  } catch (e) {
    // MX lookup failed - continue
  }

  // Check TXT records for email authentication (SPF/DKIM hints)
  try {
    const txtRecords = await dns.resolveTxt(domain);
    results.raw.txt = txtRecords.map(r => r.join(''));

    for (const record of txtRecords) {
      const txt = record.join('').toLowerCase();

      for (const [provider, patterns] of Object.entries(SIGNATURES.esp.txt)) {
        for (const pattern of patterns) {
          if (txt.includes(pattern)) {
            if (!results.esp.find(e => e.name === provider)) {
              results.esp.push({ name: provider, confidence: 'high', source: 'spf' });
            }
          }
        }
      }

      // CRM detection from TXT records
      if (SIGNATURES.crm.txt) {
        for (const [provider, patterns] of Object.entries(SIGNATURES.crm.txt)) {
          for (const pattern of patterns) {
            if (txt.includes(pattern)) {
              if (!results.crm.find(e => e.name === provider)) {
                results.crm.push({ name: provider, confidence: 'high', source: 'txt' });
              }
            }
          }
        }
      }
    }
  } catch (e) {
    // TXT lookup failed - continue
  }

  // Check CNAME for CDN and hosting
  try {
    const cname = await dns.resolveCname(`www.${domain}`);
    results.raw.cname = cname;

    for (const record of cname) {
      const cn = record.toLowerCase();

      for (const [provider, patterns] of Object.entries(SIGNATURES.cdn.cname)) {
        for (const pattern of patterns) {
          if (cn.includes(pattern)) {
            results.cdn.push({ name: provider, confidence: 'high', source: 'cname' });
          }
        }
      }

      for (const [provider, patterns] of Object.entries(SIGNATURES.hosting.cname)) {
        for (const pattern of patterns) {
          if (cn.includes(pattern)) {
            results.hosting.push({ name: provider, confidence: 'high', source: 'cname' });
          }
        }
      }
    }
  } catch (e) {
    // CNAME lookup failed - continue
  }

  // Check for ESP-specific CNAME records (tracking domains)
  const espCnameChecks = [
    { subdomain: 'email', provider: 'various' },
    { subdomain: 'click', provider: 'various' },
    { subdomain: 'links', provider: 'various' },
    { subdomain: 'track', provider: 'various' },
    { subdomain: 'em', provider: 'various' },
    { subdomain: 'mail', provider: 'various' }
  ];

  for (const check of espCnameChecks) {
    try {
      const cname = await dns.resolveCname(`${check.subdomain}.${domain}`);
      if (cname.length > 0) {
        const cn = cname[0].toLowerCase();

        for (const [provider, patterns] of Object.entries(SIGNATURES.esp.cname)) {
          for (const pattern of patterns) {
            if (cn.includes(pattern)) {
              if (!results.esp.find(e => e.name === provider)) {
                results.esp.push({ name: provider, confidence: 'high', source: 'cname' });
              }
            }
          }
        }
      }
    } catch (e) {
      // Expected to fail for most subdomains
    }
  }

  return results;
}

/**
 * Browser-based detection (HTML, headers, JavaScript)
 */
async function detectFromBrowser(url) {
  const results = {
    esp: [],
    crm: [],
    cms: [],
    ecommerce: [],
    analytics: [],
    cdn: [],
    marketing: [],
    chat: [],
    ab_testing: [],
    tag_manager: [],
    payment: [],
    headersChecked: false,
    jsChecked: false
  };

  let context = null;

  try {
    const browser = await getBrowser();

    context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    });

    const page = await context.newPage();

    // Capture response headers
    let responseHeaders = {};
    page.on('response', response => {
      if (response.url() === url || response.url() === url + '/') {
        responseHeaders = response.headers();
        results.headersChecked = true;
      }
    });

    // Retry navigation up to 2 times with increasing timeout
    const timeouts = [30000, 45000];
    let lastError = null;
    for (const timeout of timeouts) {
      try {
        await page.goto(url, {
          waitUntil: 'domcontentloaded',
          timeout
        });
        lastError = null;
        break;
      } catch (navErr) {
        lastError = navErr;
      }
    }
    if (lastError) throw lastError;

    // Brief wait for scripts to load
    await page.waitForTimeout(2000);

    // Get page content
    const html = await page.content();
    const $ = cheerio.load(html);

    // Analyze HTML
    analyzeHTML($, results);

    // Analyze headers
    analyzeHeaders(responseHeaders, results);

    // Analyze JavaScript globals
    results.jsChecked = true;
    const jsGlobals = await page.evaluate(() => {
      const globals = {};

      // Check for common tracking/analytics globals
      const checks = [
        'ga', 'gtag', '_gaq', 'dataLayer', 'fbq', '_fbq',
        'ttq', 'pintrk', 'lintrk', 'obApi', 'twq',
        'Intercom', 'Drift', 'HubSpot', 'Klaviyo', '_klOnsite',
        'Shopify', 'BigCommerce', 'WooCommerce',
        'Optimizely', 'VWO', 'ABTasty',
        '_satellite', 'Tealium', 'analytics',
        'Stripe', 'Braintree', 'PayPal',
        'mailchimp_campaign_id', 'mc_cid', '_mailchimp',
        '__NEXT_DATA__', '__NUXT__', 'webpackChunk',
        'Drupal', 'wp', 'joomla'
      ];

      for (const check of checks) {
        if (typeof window[check] !== 'undefined') {
          globals[check] = true;
        }
      }

      return globals;
    });

    analyzeJSGlobals(jsGlobals, results);

    await context.close();

  } catch (err) {
    if (context) {
      await context.close().catch(() => {});
    }
    throw err;
  }

  return results;
}

/**
 * Analyze HTML content for tech signatures
 */
function analyzeHTML($, results) {
  const html = $.html().toLowerCase();
  const scripts = [];
  const links = [];
  const metas = [];

  // Collect all script srcs
  $('script[src]').each((_, el) => {
    scripts.push($(el).attr('src'));
  });

  // Collect all link hrefs
  $('link[href]').each((_, el) => {
    links.push($(el).attr('href'));
  });

  // Collect meta tags
  $('meta').each((_, el) => {
    const name = $(el).attr('name') || $(el).attr('property') || '';
    const content = $(el).attr('content') || '';
    metas.push({ name, content });
  });

  // Check scripts for signatures
  for (const src of scripts) {
    if (!src) continue;
    const srcLower = src.toLowerCase();

    // ESP detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.esp.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.esp, provider, 'medium', 'script');
        }
      }
    }

    // Analytics detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.analytics.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.analytics, provider, 'high', 'script');
        }
      }
    }

    // Chat detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.chat.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.chat, provider, 'high', 'script');
        }
      }
    }

    // Marketing detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.marketing.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.marketing, provider, 'high', 'script');
        }
      }
    }

    // Tag manager detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.tagManager.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.tag_manager, provider, 'high', 'script');
        }
      }
    }

    // A/B testing detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.abTesting.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.ab_testing, provider, 'high', 'script');
        }
      }
    }

    // Payment detection
    for (const [provider, patterns] of Object.entries(SIGNATURES.payment.script)) {
      for (const pattern of patterns) {
        if (srcLower.includes(pattern)) {
          addDetection(results.payment, provider, 'high', 'script');
        }
      }
    }

    // CRM detection
    if (SIGNATURES.crm.script) {
      for (const [provider, patterns] of Object.entries(SIGNATURES.crm.script)) {
        for (const pattern of patterns) {
          if (srcLower.includes(pattern)) {
            addDetection(results.crm, provider, 'high', 'script');
          }
        }
      }
    }
  }

  // Check meta tags for CMS
  for (const meta of metas) {
    const combined = `${meta.name} ${meta.content}`.toLowerCase();

    for (const [provider, patterns] of Object.entries(SIGNATURES.cms.meta)) {
      for (const pattern of patterns) {
        if (combined.includes(pattern)) {
          addDetection(results.cms, provider, 'high', 'meta');
        }
      }
    }

    for (const [provider, patterns] of Object.entries(SIGNATURES.ecommerce.meta)) {
      for (const pattern of patterns) {
        if (combined.includes(pattern)) {
          addDetection(results.ecommerce, provider, 'high', 'meta');
        }
      }
    }
  }

  // Check HTML for platform-specific markers
  for (const [provider, patterns] of Object.entries(SIGNATURES.cms.html)) {
    for (const pattern of patterns) {
      if (html.includes(pattern)) {
        addDetection(results.cms, provider, 'medium', 'html');
      }
    }
  }

  for (const [provider, patterns] of Object.entries(SIGNATURES.ecommerce.html)) {
    for (const pattern of patterns) {
      if (html.includes(pattern)) {
        addDetection(results.ecommerce, provider, 'medium', 'html');
      }
    }
  }

  // Check inline scripts
  const inlineScripts = [];
  $('script:not([src])').each((_, el) => {
    inlineScripts.push($(el).html() || '');
  });

  const allInline = inlineScripts.join(' ').toLowerCase();

  for (const [provider, patterns] of Object.entries(SIGNATURES.esp.inline)) {
    for (const pattern of patterns) {
      if (allInline.includes(pattern)) {
        addDetection(results.esp, provider, 'medium', 'inline');
      }
    }
  }

  // CRM inline detection
  if (SIGNATURES.crm.inline) {
    for (const [provider, patterns] of Object.entries(SIGNATURES.crm.inline)) {
      for (const pattern of patterns) {
        if (allInline.includes(pattern)) {
          addDetection(results.crm, provider, 'medium', 'inline');
        }
      }
    }
  }
}

/**
 * Analyze HTTP headers for tech signatures
 */
function analyzeHeaders(headers, results) {
  const server = (headers['server'] || '').toLowerCase();
  const poweredBy = (headers['x-powered-by'] || '').toLowerCase();
  const cdn = (headers['x-cdn'] || headers['x-served-by'] || '').toLowerCase();

  // CDN detection from headers
  for (const [provider, patterns] of Object.entries(SIGNATURES.cdn.header)) {
    for (const pattern of patterns) {
      if (server.includes(pattern) || cdn.includes(pattern)) {
        addDetection(results.cdn, provider, 'high', 'header');
      }
    }
  }

  // CMS/Platform detection from headers
  if (poweredBy.includes('shopify')) {
    addDetection(results.ecommerce, 'Shopify', 'high', 'header');
  }
  if (poweredBy.includes('express')) {
    addDetection(results.cms, 'Express.js', 'high', 'header');
  }
  if (poweredBy.includes('next.js')) {
    addDetection(results.cms, 'Next.js', 'high', 'header');
  }
  if (poweredBy.includes('php')) {
    addDetection(results.cms, 'PHP', 'medium', 'header');
  }
}

/**
 * Analyze JavaScript globals for tech signatures
 */
function analyzeJSGlobals(globals, results) {
  // Analytics
  if (globals.ga || globals._gaq || globals.gtag) {
    addDetection(results.analytics, 'Google Analytics', 'high', 'js');
  }
  if (globals.dataLayer) {
    addDetection(results.tag_manager, 'Google Tag Manager', 'high', 'js');
  }
  if (globals.fbq || globals._fbq) {
    addDetection(results.marketing, 'Facebook Pixel', 'high', 'js');
  }
  if (globals.ttq) {
    addDetection(results.marketing, 'TikTok Pixel', 'high', 'js');
  }
  if (globals.pintrk) {
    addDetection(results.marketing, 'Pinterest Tag', 'high', 'js');
  }
  if (globals.lintrk) {
    addDetection(results.marketing, 'LinkedIn Insight', 'high', 'js');
  }
  if (globals.twq) {
    addDetection(results.marketing, 'Twitter Pixel', 'high', 'js');
  }

  // Chat
  if (globals.Intercom) {
    addDetection(results.chat, 'Intercom', 'high', 'js');
  }
  if (globals.Drift) {
    addDetection(results.chat, 'Drift', 'high', 'js');
  }

  // ESP
  if (globals.HubSpot) {
    addDetection(results.esp, 'HubSpot', 'high', 'js');
    addDetection(results.marketing, 'HubSpot', 'high', 'js');
  }
  if (globals.Klaviyo || globals._klOnsite) {
    addDetection(results.esp, 'Klaviyo', 'high', 'js');
  }

  // E-commerce
  if (globals.Shopify) {
    addDetection(results.ecommerce, 'Shopify', 'high', 'js');
  }

  // A/B Testing
  if (globals.Optimizely) {
    addDetection(results.ab_testing, 'Optimizely', 'high', 'js');
  }
  if (globals.VWO) {
    addDetection(results.ab_testing, 'VWO', 'high', 'js');
  }
  if (globals.ABTasty) {
    addDetection(results.ab_testing, 'AB Tasty', 'high', 'js');
  }

  // Tag Managers
  if (globals._satellite) {
    addDetection(results.tag_manager, 'Adobe Launch', 'high', 'js');
  }
  if (globals.Tealium) {
    addDetection(results.tag_manager, 'Tealium', 'high', 'js');
  }

  // Payment
  if (globals.Stripe) {
    addDetection(results.payment, 'Stripe', 'high', 'js');
  }

  // CMS/Framework
  if (globals.__NEXT_DATA__) {
    addDetection(results.cms, 'Next.js', 'high', 'js');
  }
  if (globals.__NUXT__) {
    addDetection(results.cms, 'Nuxt.js', 'high', 'js');
  }
  if (globals.wp) {
    addDetection(results.cms, 'WordPress', 'high', 'js');
  }
}

/**
 * Add detection if not already present
 */
function addDetection(array, name, confidence, source) {
  const existing = array.find(d => d.name === name);
  if (!existing) {
    array.push({ name, confidence, source });
  } else if (confidence === 'high' && existing.confidence !== 'high') {
    existing.confidence = 'high';
    existing.source = source;
  }
}

/**
 * Merge detection arrays, removing duplicates
 */
function mergeDetections(arr1, arr2) {
  const merged = [...arr1];
  for (const item of arr2) {
    if (!merged.find(m => m.name === item.name)) {
      merged.push(item);
    }
  }
  return merged;
}
