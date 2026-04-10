/**
 * Tech Stack Detection API
 * Multi-method website technology detection
 */

import express from 'express';
import { detectTechStack, closeBrowser } from './services/detector.js';
import { getCache, setCache, getCacheStats, clearCache } from './services/cache.js';
import { flattenForClay } from './services/flatten.js';
import { requireApiKey } from './middleware/auth.js';
import { rateLimiter, getRateLimiterStats } from './middleware/rateLimiter.js';
import { log, nextRequestId } from './services/logger.js';
import { getBanStats, getBrowserHealthStats, isDowngraded } from './services/banTracker.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

function normalizeDomain(domain) {
  return domain
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/$/, '');
}

/**
 * GET /api/techstack
 * Detect tech stack for a domain
 * Default mode: smart (DNS first, browser only if score >= 15)
 */
app.get('/api/techstack', requireApiKey, rateLimiter('single'), async (req, res) => {
  const reqId = nextRequestId();
  const startTime = Date.now();
  const { domain, refresh, mode, format, builtwith } = req.query;
  const forceRefresh = refresh === 'true';
  const fastMode = mode === 'fast';
  const fullMode = mode === 'full';
  const smartMode = !fastMode && !fullMode; // default to smart when mode is omitted
  const useBuiltWith = builtwith === 'true';

  log.info('request_received', {
    reqId,
    endpoint: 'GET /api/techstack',
    ip: req.ip,
    params: { domain, mode: mode || 'smart', format, refresh, builtwith }
  });

  if (!domain) {
    log.warn('validation_error', { reqId, error: 'missing_param', duration_ms: Date.now() - startTime });
    return res.status(400).json({
      error: 'missing_param',
      message: 'domain parameter required'
    });
  }

  const normalizedDomain = normalizeDomain(domain);

  // Check cache first (unless refresh=true)
  if (!forceRefresh) {
    const cached = getCache(normalizedDomain);
    if (cached) {
      log.info('cache_hit', { reqId, domain: normalizedDomain, cache_age_hours: cached.cache_age_hours, duration_ms: Date.now() - startTime });
      const response = { domain: normalizedDomain, ...cached };
      if (format === 'clay' || format === 'flat') {
        return res.json(flattenForClay(response));
      }
      return res.json(response);
    }
  }

  try {
    log.info('detection_started', { reqId, domain: normalizedDomain, mode: mode || 'smart', builtwith: useBuiltWith });
    const result = await detectTechStack(normalizedDomain, { fastMode, smartMode, useBuiltWith });
    const duration = Date.now() - startTime;

    const espCount = result.esp?.length || 0;
    const totalDetections = ['esp', 'crm', 'cms', 'ecommerce', 'analytics', 'marketing', 'chat', 'ab_testing', 'tag_manager', 'payment', 'cdn', 'hosting']
      .reduce((sum, cat) => sum + (result[cat]?.length || 0), 0);

    log.info('detection_complete', {
      reqId,
      domain: normalizedDomain,
      duration_ms: duration,
      tech_score: result.tech_score,
      primary: result.tech_stack_primary,
      esp_count: espCount,
      total_detections: totalDetections,
      methods: result.detection_methods,
      partial: result.partial || false
    });

    const response = {
      domain: normalizedDomain,
      duration_ms: duration,
      cached: false,
      ...result
    };

    setCache(normalizedDomain, { duration_ms: duration, ...result });

    if (format === 'clay' || format === 'flat') {
      return res.json(flattenForClay(response));
    }

    return res.json(response);
  } catch (err) {
    const duration = Date.now() - startTime;
    log.error('detection_failed', { reqId, domain: normalizedDomain, error: err.message, duration_ms: duration });
    return res.status(500).json({
      error: 'detection_failed',
      message: err.message,
      domain: normalizedDomain
    });
  }
});

/**
 * POST /api/techstack/batch
 * Detect tech stack for multiple domains
 * Default mode: smart
 * Supports per-domain mode override: { domain: "x.com", mode: "fast", builtwith: true }
 */
app.post('/api/techstack/batch', requireApiKey, rateLimiter('batch'), async (req, res) => {
  const reqId = nextRequestId();
  const startTime = Date.now();
  const { domains, mode, concurrency = 10, builtwith = false, format } = req.body;
  const fastMode = mode === 'fast';
  const fullMode = mode === 'full';
  const smartMode = !fastMode && !fullMode; // default to smart
  const useBuiltWith = builtwith === true || builtwith === 'true';
  const maxConcurrency = Math.min(fastMode ? 50 : (smartMode ? 20 : 5), concurrency);

  log.info('request_received', {
    reqId,
    endpoint: 'POST /api/techstack/batch',
    ip: req.ip,
    params: { domain_count: domains?.length, mode: mode || 'smart', concurrency, builtwith: useBuiltWith, format }
  });

  if (!domains || !Array.isArray(domains)) {
    log.warn('validation_error', { reqId, error: 'invalid_param', duration_ms: Date.now() - startTime });
    return res.status(400).json({
      error: 'invalid_param',
      message: 'domains array required in request body'
    });
  }

  // Fast: 500, smart: 200, full: 20
  const maxDomains = fastMode ? 500 : (smartMode ? 200 : 20);
  if (domains.length > maxDomains) {
    log.warn('validation_error', { reqId, error: 'too_many_domains', count: domains.length, max: maxDomains, duration_ms: Date.now() - startTime });
    return res.status(400).json({
      error: 'too_many_domains',
      message: `Maximum ${maxDomains} domains per batch (mode=${mode || 'smart'})`
    });
  }

  // Normalize — supports strings or { domain, mode, builtwith } objects
  const domainEntries = domains.map(d => {
    if (typeof d === 'string') {
      return { domain: normalizeDomain(d), mode, builtwith: useBuiltWith };
    }
    if (!d || !d.domain) return null;
    return {
      domain: normalizeDomain(d.domain),
      mode: d.mode || mode,
      builtwith: d.builtwith !== undefined ? (d.builtwith === true || d.builtwith === 'true') : useBuiltWith
    };
  }).filter(Boolean);

  log.info('batch_started', { reqId, total: domainEntries.length, mode: mode || 'smart', concurrency: maxConcurrency });

  const results = [];
  const chunks = [];
  for (let i = 0; i < domainEntries.length; i += maxConcurrency) {
    chunks.push(domainEntries.slice(i, i + maxConcurrency));
  }

  let chunkIndex = 0;
  for (const chunk of chunks) {
    chunkIndex++;
    log.info('batch_chunk_started', { reqId, chunk: chunkIndex, chunk_size: chunk.length, total_chunks: chunks.length });

    const chunkResults = await Promise.all(
      chunk.map(async (entry) => {
        const { domain: normalizedDomain, mode: domainMode, builtwith: domainBuiltWith } = entry;

        const cached = getCache(normalizedDomain);
        if (cached) {
          log.info('batch_domain_cache_hit', { reqId, domain: normalizedDomain });
          const result = { domain: normalizedDomain, success: true, ...cached };
          if (format === 'clay' || format === 'flat') return flattenForClay(result);
          return result;
        }

        const domainFastMode = domainMode === 'fast';
        const domainFullMode = domainMode === 'full';
        const domainSmartMode = !domainFastMode && !domainFullMode;
        const domainStart = Date.now();

        try {
          const result = await detectTechStack(normalizedDomain, {
            fastMode: domainFastMode,
            smartMode: domainSmartMode,
            useBuiltWith: domainBuiltWith
          });
          setCache(normalizedDomain, result);
          log.info('batch_domain_complete', { reqId, domain: normalizedDomain, duration_ms: Date.now() - domainStart, tech_score: result.tech_score });
          const fullResult = { domain: normalizedDomain, success: true, cached: false, ...result };
          if (format === 'clay' || format === 'flat') return flattenForClay(fullResult);
          return fullResult;
        } catch (err) {
          log.error('batch_domain_failed', { reqId, domain: normalizedDomain, error: err.message, duration_ms: Date.now() - domainStart });
          return { domain: normalizedDomain, success: false, error: err.message };
        }
      })
    );
    results.push(...chunkResults);
  }

  const successful = results.filter(r => r.success !== false).length;
  log.info('batch_complete', { reqId, total: results.length, successful, failed: results.length - successful, duration_ms: Date.now() - startTime });

  return res.json({
    mode: fastMode ? 'fast' : (smartMode ? 'smart' : 'full'),
    total: results.length,
    successful,
    results
  });
});

/**
 * GET /api/techstack/recommend
 * Recommend detection mode for a single domain based on ban history
 */
app.get('/api/techstack/recommend', requireApiKey, (req, res) => {
  const { domain } = req.query;
  if (!domain) {
    return res.status(400).json({ error: 'missing_param', message: 'domain parameter required' });
  }
  const normalizedDomain = normalizeDomain(domain);
  const banned = isDowngraded(normalizedDomain);
  const banEntry = getBanStats().domains.find(d => d.domain === normalizedDomain) || null;

  return res.json({
    domain: normalizedDomain,
    recommended_mode: banned ? 'fast' : 'smart',
    reason: banned
      ? 'Domain has recent browser detection failures; auto-downgraded to fast mode'
      : 'No known issues; smart mode provides the best balance of accuracy and safety',
    builtwith_recommended: banned,
    ban_history: banEntry
  });
});

/**
 * POST /api/techstack/recommend
 * Recommend detection mode for multiple domains
 */
app.post('/api/techstack/recommend', requireApiKey, (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains)) {
    return res.status(400).json({ error: 'invalid_param', message: 'domains array required' });
  }
  const recommendations = domains.map(d => {
    const raw = typeof d === 'string' ? d : d.domain;
    if (!raw) return null;
    const normalizedDomain = normalizeDomain(raw);
    const banned = isDowngraded(normalizedDomain);
    return {
      domain: normalizedDomain,
      recommended_mode: banned ? 'fast' : 'smart',
      builtwith_recommended: banned,
      reason: banned
        ? 'Domain has recent browser detection failures; auto-downgraded to fast mode'
        : 'No known issues; smart mode provides the best balance of accuracy and safety'
    };
  }).filter(Boolean);

  return res.json({ recommendations });
});

/**
 * GET /api/bans
 * View auto-downgraded domains tracked by the ban tracker
 */
app.get('/api/bans', requireApiKey, (req, res) => {
  res.json(getBanStats());
});

/**
 * POST /api/cache/clear
 * Clear all cached data
 */
app.post('/api/cache/clear', requireApiKey, (req, res) => {
  const reqId = nextRequestId();
  const count = clearCache();
  log.info('cache_cleared', { reqId, endpoint: 'POST /api/cache/clear', ip: req.ip, entries_cleared: count });
  res.json({
    success: true,
    message: `Cleared ${count} cached entries`
  });
});

/**
 * GET /health
 * Health check with cache, browser health, and rate limiter stats (no auth required)
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    cache: getCacheStats(),
    browser_health: getBrowserHealthStats(),
    rate_limiter: getRateLimiterStats()
  });
});

const server = app.listen(PORT, () => {
  console.log(`Tech Stack Detection API running on port ${PORT}`);
  console.log('Default mode: smart (DNS first, browser only when score >= 15)');
  if (process.env.API_KEY) {
    console.log('API key authentication enabled');
  } else {
    console.log('WARNING: No API_KEY set - authentication disabled');
  }
  if (process.env.BUILTWITH_API_KEY) {
    console.log('BuiltWith API integration available (builtwith=true or auto-fallback on browser failure)');
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down...');
  await closeBrowser();
  server.close(() => process.exit(0));
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down...');
  await closeBrowser();
  server.close(() => process.exit(0));
});
