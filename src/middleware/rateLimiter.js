/**
 * In-memory rate limiter per API key + endpoint type + mode
 */

const windows = new Map();
const WINDOW_MS = 60 * 1000; // 1 minute

// Limits per mode for single vs batch endpoints
const LIMITS = {
  single: { fast: 100, smart: 30, full: 10 },
  batch:  { fast: 20,  smart: 10, full: 5 }
};

let throttledCount = 0;

function resolveKey(req) {
  return req.headers['x-api-key'] || req.query.api_key || req.ip;
}

function resolveMode(req) {
  const mode = req.query.mode || (req.body && req.body.mode);
  if (mode === 'fast') return 'fast';
  if (mode === 'full') return 'full';
  return 'smart'; // default matches new API default
}

export function rateLimiter(type) {
  return (req, res, next) => {
    const key = resolveKey(req);
    const mode = resolveMode(req);
    const limit = LIMITS[type][mode];
    const now = Date.now();
    const id = `${key}:${type}:${mode}`;

    const timestamps = (windows.get(id) || []).filter(t => now - t < WINDOW_MS);

    if (timestamps.length >= limit) {
      throttledCount++;
      const retryAfter = Math.ceil((timestamps[0] + WINDOW_MS - now) / 1000);
      return res.status(429).json({
        error: 'rate_limit_exceeded',
        message: `Too many requests. Retry after ${retryAfter} seconds.`,
        retry_after: retryAfter
      });
    }

    timestamps.push(now);
    windows.set(id, timestamps);
    next();
  };
}

export function getRateLimiterStats() {
  const now = Date.now();
  let activeKeys = 0;

  for (const [id, timestamps] of windows.entries()) {
    const recent = timestamps.filter(t => now - t < WINDOW_MS);
    if (recent.length > 0) {
      activeKeys++;
      windows.set(id, recent);
    } else {
      windows.delete(id);
    }
  }

  return {
    active_keys: activeKeys,
    throttled_requests_last_hour: throttledCount
  };
}
