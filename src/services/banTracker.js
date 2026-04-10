/**
 * Ban tracker — tracks browser detection failures per domain
 * After 3 failures within 6 hours, auto-downgrades domain to fast + BuiltWith
 */

const failures = new Map();
const FAILURE_THRESHOLD = 3;
const WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours

const browserStats = {
  total_attempts: 0,
  failures: 0,
  last_failure: null
};

export function recordBrowserAttempt() {
  browserStats.total_attempts++;
}

export function recordBrowserFailure(domain, reason = 'unknown') {
  browserStats.failures++;
  browserStats.last_failure = new Date().toISOString();

  const now = Date.now();
  const entry = failures.get(domain) || { count: 0, lastFailure: null, reason: null, expires: null };

  // Reset count if previous failure was outside the window
  if (entry.lastFailure && (now - entry.lastFailure) > WINDOW_MS) {
    entry.count = 0;
  }

  entry.count++;
  entry.lastFailure = now;
  entry.reason = reason;
  entry.expires = now + WINDOW_MS;

  failures.set(domain, entry);
}

export function isDowngraded(domain) {
  const entry = failures.get(domain);
  if (!entry) return false;
  if (Date.now() > entry.expires) {
    failures.delete(domain);
    return false;
  }
  return entry.count >= FAILURE_THRESHOLD;
}

export function getBanStats() {
  const now = Date.now();
  const banned = [];

  for (const [domain, entry] of failures.entries()) {
    if (now > entry.expires) {
      failures.delete(domain);
      continue;
    }
    if (entry.count >= FAILURE_THRESHOLD) {
      banned.push({
        domain,
        failures: entry.count,
        last_failure: new Date(entry.lastFailure).toISOString(),
        reason: entry.reason,
        auto_downgraded: true,
        expires: new Date(entry.expires).toISOString()
      });
    }
  }

  return {
    banned_domains: banned.length,
    domains: banned
  };
}

export function getBrowserHealthStats() {
  const banStats = getBanStats();
  return {
    total_attempts: browserStats.total_attempts,
    failures: browserStats.failures,
    failure_rate: browserStats.total_attempts > 0
      ? Math.round((browserStats.failures / browserStats.total_attempts) * 100) / 100
      : 0,
    banned_domains: banStats.banned_domains,
    last_failure: browserStats.last_failure
  };
}
