/**
 * BuiltWith API integration (v21)
 * https://api.builtwith.com/v21/api.json
 *
 * Provides additional technology detection as a fallback/enrichment layer.
 * Costs 1 API credit per domain lookup.
 */

const BUILTWITH_API_URL = 'https://api.builtwith.com/v21/api.json';
const BUILTWITH_TIMEOUT_MS = 30_000;
const RECENCY_DAYS = 180;

const TAG_TO_CATEGORY = {
  'analytics':  'analytics',
  'stats':      'analytics',
  'ads':        'marketing',
  'widgets':    'chat',
  'live-chat':  'chat',
  'payment':    'payment',
  'cdn':        'cdn',
  'hosting':    'hosting',
  'server':     'hosting',
  'cms':        'cms',
  'framework':  'cms',
  'ecommerce':  'ecommerce',
  'shop':       'ecommerce',
  'email':      'esp',
  'mx':         'esp',
  'marketing-automation': 'esp',
  'a-b-testing': 'ab_testing',
  'tag-managers': 'tag_manager',
};

const CRM_NAMES = new Set([
  'salesforce', 'hubspot', 'zoho', 'pipedrive', 'freshsales',
  'microsoft dynamics', 'dynamics 365', 'zendesk sell', 'copper',
  'insightly', 'nimble', 'close', 'monday', 'keap', 'infusionsoft',
  'activecampaign', 'nutshell', 'capsule', 'streak', 'agile crm',
  'sugarcrm', 'vtiger', 'bitrix24', 'pardot', 'marketo',
]);

/**
 * Query BuiltWith API and return detections in the same shape
 * used by the rest of the detector pipeline.
 */
export async function detectFromBuiltWith(domain) {
  const apiKey = process.env.BUILTWITH_API_KEY;
  if (!apiKey) {
    throw new Error('BUILTWITH_API_KEY environment variable not set');
  }

  const url = `${BUILTWITH_API_URL}?KEY=${encodeURIComponent(apiKey)}&LOOKUP=${encodeURIComponent(domain)}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BUILTWITH_TIMEOUT_MS);

  let json;
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`BuiltWith API HTTP ${response.status}: ${response.statusText}`);
    }
    json = await response.json();
  } finally {
    clearTimeout(timer);
  }

  return parseBuiltWithResponse(json);
}

/**
 * Parse the v21 response into our internal detection format.
 */
function parseBuiltWithResponse(json) {
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
    hosting: [],
  };

  const paths = json?.Results?.[0]?.Result?.Paths;
  if (!Array.isArray(paths)) return results;

  const cutoff = Date.now() - RECENCY_DAYS * 24 * 60 * 60 * 1000;

  for (const path of paths) {
    const techs = path.Technologies;
    if (!Array.isArray(techs)) continue;

    for (const tech of techs) {
      if (isStale(tech, cutoff)) continue;

      const name = tech.Name;
      if (!name) continue;

      const categories = resolveCategories(tech);

      for (const cat of categories) {
        addIfMissing(results[cat], name);
      }

      if (isCrm(name)) {
        addIfMissing(results.crm, name);
      }
    }
  }

  return results;
}

function isStale(tech, cutoff) {
  const ld = tech.LastDetected;
  if (!ld) return false;
  try {
    const ts = typeof ld === 'number' ? ld : parseInt(ld, 10);
    return ts < cutoff;
  } catch {
    return false;
  }
}

/**
 * Map BuiltWith tag/categories to our internal category keys.
 */
function resolveCategories(tech) {
  const mapped = new Set();

  const tag = (tech.Tag || '').toLowerCase();
  if (TAG_TO_CATEGORY[tag]) {
    mapped.add(TAG_TO_CATEGORY[tag]);
  }

  const cats = tech.Categories;
  if (Array.isArray(cats)) {
    for (const c of cats) {
      const key = c.toLowerCase().replace(/\s+/g, '-');
      if (TAG_TO_CATEGORY[key]) {
        mapped.add(TAG_TO_CATEGORY[key]);
      }
    }
  }

  if (mapped.size === 0) {
    const lowerTag = tag;
    for (const [pattern, cat] of Object.entries(TAG_TO_CATEGORY)) {
      if (lowerTag.includes(pattern)) {
        mapped.add(cat);
        break;
      }
    }
  }

  return mapped;
}

function isCrm(name) {
  const lower = name.toLowerCase();
  return [...CRM_NAMES].some(crm => lower.includes(crm));
}

function addIfMissing(arr, name) {
  if (!arr.find(d => d.name === name)) {
    arr.push({ name, confidence: 'high', source: 'builtwith' });
  }
}
