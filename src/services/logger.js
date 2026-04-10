/**
 * Structured logger for API traceability.
 * Every log line is a JSON object for easy parsing in Render logs / log aggregators.
 */

let requestCounter = 0;

export function nextRequestId() {
  requestCounter++;
  return `req_${Date.now()}_${requestCounter}`;
}

function formatLog(level, event, data) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...data,
  };
  return JSON.stringify(entry);
}

export const log = {
  info(event, data = {}) {
    console.log(formatLog('INFO', event, data));
  },
  warn(event, data = {}) {
    console.warn(formatLog('WARN', event, data));
  },
  error(event, data = {}) {
    console.error(formatLog('ERROR', event, data));
  },
};
