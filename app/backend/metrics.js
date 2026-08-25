const client = require('prom-client');

// Enable collection of default metrics (CPU, Memory, GC, etc.)
client.collectDefaultMetrics({ prefix: 'secureflow_' });

// Custom metrics
const httpRequestCounter = new client.Counter({
  name: 'secureflow_http_requests_total',
  help: 'Total number of HTTP requests processed',
  labelNames: ['method', 'route', 'status']
});

const httpRequestDuration = new client.Histogram({
  name: 'secureflow_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5]
});

const activeIncidentsGauge = new client.Gauge({
  name: 'secureflow_active_incidents',
  help: 'Number of active incidents in the platform',
  labelNames: ['severity']
});

const securityScoreGauge = new client.Gauge({
  name: 'secureflow_security_score',
  help: 'Calculated platform security score (out of 100)'
});

// Telemetry history buffer
const telemetryHistory = [];
const HISTORY_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

function getTelemetrySummary() {
  const now = Date.now();
  // Clean expired
  while (telemetryHistory.length > 0 && telemetryHistory[0].timestamp < now - HISTORY_WINDOW_MS) {
    telemetryHistory.shift();
  }

  // Create 10 buckets of 10 seconds for the last 100 seconds
  const bucketSize = 10 * 1000;
  const buckets = [];
  
  for (let i = 9; i >= 0; i--) {
    const bucketStart = now - (i + 1) * bucketSize;
    const bucketEnd = now - i * bucketSize;
    
    const events = telemetryHistory.filter(e => e.timestamp >= bucketStart && e.timestamp < bucketEnd);
    const requests = events.length;
    const avgLatency = requests > 0 
      ? Math.round(events.reduce((acc, e) => acc + e.latencyMs, 0) / requests)
      : 0;
    
    const timeStr = new Date(bucketStart).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    buckets.push({ time: timeStr, requests, latency: avgLatency });
  }
  
  return buckets;
}

// Middleware to track metrics
function metricsMiddleware(req, res, next) {
  const start = process.hrtime();
  
  res.on('finish', () => {
    const duration = process.hrtime(start);
    const durationInSeconds = duration[0] + duration[1] / 1e9;
    const latencyMs = Math.round(durationInSeconds * 1000);
    
    // Clean routes to prevent label card cardinality explosion
    let route = req.baseUrl + req.path;
    if (req.route && req.route.path) {
      route = req.baseUrl + req.route.path;
    }
    
    const labels = {
      method: req.method,
      route: route || req.path,
      status: res.statusCode
    };
    
    httpRequestCounter.inc(labels);
    httpRequestDuration.observe(labels, durationInSeconds);

    // Push to rolling telemetry history (except /metrics and /api/telemetry itself to prevent noise)
    if (req.path !== '/metrics' && req.path !== '/api/telemetry') {
      telemetryHistory.push({
        timestamp: Date.now(),
        latencyMs,
        route: route || req.path,
        status: res.statusCode
      });
    }
  });
  
  next();
}

module.exports = {
  client,
  metricsMiddleware,
  activeIncidentsGauge,
  securityScoreGauge,
  getTelemetrySummary
};
