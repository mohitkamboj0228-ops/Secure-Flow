const { Pool } = require('pg');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

let pgPool = null;
let sqliteDb = null;
let isPostgres = false;

// Initialize Database connection
async function initDb() {
  const pgHost = process.env.DB_HOST;
  const pgUser = process.env.DB_USER || 'postgres';
  const pgPassword = process.env.DB_PASSWORD || 'postgres';
  const pgDatabase = process.env.DB_NAME || 'secureflow';
  const pgPort = process.env.DB_PORT || 5432;

  if (pgHost) {
    console.log(`[DB] Attempting PostgreSQL connection to ${pgHost}:${pgPort}...`);
    try {
      pgPool = new Pool({
        host: pgHost,
        user: pgUser,
        password: pgPassword,
        database: pgDatabase,
        port: pgPort,
        connectionTimeoutMillis: 5000
      });
      // Test the connection
      await pgPool.query('SELECT NOW()');
      isPostgres = true;
      console.log('[DB] Connected to PostgreSQL successfully.');
      await setupPgTables();
      return;
    } catch (err) {
      console.error(`[DB] PostgreSQL connection failed: ${err.message}. Falling back to SQLite...`);
    }
  }

  // SQLite fallback
  console.log('[DB] Initializing SQLite local database...');
  const dbPath = path.join(__dirname, 'secureflow.db');
  sqliteDb = new sqlite3.Database(dbPath);
  isPostgres = false;
  await setupSqliteTables();
}

// PostgreSQL table creation
async function setupPgTables() {
  const client = await pgPool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS incidents (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        severity VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        component VARCHAR(100) NOT NULL,
        description TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolution TEXT
      );
      CREATE TABLE IF NOT EXISTS deployments (
        id SERIAL PRIMARY KEY,
        version VARCHAR(50) NOT NULL,
        status VARCHAR(50) NOT NULL,
        duration_seconds INT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        actor VARCHAR(100) NOT NULL,
        action VARCHAR(255) NOT NULL,
        resource VARCHAR(255) NOT NULL,
        result VARCHAR(50) NOT NULL,
        severity VARCHAR(50) NOT NULL
      );
    `);
    
    // Check if we need to seed initial data
    const res = await client.query('SELECT COUNT(*) FROM incidents');
    if (parseInt(res.rows[0].count) === 0) {
      await seedInitialDataPg(client);
    }
  } finally {
    client.release();
  }
}

// SQLite table creation
function setupSqliteTables() {
  return new Promise((resolve, reject) => {
    sqliteDb.serialize(() => {
      sqliteDb.run(`
        CREATE TABLE IF NOT EXISTS incidents (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          severity TEXT NOT NULL,
          status TEXT NOT NULL,
          component TEXT NOT NULL,
          description TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          resolution TEXT
        )
      `);

      sqliteDb.run(`
        CREATE TABLE IF NOT EXISTS deployments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT NOT NULL,
          status TEXT NOT NULL,
          duration_seconds INTEGER NOT NULL,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      sqliteDb.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          resource TEXT NOT NULL,
          result TEXT NOT NULL,
          severity TEXT NOT NULL
        )
      `);

      // Seed initial data if empty
      sqliteDb.get("SELECT COUNT(*) as count FROM incidents", (err, row) => {
        if (err) return reject(err);
        if (row.count === 0) {
          seedInitialDataSqlite()
            .then(resolve)
            .catch(reject);
        } else {
          resolve();
        }
      });
    });
  });
}

async function seedInitialDataPg(client) {
  console.log('[DB] Seeding default PostgreSQL data...');
  // Seed incidents
  await client.query(`
    INSERT INTO incidents (title, severity, status, component, description, timestamp, resolution) VALUES
    ('Database connection pool warnings', 'WARNING', 'RESOLVED', 'database', 'Backend service reported connection timeouts on database pool.', NOW() - INTERVAL '1 hour', 'Increased pool connections limit from 10 to 50.'),
    ('High API Latency on /api/deployments', 'INFO', 'RESOLVED', 'api-gateway', 'Response latencies exceeded 500ms on deployments dashboard requests.', NOW() - INTERVAL '30 minutes', 'Implemented memory caching layer for K8s API responses.')
  `);
  // Seed deployments
  await client.query(`
    INSERT INTO deployments (version, status, duration_seconds) VALUES
    ('v1.0.0', 'SUCCESS', 45),
    ('v1.0.1', 'SUCCESS', 42),
    ('v1.1.0-RC1', 'FAILED', 15)
  `);
  // Seed audits
  await client.query(`
    INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES
    ('CI/CD Runner', 'Pipeline Started', 'secureflow-api', 'SUCCESS', 'INFO'),
    ('Semgrep Scanner', 'SAST Analysis', 'backend/index.js', 'SUCCESS', 'INFO'),
    ('Kyverno Controller', 'Policy Validation', 'deployment-frontend', 'SUCCESS', 'INFO')
  `);
}

function seedInitialDataSqlite() {
  return new Promise((resolve, reject) => {
    sqliteDb.serialize(() => {
      const stmt1 = sqliteDb.prepare(`
        INSERT INTO incidents (title, severity, status, component, description, timestamp, resolution) VALUES (?, ?, ?, ?, ?, datetime('now', ?), ?)
      `);
      stmt1.run('Database connection pool warnings', 'WARNING', 'RESOLVED', 'database', 'Backend service reported connection timeouts on database pool.', '-1 hour', 'Increased pool connections limit from 10 to 50.');
      stmt1.run('High API Latency on /api/deployments', 'INFO', 'RESOLVED', 'api-gateway', 'Response latencies exceeded 500ms on deployments dashboard requests.', '-30 minutes', 'Implemented memory caching layer for K8s API responses.');
      stmt1.finalize();

      const stmt2 = sqliteDb.prepare(`
        INSERT INTO deployments (version, status, duration_seconds) VALUES (?, ?, ?)
      `);
      stmt2.run('v1.0.0', 'SUCCESS', 45);
      stmt2.run('v1.0.1', 'SUCCESS', 42);
      stmt2.run('v1.1.0-RC1', 'FAILED', 15);
      stmt2.finalize();

      const stmt3 = sqliteDb.prepare(`
        INSERT INTO audit_logs (actor, action, resource, result, severity) VALUES (?, ?, ?, ?, ?)
      `);
      stmt3.run('CI/CD Runner', 'Pipeline Started', 'secureflow-api', 'SUCCESS', 'INFO');
      stmt3.run('Semgrep Scanner', 'SAST Analysis', 'backend/index.js', 'SUCCESS', 'INFO');
      stmt3.run('Kyverno Controller', 'Policy Validation', 'deployment-frontend', 'SUCCESS', 'INFO');
      stmt3.finalize(err => {
        if (err) reject(err);
        else resolve();
      });
    });
  });
}

// Database query interfaces
function query(sql, params = []) {
  if (isPostgres) {
    return pgPool.query(sql, params).then(res => res.rows);
  } else {
    return new Promise((resolve, reject) => {
      sqliteDb.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }
}

function run(sql, params = []) {
  if (isPostgres) {
    return pgPool.query(sql, params);
  } else {
    return new Promise((resolve, reject) => {
      sqliteDb.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ lastID: this.lastID, changes: this.changes });
      });
    });
  }
}

module.exports = {
  initDb,
  query,
  run,
  isPostgres: () => isPostgres
};
