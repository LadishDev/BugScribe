const { Client } = require('pg');
const EventEmitter = require('events');

let client;
const events = new EventEmitter();
let connected = false;
let reconnecting = false;

function isConnected() { return !!connected; }

function setConnected(val) {
  connected = !!val;
  try {
    if (connected) events.emit('connected'); else events.emit('disconnected');
  } catch (e) { /* ignore */ }
}

async function init(options = {}) {
  // Prefer a full DATABASE_URL if provided (e.g. for managed services).
  // Otherwise construct from DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE
  const connectionString = process.env.DATABASE_URL;
  let clientConfig;
  if (connectionString) {
    clientConfig = { connectionString };
  } else {
    const host = process.env.DB_HOST || process.env.DB_HOSTNAME || '127.0.0.1';
    const port = process.env.DB_PORT || 5432;
    const user = process.env.DB_USER || process.env.DB_USERNAME || 'postgres';
    const password = process.env.DB_PASSWORD || '';
    // Default database name to 'BugScribe' if not provided
    const database = process.env.DB_DATABASE || process.env.PGDATABASE || 'BugScribe';
    clientConfig = { host, port, user, password, database };
  }
  client = new Client(clientConfig);
  // Try to connect to the target database. If it doesn't exist and the config was
  // provided via individual DB_* env vars (not a single DATABASE_URL), attempt
  // to connect to an admin DB (default 'postgres' or DB_ADMIN_DATABASE) and create
  // the requested database, then reconnect. If initial connect fails and DB_STRICT
  // isn't set, a background reconnect loop with exponential backoff will start.

  async function attachClientListeners(c) {
    if (!c) return;
    c.on('error', err => {
      console.error('Postgres client error:', err.message || err);
      setConnected(false);
      // start reconnect in background
      startReconnectLoop(clientConfig).catch(() => {});
    });
    c.on('end', () => {
      console.warn('Postgres client ended connection');
      setConnected(false);
      startReconnectLoop(clientConfig).catch(() => {});
    });
  }

  async function tryConnectOnce(cfg) {
    const c = new Client(cfg);
    await c.connect();
    return c;
  }

  async function startReconnectLoop(cfg) {
    if (reconnecting) return;
    reconnecting = true;
    let attempt = 0;
    while (!connected) {
      try {
        attempt++;
        console.log(`Attempting Postgres reconnect (attempt ${attempt})...`);
        const c = await tryConnectOnce(cfg);
        client = c;
        setConnected(true);
        await attachClientListeners(client);
        console.log('Postgres reconnected');
        break;
      } catch (e) {
        const backoff = Math.min(30000, Math.pow(2, Math.min(attempt, 6)) * 1000);
        console.warn(`Postgres reconnect failed: ${e.message || e}. Retrying in ${backoff}ms`);
        await new Promise(r => setTimeout(r, backoff));
      }
    }
    reconnecting = false;
  }

  try {
    // First attempt to connect synchronously
    client = await tryConnectOnce(clientConfig);
    setConnected(true);
    await attachClientListeners(client);
  } catch (err) {
    const targetDb = clientConfig && clientConfig.database ? clientConfig.database : '(unknown)';
    const connectionString = process.env.DATABASE_URL;

    // If a connection string was used, we won't attempt to auto-create the DB
    // because modifying/parsing arbitrary URLs is error-prone. In that case return
    // the original error (or start reconnect loop if not strict).
    if (connectionString) {
      if (process.env.DB_STRICT === 'true') {
        throw new Error(`Error accessing database '${targetDb}': ${err.message}`);
      }
      console.warn(`Initial Postgres connect failed: ${err.message}. Starting background reconnect attempts.`);
      startReconnectLoop(clientConfig).catch(() => {});
      return;
    }

    // Detect common error codes/messages indicating the database does not exist.
    const msg = (err && err.message) ? err.message : '';
    const looksLikeMissingDb = err && (err.code === '3D000' || /does not exist/i.test(msg) || /database .* does not exist/i.test(msg));

    if (!looksLikeMissingDb) {
      // Not a missing-database error; surface original message or start reconnects
      if (process.env.DB_STRICT === 'true') {
        throw new Error(`Error accessing database '${targetDb}': ${err.message}`);
      }
      console.warn(`Initial Postgres connect failed: ${err.message}. Starting background reconnect attempts.`);
      startReconnectLoop(clientConfig).catch(() => {});
      return;
    }

    // Attempt to connect to admin DB to create the target DB
    const host = process.env.DB_HOST || process.env.DB_HOSTNAME || '127.0.0.1';
    const port = process.env.DB_PORT || 5432;
    const user = process.env.DB_USER || process.env.DB_USERNAME || 'postgres';
    const password = process.env.DB_PASSWORD || '';
    const adminDb = process.env.DB_ADMIN_DATABASE || 'postgres';

    const adminClient = new Client({ host, port, user, password, database: adminDb });
    try {
      await adminClient.connect();
      // Try to create the database. This requires the connecting user have CREATE DATABASE privilege.
      await adminClient.query(`CREATE DATABASE "${targetDb}"`);
      await adminClient.end();

      // Now try to connect to the newly created target DB
      client = await tryConnectOnce(clientConfig);
      setConnected(true);
      await attachClientListeners(client);
    } catch (createErr) {
      // If creation fails, provide a helpful error message including the DB name
      const createMsg = (createErr && createErr.message) ? createErr.message : String(createErr);
      const message = `Error creating or accessing database '${targetDb}': ${createMsg}. Ensure the DB user has permission to create databases or create the '${targetDb}' database manually.`;
      if (process.env.DB_STRICT === 'true') {
        throw new Error(message);
      }
      console.warn(message + ' Starting background reconnect attempts.');
      startReconnectLoop(clientConfig).catch(() => {});
      return;
    }
  }

  // We'll perform a schema compatibility check before (re)creating tables.

  // Full expected schema definitions (column names in lowercase)
  const expectedCols = {
    bug_reports: [
      'id','name','email','description','stepstoreproduce','browserinfo','timestamp','screenshot','status','createdat','updatedat','submitterip','country','cfray','spam_confidence','spam_issues','spam_is_reviewed'
    ],
    suggestions: [
      'id','name','email','description','stepstoreproduce','browserinfo','timestamp','screenshot','status','createdat','updatedat','submitterip','country','cfray','spam_confidence','spam_issues','spam_is_reviewed'
    ],
    ip_history: [
      'ip','submissions','firstseen','lastseen','cloudflarecountry','useragent'
    ],
    spam_log: [
      'id','data','createdat'
    ],
    bot_attempts: [
      'id','data','createdat'
    ]
  };

  // Check existing tables and columns
  async function getExistingTables() {
    const res = await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'");
    return res.rows.map(r => r.table_name.toLowerCase());
  }

  async function getColumns(table) {
    const res = await client.query(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1`, [table]);
    return res.rows.map(r => r.column_name.toLowerCase());
  }

  async function getRowCount(table) {
    try {
      const res = await client.query(`SELECT COUNT(*)::bigint AS cnt FROM "${table}"`);
      return parseInt(res.rows[0].cnt || 0, 10);
    } catch (e) {
      return 0; // table might not exist
    }
  }

  const existingTables = await getExistingTables();

  // Find tables that exist but have mismatched columns
  const mismatched = [];
  for (const tbl of Object.keys(expectedCols)) {
    if (existingTables.includes(tbl)) {
      const cols = await getColumns(tbl);
      // Normalize column names (lowercase) and compare sets
      const expectedSet = new Set(expectedCols[tbl].map(c => c.toLowerCase()));
      const actualSet = new Set(cols.map(c => c.toLowerCase()));
      let equal = expectedSet.size === actualSet.size && [...expectedSet].every(c => actualSet.has(c));
      if (!equal) mismatched.push(tbl);
    }
  }

  if (mismatched.length > 0) {
    // If any mismatched table contains data, abort with a clear terminal message
    const tablesWithData = [];
    for (const t of mismatched) {
      const cnt = await getRowCount(t);
      if (cnt > 0) tablesWithData.push({ table: t, count: cnt });
    }
    if (tablesWithData.length > 0) {
      console.error('❌ Database schema mismatch detected for existing tables with data:');
      for (const t of tablesWithData) {
        console.error(`  - Table '${t.table}' has ${t.count} rows but schema does not match expected structure.`);
      }
      console.error(`Please inspect your database '${clientConfig && clientConfig.database ? clientConfig.database : '(unknown)'}'. To recover, either remove or rename the database and allow the server to create a fresh one, or migrate/transform your data to match expected schema.`);
      // Exit program as requested
      process.exit(1);
    }
    // If mismatched but empty, drop and recreate the structure
    for (const t of mismatched) {
      try { await client.query(`DROP TABLE IF EXISTS "${t}" CASCADE`); } catch (e) { /* ignore */ }
    }
  }

  // Now create tables if they don't exist
  await client.query(`
    CREATE TABLE IF NOT EXISTS bug_reports (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT,
      description TEXT,
      stepsToReproduce TEXT,
      browserInfo TEXT,
      timestamp TEXT,
      screenshot TEXT,
      status TEXT,
      createdAt TEXT,
      updatedAt TEXT,
      submitterIP TEXT,
      country TEXT,
      cfRay TEXT,
      spam_confidence INTEGER,
      spam_issues TEXT,
      spam_is_reviewed BOOLEAN
    );

    CREATE TABLE IF NOT EXISTS suggestions (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT,
      description TEXT,
      stepsToReproduce TEXT,
      browserInfo TEXT,
      timestamp TEXT,
      screenshot TEXT,
      status TEXT,
      createdAt TEXT,
      updatedAt TEXT,
      submitterIP TEXT,
      country TEXT,
      cfRay TEXT,
      spam_confidence INTEGER,
      spam_issues TEXT,
      spam_is_reviewed BOOLEAN
    );

    CREATE TABLE IF NOT EXISTS ip_history (
      ip TEXT PRIMARY KEY,
      submissions TEXT,
      firstSeen BIGINT,
      lastSeen BIGINT,
      cloudflareCountry TEXT,
      userAgent TEXT
    );

    CREATE TABLE IF NOT EXISTS spam_log (
      id TEXT PRIMARY KEY,
      data TEXT,
      createdAt TEXT
    );

    CREATE TABLE IF NOT EXISTS bot_attempts (
      id TEXT PRIMARY KEY,
      data TEXT,
      createdAt TEXT
    );
  `);
}

async function readIPHistory() {
  const res = await client.query('SELECT * FROM ip_history');
  const out = {};
  for (const r of res.rows) {
    out[r.ip] = {
      submissions: r.submissions ? JSON.parse(r.submissions) : [],
      firstSeen: r.firstseen || null,
      lastSeen: r.lastseen || null,
      cloudflareCountry: r.cloudflarecountry || 'unknown',
      userAgent: r.useragent || 'unknown'
    };
  }
  return out;
}

async function appendIPHistory(ip, entry) {
  const now = Date.now();
  const res = await client.query('SELECT * FROM ip_history WHERE ip = $1', [ip]);
  if (res.rowCount === 0) {
    const submissions = [entry.timestamp || now];
    await client.query('INSERT INTO ip_history (ip, submissions, firstSeen, lastSeen, cloudflareCountry, userAgent) VALUES ($1,$2,$3,$4,$5,$6)', [
      ip, JSON.stringify(submissions), entry.firstSeen || now, entry.lastSeen || now, entry.cloudflareCountry || 'unknown', entry.userAgent || 'unknown'
    ]);
    return;
  }
  const row = res.rows[0];
  const submissions = row.submissions ? JSON.parse(row.submissions) : [];
  submissions.push(entry.timestamp || now);
  await client.query('UPDATE ip_history SET submissions = $1, lastSeen = $2 WHERE ip = $3', [JSON.stringify(submissions), now, ip]);
}

async function readSpamLog() {
  const res = await client.query('SELECT * FROM spam_log ORDER BY createdAt DESC');
  return res.rows.map(r => ({ id: r.id, ...(r.data ? JSON.parse(r.data) : {}), createdAt: r.createdat }));
}

async function appendSpamLog(entry) {
  const id = entry.id || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
  const createdAt = entry.createdAt || new Date().toISOString();
  await client.query('INSERT INTO spam_log (id, data, createdAt) VALUES ($1,$2,$3)', [id, JSON.stringify(entry), createdAt]);
}

async function readBotAttempts() {
  const res = await client.query('SELECT * FROM bot_attempts ORDER BY createdAt DESC');
  return res.rows.map(r => ({ id: r.id, ...(r.data ? JSON.parse(r.data) : {}), createdAt: r.createdat }));
}

async function appendBotAttempt(entry) {
  const id = entry.id || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
  const createdAt = entry.createdAt || new Date().toISOString();
  await client.query('INSERT INTO bot_attempts (id, data, createdAt) VALUES ($1,$2,$3)', [id, JSON.stringify(entry), createdAt]);
}

async function readBugReports() {
  const res = await client.query('SELECT * FROM bug_reports ORDER BY createdAt DESC');
  return res.rows.map(r => ({
    ...r,
    spamCheck: {
      confidence: r.spam_confidence || 0,
      issues: r.spam_issues ? JSON.parse(r.spam_issues) : [],
      isReviewed: !!r.spam_is_reviewed
    }
  }));
}

async function writeBugReports(reports) {
  // simplistic: delete all and re-insert inside a transaction
  try {
    await client.query('BEGIN');
    await client.query('TRUNCATE TABLE bug_reports');
    const insertText = `INSERT INTO bug_reports (
      id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
      createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`;
    for (const it of reports) {
      const spam = it.spamCheck || {};
      await client.query(insertText, [
        it.id, it.name, it.email, it.description, it.stepsToReproduce || '', it.browserInfo || '', it.timestamp || null,
        it.screenshot || null, it.status || 'open', it.createdAt || new Date().toISOString(), it.updatedAt || null,
        it.submitterIP || null, it.country || null, it.cfRay || null, spam.confidence || 0, JSON.stringify(spam.issues || []), spam.isReviewed ? true : false
      ]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function addBugReport(report) {
  const spam = report.spamCheck || {};
  const text = `INSERT INTO bug_reports (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
  ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    description = EXCLUDED.description,
    stepsToReproduce = EXCLUDED.stepsToReproduce,
    browserInfo = EXCLUDED.browserInfo,
    timestamp = EXCLUDED.timestamp,
    screenshot = EXCLUDED.screenshot,
    status = EXCLUDED.status,
    createdAt = EXCLUDED.createdAt,
    updatedAt = EXCLUDED.updatedAt,
    submitterIP = EXCLUDED.submitterIP,
    country = EXCLUDED.country,
    cfRay = EXCLUDED.cfRay,
    spam_confidence = EXCLUDED.spam_confidence,
    spam_issues = EXCLUDED.spam_issues,
    spam_is_reviewed = EXCLUDED.spam_is_reviewed;`;

  await client.query(text, [
    report.id, report.name, report.email, report.description, report.stepsToReproduce || '', report.browserInfo || '', report.timestamp || null,
    report.screenshot || null, report.status || 'open', report.createdAt || new Date().toISOString(), report.updatedAt || null,
    report.submitterIP || null, report.country || null, report.cfRay || null, spam.confidence || 0, JSON.stringify(spam.issues || []), spam.isReviewed ? true : false
  ]);
}

async function readSuggestions() {
  const res = await client.query('SELECT * FROM suggestions ORDER BY createdAt DESC');
  return res.rows.map(r => ({
    ...r,
    spamCheck: {
      confidence: r.spam_confidence || 0,
      issues: r.spam_issues ? JSON.parse(r.spam_issues) : [],
      isReviewed: !!r.spam_is_reviewed
    }
  }));
}

async function writeSuggestions(items) {
  try {
    await client.query('BEGIN');
    await client.query('TRUNCATE TABLE suggestions');
    const insertText = `INSERT INTO suggestions (
      id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
      createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`;
    for (const it of items) {
      const spam = it.spamCheck || {};
      await client.query(insertText, [
        it.id, it.name, it.email, it.description, it.stepsToReproduce || '', it.browserInfo || '', it.timestamp || null,
        it.screenshot || null, it.status || 'open', it.createdAt || new Date().toISOString(), it.updatedAt || null,
        it.submitterIP || null, it.country || null, it.cfRay || null, spam.confidence || 0, JSON.stringify(spam.issues || []), spam.isReviewed ? true : false
      ]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function addSuggestion(suggestion) {
  const spam = suggestion.spamCheck || {};
  const text = `INSERT INTO suggestions (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
  ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    description = EXCLUDED.description,
    stepsToReproduce = EXCLUDED.stepsToReproduce,
    browserInfo = EXCLUDED.browserInfo,
    timestamp = EXCLUDED.timestamp,
    screenshot = EXCLUDED.screenshot,
    status = EXCLUDED.status,
    createdAt = EXCLUDED.createdAt,
    updatedAt = EXCLUDED.updatedAt,
    submitterIP = EXCLUDED.submitterIP,
    country = EXCLUDED.country,
    cfRay = EXCLUDED.cfRay,
    spam_confidence = EXCLUDED.spam_confidence,
    spam_issues = EXCLUDED.spam_issues,
    spam_is_reviewed = EXCLUDED.spam_is_reviewed;`;

  await client.query(text, [
    suggestion.id, suggestion.name, suggestion.email, suggestion.description, suggestion.stepsToReproduce || '', suggestion.browserInfo || '', suggestion.timestamp || null,
    suggestion.screenshot || null, suggestion.status || 'open', suggestion.createdAt || new Date().toISOString(), suggestion.updatedAt || null,
    suggestion.submitterIP || null, suggestion.country || null, suggestion.cfRay || null, spam.confidence || 0, JSON.stringify(spam.issues || []), spam.isReviewed ? true : false
  ]);
}

module.exports = {
  init,
  readBugReports,
  writeBugReports,
  addBugReport,
  readSuggestions,
  writeSuggestions,
  addSuggestion
  ,readIPHistory, appendIPHistory, readSpamLog, appendSpamLog, readBotAttempts, appendBotAttempt
};

// Close Postgres client
async function close() {
  try {
    if (client) {
      await client.end();
    }
  } catch (e) {
    // ignore
  }
}

module.exports.close = close;

// Expose events and connection status
module.exports.events = events;
module.exports.isConnected = isConnected;
