const path = require('path');
const fs = require('fs-extra');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const EventEmitter = require('events');

const events = new EventEmitter();
let connected = false;
function isConnected() { return !!connected; }

let db;

async function init(options = {}) {
  // Determine DB path from env: DB_DATABASE can be an absolute path or a relative name/path.
  // If not provided, default to data/db.sqlite
  let dbPath;
  if (process.env.DB_DATABASE) {
    const dbEnv = process.env.DB_DATABASE;
    dbPath = path.isAbsolute(dbEnv) ? dbEnv : path.join(__dirname, '..', '..', dbEnv);
  } else if (process.env.SQLITE_PATH) {
    dbPath = process.env.SQLITE_PATH;
  } else {
    dbPath = path.join(__dirname, '..', '..', 'data', 'db.sqlite');
  }
  await fs.ensureFile(dbPath);
  db = await open({ filename: dbPath, driver: sqlite3.Database });
  // mark connected and emit
  connected = true;
  try { events.emit('connected'); } catch (e) { /* ignore */ }

  // Create tables
  await db.exec(`
    PRAGMA journal_mode = WAL;
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
      spam_is_reviewed INTEGER
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
      spam_is_reviewed INTEGER
    );
    CREATE TABLE IF NOT EXISTS ip_history (
      ip TEXT PRIMARY KEY,
      submissions TEXT,
      firstSeen INTEGER,
      lastSeen INTEGER,
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

// IP history table: store per-ip submissions array and metadata
async function readIPHistory() {
  const rows = await db.all('SELECT * FROM ip_history');
  const out = {};
  for (const r of rows) {
    out[r.ip] = {
      submissions: r.submissions ? JSON.parse(r.submissions) : [],
      firstSeen: r.firstSeen || null,
      lastSeen: r.lastSeen || null,
      cloudflareCountry: r.cloudflareCountry || 'unknown',
      userAgent: r.userAgent || 'unknown'
    };
  }
  return out;
}

async function appendIPHistory(ip, entry) {
  const row = await db.get('SELECT * FROM ip_history WHERE ip = ?', ip);
  const now = Date.now();
  if (!row) {
    const submissions = [entry.timestamp || now];
    await db.run('INSERT INTO ip_history (ip, submissions, firstSeen, lastSeen, cloudflareCountry, userAgent) VALUES (?,?,?,?,?,?)', [
      ip, JSON.stringify(submissions), entry.firstSeen || now, entry.lastSeen || now, entry.cloudflareCountry || 'unknown', entry.userAgent || 'unknown'
    ]);
    return;
  }
  const submissions = row.submissions ? JSON.parse(row.submissions) : [];
  submissions.push(entry.timestamp || now);
  await db.run('UPDATE ip_history SET submissions = ?, lastSeen = ? WHERE ip = ?', [JSON.stringify(submissions), now, ip]);
}

async function readSpamLog() {
  const rows = await db.all('SELECT * FROM spam_log ORDER BY createdAt DESC');
  return rows.map(r => ({ id: r.id, ... (r.data ? JSON.parse(r.data) : {}), createdAt: r.createdAt }));
}

async function appendSpamLog(entry) {
  const id = entry.id || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
  const createdAt = entry.createdAt || new Date().toISOString();
  await db.run('INSERT INTO spam_log (id, data, createdAt) VALUES (?,?,?)', [id, JSON.stringify(entry), createdAt]);
}

async function readBotAttempts() {
  const rows = await db.all('SELECT * FROM bot_attempts ORDER BY createdAt DESC');
  return rows.map(r => ({ id: r.id, ... (r.data ? JSON.parse(r.data) : {}), createdAt: r.createdAt }));
}

async function appendBotAttempt(entry) {
  const id = entry.id || `${Date.now()}-${Math.random().toString(36).slice(2,9)}`;
  const createdAt = entry.createdAt || new Date().toISOString();
  await db.run('INSERT INTO bot_attempts (id, data, createdAt) VALUES (?,?,?)', [id, JSON.stringify(entry), createdAt]);
}

async function readBugReports() {
  const rows = await db.all('SELECT * FROM bug_reports ORDER BY createdAt DESC');
  return rows.map(r => ({
    ...r,
    spamCheck: {
      confidence: r.spam_confidence || 0,
      issues: r.spam_issues ? JSON.parse(r.spam_issues) : [],
      isReviewed: !!r.spam_is_reviewed
    }
  }));
}

async function writeBugReports(reports) {
  const insertText = `INSERT OR REPLACE INTO bug_reports (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;

  try {
    await db.exec('BEGIN');
    await db.exec('DELETE FROM bug_reports');
    for (const it of reports) {
      const spam = it.spamCheck || {};
      await db.run(insertText, [
        it.id,
        it.name,
        it.email,
        it.description,
        it.stepsToReproduce || '',
        it.browserInfo || '',
        it.timestamp || null,
        it.screenshot || null,
        it.status || 'open',
        it.createdAt || new Date().toISOString(),
        it.updatedAt || null,
        it.submitterIP || null,
        it.country || null,
        it.cfRay || null,
        spam.confidence || 0,
        JSON.stringify(spam.issues || []),
        spam.isReviewed ? 1 : 0
      ]);
    }
    await db.exec('COMMIT');
  } catch (e) {
    await db.exec('ROLLBACK');
    throw e;
  }
}

async function addBugReport(report) {
  const insertText = `INSERT OR REPLACE INTO bug_reports (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;
  const spam = report.spamCheck || {};
  await db.run(insertText, [
    report.id,
    report.name,
    report.email,
    report.description,
    report.stepsToReproduce || '',
    report.browserInfo || '',
    report.timestamp || null,
    report.screenshot || null,
    report.status || 'open',
    report.createdAt || new Date().toISOString(),
    report.updatedAt || null,
    report.submitterIP || null,
    report.country || null,
    report.cfRay || null,
    spam.confidence || 0,
    JSON.stringify(spam.issues || []),
    spam.isReviewed ? 1 : 0
  ]);
}

async function readSuggestions() {
  const rows = await db.all('SELECT * FROM suggestions ORDER BY createdAt DESC');
  return rows.map(r => ({
    ...r,
    spamCheck: {
      confidence: r.spam_confidence || 0,
      issues: r.spam_issues ? JSON.parse(r.spam_issues) : [],
      isReviewed: !!r.spam_is_reviewed
    }
  }));
}

async function writeSuggestions(items) {
  const insertText = `INSERT OR REPLACE INTO suggestions (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;

  try {
    await db.exec('BEGIN');
    await db.exec('DELETE FROM suggestions');
    for (const it of items) {
      const spam = it.spamCheck || {};
      await db.run(insertText, [
        it.id,
        it.name,
        it.email,
        it.description,
        it.stepsToReproduce || '',
        it.browserInfo || '',
        it.timestamp || null,
        it.screenshot || null,
        it.status || 'open',
        it.createdAt || new Date().toISOString(),
        it.updatedAt || null,
        it.submitterIP || null,
        it.country || null,
        it.cfRay || null,
        spam.confidence || 0,
        JSON.stringify(spam.issues || []),
        spam.isReviewed ? 1 : 0
      ]);
    }
    await db.exec('COMMIT');
  } catch (e) {
    await db.exec('ROLLBACK');
    throw e;
  }
}

async function addSuggestion(suggestion) {
  const insertText = `INSERT OR REPLACE INTO suggestions (
    id, name, email, description, stepsToReproduce, browserInfo, timestamp, screenshot, status,
    createdAt, updatedAt, submitterIP, country, cfRay, spam_confidence, spam_issues, spam_is_reviewed
  ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;
  const spam = suggestion.spamCheck || {};
  await db.run(insertText, [
    suggestion.id,
    suggestion.name,
    suggestion.email,
    suggestion.description,
    suggestion.stepsToReproduce || '',
    suggestion.browserInfo || '',
    suggestion.timestamp || null,
    suggestion.screenshot || null,
    suggestion.status || 'open',
    suggestion.createdAt || new Date().toISOString(),
    suggestion.updatedAt || null,
    suggestion.submitterIP || null,
    suggestion.country || null,
    suggestion.cfRay || null,
    spam.confidence || 0,
    JSON.stringify(spam.issues || []),
    spam.isReviewed ? 1 : 0
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

// Graceful close: checkpoint WAL and close the DB connection
async function close() {
  try {
    if (db) {
      // Force a checkpoint and truncate WAL so files are merged
      try { await db.exec('PRAGMA wal_checkpoint(TRUNCATE);'); } catch (e) { /* ignore */ }
      try { await db.close(); } catch (e) { /* ignore */ }
      connected = false;
      try { events.emit('disconnected'); } catch (e) { /* ignore */ }
    }
  } catch (e) {
    // ignore
  }
}

module.exports.close = close;

module.exports.events = events;
module.exports.isConnected = isConnected;
