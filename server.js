require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const os = require('os');
const db = require('./lib/db');


// Resolve DB provider from env in a forgiving way:
// - honor explicit DB_PROVIDER
// - if DATABASE_URL or DB_HOST/DB_USER is present, assume postgres
// - if DB_DATABASE or SQLITE_PATH is present, assume sqlite
function resolveDbProvider() {
  const envProvider = (process.env.DB_PROVIDER || '').toLowerCase();
  if (envProvider) return envProvider;
  if (process.env.DATABASE_URL) return 'postgres';
  if (process.env.DB_HOST || process.env.DB_USER || process.env.DB_PASSWORD) return 'postgres';
  if (process.env.DB_DATABASE || process.env.SQLITE_PATH) return 'sqlite';
  // Default to sqlite when nothing explicit is provided
  return 'sqlite';
}
const RESOLVED_DB_PROVIDER = resolveDbProvider();


const app = express();
const PORT = process.env.PORT || 3001;

// Check for .env and JWT secret presence. Warn if .env missing; require JWT_SECRET to be set
// either via .env (loaded by dotenv) or environment variables. Exit if JWT_SECRET is absent.
const envPath = path.join(__dirname, '.env');
if (!fs.existsSync(envPath)) {
  console.warn(`⚠️  .env file not found at ${envPath}. If you rely on environment variables in production this may be okay, otherwise create a .env (you can copy .env.example).`);
}
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set. Please set JWT_SECRET in your environment or add it to a .env file (JWT_SECRET=your_secret). Server will exit.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

// Configure trust proxy for Cloudflare
// Cloudflare uses multiple proxy layers, so we trust all proxies
app.set('trust proxy', true);

// Function to get real client IP behind Cloudflare
function getRealClientIP(req) {
  // Cloudflare provides the real IP in these headers (in order of preference)
  const ip = req.headers['cf-connecting-ip'] ||           // Cloudflare's real IP header
         req.headers['x-forwarded-for']?.split(',')[0] || // First IP in forwarded chain
         req.headers['x-real-ip'] ||                   // Alternative real IP header
         req.ip ||                                     // Express IP (after trust proxy)
         req.connection.remoteAddress ||               // Fallback
         req.socket.remoteAddress ||                   // Another fallback
         'unknown';
  
  // Clean up the IP (remove IPv6 prefix if present)
  const cleanIP = ip?.replace(/^::ffff:/, '') || 'unknown';
  
  // Removed verbose IP detection logging to avoid exposing headers or client details in logs
  return cleanIP;
}

// Spam detection configuration
const spamKeywords = [
  'viagra', 'casino', 'lottery', 'winner', 'congratulations', 
  'click here', 'free money', 'make money fast', 'work from home',
  'cryptocurrency', 'bitcoin', 'investment opportunity', 'mlm',
  'fuck', 'shit', 'damn', 'spam', 'scam', 'phishing'
];

const suspiciousPatterns = [
  /http[s]?:\/\/[^\s]+/gi, // URLs
  /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, // Credit card numbers
  /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone numbers
  /@[^\s]+\.(com|org|net|edu|gov)/gi, // Email addresses in description
];

// Rate limiting for bug reports
const ReportLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // limit each IP to 3 requests per windowMs
  message: {
    error: 'Too many bug reports from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use real client IP for rate limiting (no logging)
    return getRealClientIP(req);
  },
  skip: (req) => {
    // Skip rate limiting for localhost/development
    const realIP = getRealClientIP(req);
    return realIP === '127.0.0.1' || realIP === '::1' || realIP === 'unknown';
  }
});

// Slow down repeated requests
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 1, // allow 1 request per windowMs without delay
  delayMs: () => 500, // add 500ms delay per request after delayAfter
  keyGenerator: (req) => getRealClientIP(req),
  validate: { delayMs: false } // Disable the warning
});

// Rate limiting for admin login
const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: {
    error: 'Too many login attempts from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use real client IP for rate limiting (no logging)
    return getRealClientIP(req);
  },
  skip: (req) => {
    // Skip rate limiting for localhost/development
    const realIP = getRealClientIP(req);
    return realIP === '127.0.0.1' || realIP === '::1' || realIP === 'unknown';
  }
});

// Function to detect spam content
function detectSpam(text, email, name) {
  const issues = [];
  const lowerText = text.toLowerCase();
  const lowerEmail = email.toLowerCase();
  const lowerName = name.toLowerCase();
  
  // Check for spam keywords
  const foundKeywords = spamKeywords.filter(keyword => 
    lowerText.includes(keyword) || lowerEmail.includes(keyword) || lowerName.includes(keyword)
  );
  
  if (foundKeywords.length > 0) {
    issues.push(`Spam keywords detected: ${foundKeywords.join(', ')}`);
  }
  
  // Check for suspicious patterns
  suspiciousPatterns.forEach((pattern, index) => {
    if (pattern.test(text)) {
      const patternNames = ['URLs', 'Credit card numbers', 'Phone numbers', 'Email addresses'];
      issues.push(`Suspicious pattern detected: ${patternNames[index] || 'Unknown pattern'}`);
    }
  });
  
  // Check for excessive caps
  const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
  if (capsRatio > 0.5 && text.length > 10) {
    issues.push('Excessive capital letters');
  }
  
  // Check for repeated characters
  if (/(.)\1{4,}/.test(text)) {
    issues.push('Excessive repeated characters');
  }
  
  // Check for very short descriptions
  if (text.trim().length < 10) {
    issues.push('Description too short (likely spam)');
  }
  
  // Check for obvious test data
  const testPatterns = ['test', 'testing', 'asdf', 'qwerty', '123456'];
  if (testPatterns.some(pattern => lowerText.includes(pattern) && text.length < 50)) {
    issues.push('Appears to be test data');
  }
  
  return {
    isSpam: issues.length > 0,
    issues: issues,
    confidence: Math.min(issues.length * 25, 100) // 25% confidence per issue, max 100%
  };
}

// Function to track IP submission history
async function checkIPHistory(req) {
  const clientIP = getRealClientIP(req);
  
  // Skip IP history check for localhost/development
  if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP === 'unknown') {
    // Removed verbose logging for localhost checks
    return {
      isSuspicious: false,
      recentCount: 0,
      totalCount: 0,
      message: 'Development mode - IP history check skipped'
    };
  }
  
  // If DB provider is configured, try to use DB-backed IP history
  let history = {};
  const provider = RESOLVED_DB_PROVIDER;
  if (provider === 'sqlite' || provider === 'postgres') {
    try {
      history = await db.readIPHistory();
    } catch (e) {
      // fallback to file if DB read fails
      const historyFile = path.join(__dirname, 'data', 'ip-history.json');
      if (await fs.pathExists(historyFile)) {
        history = await fs.readJson(historyFile);
      }
    }
  } else {
    const historyFile = path.join(__dirname, 'data', 'ip-history.json');
    if (await fs.pathExists(historyFile)) {
      history = await fs.readJson(historyFile);
    }
  }
  
  const now = Date.now();
  const oneHour = 60 * 60 * 1000;
  const oneDay = 24 * oneHour;
  
  if (!history[clientIP]) {
    history[clientIP] = { 
      submissions: [], 
      firstSeen: now,
      cloudflareCountry: req.headers['cf-ipcountry'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    };
  }
  
  // Clean old submissions (older than 24 hours)
  history[clientIP].submissions = history[clientIP].submissions.filter(time => now - time < oneDay);
  
  const recentSubmissions = history[clientIP].submissions.filter(time => now - time < oneHour);
  
  // Check if IP is suspicious (more than 3 submissions in 1 hour instead of 2)
  const isSuspicious = recentSubmissions.length >= 3; // Increased from 2 to 3
  
  if (!isSuspicious) {
    // Add current submission
    history[clientIP].submissions.push(now);
    history[clientIP].lastSeen = now;
    // Persist to DB if available, otherwise to file
  const provider = RESOLVED_DB_PROVIDER;
    if (provider === 'sqlite' || provider === 'postgres') {
      try {
        await db.appendIPHistory(clientIP, {
          timestamp: now,
          firstSeen: history[clientIP].firstSeen,
          lastSeen: history[clientIP].lastSeen,
          cloudflareCountry: history[clientIP].cloudflareCountry,
          userAgent: history[clientIP].userAgent
        });
      } catch (e) {
        const historyFile = path.join(__dirname, 'data', 'ip-history.json');
        await fs.ensureDir(path.dirname(historyFile));
        await fs.writeJson(historyFile, history, { spaces: 2 });
      }
    } else {
      const historyFile = path.join(__dirname, 'data', 'ip-history.json');
      await fs.ensureDir(path.dirname(historyFile));
      await fs.writeJson(historyFile, history, { spaces: 2 });
    }
  }

  // Removed detailed IP history console logging to reduce verbosity
  return {
    isSuspicious,
    recentCount: recentSubmissions.length,
    totalCount: history[clientIP].submissions.length,
    clientIP
  };
}

// Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for mobile testing
}));

// Replace detailed debug middleware with minimal request logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  // Minimal log: timestamp, method and path only
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  next();
});

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow all origins for development/local network access
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Create necessary directories
const uploadsDir = path.join(__dirname, 'uploads');
const dataDir = path.join(__dirname, 'data');

// Single JSON file paths
const bugReportsFile = path.join(dataDir, 'bug-reports.json');
const suggestionsFile = path.join(dataDir, 'suggestions-reports.json');

fs.ensureDirSync(uploadsDir);
fs.ensureDirSync(dataDir);

// Initialize data files
async function initializeDataFiles() {
  try {
  const provider = RESOLVED_DB_PROVIDER;
    // If a DB provider is configured, don't create JSON storage files - DB will be used instead
    if (provider === 'sqlite' || provider === 'postgres') {
      console.log(`ℹ️  DB provider set (${provider}) - skipping JSON data file initialization`);
      return;
    }
    // Initialize bug reports file
    if (!await fs.pathExists(bugReportsFile)) {
      await fs.writeJson(bugReportsFile, []);
      console.log('📄 Created bug-reports.json');
    }

    // Initialize suggestions file
    if (!await fs.pathExists(suggestionsFile)) {
      await fs.writeJson(suggestionsFile, []);
      console.log('📄 Created suggestions-reports.json');
    }
  } catch (error) {
    console.error('Error initializing data files:', error);
  }
}

// Helper functions for single JSON file operations
async function readBugReports() {
  try {
    if (await fs.pathExists(bugReportsFile)) {
      return await fs.readJson(bugReportsFile);
    }
    return [];
  } catch (error) {
    console.error('Error reading bug reports:', error);
    return [];
  }
}

async function writeBugReports(reports) {
  try {
    await fs.writeJson(bugReportsFile, reports, { spaces: 2 });
  } catch (error) {
    console.error('Error writing bug reports:', error);
    throw error;
  }
}

async function addBugReport(report) {
  const reports = await readBugReports();
  reports.push(report);
  await writeBugReports(reports);
}

async function readSuggestions() {
  try {
    if (await fs.pathExists(suggestionsFile)) {
      return await fs.readJson(suggestionsFile);
    }
    return [];
  } catch (error) {
    console.error('Error reading suggestions:', error);
    return [];
  }
}

async function writeSuggestions(suggestions) {
  try {
    await fs.writeJson(suggestionsFile, suggestions, { spaces: 2 });
  } catch (error) {
    console.error('Error writing suggestions:', error);
    throw error;
  }
}

async function addSuggestion(suggestion) {
  const suggestions = await readSuggestions();
  suggestions.push(suggestion);
  await writeSuggestions(suggestions);
}

// Initialize spam tracking files
async function initializeSpamFiles() {
  const provider = RESOLVED_DB_PROVIDER;
  // If DB provider is set, skip creating JSON spam/bot/ip files
  if (provider === 'sqlite' || provider === 'postgres') {
    console.log(`ℹ️  DB provider set (${provider}) - skipping spam/bot/ip JSON file initialization`);
    return;
  }

  const spamLogFile = path.join(dataDir, 'spam-log.json');
  const botLogFile = path.join(dataDir, 'bot-attempts.json');
  const ipHistoryFile = path.join(dataDir, 'ip-history.json');

  // Create empty files if they don't exist
  if (!await fs.pathExists(spamLogFile)) {
    await fs.writeJson(spamLogFile, [], { spaces: 2 });
    console.log('📄 Created spam-log.json');
  }

  if (!await fs.pathExists(botLogFile)) {
    await fs.writeJson(botLogFile, [], { spaces: 2 });
    console.log('📄 Created bot-attempts.json');
  }

  if (!await fs.pathExists(ipHistoryFile)) {
    await fs.writeJson(ipHistoryFile, {}, { spaces: 2 });
    console.log('📄 Created ip-history.json');
  }
}

// Initialize spam files on startup
// Initialize files on startup
initializeDataFiles();
initializeSpamFiles();
// Initialize DB (sqlite or postgres) based on DB_PROVIDER environment variable
// Log resolved DB provider and connection info (mask sensitive fields)
function getDbInfo() {
  const provider = RESOLVED_DB_PROVIDER;
  if (!provider) return { provider: '(none)' };
  if (provider === 'postgres') {
    if (process.env.DATABASE_URL) {
      try {
        const url = new URL(process.env.DATABASE_URL);
        // Mask password
        if (url.password) url.password = '****';
        return { provider: 'postgres', connection: url.toString() };
      } catch (e) {
        return { provider: 'postgres', connection: process.env.DATABASE_URL };
      }
    }
    return {
      provider: 'postgres',
      host: process.env.DB_HOST || process.env.DB_HOSTNAME || '127.0.0.1',
      port: process.env.DB_PORT || 5432,
      user: process.env.DB_USER || process.env.DB_USERNAME || 'postgres',
      database: process.env.DB_DATABASE || process.env.PGDATABASE || 'BugScribe'
    };
  }

  // sqlite
  if (provider === 'sqlite') {
    let dbPath = null;
    if (process.env.DB_DATABASE) {
      const dbEnv = process.env.DB_DATABASE;
      dbPath = path.isAbsolute(dbEnv) ? dbEnv : path.join(__dirname, dbEnv);
    } else if (process.env.SQLITE_PATH) {
      dbPath = process.env.SQLITE_PATH;
    } else {
      dbPath = path.join(__dirname, 'data', 'db.sqlite');
    }
    return { provider: 'sqlite', path: dbPath };
  }

  return { provider };
}

(async () => {
  try {
    // Print resolved DB info
    try {
      const info = getDbInfo();
      if (info.provider === 'postgres') {
        if (info.connection) console.log(`ℹ️  DB provider=postgres, connection=${info.connection}`);
        else console.log(`ℹ️  DB provider=postgres, host=${info.host}, port=${info.port}, user=${info.user}, database=${info.database}`);
      } else if (info.provider === 'sqlite') {
        console.log(`ℹ️  DB provider=sqlite, path=${info.path}`);
      } else {
        console.log(`ℹ️  DB provider=${info.provider}`);
      }
    } catch (e) { /* ignore logging errors */ }

    // Subscribe to DB events (if provided) so we can migrate JSON files when DB becomes available
    if (db && db.events && typeof db.events.on === 'function') {
      db.events.on('connected', () => {
        console.log('ℹ️  Database connected event received');
        migrateJsonFilesToDb().catch(err => console.error('Error migrating JSON to DB after connect:', err));
      });
      db.events.on('disconnected', () => {
        console.warn('⚠️  Database disconnected event received');
      });
    }

    const wasConnected = (typeof db.isConnected === 'function') ? await db.isConnected() : false;
    await db.init();
    const nowConnected = (typeof db.isConnected === 'function') ? await db.isConnected() : true;
    if (!wasConnected && nowConnected) {
      console.log('✅ Database initialized');
    }

    // If DB is connected now, try a one-time migration from JSON files
    try {
      const isConn = typeof db.isConnected === 'function' ? await db.isConnected() : true;
      if (isConn) {
        migrateJsonFilesToDb().catch(err => console.error('Error migrating JSON to DB after init:', err));
      }
    } catch (e) {
      // ignore
    }
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    // Do not exit - allow JSON fallback if desired. If you want strict DB, uncomment next line.
    // process.exit(1);
  }
})();

// Migrate any existing JSON files into the database. This runs when DB becomes available.
async function migrateJsonFilesToDb() {
  const provider = RESOLVED_DB_PROVIDER;
  if (!(provider === 'sqlite' || provider === 'postgres')) return;

  // Check if any JSON files exist first; if none, be quiet
  const candidateFiles = [bugReportsFile, suggestionsFile, path.join(__dirname, 'data', 'spam-log.json'), path.join(__dirname, 'data', 'bot-attempts.json'), path.join(__dirname, 'data', 'ip-history.json')];
  let anyFileExists = false;
  for (const f of candidateFiles) {
    if (await fs.pathExists(f)) { anyFileExists = true; break; }
  }
  if (!anyFileExists) return; // nothing to do, stay silent
  console.log('🔁 Attempting to migrate JSON files into the database (if present)');
  try {
    // Helper: safely rename file to .migrating, migrate, and only delete on full success.
    async function migrateFileAtomically(originalPath, migrateHandler) {
      if (!await fs.pathExists(originalPath)) return { found: false };
      const migratingPath = originalPath + '.migrating';
      const timestamp = Date.now();
      try {
        // If a leftover .migrating exists from a prior run, move it aside to a .migrating.failed timestamped file
        if (await fs.pathExists(migratingPath)) {
          const failedOld = originalPath + `.migrating.failed-${timestamp}`;
          await fs.move(migratingPath, failedOld, { overwrite: true });
          console.warn(`Found existing migrating file; moved to ${failedOld} for inspection`);
        }

        // Move the original file to the migrating path. New writes will recreate the original file.
        await fs.move(originalPath, migratingPath, { overwrite: false });
      } catch (moveErr) {
        console.error(`Failed to move ${originalPath} -> ${migratingPath}:`, moveErr);
        return { found: true, migrated: false, failures: 1 };
      }

      // Read and migrate from the migrating file
      let failures = 0;
      let processedAny = false;
      try {
        const content = await fs.readJson(migratingPath);
        try {
          await migrateHandler(content, (err) => { if (err) failures++; processedAny = true; });
        } catch (handlerErr) {
          console.error(`Error while migrating ${migratingPath}:`, handlerErr);
          failures++;
        }
      } catch (readErr) {
        console.error(`Failed to read renamed migrating file ${migratingPath}:`, readErr);
        failures++;
      }

      if (failures === 0 && processedAny) {
        try {
          await fs.remove(migratingPath);
          console.log(`✅ Migrated and removed ${path.basename(originalPath)}`);
        } catch (rmErr) {
          console.error(`Migration succeeded but failed to remove ${migratingPath}:`, rmErr);
        }
        return { found: true, migrated: true, failures: 0 };
      } else if (failures > 0) {
        const failedPath = originalPath + `.failed-${timestamp}`;
        try {
          await fs.move(migratingPath, failedPath, { overwrite: true });
          console.error(`⚠️ Migration had ${failures} failures. Preserved file at ${failedPath} for inspection.`);
        } catch (preserveErr) {
          console.error(`⚠️ Migration had failures and failed to move ${migratingPath} to ${failedPath}:`, preserveErr);
        }
        return { found: true, migrated: false, failures };
      } else {
        // No failures but nothing processed (empty file). Remove empty migrating file to avoid noise.
        try {
          await fs.remove(migratingPath);
          console.log(`ℹ️ Removed empty ${path.basename(originalPath)}`);
        } catch (e) {
          // ignore
        }
        return { found: true, migrated: false, failures: 0 };
      }
    }

    // Run migrations and collect whether any completed successfully
    let migratedAny = false;

    const r1 = await migrateFileAtomically(bugReportsFile, async (bugs, onItemFailure) => {
      if (Array.isArray(bugs) && bugs.length > 0) {
        console.log(`🔁 Migrating ${bugs.length} bug reports to DB`);
        for (const b of bugs) {
          try { await db.addBugReport(b); } catch (e) { console.error('Error migrating bug report:', e); onItemFailure(e); }
        }
      }
    });
    if (r1 && r1.migrated) migratedAny = true;

    const r2 = await migrateFileAtomically(suggestionsFile, async (suggestions, onItemFailure) => {
      if (Array.isArray(suggestions) && suggestions.length > 0) {
        console.log(`🔁 Migrating ${suggestions.length} suggestions to DB`);
        for (const s of suggestions) {
          try { await db.addSuggestion(s); } catch (e) { console.error('Error migrating suggestion:', e); onItemFailure(e); }
        }
      }
    });
    if (r2 && r2.migrated) migratedAny = true;

    const spamLogFile = path.join(__dirname, 'data', 'spam-log.json');
    const r3 = await migrateFileAtomically(spamLogFile, async (spamLogs, onItemFailure) => {
      if (Array.isArray(spamLogs) && spamLogs.length > 0) {
        console.log(`🔁 Migrating ${spamLogs.length} spam logs to DB`);
        for (const e of spamLogs) {
          try { await db.appendSpamLog(e); } catch (err) { console.error('Error migrating spam log:', err); onItemFailure(err); }
        }
      }
    });
    if (r3 && r3.migrated) migratedAny = true;

    const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
    const r4 = await migrateFileAtomically(botLogFile, async (botLogs, onItemFailure) => {
      if (Array.isArray(botLogs) && botLogs.length > 0) {
        console.log(`🔁 Migrating ${botLogs.length} bot attempts to DB`);
        for (const e of botLogs) {
          try { await db.appendBotAttempt(e); } catch (err) { console.error('Error migrating bot attempt:', err); onItemFailure(err); }
        }
      }
    });
    if (r4 && r4.migrated) migratedAny = true;

    const ipHistoryFile = path.join(__dirname, 'data', 'ip-history.json');
    const r5 = await migrateFileAtomically(ipHistoryFile, async (ipHistory, onItemFailure) => {
      if (ipHistory && typeof ipHistory === 'object' && Object.keys(ipHistory).length > 0) {
        console.log(`🔁 Migrating IP history (${Object.keys(ipHistory).length} entries) to DB`);
        for (const [ip, info] of Object.entries(ipHistory)) {
          try {
            const submissions = Array.isArray(info.submissions) ? info.submissions : [];
            for (const t of submissions) {
              try { await db.appendIPHistory(ip, { timestamp: t, firstSeen: info.firstSeen, lastSeen: info.lastSeen, cloudflareCountry: info.cloudflareCountry, userAgent: info.userAgent }); } catch (inner) { onItemFailure(inner); }
            }
          } catch (err) { console.error('Error migrating ip history for', ip, err); onItemFailure(err); }
        }
      }
    });
    if (r5 && r5.migrated) migratedAny = true;

    if (migratedAny) console.log('🎉 JSON -> DB migration complete');
  } catch (err) {
    console.error('Error migrating JSON files to DB:', err);
  }
}

    // Multer storage (filename generation) - restored so upload config is correct
    const storage = multer.diskStorage({
      destination: (req, file, cb) => {
        cb(null, uploadsDir);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'screenshot-' + uniqueSuffix + path.extname(file.originalname));
      }
    });

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Bug report submission endpoint with spam protection
app.post('/api/bug-reports', ReportLimiter, speedLimiter, upload.single('screenshot'), async (req, res) => {
  try {
    const { name, email, description, stepsToReproduce, browserInfo, timestamp, website } = req.body;
    const clientIP = getRealClientIP(req);
    const country = req.headers['cf-ipcountry'] || 'unknown';
    const cfRay = req.headers['cf-ray'] || 'unknown';
    
    console.log(`🐛 Bug report submission from IP: ${clientIP} (Country: ${country}, CF-Ray: ${cfRay})`);
    
    // Honeypot check - if 'website' field is filled, it's a bot
    if (website && website.trim() !== '') {
      console.log(`🕷️  Bot detected via honeypot from IP: ${clientIP} - filled website field: "${website}"`);
      
      // Log bot attempt (DB-backed when DB_PROVIDER is set)
      const botLog = {
        timestamp: new Date().toISOString(),
        ip: clientIP,
        country,
        cfRay,
        userAgent: req.headers['user-agent'],
        honeypotValue: website,
        type: 'honeypot_triggered'
      };

  const provider = RESOLVED_DB_PROVIDER;
      if (provider === 'sqlite' || provider === 'postgres') {
        try {
          await db.appendBotAttempt(botLog);
        } catch (e) {
          // Fallback to file if DB append fails
          const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
          await fs.ensureDir(path.dirname(botLogFile));
          let botLogs = [];
          if (await fs.pathExists(botLogFile)) {
            botLogs = await fs.readJson(botLogFile);
          }
          botLogs.push(botLog);
          if (botLogs.length > 1000) botLogs = botLogs.slice(-1000);
          await fs.writeJson(botLogFile, botLogs, { spaces: 2 });
        }
      } else {
        const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
        await fs.ensureDir(path.dirname(botLogFile));
        let botLogs = [];
        if (await fs.pathExists(botLogFile)) {
          botLogs = await fs.readJson(botLogFile);
        }
        botLogs.push(botLog);
        if (botLogs.length > 1000) botLogs = botLogs.slice(-1000);
        await fs.writeJson(botLogFile, botLogs, { spaces: 2 });
      }
      
      // Return success to fool the bot, but don't actually save the report
      return res.status(201).json({ 
        success: true, 
        message: 'Bug report submitted successfully',
        id: `fake-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      });
    }
    
    // Validate required fields
    if (!name || !email || !description) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check IP history for suspicious activity
    const ipCheck = await checkIPHistory(req);
    if (ipCheck.isSuspicious) {
      console.log(`⚠️  Suspicious IP activity detected: ${clientIP} (${ipCheck.recentCount} recent submissions)`);
      return res.status(429).json({ 
        error: 'Too many submissions from your IP address. Please try again later.',
        details: 'This helps us prevent spam and abuse.'
      });
    }

    // Perform spam detection
    const combinedText = `${description} ${stepsToReproduce || ''}`;
    const spamCheck = detectSpam(combinedText, email, name);
    
    if (spamCheck.isSpam && spamCheck.confidence > 50) {
      console.log(`🚫 Spam detected from ${clientIP} (${country}): ${spamCheck.issues.join(', ')}`);
      
      // Log spam attempt (DB-backed when DB_PROVIDER is set)
      const spamLog = {
        timestamp: new Date().toISOString(),
        ip: clientIP,
        country,
        cfRay,
        userAgent: req.headers['user-agent'],
        name,
        email,
        description: description.substring(0, 100) + '...',
        spamReasons: spamCheck.issues,
        confidence: spamCheck.confidence
      };

  const provider = RESOLVED_DB_PROVIDER;
      if (provider === 'sqlite' || provider === 'postgres') {
        try {
          await db.appendSpamLog(spamLog);
        } catch (e) {
          const spamLogFile = path.join(__dirname, 'data', 'spam-log.json');
          await fs.ensureDir(path.dirname(spamLogFile));
          let spamLogs = [];
          if (await fs.pathExists(spamLogFile)) {
            spamLogs = await fs.readJson(spamLogFile);
          }
          spamLogs.push(spamLog);
          if (spamLogs.length > 1000) spamLogs = spamLogs.slice(-1000);
          await fs.writeJson(spamLogFile, spamLogs, { spaces: 2 });
        }
      } else {
        const spamLogFile = path.join(__dirname, 'data', 'spam-log.json');
        await fs.ensureDir(path.dirname(spamLogFile));
        let spamLogs = [];
        if (await fs.pathExists(spamLogFile)) {
          spamLogs = await fs.readJson(spamLogFile);
        }
        spamLogs.push(spamLog);
        if (spamLogs.length > 1000) spamLogs = spamLogs.slice(-1000);
        await fs.writeJson(spamLogFile, spamLogs, { spaces: 2 });
      }
      
      return res.status(400).json({ 
        error: 'Your submission appears to contain spam or inappropriate content.',
        details: 'Please review your submission and try again with a genuine bug report.'
      });
    }

    // Create bug report object with truly unique ID
    const bugReport = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      description: description.trim(),
      stepsToReproduce: (stepsToReproduce || '').trim(),
      browserInfo,
      timestamp,
      screenshot: req.file ? req.file.filename : null,
      status: 'open',
      createdAt: new Date().toISOString(),
      submitterIP: clientIP,
      country,
      cfRay,
      spamCheck: {
        confidence: spamCheck.confidence,
        issues: spamCheck.issues,
        isReviewed: spamCheck.confidence > 25 // Flag for manual review if confidence > 25%
      }
    };

    // Save to JSON file
    await addBugReport(bugReport);

  // Send thank you email

    console.log(`✅ Bug report submitted: ${bugReport.id} from ${clientIP} (${country}, spam confidence: ${spamCheck.confidence}%)`);

    res.status(201).json({ 
      success: true, 
      message: 'Bug report submitted successfully',
      id: bugReport.id 
    });

  } catch (error) {
    console.error('Error submitting bug report:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

///////////////////////////////////////////////////////
// Suggestion submission endpoint with spam protection
app.post('/api/add-suggestion', ReportLimiter, speedLimiter, upload.none(), async (req, res) => {
  try {
    const { name, email, description, stepsToReproduce, browserInfo, timestamp, website } = req.body;
    const clientIP = getRealClientIP(req);
    const country = req.headers['cf-ipcountry'] || 'unknown';
    const cfRay = req.headers['cf-ray'] || 'unknown';
    
    console.log(`🐛 Bug report submission from IP: ${clientIP} (Country: ${country}, CF-Ray: ${cfRay})`);
    
    // Honeypot check - if 'website' field is filled, it's a bot
    if (website && website.trim() !== '') {
      console.log(`🕷️  Bot detected via honeypot from IP: ${clientIP} - filled website field: "${website}"`);
      
      // Log bot attempt (DB-backed when DB_PROVIDER is set)
      const botLog = {
        timestamp: new Date().toISOString(),
        ip: clientIP,
        country,
        cfRay,
        userAgent: req.headers['user-agent'],
        honeypotValue: website,
        type: 'honeypot_triggered'
      };

  const provider = RESOLVED_DB_PROVIDER;
      if (provider === 'sqlite' || provider === 'postgres') {
        try {
          await db.appendBotAttempt(botLog);
        } catch (e) {
          const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
          await fs.ensureDir(path.dirname(botLogFile));
          let botLogs = [];
          if (await fs.pathExists(botLogFile)) {
            botLogs = await fs.readJson(botLogFile);
          }
          botLogs.push(botLog);
          if (botLogs.length > 1000) botLogs = botLogs.slice(-1000);
          await fs.writeJson(botLogFile, botLogs, { spaces: 2 });
        }
      } else {
        const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
        await fs.ensureDir(path.dirname(botLogFile));
        let botLogs = [];
        if (await fs.pathExists(botLogFile)) {
          botLogs = await fs.readJson(botLogFile);
        }
        botLogs.push(botLog);
        if (botLogs.length > 1000) botLogs = botLogs.slice(-1000);
        await fs.writeJson(botLogFile, botLogs, { spaces: 2 });
      }
      
      // Return success to fool the bot, but don't actually save the Suggestion
      return res.status(201).json({ 
        success: true, 
        message: 'Suggestion submitted successfully',
        id: `fake-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      });
    }
    
    // Validate required fields
    if (!name || !email || !description) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check IP history for suspicious activity
    const ipCheck = await checkIPHistory(req);
    if (ipCheck.isSuspicious) {
      console.log(`⚠️  Suspicious IP activity detected: ${clientIP} (${ipCheck.recentCount} recent submissions)`);
      return res.status(429).json({ 
        error: 'Too many submissions from your IP address. Please try again later.',
        details: 'This helps us prevent spam and abuse.'
      });
    }

    // Perform spam detection
    const combinedText = `${description} ${stepsToReproduce || ''}`;
    const spamCheck = detectSpam(combinedText, email, name);
    
    if (spamCheck.isSpam && spamCheck.confidence > 50) {
      console.log(`🚫 Spam detected from ${clientIP} (${country}): ${spamCheck.issues.join(', ')}`);
      
      // Log spam attempt
      const spamLogFile = path.join(__dirname, 'data', 'spam-log.json');
      const spamLog = {
        timestamp: new Date().toISOString(),
        ip: clientIP,
        country,
        cfRay,
        userAgent: req.headers['user-agent'],
        name,
        email,
        description: description.substring(0, 100) + '...',
        spamReasons: spamCheck.issues,
        confidence: spamCheck.confidence
      };
      
      const provider = (process.env.DB_PROVIDER || '').toLowerCase();
      if (provider === 'sqlite' || provider === 'postgres') {
        try {
          await db.appendSpamLog(spamLog);
        } catch (e) {
          await fs.ensureDir(path.dirname(spamLogFile));
          let spamLogs = [];
          if (await fs.pathExists(spamLogFile)) {
            spamLogs = await fs.readJson(spamLogFile);
          }
          spamLogs.push(spamLog);
          if (spamLogs.length > 1000) spamLogs = spamLogs.slice(-1000);
          await fs.writeJson(spamLogFile, spamLogs, { spaces: 2 });
        }
      } else {
        await fs.ensureDir(path.dirname(spamLogFile));
        let spamLogs = [];
        if (await fs.pathExists(spamLogFile)) {
          spamLogs = await fs.readJson(spamLogFile);
        }
        spamLogs.push(spamLog);
        if (spamLogs.length > 1000) spamLogs = spamLogs.slice(-1000);
        await fs.writeJson(spamLogFile, spamLogs, { spaces: 2 });
      }
      
      return res.status(400).json({ 
        error: 'Your submission appears to contain spam or inappropriate content.',
        details: 'Please review your submission and try again with a genuine bug report.'
      });
    }

    // Create Suggestion object with truly unique ID
    const SuggestionReport = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      description: description.trim(),
      stepsToReproduce: (stepsToReproduce || '').trim(),
      browserInfo,
      timestamp,
      status: 'open',
      createdAt: new Date().toISOString(),
      submitterIP: clientIP,
      country,
      cfRay,
      spamCheck: {
        confidence: spamCheck.confidence,
        issues: spamCheck.issues,
        isReviewed: spamCheck.confidence > 25 // Flag for manual review if confidence > 25%
      }
    };

    // Save to JSON file
    await addSuggestion(SuggestionReport);

  // Send thank you email

    console.log(`✅ Suggestion submitted: ${SuggestionReport.id} from ${clientIP} (${country}, spam confidence: ${spamCheck.confidence}%)`);

    res.status(201).json({ 
      success: true, 
      message: 'Suggestion submitted successfully',
      id: SuggestionReport.id 
    });

  } catch (error) {
    console.error('Error submitting suggestion report:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
/////////////////////////////////////

// Serve index.html from project root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve static files from /public under /public path
app.use('/public', express.static(path.join(__dirname, 'public')));

// Handle preflight requests for admin login
app.options('/api/admin/login', (req, res) => {
  const realIP = getRealClientIP(req);
  console.log(`🔄 OPTIONS request for /api/admin/login from ${realIP}`);
  
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.header('Access-Control-Max-Age', '86400'); // 24 hours
  res.status(200).end();
});

// Admin login endpoint with rate limiting
app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
  const realIP = getRealClientIP(req);
  const userAgent = req.headers['user-agent'] || 'unknown';
  
  try {
    console.log(`🔐 Admin login attempt from ${realIP} (${userAgent})`);
    
    const { username, password } = req.body;
    
    console.log(`   Received data - Username: ${username ? 'provided' : 'missing'}, Password: ${password ? 'provided' : 'missing'}`);
    
    if (!username || !password) {
      console.log(`   ❌ Missing credentials from ${realIP}`);
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
  // Load admin credentials from data/ directory
  const adminFile = path.join(__dirname, 'data', 'admin-credentials.json');
    
    if (!await fs.pathExists(adminFile)) {
      console.log(`   ❌ Admin credentials file not found from ${realIP}`);
      return res.status(401).json({ error: 'No admin accounts configured. Run node lib/tools/create-admin.js or run support-panel.js add-admin to create one. The admin credentials file should be at data/admin-credentials.json.' });
    }
    
    const adminCredentials = await fs.readJson(adminFile);
    console.log(`   📋 Loaded admin credentials, checking user: ${username}`);
    
    // Find user in the credentials file
    const user = adminCredentials.users.find(u => u.username === username);
    
    if (!user) {
      console.log(`   ❌ User ${username} not found from ${realIP}`);
      // Add delay to prevent brute force attacks
      await new Promise(resolve => setTimeout(resolve, 1000));
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    console.log(`   👤 User ${username} found, verifying password from ${realIP}`);
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValidPassword) {
      console.log(`   ❌ Invalid password for ${username} from ${realIP}`);
      // Add delay to prevent brute force attacks
      await new Promise(resolve => setTimeout(resolve, 1000));
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    console.log(`   ✅ Password verified for ${username} from ${realIP}`);
    
    // Update last login time
    user.lastLogin = new Date().toISOString();
    await fs.writeJson(adminFile, adminCredentials, { spaces: 2 });
    
    // Generate secure JWT token
    const token = jwt.sign(
      { 
        username: user.username, 
        role: 'admin',
        loginTime: user.lastLogin 
      },
      JWT_SECRET,
      { expiresIn: '8h' } // Shorter session time for security
    );
    
    console.log(`   🎟️  JWT token generated for ${username} from ${realIP}`);
    
    res.json({ 
      token, 
      message: 'Login successful',
      expiresIn: '8h'
    });
    
    console.log(`   ✅ Login successful for ${username} from ${realIP}`);
    
  } catch (error) {
    console.error(`💥 Login error from ${realIP}:`, error);
    console.error(`   Error stack:`, error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify admin token
const authenticateAdmin = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
  const decoded = jwt.verify(token, JWT_SECRET);
    
  // Verify admin still exists and hasn't been disabled (moved to data/)
  const adminFile = path.join(__dirname, 'data', 'admin-credentials.json');
    if (!await fs.pathExists(adminFile)) {
      return res.status(401).json({ error: 'Admin credentials file no longer exists.' });
    }
    
    const adminCredentials = await fs.readJson(adminFile);
    const user = adminCredentials.users.find(u => u.username === decoded.username);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token - user no longer exists.' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      res.status(401).json({ error: 'Token expired. Please login again.' });
    } else {
      res.status(400).json({ error: 'Invalid token.' });
    }
  }
};

// Get all bug reports (admin only)
app.get('/api/admin/bug-reports', authenticateAdmin, async (req, res) => {
  try {
    const bugReports = await readBugReports();
    
    // Sort by creation date (newest first) - use createdAt, fallback to timestamp
    bugReports.sort((a, b) => {
      const dateA = new Date(a.createdAt || a.timestamp);
      const dateB = new Date(b.createdAt || b.timestamp);
      return dateB - dateA;
    });
    
    res.json(bugReports);
  } catch (error) {
    console.error('Error fetching bug reports:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all feature suggestions (admin only)
app.get('/api/admin/suggestions-reports', authenticateAdmin, async (req, res) => {
  try {
    const suggestions = await readSuggestions();
    
    // Sort by creation date (newest first) - use createdAt, fallback to timestamp
    suggestions.sort((a, b) => {
      const dateA = new Date(a.createdAt || a.timestamp);
      const dateB = new Date(b.createdAt || b.timestamp);
      return dateB - dateA;
    });
    
    res.json(suggestions);
  } catch (error) {
    console.error('Error fetching suggestions:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update bug report status (admin only)
app.patch('/api/admin/bug-reports/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const bugReports = await readBugReports();
    const reportIndex = bugReports.findIndex(report => report.id === id);
    
    if (reportIndex !== -1) {
      bugReports[reportIndex].status = status;
      bugReports[reportIndex].updatedAt = new Date().toISOString();
      
      await writeBugReports(bugReports);
      res.json({ success: true, message: 'Bug report updated' });
    } else {
      res.status(404).json({ error: 'Bug report not found' });
    }
  } catch (error) {
    console.error('Error updating bug report:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update suggestion status (admin only)
app.patch('/api/admin/suggestions-reports/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const suggestions = await readSuggestions();
    const suggestionIndex = suggestions.findIndex(suggestion => suggestion.id === id);
    
    if (suggestionIndex !== -1) {
      suggestions[suggestionIndex].status = status;
      suggestions[suggestionIndex].updatedAt = new Date().toISOString();

      await writeSuggestions(suggestions);
      res.json({ success: true, message: 'Suggestion updated' });
    } else {
      res.status(404).json({ error: 'Suggestion not found' });
    }
  } catch (error) {
    console.error('Error updating suggestion:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a bug report (admin only) - RESTful route
app.delete('/api/admin/bug-reports/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const bugReports = await readBugReports();
    const reportIndex = bugReports.findIndex(report => report.id === id);
    
    if (reportIndex !== -1) {
      bugReports.splice(reportIndex, 1);
      await writeBugReports(bugReports);
      return res.json({ success: true, message: 'Bug report deleted' });
    }
    return res.status(404).json({ error: 'Bug report not found' });
  } catch (error) {
    console.error('Error deleting bug report:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a suggestion (admin only) - RESTful route
app.delete('/api/admin/suggestions-reports/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const suggestions = await readSuggestions();
    const suggestionIndex = suggestions.findIndex(suggestion => suggestion.id === id);
    
    if (suggestionIndex !== -1) {
      suggestions.splice(suggestionIndex, 1);
      await writeSuggestions(suggestions);
      return res.json({ success: true, message: 'Suggestion deleted' });
    }
    return res.status(404).json({ error: 'Suggestion not found' });
  } catch (error) {
    console.error('Error deleting suggestion:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a bug report using query param (supports clients that send ?id=...)
app.delete('/api/admin/bug-reports', authenticateAdmin, async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ error: 'Missing id query parameter' });
    
    const bugReports = await readBugReports();
    const reportIndex = bugReports.findIndex(report => report.id === id);
    
    if (reportIndex !== -1) {
      bugReports.splice(reportIndex, 1);
      await writeBugReports(bugReports);
      return res.json({ success: true, message: 'Bug report deleted' });
    }
    return res.status(404).json({ error: 'Bug report not found' });
  } catch (error) {
    console.error('Error deleting bug report (query):', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete a suggestion using query param (supports clients that send ?id=...)
app.delete('/api/admin/suggestions-reports', authenticateAdmin, async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ error: 'Missing id query parameter' });
    
    const suggestions = await readSuggestions();
    const suggestionIndex = suggestions.findIndex(suggestion => suggestion.id === id);
    
    if (suggestionIndex !== -1) {
      suggestions.splice(suggestionIndex, 1);
      await writeSuggestions(suggestions);
      return res.json({ success: true, message: 'Suggestion deleted' });
    }
    return res.status(404).json({ error: 'Suggestion not found' });
  } catch (error) {
    console.error('Error deleting suggestion (query):', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve screenshots (admin only)
app.get('/api/admin/screenshots/:filename', authenticateAdmin, (req, res) => {
  const { filename } = req.params;
  const filePath = path.join(uploadsDir, filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'Screenshot not found' });
  }
});

// Notifications removed by user request - sendNotification intentionally omitted

// Helper functions - delegate to DB layer. The DB layer currently implements
// read/write/add for bug reports and suggestions for sqlite or postgres.
async function readBugReports() {
  try {
    return await db.readBugReports();
  } catch (error) {
    console.error('Error reading bug reports from DB:', error);
    // Fallback to JSON file if DB fails
    try { if (await fs.pathExists(bugReportsFile)) return await fs.readJson(bugReportsFile); } catch (e) { /* ignore */ }
    return [];
  }
}

async function writeBugReports(reports) {
  try {
    return await db.writeBugReports(reports);
  } catch (error) {
    console.error('Error writing bug reports to DB:', error);
    // Fallback: write JSON file
    await fs.writeJson(bugReportsFile, reports, { spaces: 2 });
  }
}

async function addBugReport(report) {
  try {
    return await db.addBugReport(report);
  } catch (error) {
    console.error('Error adding bug report to DB:', error);
    // Fallback: append to JSON
    const reports = await readBugReports();
    reports.push(report);
    await fs.writeJson(bugReportsFile, reports, { spaces: 2 });
  }
}

async function readSuggestions() {
  try {
    return await db.readSuggestions();
  } catch (error) {
    console.error('Error reading suggestions from DB:', error);
    try { if (await fs.pathExists(suggestionsFile)) return await fs.readJson(suggestionsFile); } catch (e) { /* ignore */ }
    return [];
  }
}

async function writeSuggestions(suggestions) {
  try {
    return await db.writeSuggestions(suggestions);
  } catch (error) {
    console.error('Error writing suggestions to DB:', error);
    await fs.writeJson(suggestionsFile, suggestions, { spaces: 2 });
  }
}

async function addSuggestion(suggestion) {
  try {
    return await db.addSuggestion(suggestion);
  } catch (error) {
    console.error('Error adding suggestion to DB:', error);
    const suggestions = await readSuggestions();
    suggestions.push(suggestion);
    await fs.writeJson(suggestionsFile, suggestions, { spaces: 2 });
  }
}

// Get spam statistics (admin only)
app.get('/api/admin/spam-stats', authenticateAdmin, async (req, res) => {
  try {
    const { search, status, type } = req.query;
    
  const provider = RESOLVED_DB_PROVIDER;
    let spamAttempts = [];
    let botAttempts = [];
    let ipHistory = {};

    if (provider === 'sqlite' || provider === 'postgres') {
      try { spamAttempts = await db.readSpamLog(); } catch (e) { spamAttempts = []; }
      try { botAttempts = await db.readBotAttempts(); } catch (e) { botAttempts = []; }
      try { ipHistory = await db.readIPHistory(); } catch (e) { ipHistory = {}; }
    } else {
      const spamLogFile = path.join(__dirname, 'data', 'spam-log.json');
      const botLogFile = path.join(__dirname, 'data', 'bot-attempts.json');
      const ipHistoryFile = path.join(__dirname, 'data', 'ip-history.json');

      if (await fs.pathExists(spamLogFile)) {
        spamAttempts = await fs.readJson(spamLogFile);
      }

      if (await fs.pathExists(botLogFile)) {
        botAttempts = await fs.readJson(botLogFile);
      }

      if (await fs.pathExists(ipHistoryFile)) {
        ipHistory = await fs.readJson(ipHistoryFile);
      }
    }
    
    // Get filtered reports for statistical analysis
    let allReports = [];
    try {
      // Load both bugs and suggestions based on type filter
      if (type === 'bugs' || !type) {
        const bugs = await readBugReports();
        allReports.push(...bugs.map(b => ({ ...b, type: 'bug' })));
      }
      
      if (type === 'suggestions' || !type) {
        const suggestions = await readSuggestions();
        allReports.push(...suggestions.map(s => ({ ...s, type: 'suggestion' })));
      }
      
      // Apply filters to reports (same logic as admin panel)
      if (status && status !== 'all') {
        allReports = allReports.filter(report => report.status === status);
      }

      if (search && search.trim()) {
        const searchTerm = search.toLowerCase();
        allReports = allReports.filter(report => {
          const searchableText = [
            report.id.toString(),
            report.name || '',
            report.email || '',
            report.description || '',
            report.browserInfo || '',
            report.stepsToReproduce || ''
          ].join(' ').toLowerCase();
          
          return searchableText.includes(searchTerm);
        });
      }
    } catch (error) {
      console.error('Error loading reports for stats:', error);
    }
    
    // Calculate statistics
    const stats = {
      totalSpamAttempts: allReports.length,
      totalBotAttempts: botAttempts.length,
      filteredReports: allReports.length,
      last24Hours: {
        spam: allReports.filter(report => 
          Date.now() - new Date(report.createdAt || report.timestamp).getTime() < 24 * 60 * 60 * 1000
        ).length,
        bots: botAttempts.filter(log => 
          Date.now() - new Date(log.timestamp).getTime() < 24 * 60 * 60 * 1000
        ).length
      },
      topCountries: {},
      commonSpamReasons: {},
      honeypotValues: {},
      totalTrackedIPs: Object.keys(ipHistory).length,
      isFiltered: (search && search.trim()) || (status && status !== 'all') || (type && type !== 'all')
    };
    
    // Count countries from reports
    allReports.forEach(report => {
      if (report.country && report.country !== 'unknown') {
        stats.topCountries[report.country] = (stats.topCountries[report.country] || 0) + 1;
      }
    });
    
    // Count actual spam reasons from spam check issues
    allReports.forEach(report => {
      if (report.spamCheck && report.spamCheck.issues && Array.isArray(report.spamCheck.issues)) {
        report.spamCheck.issues.forEach(issue => {
          if (issue) {
            stats.commonSpamReasons[issue] = (stats.commonSpamReasons[issue] || 0) + 1;
          }
        });
      }
    });
    
    res.json({
      success: true,
      stats
    });
    
  } catch (error) {
    console.error('Error fetching spam stats:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get email statistics (admin only)
app.get('/api/admin/email-stats', authenticateAdmin, async (req, res) => {
  try {    res.json({
      success: true,
      stats: {
        ...stats,
        isEnabled: process.env.THANK_YOU_EMAIL_ENABLED === 'true'
      }
    });
  } catch (error) {
    console.error('Error fetching email stats:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Debug endpoint for IP detection
app.get('/debug/ip', (req, res) => {
  const realIP = getRealClientIP(req);
  
  res.json({
    detectedIP: realIP,
    headers: {
      'cf-connecting-ip': req.headers['cf-connecting-ip'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip'],
      'user-agent': req.headers['user-agent']
    },
    expressIP: req.ip,
    connectionIP: req.connection.remoteAddress,
    socketIP: req.socket.remoteAddress,
    timestamp: new Date().toISOString()
  });
});

// Get spam files info (admin only)
app.get('/api/admin/spam-files', authenticateAdmin, async (req, res) => {
  try {
  const dataDir = path.join(__dirname, 'data');
  const provider = RESOLVED_DB_PROVIDER;

    const spamLogFile = path.join(dataDir, 'spam-log.json');
    const botLogFile = path.join(dataDir, 'bot-attempts.json');
    const ipHistoryFile = path.join(dataDir, 'ip-history.json');

    const files = {
      spamLog: { path: spamLogFile, exists: false, size: 0, count: 0 },
      botAttempts: { path: botLogFile, exists: false, size: 0, count: 0 },
      ipHistory: { path: ipHistoryFile, exists: false, size: 0, count: 0 }
    };

    if (provider === 'sqlite' || provider === 'postgres') {
      // Report counts from DB
      try {
        const spamData = await db.readSpamLog();
        files.spamLog.path = 'database';
        files.spamLog.exists = true;
        files.spamLog.count = Array.isArray(spamData) ? spamData.length : 0;
      } catch (e) { /* ignore - leave defaults */ }

      try {
        const botData = await db.readBotAttempts();
        files.botAttempts.path = 'database';
        files.botAttempts.exists = true;
        files.botAttempts.count = Array.isArray(botData) ? botData.length : 0;
      } catch (e) { /* ignore */ }

      try {
        const ipData = await db.readIPHistory();
        files.ipHistory.path = 'database';
        files.ipHistory.exists = true;
        files.ipHistory.count = ipData && typeof ipData === 'object' ? Object.keys(ipData).length : 0;
      } catch (e) { /* ignore */ }
    } else {
      // File system based stats
      files.spamLog.exists = await fs.pathExists(spamLogFile);
      files.botAttempts.exists = await fs.pathExists(botLogFile);
      files.ipHistory.exists = await fs.pathExists(ipHistoryFile);

      if (files.spamLog.exists) {
        const stats = await fs.stat(spamLogFile);
        const data = await fs.readJson(spamLogFile);
        files.spamLog.size = stats.size;
        files.spamLog.count = Array.isArray(data) ? data.length : 0;
      }

      if (files.botAttempts.exists) {
        const stats = await fs.stat(botLogFile);
        const data = await fs.readJson(botLogFile);
        files.botAttempts.size = stats.size;
        files.botAttempts.count = Array.isArray(data) ? data.length : 0;
      }

      if (files.ipHistory.exists) {
        const stats = await fs.stat(ipHistoryFile);
        const data = await fs.readJson(ipHistoryFile);
        files.ipHistory.size = stats.size;
        files.ipHistory.count = typeof data === 'object' ? Object.keys(data).length : 0;
      }
    }
    
    res.json({
      success: true,
      dataDirectory: dataDir,
      files
    });
    
  } catch (error) {
    console.error('Error fetching spam files info:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Bug report server running on port ${PORT}`);
  console.log(`BugScribe panel available at:`);
  const interfaces = os.networkInterfaces();
  const localIPs = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        localIPs.push(iface.address);
      }
    }
  }

  console.log(`  - Local: http://localhost:${PORT}`);
  localIPs.forEach(ip => {
    console.log(`  - Network: http://${ip}:${PORT}`);
  });
});

// Graceful shutdown: checkpoint sqlite WAL and close DB connections, then exit
let shuttingDown = false;
async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}. Closing server and database connections...`);
  try {
    // Close DB if implemented
    if (db && typeof db.close === 'function') {
      await db.close();
      console.log('Database connections closed.');
    }
  } catch (e) {
    console.error('Error during DB close:', e);
  }

  // Allow a short delay for logs to flush
  setTimeout(() => {
    console.log('Shutdown complete. Exiting.');
    process.exit(0);
  }, 250);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('uncaughtException', err => {
  console.error('Uncaught exception:', err);
  gracefulShutdown('uncaughtException');
});

// Export reports endpoint (admin only)
app.get('/api/admin/export', authenticateAdmin, async (req, res) => {
  try {
    const { search, status, type, exportAll } = req.query;
    
    // Load all bug reports using new helper function
    const bugs = await readBugReports();
    const bugsWithType = bugs.map(bug => ({ ...bug, type: 'bug' }));

    // Load all suggestion reports using new helper function
    const suggestions = await readSuggestions();
    const suggestionsWithType = suggestions.map(suggestion => ({ ...suggestion, type: 'suggestion' }));

    // Combine all reports
    let allReports = [...bugsWithType, ...suggestionsWithType];

    // Apply filters
    if (status && status !== 'all') {
      allReports = allReports.filter(report => report.status === status);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      allReports = allReports.filter(report => {
        const searchText = [
          report.id,
          report.name,
          report.email,
          report.description,
          report.browserInfo,
          report.stepsToReproduce
        ].join(' ').toLowerCase();
        return searchText.includes(searchLower);
      });
    }

    if (type && (type === 'bugs' || type === 'suggestions')) {
      if (type === 'bugs') {
        allReports = allReports.filter(report => report.type === 'bug');
      } else if (type === 'suggestions') {
        allReports = allReports.filter(report => report.type === 'suggestion');
      }
    }

    // Sort by creation date (newest first)
    allReports.sort((a, b) => new Date(b.createdAt || b.timestamp) - new Date(a.createdAt || a.timestamp));

    // Generate CSV
    const headers = [
      'ID',
      'Type',
      'Name',
      'Email',
      'Status',
      'Created At',
      'Country',
      'Submitter IP',
      'Browser Info',
      'Description',
      'Steps to Reproduce'
    ];

    const csvRows = [headers.join(',')];

    allReports.forEach(report => {
      const row = [
        `"${(report.id || '').toString().replace(/"/g, '""')}"`,
        `"${(report.type || 'bug').replace(/"/g, '""')}"`,
        `"${(report.name || '').replace(/"/g, '""')}"`,
        `"${(report.email || '').replace(/"/g, '""')}"`,
        `"${(report.status || 'open').replace(/"/g, '""')}"`,
        `"${(report.createdAt || report.timestamp || '').replace(/"/g, '""')}"`,
        `"${(report.country || 'unknown').replace(/"/g, '""')}"`,
        `"${(report.submitterIP || '').replace(/"/g, '""')}"`,
        `"${(report.browserInfo || '').replace(/"/g, '""')}"`,
        `"${(report.description || '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`,
        `"${(report.stepsToReproduce || '').replace(/"/g, '""').replace(/\r?\n/g, ' ')}"`
      ];
      csvRows.push(row.join(','));
    });

    const csv = csvRows.join('\n');
    const filename = `finetrack-reports-${new Date().toISOString().slice(0, 10)}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);

  } catch (error) {
    console.error('Error exporting reports:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = app;
