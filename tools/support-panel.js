#!/usr/bin/env node
/*
  support-panel.js
  Terminal utility to manage admin users and simulate reports for BugScribe.

  Commands:
    node support-panel.js interactive       # interactive menu
    node support-panel.js add-admin <user> <password>
    node support-panel.js remove-admin <user>
    node support-panel.js list-admins
    node support-panel.js change-password <user> <newPassword>
  node support-panel.js bug           # POST test bug report
  node support-panel.js suggestion    # POST test suggestion report

  Notes:
  - The script edits `admin-credentials.json` in the repository root (it will create a backup before editing).
  - Uses bcryptjs for hashing (same as existing scripts).
  - Uses built-in fetch when available; falls back to node-fetch if needed.

*/

const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const ADMIN_FILE = path.join(__dirname, '..', 'admin-credentials.json');

async function loadCredentials() {
  if (await fs.pathExists(ADMIN_FILE)) {
    return fs.readJson(ADMIN_FILE);
  }
  return {
    version: '1.0',
    createdAt: new Date().toISOString(),
    users: []
  };
}

async function backupCredentials() {
  if (!(await fs.pathExists(ADMIN_FILE))) return null;
  const backupPath = ADMIN_FILE + '.bak.' + Date.now();
  await fs.copy(ADMIN_FILE, backupPath);
  return backupPath;
}

async function saveCredentials(obj) {
  await fs.writeJson(ADMIN_FILE, obj, { spaces: 2 });
}

async function addAdmin(username, password) {
  if (!username || !password) throw new Error('username and password required');
  const creds = await loadCredentials();
  const existing = creds.users.find(u => u.username === username);
  const saltRounds = 12;
  const hash = await bcrypt.hash(password, saltRounds);
  if (existing) {
    existing.passwordHash = hash;
    existing.updatedAt = new Date().toISOString();
    console.log(`Updated password for user '${username}'`);
  } else {
    creds.users.push({
      username,
      passwordHash: hash,
      createdAt: new Date().toISOString(),
      lastLogin: null
    });
    console.log(`Added user '${username}'`);
  }
  await saveCredentials(creds);
}

async function removeAdmin(username) {
  if (!username) throw new Error('username required');
  const creds = await loadCredentials();
  const before = creds.users.length;
  creds.users = creds.users.filter(u => u.username !== username);
  if (creds.users.length === before) {
    console.log(`No user '${username}' found`);
  } else {
    await saveCredentials(creds);
    console.log(`Removed user '${username}'`);
  }
}

async function listAdmins() {
  const creds = await loadCredentials();
  if (!creds.users || creds.users.length === 0) {
    console.log('No admin users found');
    return;
  }
  console.log('Admin users:');
  for (const u of creds.users) {
    console.log(`- ${u.username}  createdAt=${u.createdAt}  lastLogin=${u.lastLogin || '-'}  updatedAt=${u.updatedAt || '-'} `);
  }
}

async function changePassword(username, newPassword) {
  if (!username || !newPassword) throw new Error('username and newPassword required');
  const creds = await loadCredentials();
  const existing = creds.users.find(u => u.username === username);
  if (!existing) throw new Error(`No user '${username}'`);
  const hash = await bcrypt.hash(newPassword, 12);
  existing.passwordHash = hash;
  existing.updatedAt = new Date().toISOString();
  await saveCredentials(creds);
  console.log(`Password changed for '${username}'`);
}

// Reusable helper copied from tools/test-submit.js to post JSON with a robust fetch check and response parsing
async function postJson(url, body) {
  // prefer global fetch (Node 18+). If unavailable, instruct the user to run with Node 18+ or install node-fetch.
  if (typeof fetch === 'undefined') {
    throw new Error('fetch is not available in this Node runtime. Please run with Node 18+ or install node-fetch.');
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
  return { status: res.status, ok: res.ok, body: parsed };
}

// ---- Helpers copied from tools/test-submit.js to support `bug` / `suggestion` commands ----
function parseArgs(args) {
  const out = { flags: {} };
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.replace(/^--/, '');
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        out.flags[key] = next;
        i++;
      } else {
        out.flags[key] = true;
      }
    } else {
      rest.push(a);
    }
  }
  out._ = rest;
  return out;
}

function samplePayload(type) {
  const t = type === 'suggestion' ? 'Suggestion' : 'Bug';
  return {
    name: `${t} Tester`,
    email: `tester+${Date.now()}@example.com`,
    description: `${t} submitted by automated tester at ${new Date().toISOString()}\n\nThis is a sample ${type} to exercise the API.`,
    stepsToReproduce: '1. Open app\n2. Do thing\n3. Observe error',
    browserInfo: 'Node.js test client',
    timestamp: new Date().toISOString(),
    website: '' // honeypot must be empty
  };
}

const BASE_URL = (process.env.BASE_URL) || `http://localhost:${process.env.PORT || 3001}`;
// ---- end helpers ----

// NOTE: `simulate-report` command/function removed — use the `bug` or `suggestion` commands

function printHelp() {
  console.log('\nsupport-panel - admin/report helper for BugScribe\n');
  console.log('Usage: node support-panel.js <command> [options]\n');

  console.log('Commands:');
  const cmds = [
    ['interactive', 'Start interactive menu'],
    ['add-admin <user> <password>', 'Add or update an admin user'],
    ['remove-admin <user>', 'Remove an admin user'],
    ['list-admins', 'List admin users'],
    ['change-password <user> <password>', 'Change password for a user'],
    ['bug', 'POST test bug report'],
    ['suggestion', 'POST test suggestion report']
  ];
  const leftWidth = 48;
  for (const [left, right] of cmds) {
    console.log('  ' + left.padEnd(leftWidth) + ' ' + right);
  }

  console.log('\nExamples:');
  console.log('  node support-panel.js add-admin alice S3cret!');
  console.log('  node support-panel.js bug --name "Alice" --email "a@ex.com" --description "Found a bug"');
  console.log('  node support-panel.js suggestion --random');
}

async function interactiveMenu() {
  const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  const question = (q) => new Promise(res => rl.question(q, ans => res(ans.trim())));

  while (true) {
  console.log('\nsupport-panel interactive menu');
  console.log('1) List admins');
  console.log('2) Add / update admin');
  console.log('3) Remove admin');
  console.log('4) Change admin password');
  console.log('5) Submit test report (interactive)');
  console.log('6) Exit');
    const choice = await question('Choose an option: ');
    try {
      if (choice === '1') await listAdmins();
      else if (choice === '2') {
        const user = await question('Username: ');
        const pass = await question('Password: ');
        await backupCredentials();
        await addAdmin(user, pass);
      } else if (choice === '3') {
        const user = await question('Username to remove: ');
        const ok = await question(`Are you sure you want to remove '${user}'? (yes/no): `);
        if (ok.toLowerCase() === 'yes') {
          await backupCredentials();
          await removeAdmin(user);
        } else console.log('Aborted.');
      } else if (choice === '4') {
        const user = await question('Username: ');
        const pass = await question('New password: ');
        await backupCredentials();
        await changePassword(user, pass);
      } else if (choice === '5') {
        // Interactive test report submission (bug or suggestion)
        const chosenType = (await question('Choose report type: 1) Bug  2) Suggestion  [1]: ')).trim() === '2' ? 'suggestion' : 'bug';
        const nameAns = (await question('Name (leave blank to use sample): '));
        const emailAns = (await question('Email (leave blank to use sample): '));
        const descAns = (await question('Description (leave blank to use sample): '));
        const stepsAns = (await question('Steps to reproduce (optional): '));

        const sample = samplePayload(chosenType);
        const payload = {
          name: nameAns.trim() || sample.name,
          email: emailAns.trim() || sample.email,
          description: descAns.trim() || sample.description,
          stepsToReproduce: stepsAns.trim() || sample.stepsToReproduce,
          browserInfo: 'Node.js interactive test client',
          timestamp: new Date().toISOString(),
          website: ''
        };

        const endpoint = chosenType === 'suggestion' ? '/api/add-suggestion' : '/api/bug-reports';
        const url = `${BASE_URL.replace(/\/$/, '')}${endpoint}`;
        console.log(`Submitting ${chosenType} to ${url}`);
        try {
          const result = await postJson(url, payload);
          console.log('Response status:', result.status);
          console.log('Response body:', result.body);
        } catch (err) {
          console.error('Request failed:', err && err.message ? err.message : err);
        }
      } else if (choice === '6') {
        console.log('Bye');
        break;
      } else {
        console.log('Unknown option');
      }
    } catch (err) {
      console.error('Error:', err.message);
    }
  }
  rl.close();
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

    // Support `--help` / `-h` to print the help text and exit successfully
    if (cmd === '--help' || cmd === '-h') {
      printHelp();
      process.exit(0);
    }

  try {
    if (!cmd) { printHelp(); process.exit(0); }

    if (cmd === 'interactive') {
      await interactiveMenu();
    } else if (cmd === 'add-admin') {
      const [ , user, pass ] = process.argv;
      const username = argv[1] || user;
      const password = argv[2] || pass;
      if (!username || !password) { printHelp(); process.exit(1); }
      await backupCredentials();
      await addAdmin(username, password);
    } else if (cmd === 'bug' || cmd === 'suggestion') {
      // Support the old test-submit.js style: `bug` or `suggestion` positional command
      const type = cmd; // 'bug' or 'suggestion'
      const p = parseArgs(argv.slice(1));
      let payload = {};

      const wantInteractive = !p.flags.random && !p.flags.name && !p.flags.email && !p.flags.description && process.stdin.isTTY;
      if (wantInteractive) {
        const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
        const ask = (q) => new Promise((res) => rl.question(q, (ans) => res(ans)));

        const choice = (await ask('Choose report type: 1) Bug  2) Suggestion  [1]: ')).trim();
        const chosenType = (choice === '2') ? 'suggestion' : 'bug';

        const nameAns = (await ask('Name (leave blank to use sample): '));
        const emailAns = (await ask('Email (leave blank to use sample): '));
        const descAns = (await ask('Description (leave blank to use sample): '));
        const stepsAns = (await ask('Steps to reproduce (optional): '));
        rl.close();

        const sample = samplePayload(chosenType);
        payload.name = nameAns.trim() || sample.name;
        payload.email = emailAns.trim() || sample.email;
        payload.description = descAns.trim() || sample.description;
        payload.stepsToReproduce = stepsAns.trim() || sample.stepsToReproduce;
        payload.browserInfo = 'Node.js interactive test client';
        payload.timestamp = new Date().toISOString();
        payload.website = '';
        // override chosenType for endpoint selection
        const endpoint = chosenType === 'suggestion' ? '/api/add-suggestion' : '/api/bug-reports';
        const url = `${BASE_URL.replace(/\/$/, '')}${endpoint}`;
        console.log(`Submitting ${chosenType} to ${url}`);
        try {
          const result = await postJson(url, payload);
          console.log('Response status:', result.status);
          console.log('Response body:', result.body);
          if (!result.ok) process.exit(3);
        } catch (err) {
          console.error('Request failed:', err && err.message ? err.message : err);
          process.exit(4);
        }
      } else {
        // Non-interactive / flag mode
        const chosenType = type || 'bug';
        if (p.flags.random || p.flags.r) {
          payload = samplePayload(chosenType);
        } else {
          const sample = samplePayload(chosenType);
          payload.name = p.flags.name || p.flags.n || sample.name;
          payload.email = p.flags.email || p.flags.e || sample.email;
          payload.description = p.flags.description || p.flags.d || sample.description;
          payload.stepsToReproduce = p.flags.steps || p.flags.s || sample.stepsToReproduce;
          payload.browserInfo = p.flags.browser || 'Node.js test client';
          payload.timestamp = p.flags.timestamp || new Date().toISOString();
          payload.website = '';
        }

        const endpoint = chosenType === 'suggestion' ? '/api/add-suggestion' : '/api/bug-reports';
        const url = `${BASE_URL.replace(/\/$/, '')}${endpoint}`;

        console.log(`Submitting ${chosenType} to ${url}`);
        console.log('Payload preview:', { name: payload.name, email: payload.email, description: payload.description && payload.description.slice ? payload.description.slice(0, 120) + (payload.description.length > 120 ? '...' : '') : '' });

        try {
          const result = await postJson(url, payload);
          console.log('Response status:', result.status);
          console.log('Response body:', result.body);
          if (!result.ok) process.exit(3);
        } catch (err) {
          console.error('Request failed:', err && err.message ? err.message : err);
          process.exit(4);
        }
      }
    } else if (cmd === 'remove-admin') {
      const username = argv[1];
      if (!username) { printHelp(); process.exit(1); }
      await backupCredentials();
      await removeAdmin(username);
    } else if (cmd === 'list-admins') {
      await listAdmins();
    } else if (cmd === 'change-password') {
      const username = argv[1];
      const newPass = argv[2];
      if (!username || !newPass) { printHelp(); process.exit(1); }
      await backupCredentials();
      await changePassword(username, newPass);
  } else {
      printHelp();
      process.exit(1);
    }
  } catch (err) {
    console.error('Fatal error:', err.message);
    process.exit(1);
  }
}

if (require.main === module) main();
