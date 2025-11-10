#!/usr/bin/env node
// scripts/test-submit.js
// Simple tester to submit a bug or suggestion to the local BugScribe server.
// Usage examples:
//   node scripts/test-submit.js bug --name "Alice" --email "a@ex.com" --description "Found a bug" 
//   node scripts/test-submit.js suggestion --random
// Notes:
// - Reads PORT from .env (via dotenv) and defaults to http://localhost:3001
// - Sends JSON (application/json). The server accepts JSON for both endpoints.
// - Make sure the server is running before using this script.

require('dotenv').config();

const { argv, exit } = require('process');
const readline = require('readline');

const BASE_URL = (process.env.BASE_URL) || `http://localhost:${process.env.PORT || 3001}`;

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

async function postJson(url, body) {
  // prefer global fetch (Node 18+). If unavailable, instruct the user to run with Node 18+ or install node-fetch.
  if (typeof fetch === 'undefined') {
    console.error('fetch is not available in this Node runtime. Please run with Node 18+ or install node-fetch.');
    console.error('If installing node-fetch: npm install node-fetch@2 and modify this script to require it.');
    process.exit(2);
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

(async function main() {
  const p = parseArgs(argv.slice(2));
  const pos = p._;
  let type = (pos[0] && (pos[0] === 'suggestion' || pos[0] === 'bug')) ? pos[0] : null;

  let payload = {};

  // Interactive mode if no positional type and no identifying flags and stdin is a TTY
  const wantInteractive = !type && !p.flags.random && !p.flags.name && !p.flags.email && !p.flags.description && process.stdin.isTTY;

  if (wantInteractive) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q) => new Promise((res) => rl.question(q, (ans) => res(ans)));

    const choice = (await ask('Choose report type: 1) Bug  2) Suggestion  [1]: ')).trim();
    type = (choice === '2') ? 'suggestion' : 'bug';

    const nameAns = (await ask('Name (leave blank to use sample): '));
    const emailAns = (await ask('Email (leave blank to use sample): '));
    const descAns = (await ask('Description (leave blank to use sample): '));
    const stepsAns = (await ask('Steps to reproduce (optional): '));
    rl.close();

    const sample = samplePayload(type);
    payload.name = nameAns.trim() || sample.name;
    payload.email = emailAns.trim() || sample.email;
    payload.description = descAns.trim() || sample.description;
    payload.stepsToReproduce = stepsAns.trim() || sample.stepsToReproduce;
    payload.browserInfo = 'Node.js interactive test client';
    payload.timestamp = new Date().toISOString();
    payload.website = '';

  } else {
    // Non-interactive / flag mode
    type = type || 'bug';
    if (p.flags.random || p.flags.r) {
      payload = samplePayload(type);
    } else {
      // Build payload from flags or fall back to sample values
      const sample = samplePayload(type);
      payload.name = p.flags.name || p.flags.n || sample.name;
      payload.email = p.flags.email || p.flags.e || sample.email;
      payload.description = p.flags.description || p.flags.d || sample.description;
      payload.stepsToReproduce = p.flags.steps || p.flags.s || sample.stepsToReproduce;
      payload.browserInfo = p.flags.browser || 'Node.js test client';
      payload.timestamp = p.flags.timestamp || new Date().toISOString();
      payload.website = '';
    }
  }

  const endpoint = type === 'suggestion' ? '/api/add-suggestion' : '/api/bug-reports';
  const url = `${BASE_URL.replace(/\/$/, '')}${endpoint}`;

  console.log(`Submitting ${type} to ${url}`);
  console.log('Payload preview:', { name: payload.name, email: payload.email, description: payload.description.slice(0, 120) + (payload.description.length > 120 ? '...' : '') });

  try {
    const result = await postJson(url, payload);
    console.log('Response status:', result.status);
    console.log('Response body:', result.body);
    if (!result.ok) process.exit(3);
  } catch (err) {
    console.error('Request failed:', err && err.message ? err.message : err);
    process.exit(4);
  }
})();
