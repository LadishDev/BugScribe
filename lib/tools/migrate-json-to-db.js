const path = require('path');
const fs = require('fs-extra');
const db = require('../db');

async function main() {
  // When moved to lib/tools, repo root is two levels up from this file
  const root = path.join(__dirname, '..', '..');
  const dataDir = path.join(root, 'data');
  const bugFile = path.join(dataDir, 'bug-reports.json');
  const suggestionsFile = path.join(dataDir, 'suggestions-reports.json');

  if (!await fs.pathExists(bugFile)) {
    console.error('No bug-reports.json found at', bugFile);
    process.exit(1);
  }

  const reports = await fs.readJson(bugFile);
  const suggestions = await (await fs.pathExists(suggestionsFile) ? fs.readJson(suggestionsFile) : []);

  try {
    await db.init();
  } catch (err) {
    console.error('DB init failed:', err);
    process.exit(1);
  }

  try {
    console.log(`Migrating ${reports.length} bug reports...`);
    await db.writeBugReports(reports);
    console.log('Bug reports migrated.');

    console.log(`Migrating ${suggestions.length} suggestions...`);
    await db.writeSuggestions(suggestions);
    console.log('Suggestions migrated.');

    console.log('Migration complete.');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  }
}

main();
