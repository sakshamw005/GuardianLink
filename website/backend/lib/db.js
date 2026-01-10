const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(
  path.join(__dirname, '../db/guardianlink.db'),
  { verbose: console.log }
);

module.exports = db;