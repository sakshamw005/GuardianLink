const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH =
  process.env.DB_PATH || path.join(__dirname, '../db/guardianlink.db');
  
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH, { verbose: console.log });

module.exports = db;