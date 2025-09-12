// backend/db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.resolve(__dirname, "password_manager.sqlite");

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Error opening database", err);
  } else {
    console.log("Connected to the SQLite database.");
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      username TEXT UNIQUE,
      phone TEXT,
      password TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      site TEXT,
      username TEXT,
      password TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    // In your server.js or where you set up your database
    db.get("SELECT 1", (err, row) => {
      if (err) {
        console.error("Database connection error:", err);
      } else {
        console.log("Database connection successful");
      }
    });
    db.all("SELECT * FROM users", [], (err, rows) => {
      if (err) {
        console.error("Error fetching users:", err);
      } else {
        console.log("All users:", rows);
      }
    });
  }
});

module.exports = db;
