// backend/view_data.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'password_manager.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database', err);
  } else {
    console.log('Connected to the SQLite database.');
    
    // View users
    db.all("SELECT * FROM users", [], (err, rows) => {
      if (err) {
        throw err;
      }
      console.log("Users:");
      console.log(rows);
    });

    // View credentials
    db.all("SELECT * FROM credentials", [], (err, rows) => {
      if (err) {
        throw err;
      }
      console.log("Credentials:");
      console.log(rows);
    });

    // Close the database connection
    db.close((err) => {
      if (err) {
        console.error(err.message);
      }
      console.log('Closed the database connection.');
    });
  }
});