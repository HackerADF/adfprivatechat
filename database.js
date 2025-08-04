const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

// Create or open the database
const db = new sqlite3.Database('users.db');

// Create the users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  // Create the user_settings table if it doesn't exist
  db.run(`
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY,
      theme TEXT DEFAULT 'light',
      notifications BOOLEAN DEFAULT true,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Register a new user
function registerUser(username, password, callback) {
  // Hash password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return callback(err);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, hash], function (err) {
      if (err) return callback(err);
      // After registering user, insert default settings into user_settings table
      const userId = this.lastID;
      const insertSettingsQuery = `INSERT INTO user_settings (user_id) VALUES (?)`;
      db.run(insertSettingsQuery, [userId], (err) => {
        if (err) return callback(err);
        callback(null, { id: userId, username });
      });
    });
  });
}

// Authenticate a user
function authenticateUser(username, password, callback) {
  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [username], (err, row) => {
    if (err) return callback(err);
    if (!row) return callback(null, false); // User not found

    // Compare password with hash
    bcrypt.compare(password, row.password, (err, result) => {
      if (err) return callback(err);
      callback(null, result ? row : false); // result is true if match
    });
  });
}

// Get all users (for debugging/admin)
function getAllUsers(callback) {
  db.all(`SELECT id, username FROM users`, [], callback);
}

// Get user settings
function getUserSettings(userId, callback) {
  const query = `SELECT * FROM user_settings WHERE user_id = ?`;
  db.get(query, [userId], (err, settings) => {
    if (err) return callback(err);
    callback(null, settings);
  });
}

// Update user settings
function updateUserSettings(userId, theme, notifications, callback) {
  const query = `
    UPDATE user_settings
    SET theme = ?, notifications = ?
    WHERE user_id = ?;
  `;
  db.run(query, [theme, notifications, userId], function (err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
}

module.exports = {
  registerUser,
  authenticateUser,
  getAllUsers,
  getUserSettings,
  updateUserSettings
};
