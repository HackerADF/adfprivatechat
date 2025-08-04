let serverStatus = "enabled  ";

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const sharedSession = require('express-socket.io-session');
const fetch = require('node-fetch');
const webpush = require('web-push');

const db = new sqlite3.Database('users.db');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      muted TEXT,
      banned TEXT,
      staff TEXT,
      level INTEGER,
      rank TEXT,
      session_id TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY,
      theme TEXT DEFAULT 'light',
      notifications BOOLEAN DEFAULT true,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
  
});

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const userSockets = new Map();
const permissions = {
  1: ['mute_user'],           
  2: ['mute_user', 'ban_user'],
  3: ['change_username', 'kick_user', 'mute_user', 'ban_user'],
  3.5: ['change_username', 'kick_user', 'mute_user', 'ban_user', 'create_login', 'remove_login'],
  4: ['create_login', 'remove_login', 'mute_user', 'ban_user', 'change_username', 'kick_user', 'modify_rank'],
  10: ['create_login', 'remove_login', 'mute_user', 'ban_user', 'change_username', 'kick_user', 'modify_rank']
};

const rankStyles = {
  'member':        { label: '', color: '', icon: '' },
  'vip':           { label: 'VIP', color: '#fcba03', icon: '⭐' },
  'vipplus':       { label: 'VIP+', color: '#00ff6a', icon: '🌟' },
  'official':      { label: 'Official', color: '#4CAF50', icon: '✔️' },
  'helper':        { label: 'Helper', color: '#00ff00', icon: '⚔️' },
  'moderator':     { label: 'Moderator', color: '#4061d6', icon: '🛡️' },
  'seniormoderator': { label: 'Sr. Moderator', color: '#4061d6', icon: '🛠️' },
  'developer':     { label: 'Developer', color: '#800055', icon: '💻' },
  'verifiedstaff': { label: 'Staff', color: '#2196F3', icon: '⚒️' },
  'owner':         { label: 'Owner', color: '#e81717', icon: '👑' },
};

function getPermissions(level) {
  return permissions[level] || permissions[1]; 
}

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
const sessionStore = new session.MemoryStore();

// Session setup
const sessionMiddleware = session({
  secret: 'super-secret-adf-key', // Change this for production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false },
  store: sessionStore,
});

app.use(express.json()); // arses JSON bodies
app.use(express.urlencoded({ extended: true }));
app.use(sessionMiddleware);

// Register a new user
function registerUser(username, password, callback) {
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return callback(err);

    const query = `INSERT INTO users (username, password, rank) VALUES (?, ?, ?)`;
    db.run(query, [username, hash, "member"], function (err) {
      if (err) return callback(err);
      callback(null, { id: this.lastID, username });
    });
  });
}

// Authenticate a user
function authenticateUser(username, password, callback) {
  const query = `SELECT * FROM users WHERE username = ?`;
  db.get(query, [username], (err, row) => {
    if (err) return callback(err);
    if (!row) return callback(null, false);

    bcrypt.compare(password, row.password, (err, result) => {
      if (err) return callback(err);
      callback(null, result ? row : false);
    });
  });
}

function updateUserSettings(userId, theme, notifications, callback) {
  const query = `
    UPDATE user_settings 
    SET theme = ?, notifications = ? 
    WHERE user_id = ?;
  `;
  db.run(query, [theme, notifications, userId], function(err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
}

// Get current user settings
function getUserSettings(userId, callback) {
  const query = `SELECT * FROM user_settings WHERE user_id = ?`;
  db.get(query, [userId], (err, settings) => {
    if (err) return callback(err);
    callback(null, settings);
  });
}

function broadcastMemberList() {
  db.all('SELECT username, rank, online FROM users', (err, rows) => {
    if (err) return;

    const online = {};
    const offline = [];

    rows.forEach(user => {
      if (user.online) {
        if (!online[user.rank]) online[user.rank] = [];
        online[user.rank].push(user);
      } else {
        offline.push(user);
      }
    });

    io.emit('update-members', { online, offline });
  });
}

app.use((req, res, next) => {
  if (serverStatus === "disabled" && req.path !== "/status") {
    return res.redirect("/status");
  }
  next();
});

app.get('/offline', (req, res) => {
  if (serverStatus !== "disabled") {
    res.redirect('/status');
  }
});

app.get('/online', (req, res) => {
  if (serverStatus !== "disabled") {
    res.redirect('/status');
  }
});

app.get('/status', (req, res) => {
  const statusPage = serverStatus === "disabled" ? 'offline.html' : 'online.html';
  res.sendFile(path.join(__dirname, 'public', statusPage));
});

app.get('/', (req, res) => {
  if (serverStatus === "disabled") {
    res.sendFile(path.join(__dirname, 'public', 'offline.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

app.get('/favicon.ico', (req, res) => {
  res.redirect('https://cdn.glitch.global/69264440-8ac3-4147-9e23-e5d81d9b7ac1/project.webp?v=1745362993382');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/chat', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const username = req.session.user.username;

  db.get('SELECT banned FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Internal server error');
    }

    if (!row || row.banned === 1) {
      req.session.destroy(() => {
        return res.redirect('/login?reason=banned');
      });
    } else {
      res.sendFile(path.join(__dirname, 'public', 'chat.html'));
    }
  });
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect('/');


  function generateUserId() {
    let id = '';
    for (let i = 0; i < 15; i++) {
      id += Math.floor(Math.random() * 10);
    }
    return id;
  }

  function createUniqueUser(callback) {
    const userId = generateUserId();
    db.get('SELECT id FROM users WHERE id = ?', [userId], (err, row) => {
      if (err) return callback(err);
      if (row) return createUniqueUser(callback);
      callback(null, userId);
    });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.sendStatus(500);

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        req.session.user = { id: user.id, username: user.username };
        return res.redirect('/chat');
      } else {
        return res.send('Invalid password. <a href="/">Try again</a>');
      }
    } else {
      createUniqueUser(async (err, newUserId) => {
        if (err) return res.send('Error generating user ID. <a href="/">Try again</a>');

        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (id, username, password, staff, level, rank, online) VALUES (?, ?, ?, ?, ?, ?, ?)', [newUserId, username, hash, false, 0, "member", 1], function (err) {
      
          if (err) return res.send('Error creating account. <a href="/">Try again</a>');
          broadcastMemberList();
          req.session.user = { id: newUserId, username };
          db.run('INSERT INTO user_settings (user_id) VALUES (?)', [newUserId]);
            return res.json({ success: true });
        });
      });
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false, message: 'Please fill in both fields.' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.json({ success: false, message: 'Server error.' });
    if (!user) return res.json({ success: false, message: 'Invalid username or password.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, message: 'Invalid username or password.' });
    
    req.session.user = {
      id: user.id,
      username: user.username
    };

    db.run('UPDATE users SET session_id = ? WHERE id = ?', [req.sessionID, user.id], (err) => {
      if (err) console.error('Failed to save session ID:', err);
    });

    req.session.username = username;
    req.session.user = { id: user.id, username: user.username, token: req.sessionID };
    return res.json({ success: true });
  });
});

app.get("/offline", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "offline.html"));
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Error logging out");
        }
        res.redirect('/login');
    });
});

app.get('/settings', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const userId = req.session.user.id;

  getUserSettings(userId, (err, settings) => {
    if (err) return res.sendStatus(500);
    res.json(settings);
  });
});

app.get('/settings', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  const { theme, notifications } = req.body;
  const userId = req.session.user.id;

  updateUserSettings(userId, theme, notifications, (err, result) => {
    if (err) {
      return res.status(500).send('Error updating settings');
    }
    res.json({ success: true, changes: result.changes });
  });
});

app.get('/staff', (req, res) => {
  if (!req.session.staff) {
    return res.redirect('/staff/signin');
  }

  const staff = req.session.staff;
  res.sendFile(path.join(__dirname, 'public', 'staff.html'));
});

app.get('/test', (req, res) => {
  res.send('Test route working');
});

app.get('/mute', (req, res) => {
  res.send('GET request to /mute');
});

const allowedToMute = ['adminUser1', 'moderatorRylen', 'ADF', 'Owner | ADF'];

app.post('/mute', (req, res) => {
  const { targetUsername } = req.body;
  const currentUser = req.session.user; 

  console.log(req.body);

  if (!currentUser) {
    return res.status(403).json({ success: false, message: 'You must be logged in to mute users.' });
  }

  db.get(`SELECT staff, level FROM users WHERE username = ?`, [currentUser.username], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error.' });
    if (!row) return res.status(404).json({ success: false, message: 'Authentication error.' });

    if (row.staff === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to mute users.' });
    }
    
    const userPermissions = permissions[row.level] || [];

    if (!userPermissions.includes('mute_user')) {
      return res.status(403).json({ success: false, message: 'You do not have permission to mute users.' });
    }

  
    db.get('SELECT id, muted FROM users WHERE username = ?', [targetUsername], (err, row) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error.' });
      if (!row) return res.status(404).json({ success: false, message: 'Target user does not exist.' });

      if (row.muted === 1) {
        return res.status(409).json({ success: false, message: 'User is already muted.' });
      }

      db.run('UPDATE users SET muted = 1 WHERE id = ?', [row.id], function (updateErr) {
        if (updateErr) return res.status(500).json({ success: false, message: 'Failed to mute user.' });

        io.emit("system message", `${targetUsername} has been muted by ${currentUser.username}.`);
        return res.json({ success: true, message: `${targetUsername} has been muted.` });
      });
    });
  });
});

app.post('/unmute', (req, res) => {
  const { targetUsername } = req.body;
  const currentUser = req.session.user;

  if (!currentUser) {
    return res.status(403).json({ success: false, message: 'You must be logged in to unmute users.' });
  }
 
  db.get(`SELECT staff, level FROM users WHERE username = ?`, [currentUser.username], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error.' });
    if (!row) return res.status(404).json({ success: false, message: 'Authentication error.' });

    if (row.staff === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to unmute users.' });
    }
    
    const userPermissions = permissions[row.level] || [];

    if (!userPermissions.includes('mute_user')) {
      return res.status(403).json({ success: false, message: 'You do not have permission to unmute users.' });
    }

    db.get(`SELECT id, muted FROM users WHERE username = ?`, [targetUsername], (err, targetRow) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error.' });
      if (!targetRow) return res.status(404).json({ success: false, message: 'Target user does not exist.' });

      if (targetRow.muted === 0) {
        return res.status(409).json({ success: false, message: 'User is not muted.' });
      }

      db.run(`UPDATE users SET muted = 0 WHERE id = ?`, [targetRow.id], function (updateErr) {
        if (updateErr) return res.status(500).json({ success: false, message: 'Failed to unmute user.' });

        io.emit("system message", `${targetUsername} has been unmuted by ${currentUser.username}.`);
        return res.json({ success: true, message: `${targetUsername} has been unmuted.` });
      });
    });
  });
});

app.post('/ban', (req, res) => {
  const { targetUsername } = req.body;
  const currentUser = req.session.user;

  if (!currentUser) {
    return res.status(403).json({ success: false, message: 'You must be logged in to ban users.' });
  }

  db.get('SELECT staff, level FROM users WHERE username = ?', [currentUser.username], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error.' });
    if (!row) return res.status(404).json({ success: false, message: 'Authentication error.' });

    if (row.staff === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to ban users.' });
    }

    const userPermissions = permissions[row.level] || [];

    if (!userPermissions.includes('ban_user')) {
      return res.status(403).json({ success: false, message: 'You do not have permission to ban users.' });
    }

    db.get('SELECT id, banned, session_id FROM users WHERE username = ?', [targetUsername], (err, targetRow) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error.' });
      if (!targetRow) return res.status(404).json({ success: false, message: 'Target user does not exist.' });

      if (targetRow.banned === 1) {
        return res.status(409).json({ success: false, message: 'User is already banned.' });
      }

      db.run('UPDATE users SET banned = 1 WHERE id = ?', [targetRow.id], (updateErr) => {
        if (updateErr) return res.status(500).json({ success: false, message: 'Failed to ban user.' });

        if (targetRow.session_id && sessionStore) {
          console.log(`Destroying session for ${targetUsername}...`);

          sessionStore.destroy(targetRow.session_id, (destroyErr) => {
            if (destroyErr) {
              console.error(`Failed to destroy session for ${targetUsername}:`, destroyErr);
            } else {
              console.log(`Session for ${targetUsername} destroyed.`);
            }
          });
        } else {
          res.json({ success: true, message: `${targetUsername} has been banned.` });
        }
        const socketId = userSockets.get(targetRow.id);
          
        if (socketId) {
          io.to(socketId).emit('ban_notification');
        }
        io.emit("system message", `${targetUsername} has been banned by ${currentUser.username}.`);
      });
    });
  });
});


app.post('/unban', (req, res) => {
  const { targetUsername } = req.body;
  const currentUser = req.session.user;

  if (!currentUser) {
    return res.status(403).json({ success: false, message: 'You must be logged in to unban users.' });
  }

  db.get('SELECT staff, level FROM users WHERE username = ?', [currentUser.username], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error.' });
    if (!row) return res.status(404).json({ success: false, message: 'Authentication error.' });

    if (row.staff === 0) {
      return res.status(403).json({ success: false, message: 'You do not have permission to unban users.' });
    }

    const userPermissions = permissions[row.level] || [];
    if (!userPermissions.includes('ban_user')) {
      return res.status(403).json({ success: false, message: 'You do not have permission to unban users.' });
    }

    db.get('SELECT id, banned FROM users WHERE username = ?', [targetUsername], (err, targetRow) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error.' });
      if (!targetRow) return res.status(404).json({ success: false, message: 'Target user does not exist.' });

      if (targetRow.banned === 0) {
        return res.status(409).json({ success: false, message: 'User is not banned.' });
      }

      db.run(`UPDATE users SET banned = 0 WHERE id = ?`, [targetRow.id], function (updateErr) {
        if (updateErr) return res.status(500).json({ success: false, message: 'Failed to unban user.' });

        io.emit("system message", `${targetUsername} has been unbanned by ${currentUser.username}.`);
        return res.json({ success: true, message: `${targetUsername} has been unbanned.` });
      });
    });
  });
});

app.post('/setrank', (req, res) => {
  const { targetUsername, rankInput } = req.body;
  const currentUser = req.session.user;

  if (!currentUser) {
    return res.status(403).json({ success: false, message: 'You must be logged in to set ranks.' });
  }

  const allowedRanks = {
    helper:            { rank: "helper", level: 1, staff: 1 },
    moderator:         { rank: "moderator", level: 2, staff: 1 },
    seniormoderator:   { rank: "seniormoderator", level: 3, staff: 1 },
    srmod:             { rank: "seniormoderator", level: 3, staff: 1 },
    dev:               { rank: "developer", level: 3.5, staff: 1 },
    developer:         { rank: "developer", level: 3.5, staff: 1 },
    admin:             { rank: "verifiedstaff", level: 4, staff: 1 },
    administrator:     { rank: "verifiedstaff", level: 4, staff: 1 },
    vip:               { rank: "vip", staff: 0 },
    vipplus:           { rank: "vipplus", staff: 0 },
    member:            { rank: "member", staff: 0 },
  };

  const rankConfig = allowedRanks[rankInput];
  if (!rankConfig) {
    return res.status(400).json({ success: false, message: 'Invalid rank specified.' });
  }

  db.get(`SELECT staff, level FROM users WHERE username = ?`, [currentUser.username], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'Database error.' });
    if (!row) return res.status(404).json({ success: false, message: 'Authentication error.' });

    const userPermissions = permissions[row.level] || [];

    if (!userPermissions.includes('modify_rank')) {
      return res.status(403).json({ success: false, message: 'You do not have permission to modify ranks.' });
    }

    db.get('SELECT id, level FROM users WHERE LOWER(username) = LOWER(?)', [targetUsername], (err, userRow) => {
      if (err) return res.status(500).json({ success: false, message: 'Database error.' });
      if (!userRow) return res.status(404).json({ success: false, message: 'Target user does not exist.' });

      const levelToSet = rankConfig.hasOwnProperty("level") ? rankConfig.level : userRow.level;

      db.run(
        `UPDATE users SET rank = ?, level = ?, staff = ? WHERE id = ?`,
        [rankConfig.rank, levelToSet, rankConfig.staff, userRow.id],
        function (updateErr) {
          if (updateErr) return res.status(500).json({ success: false, message: 'Failed to update rank.' });

          io.emit("rank message", `${currentUser.username} has set ${targetUsername}'s rank to ${rankConfig.rank}.`);
          broadcastMemberList();
          return res.json({ success: true, message: `${targetUsername} has been ranked to ${rankConfig.rank}.`, rank: rankConfig.rank });
        }
      );
    });
  });
  broadcastMemberList();
});

app.post('/staff/signin', (req, res) => {
  const { username, password } = req.body;
  if (username === 'adf' && password === 'null!') {
    req.session.staff = { username: 'adf', level: 4 };
    return res.redirect('/staff');
  }

  db.get('SELECT * FROM staff WHERE username = ?', [username], async (err, staff) => {
    if (err) return res.sendStatus(500);
    if (!staff) return res.send('Invalid credentials. <a href="/staff/signin">Try again</a>');

    const match = await bcrypt.compare(password, staff.password);
    if (!match) return res.send('Invalid credentials. <a href="/staff/signin">Try again</a>');

    req.session.staff = { username: staff.username, level: staff.level };
    return res.redirect('/staff');
  });
});

app.get('/staff', (req, res) => {
  if (!req.session.staff) {
    return res.redirect('/staff/signin');
  }

  const staff = req.session.staff;
  const userPermissions = permissions[staff.level] || [];

  res.render('staff', { 
    username: staff.username,
    level: staff.level,
    permissions: userPermissions 
  });
});

app.get('/api/check-username', (req, res) => {
  const username = req.query.username ? req.query.username.toLowerCase() : undefined;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  const query = `SELECT * FROM users WHERE LOWER(username) = ?`;
  db.get(query, [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Error checking username.' });
    res.json({ exists: !!user });
  });
});

app.get('/api/members', (req, res) => {
  db.all('SELECT id, username, rank, online FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err });

    const online = {};
    const offline = [];

    rows.forEach(user => {
      if (user.online) {
        if (!online[user.rank]) online[user.rank] = [];
        online[user.rank].push(user);
      } else {
        offline.push(user);
      }
    });

    res.json({ online, offline });
  });
});

app.post("/change-username", (req, res) => {
  const user = req.session.user; // Ensure user is logged in via session
  const newUsernameRaw = req.body.newUsername;
  const password = req.body.password; // <-- Get the password from the request

  if (!user) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  if (!newUsernameRaw || typeof newUsernameRaw !== "string" || !password || typeof password !== "string") {
    return res.json({ success: false, message: "Invalid request." });
  }

  const newUsername = newUsernameRaw.trim();
  const newUsernameLower = newUsername.toLowerCase();

  const forbiddenWords = [
    "owner", "mod", "admin", "staff", "helper", "adf", "nsh", "nicole107h", "tractors101",
    "fuck", "shit", "bitch", "ass", "nigger", "nigga", "founder", "faggot", "hoe", "shigga",
    "yn", "bich", "niga"
  ];

  if (newUsername.length < 3) {
    return res.json({ success: false, message: "Username must be at least 3 characters long." });
  }

  const usernameRegex = /^[a-z0-9_\.]+$/i;
  if (!usernameRegex.test(newUsernameLower)) {
    return res.json({ success: false, message: "Username can only contain letters, numbers, underscores, and periods." });
  }

  for (const word of forbiddenWords) {
    if (newUsernameLower.includes(word)) {
      return res.json({ success: false, message: `Username cannot contain restricted words like "${word}".` });
    }
  }

  // First, verify the user's password
  const sqlPasswordCheck = "SELECT password FROM users WHERE username = ?";
  db.get(sqlPasswordCheck, [user.username], (err, row) => {
    if (err) {
      console.error("Database error during password check:", err);
      return res.status(500).json({ success: false, message: "Server error." });
    }

    if (!row) {
      return res.status(400).json({ success: false, message: "User not found." });
    }

    // Assuming passwords are hashed!
    const bcrypt = require("bcrypt"); // Make sure you have bcrypt installed
    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ success: false, message: "Server error." });
      }

      if (!isMatch) {
        return res.json({ success: false, message: "Incorrect password." });
      }

      // Password is correct, now check if username is taken
      const sqlCheck = "SELECT id FROM users WHERE LOWER(username) = ?";
      db.get(sqlCheck, [newUsernameLower], (err, row) => {
        if (err) {
          console.error("Database error during username check:", err);
          return res.status(500).json({ success: false, message: "Server error." });
        }

        if (row) {
          return res.json({ success: false, message: "Username is already taken." });
        }

        // Update username
        const sqlUpdate = "UPDATE users SET username = ? WHERE username = ?";
        db.run(sqlUpdate, [newUsername, user.username], function (err) {
          if (err) {
            console.error("Error updating username:", err);
            return res.status(500).json({ success: false, message: "Could not update username." });
          }

          // Update session too
          req.session.user.username = newUsername;

          return res.json({ success: true, message: "Username changed successfully." });
        });
      });
    });
  });
});

app.get('/check-staff', (req, res) => {
  const username = req.session.username;

  db.get("SELECT staff FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      return res.status(500).json({ error: "DB error" });
    }

    if (row && row.staff === 1) {
      return res.json({ staff: true });
    }

    return res.json({ staff: false });
  });
});

io.use(sharedSession(sessionMiddleware, {
  autoSave: true
}));

// Socket.io logic
const userMessageTimestamps = new Map();
const userMutedThisSession = new Set();

io.on('connection', (socket) => {
  const user = socket.handshake.session.user;
  
  if (user) {
    userSockets.set(user.id, socket.id);
    console.log(`[Connection] ${user.username} connected (ID: ${user.id})`);
    io.emit("connection join", `${user.username} has joined the chat!`);
    db.run('UPDATE users SET online = 1 WHERE id = ?', [user.id]);
    broadcastMemberList();

    socket.on('chat message', (msg) => {
      console.log(`[Chat] Message received from ${user.username}: "${msg}"`);

      const now = Date.now();
      const history = userMessageTimestamps.get(user.id) || [];
      const recent = history.filter(ts => now - ts < 5000); // 5-second threshold
      recent.push(now);
      userMessageTimestamps.set(user.id, recent);

      console.log(`[Spam Check] ${user.username} has sent ${recent.length} messages in the last 5 seconds`);

      if (recent.length > 8 && !userMutedThisSession.has(user.id)) {
        console.log(`[Spam Triggered] ${user.username} exceeded message limit. Muting...`);

        userMutedThisSession.add(user.id);

        db.run('UPDATE users SET muted = 1 WHERE id = ?', [user.id], (err) => {
          if (err) console.log(`[DB Error] Failed to mute ${user.username}:`, err);
          else console.log(`[DB] ${user.username} was successfully muted in the database`);
        });

        socket.emit('chat message', {
          user: 'System',
          message: 'You have been automatically muted for spamming.',
        });

        io.emit("system message", `${user.username} has been muted by System, for: Spam.`);
        return;
      }

      db.get('SELECT muted, rank FROM users WHERE id = ?', [user.id], (err, row) => {
        if (err) {
          console.log('[DB Error] Error checking mute status:', err);
          return;
        }

        if (row.muted === 1) {
          console.log(`[Muted] ${user.username} attempted to send a message but is muted.`);
          
        const rankInfo = rankStyles['official'] || rankStyles[''];
        const formattedUsername = rankInfo.label
          ? `${rankInfo.icon} <span style="color: ${rankInfo.color}">${rankInfo.label}</span> <span style="margin-left: 8px;">System</span>`
          : user.username;
          
          socket.emit('chat message', {
            user: formattedUsername,
            message: 'You are muted and cannot send messages.',
          });
          return;
        }

        const rankInfo = rankStyles[row.rank] || rankStyles[''];
        console.log(`[Rank Check] ${user.username} has rank "${row.rank}"`);
        const formattedUsername = rankInfo.label
          ? `${rankInfo.icon} <span style="color: ${rankInfo.color}">${rankInfo.label}</span> <span style="margin-left: 8px;">${user.username}</span>`
          : user.username;
        console.log(`FULL USERNAME ${formattedUsername}`);

        console.log(`[Message Allowed] ${user.username} (${row.rank || 'no rank'}) -> "${msg}"`);
        io.emit('chat message', {
          user: formattedUsername,
          message: msg,
          timestamp: new Date().toLocaleTimeString(),
        });

        fetch('https://discord.com/api/webhooks/1365189368788287529/IR4MGzgMepCk0rNXhMxVhCEDjOXCajJZZ7982krAs-CItr3jgJooePFco5IFVDZrSC4Y', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            embeds: [
              {
                title: `${rankInfo.icon || ''} ${rankInfo.label || ''} ${user.username}`,
                description: msg.message, // Ensure msg is a string
                color: parseInt((rankInfo.color || '#3498db').replace('#', ''), 16),
                timestamp: new Date().toISOString()
              }
            ]
          })
        })
        .then(res => res.json())
        .then(data => {
          console.log('[Discord Webhook] Response:', data);
        })
        .catch(err => console.error('[Discord Webhook Error]', err));

      });
    });

    socket.on('disconnect', () => {
      console.log(`[Disconnection] ${user.username} disconnected`);
      io.emit("connection leave", `${user.username} has left the chat.`);
      db.run('UPDATE users SET online = 0 WHERE id = ?', [user.id]);
      broadcastMemberList();
      userMessageTimestamps.delete(user.id);
      userSockets.delete(user.id);
    });

  } else {
    console.log('[Connection] Anonymous user connected — no session.user found');
  }
});
 


app.use((req, res) => {
  res.status(404).sendFile(__dirname + '/public/404.html');
});


// Start serverr
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  db.run('UPDATE users SET online = 0');
  console.log(`✅ Server running at http://localhost:${PORT}`);
  fetch('https://discord.com/api/webhooks/1365189368788287529/IR4MGzgMepCk0rNXhMxVhCEDjOXCajJZZ7982krAs-CItr3jgJooePFco5IFVDZrSC4Y', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      embeds: [
        {
          title: `Server Status`,
          description: "**One of ADF Private Chat's official servers has started!**",
          color: parseInt(("#42f5a1" || '#3498db').replace('#', ''), 16),
          footer: {
            text: "Server: APC Main NA-WEST-01",
          },
          timestamp: new Date().toISOString()
        }
      ]
    })
  })
  .then(res => res.json())
  .then(data => {
    console.log('[Discord Webhook] Response:', data);
  })
  .catch(err => console.error('[Discord Webhook Error]', err));
  setTimeout(() => {
    io.emit("startup");
    broadcastMemberList();
}, 2000);
});