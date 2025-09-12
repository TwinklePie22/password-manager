// backend/routes/dashboard.js
const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');
const CryptoJS = require('crypto-js');
// const verifyToken = require('../middleware/verifyToken');
const logger = require('../logger');

const router = express.Router();

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Failed to authenticate token' });
    req.userId = decoded.id;
    next();
  });
};

const encryptionKey = process.env.ENCRYPTION_KEY;

if (!encryptionKey) {
  logger.error('ENCRYPTION_KEY is not set in environment variables');
  throw new Error('ENCRYPTION_KEY is not set');
}

const encryptPassword = (password) => {
  return CryptoJS.AES.encrypt(password, encryptionKey).toString();
};

const decryptPassword = (encryptedPassword) => {
  const bytes = CryptoJS.AES.decrypt(encryptedPassword, encryptionKey);
  return bytes.toString(CryptoJS.enc.Utf8);
};
// Get all credentials for a user
router.get('/credentials', verifyToken, async (req, res) => {
  try {
    const credentials = await new Promise((resolve, reject) => {
      db.all('SELECT * FROM credentials WHERE user_id = ?', [req.userId], (err, rows) => {
        if (err) {
          logger.error(`Database error fetching credentials: ${err.message}`);
          reject(err);
        }
        resolve(rows);
      });
    });

    const decryptedCredentials = credentials.map(cred => ({
      ...cred,
      password: decryptPassword(cred.password)
    }));

    res.json(decryptedCredentials);
  } catch (error) {
    logger.error(`Error fetching credentials: ${error.message}`);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Add a new credential
// Update the add credential route
router.post('/credentials', verifyToken, async (req, res) => {
  const { site, username, password } = req.body;

  try {
    if (!site || !username || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const encryptedPassword = encryptPassword(password);

    await new Promise((resolve, reject) => {
      db.run('INSERT INTO credentials (user_id, site, username, password) VALUES (?, ?, ?, ?)', 
        [req.userId, site, username, encryptedPassword], (err) => {
          if (err) {
            logger.error(`Database error during credential insertion: ${err.message}`);
            reject(err);
          }
          resolve(this.lastID);
      });
    });

    logger.info(`New credential added for user ID: ${req.userId}`);
    res.status(201).json({ message: 'Credential added successfully' });
  } catch (error) {
    logger.error(`Error adding credential: ${error.message}`);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});


// Update a credential
router.put('/credentials/:id', verifyToken, async (req, res) => {

  const { site, username, password } = req.body;
  const { id } = req.params;

  try {
    await new Promise((resolve, reject) => {
      db.run('UPDATE credentials SET site = ?, username = ?, password = ? WHERE id = ? AND user_id = ?', 
        [site, username, password, id, req.userId], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Credential updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a credential
router.delete('/credentials/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM credentials WHERE id = ? AND user_id = ?', [id, req.userId], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Credential deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;