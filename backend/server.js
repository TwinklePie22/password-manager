// backend/server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const logger = require('./logger');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const {authenticate} = require('@google-cloud/local-auth');
const {google} = require('googleapis');
const punycode = require('punycode.js');

const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 5000;

process.removeAllListeners('warning');
process.on('warning', (warning) => {
  if (warning.name === 'DeprecationWarning' && warning.message.includes('punycode')) {
    return;
  }
  console.warn(warning);
});


const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Apply stricter rate limiting to login attempts
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login requests per windowMs
  message: 'Too many login attempts, please try again after 5 minutes'
});


app.use(cors());
app.use(express.json());
// app.use(credential.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }));


app.use(limiter);

app.use('/api', authRoutes);
app.use('/api', dashboardRoutes);

app.use('/api/login', loginLimiter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});