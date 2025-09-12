// backend/routes/auth.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../db");
const yup = require("yup");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const logger = require("../logger");
const verifyToken = require("../middleware/VerifyToken");
const bodyParser = require("body-parser");
// const { authorize, sendMail } = require('../gmail');
// At the top of auth.js
const { sendPasswordResetEmail } = require('../emailService');
// const trimmedEmail = email.trim();

const router = express.Router();

const registerSchema = yup.object().shape({
  email: yup.string().email("Invalid email").required("Email is required"),
  username: yup
    .string()
    .min(3, "Username must be at least 3 characters")
    .required("Username is required"),
  phone: yup
    .string()
    .matches(/^\d{10}$/, "Phone number must be 10 digits")
    .required("Phone is required"),
  password: yup
    .string()
    .min(8, "Password must be at least 8 characters")
    .required("Password is required"),
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

router.post("/register", async (req, res) => {
  console.log("Received registration request with body:", req.body);

  try {
    await registerSchema.validate(req.body, { abortEarly: false });

    // Validate input
    // if (!email || !username || !phone || !password) {
    //   logger.warn('Registration attempt with missing fields');
    //   return res.status(400).json({ error: 'All fields are required' });
    // }

    // Destructure the validated data
    const { email, username, phone, password } = req.body;

    logger.info(`Attempting to register user: ${username}, ${email}`);

    // Check if email or username already exists
    const checkUser = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [email, username],
        (err, row) => {
          if (err) {
            logger.error(`Database error during user check: ${err.message}`);
            reject(err);
          }
          resolve(row);
        }
      );
    });

    if (checkUser) {
      if (checkUser.email === email) {
        logger.warn(`Registration attempt with existing email: ${email}`);
        return res.status(400).json({ error: "Email already exists" });
      }
      if (checkUser.username === username) {
        logger.warn(`Registration attempt with existing username: ${username}`);
        return res.status(400).json({ error: "Username already exists" });
      }
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    await new Promise((resolve, reject) => {
      db.run(
        "INSERT INTO users (email, username, phone, password) VALUES (?, ?, ?, ?)",
        [email, username, phone, hashedPassword],
        function (err) {
          if (err) {
            logger.error(
              `Database error during user insertion: ${err.message}`
            );
            reject(err);
          }
          resolve(this.lastID);
        }
      );
    });

    logger.info(`New user registered successfully: ${username}`);
    res
      .status(201)
      .json({
        message: "User registered successfully",
        redirect: "/dashboard",
      });
  } catch (error) {
    if (error instanceof yup.ValidationError) {
      return res.status(400).json({ error: error.errors });
    }
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

router.post("/login", async (req, res) => {
  const { username, password, twoFactorToken } = req.body;

  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT * FROM users WHERE email = ? OR username = ?",
        [username, username],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    if (user.twoFactorEnabled) {
      if (!twoFactorToken) {
        return res
          .status(400)
          .json({ error: "2FA token required", require2FA: true });
      }

      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: "base32",
        token: twoFactorToken,
      });

      if (!verified) {
        return res.status(400).json({ error: "Invalid 2FA token" });
      }
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ token, message: "Login successful", redirect: "/dashboard" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/forgot-password", async (req, res) => {
  console.log("Request headers:", req.headers);
  console.log("Entire request body:", req.body);
  const { email } = req.body;

  if (!email) {
    console.log("Email is undefined or empty");
    return res.status(400).json({ error: "Email is required" });
  }

  console.log("Received forgot password request for email:", email); // Log the received email

  try {
    // Check if the user exists by email
    const user = await new Promise((resolve, reject) => {
      db.get(
        // "SELECT * FROM users WHERE LOWER(email) = LOWER(?)",
        "SELECT * FROM users WHERE email = ?",
        [email],
        (err, row) => {
          if (err) {
            console.error("Database error:", err);
            reject(err);
          }
          console.log("Database query result:", row); // Log the query result
          resolve(row);
        }
      );
    });

    if (!user) {
      console.log("User not found for email:", email); // Log when user is not found
      return res.status(404).json({ error: "User not found" });
    }

    console.log("User found:", user)

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE id = ?",
        [resetToken, resetTokenExpiry, user.id],
        (err) => {
          if (err) {
            console.error("Error updating reset token:", err);
            reject(err);
          } else {
            console.log("Reset token and expiry set successfully");
          } 
          resolve();
        }
      );
    });

    // Send email with reset link
    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

    const subject = 'Password Reset';
    const message = `
      <h1>Password Reset</h1>
      <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
      <p>Please click on the following link, or paste this into your browser to complete the process:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
    `;

    await sendPasswordResetEmail(user.email, subject, message);

    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


// Route to handle the reset token
router.get("/reset-password/:token", (req, res) => {
  const { token } = req.params;
  // Check if the token exists and is still valid
  if (users.some((user) => user.resetToken === token)) {
    // Render a form for the user to enter a new password
    res.send(
      '<form method="post" action="/reset-password"><input type="password" name="password" required><input type="submit" value="Reset Password"></form>'
    );
  } else {
    res.status(404).send("Invalid or expired token");
  }
});

router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?', [token, Date.now()], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?', 
        [hashedPassword, user.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT id, email, username, phone FROM users WHERE id = ?",
        [req.userId],
        (err, row) => {
          if (err) {
            logger.error(
              `Database error fetching user profile: ${err.message}`
            );
            reject(err);
          }
          resolve(row);
        }
      );
    });

    if (!user) {
      logger.warn(`Profile request for non-existent user ID: ${req.userId}`);
      return res.status(404).json({ error: "User not found" });
    }
    logger.info(`Profile fetched successfully for user ID: ${req.userId}`);
    res.json(user);
  } catch (error) {
    logger.error(`Error fetching user profile: ${error.message}`);
    res.status(500).json({ error: "Server error" });
  }
});

router.put("/profile", verifyToken, async (req, res) => {
  const { email, username, phone } = req.body;

  try {
    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE users SET email = ?, username = ?, phone = ? WHERE id = ?",
        [email, username, phone, req.userId],
        (err) => {
          if (err) {
            logger.error(
              `Database error updating user profile: ${err.message}`
            );
            reject(err);
          }
          resolve();
        }
      );
    });
    logger.info(`Profile updated successfully for user ID: ${req.userId}`);
    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    logger.error(`Error updating user profile: ${error.message}`);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/enable-2fa", verifyToken, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: "PasswordManager" });

    await new Promise((resolve, reject) => {
      db.run(
        "UPDATE users SET twoFactorSecret = ? WHERE id = ?",
        [secret.base32, req.userId],
        (err) => {
          if (err) reject(err);
          resolve();
        }
      );
    });

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.json({ secret: secret.base32, qrCodeUrl });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/verify-2fa", verifyToken, async (req, res) => {
  const { token } = req.body;

  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        "SELECT twoFactorSecret FROM users WHERE id = ?",
        [req.userId],
        (err, row) => {
          if (err) reject(err);
          resolve(row);
        }
      );
    });

    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: "2FA not enabled for this user" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: token,
    });

    if (verified) {
      await new Promise((resolve, reject) => {
        db.run(
          "UPDATE users SET twoFactorEnabled = ? WHERE id = ?",
          [true, req.userId],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });

      res.json({ message: "2FA enabled successfully" });
    } else {
      res.status(400).json({ error: "Invalid 2FA token" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
