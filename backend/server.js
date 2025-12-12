// Load env safely (won’t crash if missing)
try {
  require("dotenv").config();
} catch (e) {}

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");

const app = express();

// Railway provides PORT automatically
const PORT = process.env.PORT || 8080;

/* -------------------- middleware -------------------- */

app.use(cors({
  origin: true,
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: "fails.sid",
    secret: process.env.ADMIN_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true",
      sameSite: process.env.COOKIE_SAMESITE || "none",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    },
  })
);

/* -------------------- frontend -------------------- */

// Serve files from repo root (index.html, admin.html, etc)
app.use(express.static(path.join(__dirname, "..")));

// Homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "index.html"));
});

// Admin page
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "admin.html"));
});

/* -------------------- api routes -------------------- */

// Health check (useful for Railway)
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Example API route
app.get("/api/status", (req, res) => {
  res.json({ status: "Fails API running" });
});

/* -------------------- start server -------------------- */

app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});





