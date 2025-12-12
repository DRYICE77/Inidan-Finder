// backend/server.js
try { require("dotenv").config({ override: true }); } catch (e) {}

const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 8080;

// The repo root is one level ABOVE /backend
const ROOT_DIR = path.join(__dirname, "..");

// ---------- middleware ----------
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// If you don't need sessions for the twitter flow yet, you can delete this block.
// Leaving it since your earlier server.js uses sessions.
app.use(
  session({
    name: "indian.sid",
    secret: process.env.ADMIN_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true",
      sameSite: process.env.COOKIE_SAMESITE || "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

// ---------- static site ----------
// Serve everything in repo root (index.html, admin.html, images/, videos/, etc.)
app.use(express.static(ROOT_DIR));

// Make / always return index.html (prevents "Cannot GET /")
app.get("/", (req, res) => {
  res.sendFile(path.join(ROOT_DIR, "index.html"));
});

// ---------- health / status ----------
app.get("/health", (req, res) => res.json({ ok: true }));
app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    time: new Date().toISOString(),
    env: {
      hasTwitterKey: !!process.env.TWITTER_CLIENT_ID,
      hasTwitterSecret: !!process.env.TWITTER_CLIENT_SECRET,
      hasCallback: !!process.env.TWITTER_CALLBACK_URL,
    },
  });
});

// ---------- TODO: Twitter routes ----------
// We'll plug the real OAuth + tweet endpoints here once we confirm what method you’re using
// (OAuth 2.0 PKCE vs OAuth 1.0a).
// Example placeholders:
app.post("/api/twitter/test", (req, res) => {
  res.json({ ok: true, received: req.body });
});

app.listen(PORT, () => {
  console.log(`Indian Finder API running on port ${PORT}`);
});





