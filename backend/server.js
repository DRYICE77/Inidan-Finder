// server.js – Fails.com backend (Railway) + X (Twitter) connect + share
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");

// --- Config ----------------------------------------------------

const PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, "videos.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const X_USERS_FILE = path.join(__dirname, "x_users.json");

// IMPORTANT: set this in Railway → Variables
const ADMIN_SECRET = process.env.ADMIN_SECRET || "changeme-super-secret";

// X (Twitter) OAuth2
// In Railway → Variables:
//   X_CLIENT_ID=...
//   X_CLIENT_SECRET=...   (optional, but recommended if your app is confidential)
//   X_REDIRECT_URI=https://<your-railway-domain>/auth/x/callback
//   PUBLIC_SITE_URL=https://fails.com   (or your Netlify site; used in tweet links)
const X_CLIENT_ID = process.env.X_CLIENT_ID || "";
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || ""; // optional for some setups
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || "";
const PUBLIC_SITE_URL = (process.env.PUBLIC_SITE_URL || "").replace(/\/+$/, "");

const COOKIE_SECURE = (process.env.COOKIE_SECURE || "true").toLowerCase() === "true"; // set false locally
const COOKIE_SAME_SITE = process.env.COOKIE_SAMESITE || "none"; // "none" for cross-site Netlify→Railway cookies
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined; // usually leave unset

// --- Helpers ---------------------------------------------------

async function ensureDirs() {
  try {
    await fsp.mkdir(UPLOAD_DIR, { recursive: true });
  } catch (err) {
    console.error("Error ensuring upload dir:", err);
  }
}

async function ensureFileExists(filePath, defaultValue) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
  } catch {
    await fsp.writeFile(filePath, JSON.stringify(defaultValue, null, 2), "utf8");
  }
}

async function loadJson(filePath, defaultValue) {
  try {
    await ensureFileExists(filePath, defaultValue);
    const raw = await fsp.readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed ?? defaultValue;
  } catch (err) {
    console.error("Error reading json:", filePath, err);
    return defaultValue;
  }
}

async function saveJson(filePath, data) {
  try {
    await fsp.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Error saving json:", filePath, err);
  }
}

async function loadMediaList() {
  const arr = await loadJson(DATA_FILE, []);
  if (!Array.isArray(arr)) return [];
  return arr.map(normalizeItem);
}

async function saveMediaList(list) {
  await saveJson(DATA_FILE, list);
}

// Ensure every item has id/upvotes/status/createdAt so older files still work
function normalizeItem(item) {
  if (!item) return item;
  const clone = { ...item };

  if (!clone.id) clone.id = Date.now().toString() + Math.random().toString(16).slice(2);
  if (typeof clone.upvotes !== "number") clone.upvotes = 0;
  if (!clone.status) clone.status = "approved";
  if (!clone.createdAt) clone.createdAt = new Date().toISOString();

  // X fields (optional)
  if (!clone.ownerUserId) clone.ownerUserId = null; // failsUserId cookie owner
  if (!clone.xUser) clone.xUser = null; // { id, username, name }
  if (!clone.shareToXOnApprove) clone.shareToXOnApprove = false;
  if (!clone.sharedToX) clone.sharedToX = null; // { tweetId, sharedAt }

  return clone;
}

// --- Multer setup for uploads ----------------------------------

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || "";
    const base =
      path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, "_") ||
      "file";
    const stamp = Date.now();
    cb(null, `${base}_${stamp}${ext}`);
  },
});
const upload = multer({ storage });

// --- Admin auth middleware -------------------------------------

function requireAdmin(req, res, next) {
  const secretFromHeader = req.get("x-admin-secret");
  const secretFromQuery = req.query.adminSecret;
  const provided = (secretFromHeader || secretFromQuery || "").trim();
  const expected = (process.env.ADMIN_SECRET || "changeme-super-secret").trim();

  if (provided !== expected) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// --- Cookie identity (lightweight “user account”) ---------------

function newId() {
  return crypto.randomBytes(16).toString("hex");
}

function ensureFailsUserId(req, res) {
  let id = req.cookies.failsUserId;
  if (!id || typeof id !== "string" || id.length < 8) {
    id = newId();
    res.cookie("failsUserId", id, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      domain: COOKIE_DOMAIN,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
      path: "/",
    });
  }
  return id;
}

// --- X OAuth2 + PKCE helpers -----------------------------------

function base64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function sha256Base64Url(str) {
  return base64url(crypto.createHash("sha256").update(str).digest());
}

function xEnabled() {
  return Boolean(X_CLIENT_ID && X_REDIRECT_URI);
}

async function getXUsers() {
  return await loadJson(X_USERS_FILE, {}); // keyed by failsUserId
}
async function saveXUsers(obj) {
  await saveJson(X_USERS_FILE, obj);
}

function setShortCookie(res, name, value) {
  res.cookie(name, value, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAME_SITE,
    domain: COOKIE_DOMAIN,
    maxAge: 1000 * 60 * 10, // 10 min
    path: "/",
  });
}

async function xTokenExchange({ code, codeVerifier }) {
  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("client_id", X_CLIENT_ID);
  params.set("code", code);
  params.set("redirect_uri", X_REDIRECT_URI);
  params.set("code_verifier", codeVerifier);

  const headers = { "Content-Type": "application/x-www-form-urlencoded" };

  // If your app is confidential, send Basic auth with client secret:
  if (X_CLIENT_SECRET) {
    const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64");
    headers.Authorization = `Basic ${basic}`;
  }

  const resp = await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers,
    body: params.toString(),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`Token exchange failed (${resp.status}): ${JSON.stringify(json)}`);
  }
  return json; // { token_type, access_token, expires_in, refresh_token, scope }
}

async function xRefreshToken(refreshToken) {
  const params = new URLSearchParams();
  params.set("grant_type", "refresh_token");
  params.set("refresh_token", refreshToken);
  params.set("client_id", X_CLIENT_ID);

  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (X_CLIENT_SECRET) {
    const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64");
    headers.Authorization = `Basic ${basic}`;
  }

  const resp = await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers,
    body: params.toString(),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(`Token refresh failed (${resp.status}): ${JSON.stringify(json)}`);
  }
  return json;
}

async function xFetchMe(accessToken) {
  const resp = await fetch("https://api.twitter.com/2/users/me?user.fields=username,name", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(`Fetch me failed (${resp.status}): ${JSON.stringify(json)}`);
  return json?.data; // { id, name, username }
}

async function xPostTweet(accessToken, text) {
  const resp = await fetch("https://api.twitter.com/2/tweets", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });

  const json = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(`Tweet failed (${resp.status}): ${JSON.stringify(json)}`);
  return json?.data; // { id, text }
}

async function getValidAccessTokenForFailsUser(failsUserId) {
  const users = await getXUsers();
  const entry = users[failsUserId];
  if (!entry) return null;

  // If token is still valid (with a little buffer), use it.
  const now = Date.now();
  if (entry.accessToken && entry.expiresAt && now < entry.expiresAt - 30_000) {
    return { accessToken: entry.accessToken, xUser: entry.xUser };
  }

  // Try refresh
  if (!entry.refreshToken) return null;
  const refreshed = await xRefreshToken(entry.refreshToken);

  const expiresAt = Date.now() + (refreshed.expires_in || 3600) * 1000;
  entry.accessToken = refreshed.access_token;
  if (refreshed.refresh_token) entry.refreshToken = refreshed.refresh_token;
  entry.expiresAt = expiresAt;
  entry.scope = refreshed.scope || entry.scope;

  users[failsUserId] = entry;
  await saveXUsers(users);

  return { accessToken: entry.accessToken, xUser: entry.xUser };
}

// --- App setup -------------------------------------------------

const app = express();

// CORS: allow Netlify frontend to call API + allow cookies
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(cookieParser());
app.use(express.json());

// static for uploaded media
app.use("/uploads", express.static(UPLOAD_DIR));

// health check
app.get("/", (req, res) => {
  res.send("Fails API is running");
});

// --- X Auth Routes ---------------------------------------------

// Start X connect (OAuth2 PKCE)
app.get("/auth/x/start", async (req, res) => {
  try {
    if (!xEnabled()) {
      return res.status(500).send("X auth not configured (missing X_CLIENT_ID or X_REDIRECT_URI).");
    }

    const failsUserId = ensureFailsUserId(req, res);

    const state = newId();
    const codeVerifier = base64url(crypto.randomBytes(32));
    const codeChallenge = sha256Base64Url(codeVerifier);

    setShortCookie(res, "x_oauth_state", state);
    setShortCookie(res, "x_code_verifier", codeVerifier);

    const scopes = [
      "tweet.read",
      "users.read",
      "tweet.write",
      "offline.access",
    ].join(" ");

    const authUrl = new URL("https://twitter.com/i/oauth2/authorize");
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", X_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", X_REDIRECT_URI);
    authUrl.searchParams.set("scope", scopes);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    // optional: return to site after connect
    const returnTo = (req.query.returnTo || "").toString();
    if (returnTo) setShortCookie(res, "x_return_to", returnTo);

    console.log("X connect start for failsUserId:", failsUserId);
    res.redirect(authUrl.toString());
  } catch (err) {
    console.error("GET /auth/x/start error:", err);
    res.status(500).send("Could not start X auth.");
  }
});

// X callback
app.get("/auth/x/callback", async (req, res) => {
  try {
    const { state, code, error, error_description } = req.query;

    if (error) {
      console.error("X callback error:", error, error_description);
      return res.status(400).send(`X auth error: ${error}`);
    }

    const expectedState = req.cookies.x_oauth_state;
    const codeVerifier = req.cookies.x_code_verifier;

    if (!state || !expectedState || state !== expectedState) {
      return res.status(400).send("Invalid state. Please try connecting again.");
    }
    if (!code || !codeVerifier) {
      return res.status(400).send("Missing code verifier. Please try connecting again.");
    }

    const failsUserId = ensureFailsUserId(req, res);

    const token = await xTokenExchange({ code, codeVerifier });
    const accessToken = token.access_token;
    const refreshToken = token.refresh_token || null;
    const expiresAt = Date.now() + (token.expires_in || 3600) * 1000;

    const me = await xFetchMe(accessToken);

    const users = await getXUsers();
    users[failsUserId] = {
      xUser: { id: me.id, username: me.username, name: me.name },
      accessToken,
      refreshToken,
      expiresAt,
      scope: token.scope,
      connectedAt: new Date().toISOString(),
    };
    await saveXUsers(users);

    // clear short cookies
    res.clearCookie("x_oauth_state");
    res.clearCookie("x_code_verifier");

    const returnTo = req.cookies.x_return_to;
    res.clearCookie("x_return_to");

    const dest = returnTo || (PUBLIC_SITE_URL ? `${PUBLIC_SITE_URL}/?x=connected` : "/");
    res.redirect(dest);
  } catch (err) {
    console.error("GET /auth/x/callback error:", err);
    res.status(500).send("X auth failed.");
  }
});

// Disconnect X
app.post("/api/x/disconnect", async (req, res) => {
  try {
    const failsUserId = ensureFailsUserId(req, res);
    const users = await getXUsers();
    delete users[failsUserId];
    await saveXUsers(users);
    res.json({ ok: true });
  } catch (err) {
    console.error("POST /api/x/disconnect error:", err);
    res.status(500).json({ error: "Could not disconnect." });
  }
});

// Who am I / is X connected?
app.get("/api/me", async (req, res) => {
  try {
    const failsUserId = ensureFailsUserId(req, res);
    const users = await getXUsers();
    const entry = users[failsUserId];
    res.json({
      failsUserId,
      xConnected: Boolean(entry?.xUser),
      xUser: entry?.xUser || null,
    });
  } catch (err) {
    console.error("GET /api/me error:", err);
    res.status(500).json({ error: "Could not load profile." });
  }
});

// --- Public API ------------------------------------------------

// Return only APPROVED media for the main site
app.get("/api/media", async (req, res) => {
  try {
    const list = await loadMediaList();
    const approved = list.filter((item) => item.status === "approved");
    res.json(approved);
  } catch (err) {
    console.error("GET /api/media error:", err);
    res.status(500).json({ error: "Could not load media" });
  }
});

// Upload a new fail (video or image) – goes in as PENDING
// NEW optional body fields:
//   shareToXOnApprove: "true"/"false"
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const failsUserId = ensureFailsUserId(req, res);

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const title = (req.body.title || "").trim();
    const uploader = (req.body.uploader || "").trim();
    const mime = req.file.mimetype || "";

    const mediaType = mime.startsWith("image/") ? "image" : "video";

    // If connected to X, attach xUser snapshot to the post
    const users = await getXUsers();
    const xUser = users[failsUserId]?.xUser || null;

    const shareToXOnApprove =
      String(req.body.shareToXOnApprove || "").toLowerCase() === "true";

    const mediaItem = normalizeItem({
      id: Date.now().toString(),
      mediaType,
      src: `/uploads/${req.file.filename}`,
      title,
      uploader,
      upvotes: 0,
      status: "pending",
      createdAt: new Date().toISOString(),

      ownerUserId: failsUserId,
      xUser,
      shareToXOnApprove: Boolean(shareToXOnApprove && xUser),
      sharedToX: null,
    });

    const list = await loadMediaList();
    list.push(mediaItem);
    await saveMediaList(list);

    res.json(mediaItem);
  } catch (err) {
    console.error("POST /api/upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// Upvote a fail
app.post("/api/media/:id/upvote", async (req, res) => {
  try {
    const id = req.params.id;
    const list = await loadMediaList();
    const item = list.find((m) => m.id === id);

    if (!item) {
      return res.status(404).json({ error: "Media not found" });
    }

    item.upvotes = (item.upvotes || 0) + 1;
    await saveMediaList(list);

    res.json(item);
  } catch (err) {
    console.error("POST /api/media/:id/upvote error:", err);
    res.status(500).json({ error: "Could not upvote" });
  }
});

// Share a fail to X (tweet)
// Only allowed if the caller owns the fail (same failsUserId) AND has X connected.
app.post("/api/media/:id/share/x", async (req, res) => {
  try {
    if (!xEnabled()) {
      return res.status(500).json({ error: "X auth not configured." });
    }

    const failsUserId = ensureFailsUserId(req, res);
    const id = req.params.id;

    const list = await loadMediaList();
    const item = list.find((m) => m.id === id);
    if (!item) return res.status(404).json({ error: "Media not found" });

    if (item.ownerUserId !== failsUserId) {
      return res.status(403).json({ error: "Not allowed to share this fail." });
    }

    if (item.sharedToX?.tweetId) {
      return res.status(400).json({ error: "Already shared to X." });
    }

    const tokenInfo = await getValidAccessTokenForFailsUser(failsUserId);
    if (!tokenInfo?.accessToken) {
      return res.status(401).json({ error: "X not connected." });
    }

    const failUrl = PUBLIC_SITE_URL ? `${PUBLIC_SITE_URL}/?fail=${encodeURIComponent(item.id)}` : "";
    const title = item.title ? `“${item.title}”` : "my fail";
    const textFromBody = (req.body?.text || "").toString().trim();

    const tweetText =
      textFromBody ||
      `I just posted ${title} on Fails.com 💀\n${failUrl}`.trim();

    const tweet = await xPostTweet(tokenInfo.accessToken, tweetText);

    item.sharedToX = { tweetId: tweet.id, sharedAt: new Date().toISOString() };
    await saveMediaList(list);

    res.json({ ok: true, tweetId: tweet.id, tweetText });
  } catch (err) {
    console.error("POST /api/media/:id/share/x error:", err);
    res.status(500).json({ error: "Could not post to X." });
  }
});

// --- Admin API -------------------------------------------------

// List submissions for admin panel
// GET /api/submissions?status=pending|approved|rejected|all
app.get("/api/submissions", requireAdmin, async (req, res) => {
  try {
    const status = (req.query.status || "pending").toLowerCase();
    const list = await loadMediaList();

    let filtered = list;
    if (status !== "all") {
      filtered = list.filter((item) => item.status === status);
    }

    res.json(filtered);
  } catch (err) {
    console.error("GET /api/submissions error:", err);
    res.status(500).json({ error: "Could not load submissions" });
  }
});

// Update a submission (approve / reject)
// BONUS: if approving and shareToXOnApprove === true, auto-tweet using the submitter’s connected X.
app.patch("/api/submissions/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;

    if (!status || !["pending", "approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const list = await loadMediaList();
    const item = list.find((m) => m.id === id);

    if (!item) {
      return res.status(404).json({ error: "Submission not found" });
    }

    item.status = status;

    // Auto-share on approval if requested and not already shared
    if (
      status === "approved" &&
      item.shareToXOnApprove &&
      !item.sharedToX?.tweetId &&
      item.ownerUserId &&
      xEnabled()
    ) {
      try {
        const tokenInfo = await getValidAccessTokenForFailsUser(item.ownerUserId);
        if (tokenInfo?.accessToken) {
          const failUrl = PUBLIC_SITE_URL ? `${PUBLIC_SITE_URL}/?fail=${encodeURIComponent(item.id)}` : "";
          const title = item.title ? `“${item.title}”` : "my fail";
          const tweetText = `My fail just got approved 💀👇\n${title}\n${failUrl}`.trim();
          const tweet = await xPostTweet(tokenInfo.accessToken, tweetText);
          item.sharedToX = { tweetId: tweet.id, sharedAt: new Date().toISOString() };
        }
      } catch (e) {
        // Don’t fail the approval if tweeting fails
        console.error("Auto-tweet failed for submission:", id, e);
      }
    }

    await saveMediaList(list);
    res.json(item);
  } catch (err) {
    console.error("PATCH /api/submissions/:id error:", err);
    res.status(500).json({ error: "Could not update submission" });
  }
});

// --- Start server ----------------------------------------------

(async () => {
  await ensureDirs();
  await ensureFileExists(DATA_FILE, []);
  await ensureFileExists(X_USERS_FILE, {});
  app.listen(PORT, () => {
    console.log(`Fails API running on port ${PORT}`);
  });
})();



