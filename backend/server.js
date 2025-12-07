// backend/server.js
import express from "express";
import fs from "fs/promises";
import { randomUUID } from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;
const SUBMISSIONS_PATH = "./submissions.json";

app.use(express.json());

async function loadSubmissions() {
  try {
    const raw = await fs.readFile(SUBMISSIONS_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function saveSubmissions(data) {
  await fs.writeFile(SUBMISSIONS_PATH, JSON.stringify(data, null, 2), "utf8");
}

// Create submission
app.post("/api/submissions", async (req, res) => {
  const { mediaType, src, title, submittedBy, wallet, notes } = req.body || {};

  if (!src || !title) {
    return res.status(400).json({ error: "Missing title or src" });
  }

  const submissions = await loadSubmissions();
  const submission = {
    id: "sub_" + randomUUID(),
    mediaType: mediaType || "video",
    src,
    title,
    submittedBy: submittedBy || null,
    wallet: wallet || null,
    notes: notes || null,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  submissions.push(submission);
  await saveSubmissions(submissions);

  res.json({ ok: true, submission });
});

// Get pending submissions
app.get("/api/submissions", async (req, res) => {
  const { status } = req.query;
  const submissions = await loadSubmissions();
  const filtered = status
    ? submissions.filter((s) => s.status === status)
    : submissions;

  res.json(filtered);
});

// Approve / Reject
app.patch("/api/submissions/:id", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body || {};

  const submissions = await loadSubmissions();
  const idx = submissions.findIndex((s) => s.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  if (status) submissions[idx].status = status;

  await saveSubmissions(submissions);

  res.json({ ok: true, submission: submissions[idx] });
});

app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});
