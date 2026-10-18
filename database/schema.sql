CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  scheme TEXT DEFAULT 'https',
  scan_type TEXT DEFAULT 'G',
  depth TEXT DEFAULT '2',
  started TEXT,
  finished TEXT,
  duration_s INTEGER DEFAULT 0,
  results_json TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
