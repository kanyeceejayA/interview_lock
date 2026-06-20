CREATE TABLE IF NOT EXISTS events (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,   -- epoch ms
  email   TEXT,               -- candidate email captured at login
  type    TEXT,               -- 'tab_switch' | 'clipboard_blocked'
  strikes INTEGER,            -- strike number at time of event
  path    TEXT,               -- page path where it happened
  ip      TEXT                -- candidate IP (cf-connecting-ip)
);
CREATE INDEX IF NOT EXISTS idx_events_email ON events(email);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
