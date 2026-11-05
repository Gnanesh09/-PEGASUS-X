import json, sqlite3, os, threading
from datetime import datetime, timezone
from .config import DB_PATH, DATA_DIR

_lock = threading.Lock()

def now():
    return datetime.now(timezone.utc).isoformat()

def connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn

def init_store():
    with _lock, connect() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, round_no INTEGER NOT NULL,
            agent TEXT NOT NULL, kind TEXT NOT NULL,
            severity TEXT NOT NULL, message TEXT NOT NULL,
            details TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS rounds (
            round_no INTEGER PRIMARY KEY, scenario TEXT, outcome TEXT,
            score INTEGER, report TEXT, timestamp TEXT
        )''')
        c.commit()

def add_event(round_no, agent, kind, severity, message, details=None):
    with _lock, connect() as c:
        c.execute(
            "INSERT INTO events(timestamp,round_no,agent,kind,severity,message,details) VALUES(?,?,?,?,?,?,?)",
            (now(), round_no, agent, kind, severity, message, json.dumps(details or {}))
        )
        c.commit()

def add_round(round_no, scenario, outcome, score, report):
    with _lock, connect() as c:
        c.execute("INSERT OR REPLACE INTO rounds VALUES(?,?,?,?,?,?)",
                  (round_no, scenario, outcome, score, report, now()))
        c.commit()

def get_events(limit=100):
    with connect() as c:
        rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) | {"details": json.loads(r["details"])} for r in rows]

def get_rounds():
    with connect() as c:
        rows = c.execute("SELECT * FROM rounds ORDER BY round_no DESC").fetchall()
    return [dict(r) for r in rows]

def clear_events():
    with _lock, connect() as c:
        c.execute("DELETE FROM events")
        c.execute("DELETE FROM rounds")
        c.commit()
