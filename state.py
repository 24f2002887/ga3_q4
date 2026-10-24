# state.py
import json, sqlite3, threading, hashlib
from contextlib import contextmanager

DB = "runs.db"
_lock = threading.Lock()

def _conn():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
          run_id TEXT PRIMARY KEY,
          request_hash TEXT NOT NULL,
          request_json TEXT NOT NULL,
          state_json TEXT,          -- internal FSM state
          final_json TEXT,          -- exact response to replay
          status TEXT NOT NULL      -- 'waiting' | 'completed' | 'failed'
        );
        CREATE TABLE IF NOT EXISTS receipts (
          run_id TEXT NOT NULL,
          receipt_id TEXT NOT NULL,
          receipt_hash TEXT NOT NULL,
          receipt_json TEXT NOT NULL,
          response_json TEXT NOT NULL,
          PRIMARY KEY (run_id, receipt_id)
        );
        """)

def sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

@contextmanager
def tx():
    with _lock:
        c = _conn()
        try:
            yield c
            c.commit()
        finally:
            c.close()

def get_run(run_id):
    with tx() as c:
        r = c.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(zip([d[0] for d in c.execute("SELECT * FROM runs LIMIT 0").description], r)) if r else None

def get_receipt(run_id, receipt_id):
    with tx() as c:
        r = c.execute("SELECT * FROM receipts WHERE run_id=? AND receipt_id=?", (run_id, receipt_id)).fetchone()
        if not r: return None
        cols = [d[0] for d in c.execute("SELECT * FROM receipts LIMIT 0").description]
        return dict(zip(cols, r))
