import json, os, sqlite3, threading
from contextlib import contextmanager

DATABASE_PATH = os.getenv("DATABASE_PATH", "incidents.sqlite3")
_locks, _guard = {}, threading.Lock()

def run_lock(run_id):
    with _guard:
        return _locks.setdefault(run_id, threading.Lock())

@contextmanager
def db():
    c = sqlite3.connect(os.getenv("DATABASE_PATH", DATABASE_PATH), timeout=15)
    try:
        c.execute("PRAGMA journal_mode=WAL")
        yield c
        c.commit()
    finally:
        c.close()

def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS runs(
            run_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL,
            state_json TEXT NOT NULL, first_response_json TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS receipts(
            run_id TEXT NOT NULL, receipt_id TEXT NOT NULL, receipt_digest TEXT NOT NULL,
            response_json TEXT NOT NULL, PRIMARY KEY(run_id, receipt_id))""")

def get_run(run_id):
    with db() as c:
        r = c.execute("SELECT request_digest,state_json,first_response_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
    return None if not r else {"digest": r[0], "state": json.loads(r[1]), "first": json.loads(r[2])}

def create_run(run_id, digest, state, first_response):
    with db() as c:
        c.execute("INSERT INTO runs VALUES(?,?,?,?)",
                  (run_id, digest, json.dumps(state), json.dumps(first_response)))

def get_receipt(run_id, receipt_id):
    with db() as c:
        r = c.execute("SELECT receipt_digest,response_json FROM receipts WHERE run_id=? AND receipt_id=?",
                      (run_id, receipt_id)).fetchone()
    return None if not r else {"digest": r[0], "response": json.loads(r[1])}

def commit_receipt(run_id, receipt_id, digest, state, response):
    """State and receipt are written in one transaction."""
    with db() as c:
        c.execute("UPDATE runs SET state_json=? WHERE run_id=?", (json.dumps(state), run_id))
        c.execute("INSERT INTO receipts VALUES(?,?,?,?)", (run_id, receipt_id, digest, json.dumps(response)))
