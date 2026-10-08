import sqlite3, json, hashlib, uuid, os
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
ROOT=Path(__file__).resolve().parents[1]
def now(): return datetime.now(timezone.utc).isoformat()
def digest(value): return hashlib.sha256(value if isinstance(value,bytes) else value.encode()).hexdigest()
def canonical(v): return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'))
def uid(prefix,*parts): return prefix+'_'+uuid.uuid5(uuid.NAMESPACE_URL,canonical(parts)).hex
class Store:
    def __init__(self,path=None):
        self.root=Path(path or os.getenv('ITI_DATA_DIR',ROOT/'runtime')).resolve(); self.root.mkdir(parents=True,exist_ok=True)
        (self.root/'blobs').mkdir(exist_ok=True); (self.root/'artifacts').mkdir(exist_ok=True)
        self.db=self.root/'iti.sqlite3'
        with self.connect() as c:
            c.executescript('''PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS records(kind TEXT,id TEXT,data TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS identities(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,unique_key TEXT UNIQUE NOT NULL,state TEXT NOT NULL,stage TEXT NOT NULL,data TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity(seq INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,kind TEXT NOT NULL,scope TEXT NOT NULL,data TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS immutable_activity_update BEFORE UPDATE ON activity BEGIN SELECT RAISE(ABORT,'activity is append-only'); END;
CREATE TRIGGER IF NOT EXISTS immutable_activity_delete BEFORE DELETE ON activity BEGIN SELECT RAISE(ABORT,'activity is append-only'); END;
PRAGMA user_version=1;''')
    @contextmanager
    def connect(self):
        c=sqlite3.connect(self.db,timeout=30); c.row_factory=sqlite3.Row
        try: yield c; c.commit()
        except: c.rollback(); raise
        finally: c.close()
    def put(self,kind,id,data,immutable=False):
        with self.connect() as c:
            if immutable: c.execute('INSERT OR IGNORE INTO records VALUES(?,?,?,?)',(kind,id,canonical(data),now()))
            else: c.execute('INSERT INTO records VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data',(kind,id,canonical(data),now()))
        return data
    def get(self,kind,id):
        with self.connect() as c: r=c.execute('SELECT data FROM records WHERE kind=? AND id=?',(kind,id)).fetchone()
        if r is None: raise KeyError(f'{kind} {id} not found')
        return json.loads(r['data'])
    def maybe(self,kind,id):
        try: return self.get(kind,id)
        except KeyError: return None
    def all(self,kind):
        with self.connect() as c: rows=c.execute('SELECT data FROM records WHERE kind=? ORDER BY created_at,id',(kind,)).fetchall()
        return [json.loads(r['data']) for r in rows]
    def event(self,kind,scope,data):
        with self.connect() as c: c.execute('INSERT INTO activity(at,kind,scope,data) VALUES(?,?,?,?)',(now(),kind,scope,canonical(data)))
    def history(self,scope):
        with self.connect() as c: rows=c.execute('SELECT * FROM activity WHERE scope=? ORDER BY seq',(scope,)).fetchall()
        return [dict(r)|{'data':json.loads(r['data'])} for r in rows]
    def identity(self,key,typ=None):
        with self.connect() as c:
            value=(typ+'--' if typ else '')+str(uuid.uuid4())
            c.execute('INSERT OR IGNORE INTO identities VALUES(?,?)',(key,value))
            return c.execute('SELECT value FROM identities WHERE key=?',(key,)).fetchone()[0]
    def blob(self,data):
        h=digest(data); p=self.root/'blobs'/h
        try:
            with p.open('xb') as f: f.write(data)
            p.chmod(0o600)
        except FileExistsError: pass
        return h
    def clock(self,kind,id):
        self.put(kind,id,{'at':now()},immutable=True); return self.get(kind,id)['at']

    @contextmanager
    def lock(self,key):
        """Cross-process local advisory lock; macOS/Linux, released automatically on crash."""
        import fcntl
        directory=self.root/'locks';directory.mkdir(exist_ok=True)
        with (directory/digest(key)).open('a') as handle:
            fcntl.flock(handle.fileno(),fcntl.LOCK_EX)
            try:yield
            finally:fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
