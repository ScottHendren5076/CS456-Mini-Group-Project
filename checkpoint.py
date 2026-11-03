"""State sync / checkpoint module (Part 2, deliverable b).

Shared by service.py, monitor.py and client.py.

* Chain: the SHA-256 hash-chain log state from Part 1 (hash_n = SHA256(hash_(n-1) + event_n)),
  now with a bounded event window, idempotent event ids and snapshot/verify support.
* CheckpointStore: atomic, HMAC-signed checkpoint files on shared storage.
      ckpt_e<epoch>_n<count>.json   newest = highest (epoch, count)
  On load every candidate is verified (MAC -> schema -> hash-chain recomputation); invalid
  files are rejected and the next newest valid one is used (rollback to last known good).
* Epoch file (fencing token): epoch.json, HMAC-signed. A node whose epoch is lower than the
  file's epoch has been superseded and must stop (split-brain protection).
* sign()/verify(): HMAC-SHA256 over canonical JSON, also used for control messages.

Threat model: an attacker with filesystem access but WITHOUT the cluster key cannot forge or
edit a checkpoint/epoch file undetected. Known limit: a *valid older* checkpoint can still be
swapped in (rollback); the failover controller reports the resulting event-count gap.
"""
import glob, hashlib, hmac, json, os, threading, time

GENESIS = "0" * 64
MAX_EVENTS = 5000          # events kept in memory / in each checkpoint (older ones folded into base_head)
DEMO_KEY = "cs456-demo-key-CHANGE-ME"


def get_key(arg):
    """Key from --key / CLUSTER_KEY; falls back to an insecure demo key (with a warning)."""
    k = arg or os.environ.get("CLUSTER_KEY")
    if not k:
        print("WARNING: no --key / CLUSTER_KEY set; using INSECURE built-in demo key", flush=True)
        k = DEMO_KEY
    return k.encode()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def sign(obj, key):
    body = {k: v for k, v in obj.items() if k != "mac"}
    return hmac.new(key, canon(body), hashlib.sha256).hexdigest()


def verify(obj, key):
    m = obj.get("mac")
    return isinstance(m, str) and hmac.compare_digest(m, sign(obj, key))


def chain_step(head, event):
    return hashlib.sha256((head + json.dumps(event, sort_keys=True)).encode()).hexdigest()


class Chain:
    """Dynamic state of the integrity monitor / log aggregator."""

    def __init__(self, state=None):
        self.lock = threading.Lock()
        s = state or {"base_head": GENESIS, "base_count": 0, "events": [], "head": GENESIS, "count": 0}
        self.base_head, self.base_count = s["base_head"], s["base_count"]
        self.events, self.head, self.count = list(s["events"]), s["head"], s["count"]
        self.index = {}   # event id -> (n, hash) so client retries are idempotent
        h, n = self.base_head, self.base_count
        for e in self.events:
            h, n = chain_step(h, e), n + 1
            if "id" in e:
                self.index[e["id"]] = (n, h)

    def append(self, event):
        """Returns (n, hash, duplicate)."""
        with self.lock:
            eid = event.get("id")
            if eid is not None and eid in self.index:
                return (*self.index[eid], True)
            self.head = chain_step(self.head, event)
            self.count += 1
            self.events.append(event)
            if eid is not None:
                self.index[eid] = (self.count, self.head)
            if len(self.events) > MAX_EVENTS:
                old = self.events.pop(0)
                self.base_head = chain_step(self.base_head, old)
                self.base_count += 1
                self.index.pop(old.get("id"), None)
            return self.count, self.head, False

    def snapshot(self):
        with self.lock:
            return {"base_head": self.base_head, "base_count": self.base_count,
                    "events": list(self.events), "head": self.head, "count": self.count}

    def tail(self, k):
        with self.lock:
            return list(self.events[-k:]) if k > 0 else []


def verify_state(s):
    """Recompute the hash chain from the snapshot. Returns (ok, reason)."""
    try:
        if not isinstance(s["events"], list) or not all(isinstance(e, dict) for e in s["events"]):
            return False, "bad events list"
        h = s["base_head"]
        for e in s["events"]:
            h = chain_step(h, e)
        if h != s["head"]:
            return False, "hash chain does not match head (events edited)"
        if s["base_count"] + len(s["events"]) != s["count"]:
            return False, "count does not match events"
        return True, ""
    except (KeyError, TypeError) as e:
        return False, f"bad state schema ({e!r})"


class CheckpointStore:
    def __init__(self, directory, key, keep=6):
        self.dir, self.key, self.keep = directory, key, keep
        os.makedirs(directory, exist_ok=True)

    # ---- checkpoints --------------------------------------------------------
    def save(self, chain, node, epoch):
        snap = chain.snapshot()
        rec = {"v": 1, "node": node, "epoch": epoch, "saved_at": time.time(), "state": snap}
        rec["mac"] = sign(rec, self.key)
        name = f"ckpt_e{epoch:06d}_n{snap['count']:010d}.json"
        path = os.path.join(self.dir, name)
        tmp = f"{path}.tmp{os.getpid()}"
        with open(tmp, "w") as f:           # write-then-rename: a crash mid-write leaves older files intact
            json.dump(rec, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        for old in sorted(glob.glob(os.path.join(self.dir, "ckpt_e*.json")))[:-self.keep]:
            try:
                os.remove(old)
            except OSError:
                pass
        return name, snap["count"]

    def files(self):
        return sorted(glob.glob(os.path.join(self.dir, "ckpt_e*.json")), reverse=True)

    def load_latest(self):
        """Return (Chain or None, meta or None, rejected[{file,reason}])."""
        rejected = []
        for path in self.files():
            name = os.path.basename(path)
            try:
                with open(path) as f:
                    rec = json.load(f)
                if not isinstance(rec, dict) or "state" not in rec:
                    raise ValueError("not a checkpoint record")
                if not verify(rec, self.key):
                    rejected.append({"file": name, "reason": "BAD MAC (forged or tampered)"})
                    continue
                ok, why = verify_state(rec["state"])
                if not ok:
                    rejected.append({"file": name, "reason": why})
                    continue
                meta = {"file": name, "epoch": rec["epoch"], "node": rec["node"],
                        "age_s": round(time.time() - rec["saved_at"], 2)}
                return Chain(rec["state"]), meta, rejected
            except (OSError, ValueError, KeyError, TypeError) as e:
                rejected.append({"file": name, "reason": f"unreadable/corrupt ({type(e).__name__})"})
        return None, None, rejected

    # ---- fencing token --------------------------------------------------------
    def write_epoch(self, epoch, node):
        rec = {"epoch": epoch, "node": node, "ts": time.time()}
        rec["mac"] = sign(rec, self.key)
        path = os.path.join(self.dir, "epoch.json")
        tmp = f"{path}.tmp{os.getpid()}"
        with open(tmp, "w") as f:
            json.dump(rec, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def read_epoch(self):
        """Highest authentic epoch recorded (0 if missing or the file fails its MAC)."""
        try:
            with open(os.path.join(self.dir, "epoch.json")) as f:
                rec = json.load(f)
            if verify(rec, self.key) and isinstance(rec.get("epoch"), int):
                return rec["epoch"]
        except (OSError, ValueError, TypeError):
            pass
        return 0

    def wipe(self):
        for p in self.files() + [os.path.join(self.dir, "epoch.json")]:
            try:
                os.remove(p)
            except OSError:
                pass
