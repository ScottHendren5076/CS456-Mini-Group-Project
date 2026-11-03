"""Critical service node, Part 2: Integrity Monitor / Log Aggregator with PASSIVE redundancy.

One program, two roles (deliverable a: Replica/Secondary process = `--role standby`).

  primary : serves clients on TCP --port, checkpoints state to --state-dir, sends heartbeats,
            and keeps the Part 1 NON-DETERMINISTIC crash injection (random background faults +
            random crash per request, much higher on malformed input).
  standby : warm spare. Runs, sends heartbeats (role=standby) and listens on a control port.
            Does NOT serve clients and holds NO client port until the monitor PROMOTEs it.

Client protocol (one JSON object per line over TCP, as in Part 1):
  {"id": "...", ...any fields}  -> appended to the hash chain; reply {"status":"OK","n","hash",...}
                                   (an event whose "id" was already applied is NOT applied twice)
  {"cmd":"PING"} / {"cmd":"STATUS"} / {"cmd":"TAIL","k":5}   read-only queries, never crash-injected

Control protocol (monitor -> node, TCP JSON line on --ctl-port, HMAC-signed with the cluster key):
  PROMOTE{epoch}  standby loads the newest VALID checkpoint, takes the client port, becomes primary
  FENCE{epoch}    node with a lower epoch must stop immediately (split-brain protection)
  PING            unauthenticated liveness/role query

Split-brain defences implemented here: promotion only on a signed command whose epoch is higher
than anything seen (replays rejected); a fencing-token file (epoch.json) that a superseded
primary notices within ~100 ms and exits; the single client port acts as a mutex on one host.
"""
import argparse, json, os, random, socket, threading, time
from checkpoint import Chain, CheckpointStore, get_key, sign, verify


def ts():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"


class Node:
    def __init__(self, a, key):
        self.a, self.key, self.name = a, key, a.node
        self.role, self.epoch = "standby", 0
        self.chain = Chain()
        self.store = CheckpointStore(a.state_dir, key)
        self.lock = threading.RLock()
        self.degraded, self.last_saved = False, -1
        self.srv = None
        self.p_crash = 0.0

    def log(self, msg):
        print(f"[{ts()}] [node-{self.name} {self.role} e{self.epoch} pid={os.getpid()}] {msg}", flush=True)

    def crash(self, reason):
        self.log(f"CRASH: {reason}")
        os._exit(1)   # ends the whole process, not a sleep

    # ---- state -----------------------------------------------------------------------------
    def load_state(self):
        chain, meta, rejected = self.store.load_latest()
        for r in rejected:
            self.log(f"!! REJECTED checkpoint {r['file']}: {r['reason']}")
        if chain:
            self.chain, self.degraded = chain, False
            self.log(f"restored {meta['file']} (age {meta['age_s']}s): {chain.count} events, head {chain.head[:12]}")
        elif rejected:
            self.chain, self.degraded = Chain(), True
            self.log("!! NO VALID CHECKPOINT: starting with EMPTY state (DEGRADED, state lost)")
        else:
            self.log("no checkpoint found: starting with empty state")
        self.last_saved = self.chain.count
        return meta, rejected

    def check_fence(self):
        e = self.store.read_epoch()
        if e > self.epoch:
            self.log(f"FENCED: epoch file says {e} > my epoch {self.epoch}; I was superseded. Exiting.")
            os._exit(3)

    def checkpoint_now(self):
        self.check_fence()
        name, n = self.store.save(self.chain, self.name, self.epoch)
        self.last_saved = n
        return name

    # ---- serving -----------------------------------------------------------------------------
    def start_serving(self, bind_wait):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        deadline = time.time() + bind_wait
        while True:
            try:
                srv.bind(("0.0.0.0", self.a.port))
                break
            except OSError as e:
                if time.time() >= deadline:
                    self.log(f"cannot bind client port {self.a.port}: {e}")
                    srv.close()
                    return False
                time.sleep(0.05)
        srv.listen(64)
        self.srv, self.role = srv, "primary"
        rate = self.a.fault_rate if self.epoch_is_initial else self.a.promoted_fault_rate
        self.p_crash = self.a.request_crash_p if self.epoch_is_initial else self.a.promoted_request_crash_p
        for fn, args in ((self.accept_loop, ()), (self.fence_watcher, ()), (self.fault_injector, (rate,)),
                         (self.checkpointer, ())):
            threading.Thread(target=fn, args=args, daemon=True).start()
        self.log(f"SERVING clients on TCP {self.a.port}; checkpoint every "
                 f"{'write' if self.a.checkpoint_ms == 0 else str(self.a.checkpoint_ms) + ' ms'}")
        return True

    def accept_loop(self):
        while True:
            conn, addr = self.srv.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def fence_watcher(self):
        while True:
            time.sleep(0.1)
            self.check_fence()

    def checkpointer(self):
        if self.a.checkpoint_ms <= 0:
            return                       # write-through mode: saved inside handle()
        while True:
            time.sleep(self.a.checkpoint_ms / 1000)
            if self.chain.count != self.last_saved:
                self.checkpoint_now()

    def fault_injector(self, rate):
        period = self.a.interval_ms / 1000
        while rate > 0:
            time.sleep(random.uniform(0.5, 1.5) * period)
            if random.random() < rate:
                self.crash(random.choice(["simulated segfault in hashing worker",
                                          "simulated use-after-free in log buffer"]))

    def query(self, ev):
        c = ev["cmd"]
        base = {"status": "OK", "node": self.name, "role": self.role, "epoch": self.epoch}
        if c == "PING":
            return base
        if c == "STATUS":
            return {**base, "count": self.chain.count, "head": self.chain.head, "degraded": self.degraded}
        if c == "TAIL":
            k = ev.get("k", 5)
            return {**base, "events": self.chain.tail(k if isinstance(k, int) and 0 < k <= 50 else 5)}
        return {"status": "ERROR", "reason": "unknown cmd"}

    def handle(self, conn, addr):
        with conn, conn.makefile("rb") as rf:
            for line in rf:
                try:
                    ev = json.loads(line)
                    if not isinstance(ev, dict):
                        raise ValueError
                except ValueError:
                    if random.random() < min(1.0, self.p_crash * 10):
                        self.crash(f"parse fault on malformed input from {addr[0]}")
                    conn.sendall(b'{"status":"ERROR","reason":"malformed event"}\n')
                    continue
                if "cmd" in ev:
                    conn.sendall(json.dumps(self.query(ev)).encode() + b"\n")
                    continue
                if random.random() < self.p_crash:
                    self.crash(f"simulated segfault while hashing event from {addr[0]}")
                n, h, dup = self.chain.append(ev)
                if self.a.checkpoint_ms == 0 and not dup:
                    self.checkpoint_now()           # write-through: durable before we acknowledge
                reply = {"status": "OK", "n": n, "hash": h, "epoch": self.epoch}
                if dup:
                    reply["dup"] = True
                conn.sendall(json.dumps(reply).encode() + b"\n")

    # ---- heartbeat (push, own thread, signed) -----------------------------------------------
    def heartbeat_loop(self, addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        seq, period = 0, self.a.interval_ms / 1000
        while True:
            seq += 1
            hb = {"type": "HEARTBEAT", "node": self.name, "role": self.role, "epoch": self.epoch,
                  "pid": os.getpid(), "seq": seq, "ts": time.time(), "events": self.chain.count}
            hb["mac"] = sign(hb, self.key)
            try:
                sock.sendto(json.dumps(hb).encode(), addr)
            except OSError:
                pass
            time.sleep(period)

    # ---- control plane ------------------------------------------------------------------------
    def reply(self, d):
        d = dict(d, node=self.name, ts=time.time())
        d["mac"] = sign(d, self.key)
        return json.dumps(d).encode() + b"\n"

    def ctl_handle(self, conn):
        with conn:
            conn.settimeout(3)
            try:
                msg = json.loads(conn.makefile("rb").readline())
            except (ValueError, OSError):
                return
            if not isinstance(msg, dict):
                return
            cmd = msg.get("cmd")
            if cmd == "PING":
                conn.sendall(json.dumps({"ok": True, "node": self.name, "role": self.role,
                                         "epoch": self.epoch, "pid": os.getpid()}).encode() + b"\n")
                return
            if not verify(msg, self.key) or abs(time.time() - msg.get("ts", 0)) > 10:
                self.log(f"!! control message {cmd!r} REJECTED (bad MAC / stale timestamp)")
                conn.sendall(self.reply({"ok": False, "reason": "bad MAC or stale timestamp"}))
                return
            if cmd == "PROMOTE":
                conn.sendall(self.reply(self.do_promote(msg)))
            elif cmd == "FENCE":
                if self.role == "primary" and isinstance(msg.get("epoch"), int) and msg["epoch"] > self.epoch:
                    self.log(f"FENCE received (epoch {msg['epoch']} > {self.epoch}): stopping now")
                    conn.sendall(self.reply({"ok": True, "fenced": True}))
                    os._exit(3)
                conn.sendall(self.reply({"ok": True, "fenced": False, "reason": "not a superseded primary"}))
            else:
                conn.sendall(self.reply({"ok": False, "reason": "unknown cmd"}))

    def ctl_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.a.ctl_port))
        s.listen(16)
        while True:
            conn, _ = s.accept()
            threading.Thread(target=self.ctl_handle, args=(conn,), daemon=True).start()

    def do_promote(self, msg):
        with self.lock:
            seen = max(self.epoch, self.store.read_epoch())
            if self.role == "primary":
                return {"ok": False, "reason": "already primary", "epoch_seen": seen}
            e = msg.get("epoch")
            if not isinstance(e, int) or e <= seen:
                self.log(f"!! PROMOTE epoch {e} REJECTED (must be > {seen}): stale or replayed")
                return {"ok": False, "reason": f"stale epoch {e} <= {seen}", "epoch_seen": seen}
            t0 = time.time()
            self.log(f"PROMOTE accepted: epoch {seen} -> {e}")
            self.store.write_epoch(e, self.name)       # fencing token first: any zombie primary now exits
            meta, rejected = self.load_state()
            self.epoch, self.epoch_is_initial = e, False
            if not self.start_serving(self.a.bind_wait):
                return {"ok": False, "reason": "could not bind client port", "epoch_seen": e}
            last = msg.get("last_events")
            lost = max(0, last - self.chain.count) if isinstance(last, int) else None
            self.log(f"now PRIMARY at epoch {e}; {self.chain.count} events restored"
                     f"{f', monitor last saw {last} => at least {lost} un-checkpointed events lost' if lost else ''}")
            return {"ok": True, "epoch": e, "count": self.chain.count, "head": self.chain.head,
                    "restored_from": meta["file"] if meta else None, "rejected": rejected,
                    "degraded": self.degraded, "lost_estimate": lost,
                    "took_ms": round((time.time() - t0) * 1000)}


def main():
    ap = argparse.ArgumentParser(description="Log aggregator node (primary or warm standby)")
    ap.add_argument("--node", default="a", help="node id: a or b (decides default control port)")
    ap.add_argument("--role", choices=["primary", "standby"], default="standby")
    ap.add_argument("--port", type=int, default=6000, help="client TCP port (shared; taken over on failover)")
    ap.add_argument("--ctl-port", type=int, default=None, help="control port (default 6100 for a, 6101 for b)")
    ap.add_argument("--monitor", default="127.0.0.1:7000")
    ap.add_argument("--interval-ms", type=int, default=500, help="heartbeat period T")
    ap.add_argument("--state-dir", default="state", help="shared checkpoint directory")
    ap.add_argument("--checkpoint-ms", type=int, default=200,
                    help="checkpoint period; 0 = write-through (every acknowledged event is durable)")
    ap.add_argument("--fault-rate", type=float, default=0.02, help="background crash chance per tick (primary)")
    ap.add_argument("--request-crash-p", type=float, default=0.02, help="crash chance per request")
    ap.add_argument("--promoted-fault-rate", type=float, default=0.0,
                    help="background crash chance per tick AFTER a standby was promoted (0 = stable demo)")
    ap.add_argument("--promoted-request-crash-p", type=float, default=0.0,
                    help="per-request crash chance AFTER promotion (0 = stable demo)")
    ap.add_argument("--bind-wait", type=float, default=3.0, help="seconds to wait for the client port on promotion")
    ap.add_argument("--fresh", action="store_true", help="primary only: wipe old checkpoints/epoch first")
    ap.add_argument("--key", default=None, help="cluster secret (or env CLUSTER_KEY)")
    a = ap.parse_args()
    if a.ctl_port is None:
        a.ctl_port = 6100 + (ord(a.node[0].lower()) - ord("a"))
    n = Node(a, get_key(a.key))
    n.epoch_is_initial = True
    host, port = a.monitor.split(":")
    threading.Thread(target=n.ctl_loop, daemon=True).start()

    if a.role == "primary":
        if a.fresh:
            n.store.wipe()
        n.epoch = n.store.read_epoch() + 1        # a (re)started primary opens a NEW epoch: fences any zombie
        n.store.write_epoch(n.epoch, n.name)
        n.role = "starting"
        n.load_state()
        if not n.start_serving(5.0):
            raise SystemExit(1)
    else:
        n.log(f"warm standby ready; control port {a.ctl_port}; waiting for PROMOTE from the monitor")
    threading.Thread(target=n.heartbeat_loop, args=((host, int(port)),), daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
