"""Heartbeat monitor + automated FAILOVER CONTROLLER (Part 2, deliverable c).

Part 1 behaviour is kept: push heartbeats over UDP, window W = N x T, timestamped alerts,
incident log, never crashes. Part 2 adds, when the primary stops beating:

  [CRASH DETECTED]    timeout W exceeded
  [PROBE]             second, independent check over TCP (is the primary REALLY dead?).
                      If it answers, heartbeats are being dropped/delayed -> SUSPECT, no failover.
  [FAILOVER TRIGGERED] new epoch = old + 1; the old primary is FENCED (SIGKILL if it is a local,
                      authenticated node process, plus a signed FENCE message)
  PROMOTE             signed control message to the warm standby: load newest valid checkpoint,
                      take the client port, become primary
  [SERVICE RESTORED]  verified by a STATUS query to the client port, with MTTR figures

Security properties: heartbeats and control messages are HMAC-signed (spoofing/tampering fails),
heartbeats carry seq + timestamp (replay fails), heartbeats from a lower epoch are treated as a
zombie primary and fenced, the monitor never kills a pid unless it is authenticated, local and
verified to be a service.py process.
"""
import argparse, json, os, signal, socket, subprocess, sys, time
from checkpoint import get_key, sign, verify

LOCAL = ("127.0.0.1", "::1")


def ts(t=None):
    t = t or time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def tcp_json(addr, obj, timeout):
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(json.dumps(obj).encode() + b"\n")
        line = s.makefile("rb").readline()
    if not line:
        raise ConnectionError("closed without reply")
    return json.loads(line)


class Monitor:
    def __init__(self, a):
        self.a, self.key = a, get_key(a.key)
        self.T = a.interval_ms / 1000
        self.W = a.missed * self.T
        self.svc = hostport(a.service)
        self.nodes = {}
        for item in a.nodes.split(","):
            name, addr = item.split("=")
            self.nodes[name] = {"ctl": hostport(addr), "last": 0.0, "pid": None, "role": None, "epoch": 0,
                                "events": 0, "src": None, "seq": {}}
        self.primary, self.epoch, self.state = None, 0, "WAITING"
        self.last_beat = 0.0
        self.next_try = self.next_suspect = self.last_rej = self.last_zombie = 0.0
        self.rej_suppressed = 0

    # ---- output --------------------------------------------------------------------------------
    def incident(self, msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        try:
            with open(self.a.log, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"[{ts()}] could not write log: {e}", flush=True)

    # ---- heartbeat validation (signed, fresh, increasing seq) -----------------------------------
    def check_hb(self, data, src):
        hb = json.loads(data)
        if not isinstance(hb, dict) or hb.get("type") != "HEARTBEAT":
            raise ValueError("not a heartbeat")
        if hb.get("node") not in self.nodes:
            raise ValueError("unknown node id")
        if not verify(hb, self.key):
            raise ValueError("bad MAC (forged/tampered heartbeat)")
        if abs(time.time() - hb["ts"]) > self.a.max_skew:
            raise ValueError(f"stale timestamp ({time.time() - hb['ts']:.1f}s old: replay?)")
        n = self.nodes[hb["node"]]
        if hb["seq"] <= n["seq"].get(hb["pid"], 0):
            raise ValueError(f"replayed/old seq {hb['seq']}")
        n["seq"][hb["pid"]] = hb["seq"]
        if len(n["seq"]) > 32:
            n["seq"].pop(next(iter(n["seq"])))
        return hb

    # ---- fencing ------------------------------------------------------------------------------
    def is_service_pid(self, pid, name):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().decode(errors="replace").split("\0")
        except OSError:
            try:
                argv = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True,
                                      text=True, timeout=2).stdout.split()
            except (OSError, subprocess.SubprocessError):
                return False
        return any(x.endswith("service.py") for x in argv) and name in argv

    def fence(self, name, new_epoch, why):
        n = self.nodes[name]
        pid = n["pid"]
        if self.a.stonith and pid and pid != os.getpid() and n["src"] in LOCAL:
            if not self.is_service_pid(pid, name):
                self.incident(f"[FENCE] pid {pid} is not a live service.py node {name}: not killing "
                              f"(already dead / pid reused)")
            else:
                try:
                    os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                    self.incident(f"[FENCE] {why}: SIGKILL sent to node {name} pid {pid}")
                except ProcessLookupError:
                    self.incident(f"[FENCE] node {name} pid {pid} already gone")
                except OSError as e:
                    self.incident(f"[FENCE] could not kill pid {pid}: {e}")
        try:
            r = self.ctl(name, {"cmd": "FENCE", "epoch": new_epoch}, 0.3)
            self.incident(f"[FENCE] FENCE(epoch {new_epoch}) delivered to node {name}: {r.get('fenced')}")
        except (OSError, ValueError):
            pass                                    # dead nodes cannot be reached; that is the goal

    def ctl(self, name, msg, timeout):
        msg = dict(msg, ts=time.time())
        msg["mac"] = sign(msg, self.key)
        r = tcp_json(self.nodes[name]["ctl"], msg, timeout)
        if not verify(r, self.key):
            raise ValueError("control reply failed MAC check")
        return r

    # ---- failure handling -------------------------------------------------------------------------
    def probe_primary(self):
        """Independent TCP check on the client port. Returns reply dict or None."""
        for _ in range(2):
            try:
                r = tcp_json(self.svc, {"cmd": "PING"}, self.a.probe_timeout_ms / 1000)
                if r.get("status") == "OK" and r.get("role") == "primary":
                    return r
            except (OSError, ValueError):
                pass
        return None

    def standby_ready(self):
        now = time.time()
        for name, n in self.nodes.items():
            if name != self.primary and n["role"] == "standby" and now - n["last"] <= self.W:
                return name
        return None

    def on_timeout(self):
        now = time.time()
        gap = now - self.last_beat
        old = self.primary
        self.incident(f"[CRASH DETECTED] primary node {old} (pid {self.nodes[old]['pid']}, epoch {self.epoch}): "
                      f"no heartbeat for {gap:.2f}s ({self.a.missed} missed beats)")
        if self.a.detect_only:
            self.state = "DOWN"
            return
        alive = self.probe_primary()
        if alive:
            self.state = "SUSPECT"
            self.next_suspect = now + 2.0
            self.incident(f"[SUSPECT] heartbeats are missing but node {old} still answers the TCP probe "
                          f"(epoch {alive.get('epoch')}) -> NOT failing over (dropped/delayed heartbeats?)")
            return
        self.incident(f"[PROBE] node {old} also failed the TCP probe on {self.a.service}: confirmed dead")
        self.failover(old, now)

    def failover(self, old, t_detect):
        standby = self.standby_ready()
        if not standby:
            self.state, self.next_try = "DOWN", time.time() + 1.0
            self.incident("[FAILOVER IMPOSSIBLE] no healthy standby is sending heartbeats; "
                          "start one with: python3 service.py --node X --role standby (will retry)")
            return
        new_epoch = self.epoch + 1
        t_trig = time.time()
        self.incident(f"[FAILOVER TRIGGERED] epoch {self.epoch} -> {new_epoch}; fencing node {old}, "
                      f"promoting node {standby} (+{(t_trig - t_detect) * 1000:.0f} ms after detection)")
        self.fence(old, new_epoch, "old primary declared dead")
        for attempt in (1, 2):
            try:
                r = self.ctl(standby, {"cmd": "PROMOTE", "epoch": new_epoch,
                                       "last_events": self.nodes[old]["events"]}, self.a.promote_timeout)
            except (OSError, ValueError) as e:
                r = {"ok": False, "reason": f"no reply: {e!r}"}
            if r.get("ok"):
                break
            seen = r.get("epoch_seen", 0)
            self.incident(f"[PROMOTE FAILED] {r.get('reason')} (attempt {attempt})")
            if attempt == 1 and isinstance(seen, int) and seen >= new_epoch:
                new_epoch = seen + 1
                continue
            break
        if not r.get("ok"):
            self.epoch = max(self.epoch, new_epoch)
            self.state, self.next_try = "DOWN", time.time() + 2.0
            return
        t_done = time.time()
        self.primary, self.epoch, self.state = standby, new_epoch, "UP"
        self.last_beat = t_done
        self.nodes[old]["role"] = None
        warn = ""
        if r.get("rejected"):
            warn += f" | {len(r['rejected'])} checkpoint(s) REJECTED: " + "; ".join(
                f"{x['file']} ({x['reason']})" for x in r["rejected"])
        if r.get("degraded"):
            warn += " | DEGRADED: all checkpoints invalid, state lost"
        try:
            st = tcp_json(self.svc, {"cmd": "STATUS"}, 1.0)
            ver = f"verified: node {st['node']} role={st['role']} epoch={st['epoch']} events={st['count']}"
        except (OSError, ValueError, KeyError) as e:
            ver = f"VERIFY FAILED ({e!r})"
        lost = r.get("lost_estimate")
        self.incident(f"[SERVICE RESTORED] node {standby} is primary (epoch {new_epoch}), restored from "
                      f"{r.get('restored_from')}, {r.get('count')} events"
                      f"{'' if not lost else f', at least {lost} un-checkpointed events lost'}{warn}")
        self.incident(f"[RECOVERY] {ver}; repair time {t_done - t_detect:.3f}s after detection, "
                      f"outage {t_done - self.nodes[old]['last']:.3f}s since last heartbeat "
                      f"(promote took {r.get('took_ms')} ms)")

    # ---- main loop ----------------------------------------------------------------------------------
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.a.port))
        sock.settimeout(self.T / 4)
        mode = "detect-only" if self.a.detect_only else f"failover (STONITH {'on' if self.a.stonith else 'off'})"
        print(f"[{ts()}] monitor on UDP {self.a.port}, T={self.a.interval_ms} ms, N={self.a.missed}, "
              f"W={self.W:.2f}s, nodes={self.a.nodes}, mode={mode}", flush=True)
        while True:
            try:
                data, src = sock.recvfrom(4096)
                self.on_beat(self.check_hb(data, src), src)
            except socket.timeout:
                pass
            except (ValueError, KeyError, TypeError) as e:
                self.reject(f"ignored bad packet: {e}")
            except OSError as e:
                self.reject(f"socket error ignored: {e}")
            try:
                self.tick()
            except Exception as e:                       # the monitor must never die
                self.incident(f"[MONITOR ERROR] {e!r} (continuing)")

    def reject(self, msg):
        now = time.time()
        if now - self.last_rej >= 1.0:
            extra = f" (+{self.rej_suppressed} more suppressed)" if self.rej_suppressed else ""
            print(f"[{ts()}] {msg}{extra}", flush=True)
            self.last_rej, self.rej_suppressed = now, 0
        else:
            self.rej_suppressed += 1

    def on_beat(self, hb, src):
        now, name = time.time(), hb["node"]
        n = self.nodes[name]
        was_standby_ok = n["role"] == "standby" and now - n["last"] <= self.W
        n.update(last=now, pid=hb["pid"], role=hb["role"], epoch=hb["epoch"], events=hb["events"], src=src[0])
        if hb["role"] == "standby":
            if not was_standby_ok:
                self.incident(f"standby READY: node {name} pid {hb['pid']}")
            elif self.a.verbose:
                print(f"[{ts()}] beat standby {name} seq={hb['seq']}", flush=True)
        elif hb["role"] == "primary":
            if self.primary is None or hb["epoch"] > self.epoch:
                self.incident(f"service UP: primary node {name} pid {hb['pid']} epoch {hb['epoch']} from {src[0]}:{src[1]}")
                self.primary, self.epoch, self.state, self.last_beat = name, hb["epoch"], "UP", now
            elif name == self.primary and hb["epoch"] == self.epoch:
                if self.state in ("SUSPECT", "DOWN"):
                    self.incident(f"[CLEARED] heartbeats from primary {name} resumed: false alarm, no failover needed")
                self.state, self.last_beat = "UP", now
                if self.a.verbose:
                    print(f"[{ts()}] beat primary {name} pid={hb['pid']} seq={hb['seq']} events={hb['events']}", flush=True)
            elif now - self.last_zombie > 1.0:           # stale epoch or a second primary: split-brain attempt
                self.last_zombie = now
                self.incident(f"[SPLIT-BRAIN ALERT] node {name} (pid {hb['pid']}, epoch {hb['epoch']}) claims PRIMARY "
                              f"but the authoritative primary is {self.primary} at epoch {self.epoch}: fencing {name}")
                self.fence(name, self.epoch, "zombie primary")

    def tick(self):
        now = time.time()
        if self.state == "UP" and now - self.last_beat > self.W:
            self.on_timeout()
        elif self.state == "SUSPECT" and now >= self.next_suspect:
            self.next_suspect = now + 2.0
            if self.probe_primary():
                self.incident(f"[SUSPECT] primary {self.primary} still answers probes; heartbeats still missing")
            else:
                self.incident(f"[PROBE] suspected primary {self.primary} has now stopped answering: confirmed dead")
                self.failover(self.primary, now)
        elif self.state == "DOWN" and not self.a.detect_only and now >= self.next_try:
            self.next_try = now + 1.0
            self.failover(self.primary, now)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7000, help="UDP heartbeat port")
    ap.add_argument("--interval-ms", type=int, default=500, help="expected period T")
    ap.add_argument("--missed", type=int, default=3, help="N missed beats before alert")
    ap.add_argument("--nodes", default="a=127.0.0.1:6100,b=127.0.0.1:6101", help="id=ctl_host:ctl_port,...")
    ap.add_argument("--service", default="127.0.0.1:6000", help="client address (for TCP probe / verification)")
    ap.add_argument("--log", default="incidents.log")
    ap.add_argument("--key", default=None, help="cluster secret (or env CLUSTER_KEY)")
    ap.add_argument("--max-skew", type=float, default=5.0, help="max heartbeat age in seconds")
    ap.add_argument("--probe-timeout-ms", type=int, default=500)
    ap.add_argument("--promote-timeout", type=float, default=6.0)
    ap.add_argument("--no-stonith", dest="stonith", action="store_false", help="never SIGKILL the old primary")
    ap.add_argument("--detect-only", action="store_true", help="Part 1 behaviour: alert but do not fail over")
    ap.add_argument("--verbose", action="store_true", help="print every heartbeat")
    a = ap.parse_args()
    try:
        Monitor(a).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
