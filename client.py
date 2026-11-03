"""Demo client (Part 2): sends log events, survives failover, and PROVES the state survived.

It keeps its own copy of the hash chain of every event the service acknowledged. After an outage
it asks the service for STATUS and compares count + head hash with its local copy:
  * equal                  -> pre-crash state is intact on the new primary
  * server count < local   -> that many ACKNOWLEDGED events were lost (checkpoint window)
  * same count, other head -> state diverged / was tampered with
It retries each event until acknowledged (events carry an "id", so a retry is never applied twice).
"""
import argparse, itertools, json, random, secrets, socket, time
from checkpoint import GENESIS, chain_step


def ts():
    t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"


def say(msg):
    print(f"[{ts()}] [client] {msg}", flush=True)


def request(addr, obj, timeout=1.0):
    with socket.create_connection(addr, timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((obj if isinstance(obj, bytes) else json.dumps(obj).encode()) + b"\n")
        line = s.makefile("rb").readline()
    if not line:
        raise ConnectionError("connection closed without reply (server crashed?)")
    return json.loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="127.0.0.1:6000")
    ap.add_argument("--rate", type=float, default=4.0, help="events per second")
    ap.add_argument("--count", type=int, default=0, help="stop after N events (0 = forever)")
    ap.add_argument("--bad-fraction", type=float, default=0.0, help="fraction of malformed requests (can crash the service)")
    ap.add_argument("--name", default=None, help="event id prefix (default: random per run)")
    a = ap.parse_args()
    h, p = a.server.rsplit(":", 1)
    addr = (h, int(p))
    if not a.name:
        a.name = "c" + secrets.token_hex(2)
    head, count = GENESIS, 0
    try:                                         # resume from whatever the service already holds
        st = request(addr, {"cmd": "STATUS"})
        head, count = st["head"], st["count"]
        say(f"connected to node {st['node']} (epoch {st['epoch']}); service already holds {count} events")
    except (OSError, ValueError, KeyError):
        say("service not reachable yet; starting from an empty chain")
    outage_start = None

    for i in itertools.count(1):
        if a.count and i > a.count:
            break
        if random.random() < a.bad_fraction:
            try:
                request(addr, b"{ this is not json")
            except (OSError, ValueError):
                say("malformed request -> connection dropped (service may have crashed)")
            time.sleep(1 / a.rate)
            continue
        ev = {"id": f"{a.name}-{i}", "user": random.choice(["alice", "bob", "carol"]),
              "action": random.choice(["login", "logout", "read", "write", "sudo"]), "t": round(time.time(), 3)}
        while True:                                     # retry until acknowledged
            try:
                r = request(addr, ev)
                if r.get("status") != "OK":
                    raise ValueError(f"error reply {r}")
                break
            except (OSError, ValueError) as e:
                if outage_start is None:
                    outage_start = time.time()
                    say(f"!! request {ev['id']} failed ({type(e).__name__}); retrying until the service is back...")
                time.sleep(0.1)
        recovered = outage_start is not None
        if recovered:
            say(f"SERVICE BACK after {time.time() - outage_start:.2f}s client-side outage (answered by epoch {r.get('epoch')})")
            outage_start = None
        # integrity check: the server's hash for this event must equal our local chain extended by it
        exp_n, exp_head = count + 1, chain_step(head, ev)
        if r["n"] == exp_n and r["hash"] == exp_head:
            if recovered:
                say(f"STATE CHECK: OK -- all {count} pre-crash events are present and the hash chain matches")
        else:
            if r["n"] < exp_n:
                say(f"STATE CHECK: LOST {exp_n - r['n']} acknowledged event(s) (newer than the last checkpoint); "
                    f"server is at n={r['n']}, client expected {exp_n}. Continuing from the server's state.")
            elif r["n"] == exp_n:
                say(f"STATE CHECK: DIVERGED -- same count {r['n']} but different hash (tampering / corruption?)")
            else:
                say(f"STATE CHECK: server has MORE events than acknowledged (n={r['n']}, expected {exp_n})")
        head, count = r["hash"], r["n"]                  # always continue from the server's view
        if recovered:
            try:
                st = request(addr, {"cmd": "STATUS"})
                tail = request(addr, {"cmd": "TAIL", "k": 3})["events"]
                say(f"new primary: node {st['node']} epoch {st['epoch']} count {st['count']}"
                    f"{' DEGRADED (no valid checkpoint)' if st.get('degraded') else ''}; "
                    f"last events: " + ", ".join(e.get("id", "?") for e in tail))
            except (OSError, ValueError, KeyError) as e:
                say(f"could not fetch STATUS: {e}")
        say(f"#{i} {ev['id']} {ev['action']:<6} -> OK n={r['n']} hash={r['hash'][:12]} epoch={r.get('epoch')}"
            f"{' (dup, applied once)' if r.get('dup') else ''}")
        time.sleep(1 / a.rate)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
client.py
6 KB
