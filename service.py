"""Critical service: Integrity Monitor / Log Aggregator (CS456 Mini Project 1, Task 2 + 3).

Clients send one JSON log event per line over TCP. Each event is added to a SHA-256 hash
chain: hash_n = SHA256(hash_(n-1) + event_n), so editing any old log breaks later hashes.

A separate thread sends a UDP "HEARTBEAT" to the monitor every T ms (push model).

Simulated failure (Task 3), never a fixed counter:
  * a background fault-injection thread with a random chance of crashing each tick
  * a random chance of crashing on each request (much higher on malformed input)
Every crash calls os._exit(1), which terminates the whole process immediately.
"""
import argparse, hashlib, json, os, random, socket, threading, time

def ts():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"

def log(msg):
    print(f"[{ts()}] [service pid={os.getpid()}] {msg}", flush=True)

def crash(reason):
    log(f"CRASH: {reason}")
    os._exit(1)   # ends the whole process, not a sleep

class Chain:
    def __init__(self):
        self.head, self.count, self.lock = "0" * 64, 0, threading.Lock()
    def append(self, event):
        with self.lock:
            data = json.dumps(event, sort_keys=True)
            self.head = hashlib.sha256((self.head + data).encode()).hexdigest()
            self.count += 1
            return self.count, self.head

def heartbeat_loop(addr, period, chain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    while True:
        seq += 1
        beat = {"type": "HEARTBEAT", "pid": os.getpid(), "seq": seq, "ts": time.time(), "events": chain.count}
        try:
            sock.sendto(json.dumps(beat).encode(), addr)
        except OSError:
            pass
        time.sleep(period)

def fault_injector(rate, period):
    while True:
        time.sleep(random.uniform(0.5, 1.5) * period)
        if random.random() < rate:
            crash(random.choice(["simulated segfault in hashing worker",
                                 "simulated use-after-free in log buffer"]))

def handle(conn, addr, chain, p_crash):
    with conn, conn.makefile("rb") as rf:
        for line in rf:
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError
            except ValueError:
                if random.random() < min(1.0, p_crash * 10):
                    crash(f"parse fault on malformed input from {addr[0]}")
                conn.sendall(b'{"status":"ERROR","reason":"malformed event"}\n')
                continue
            if random.random() < p_crash:
                crash(f"simulated segfault while hashing event from {addr[0]}")
            n, h = chain.append(event)
            conn.sendall(json.dumps({"status": "OK", "n": n, "hash": h}).encode() + b"\n")

def main():
    ap = argparse.ArgumentParser(description="Integrity Monitor / Log Aggregator service")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--monitor", default="127.0.0.1:7000")
    ap.add_argument("--interval-ms", type=int, default=500, help="heartbeat period T")
    ap.add_argument("--fault-rate", type=float, default=0.02, help="background crash chance per tick")
    ap.add_argument("--request-crash-p", type=float, default=0.02, help="crash chance per request")
    a = ap.parse_args()
    T = a.interval_ms / 1000
    host, port = a.monitor.split(":")
    chain = Chain()
    threading.Thread(target=heartbeat_loop, args=((host, int(port)), T, chain), daemon=True).start()
    threading.Thread(target=fault_injector, args=(a.fault_rate, T), daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.port)); srv.listen(64)
    log(f"listening on TCP {a.port}; heartbeats every {a.interval_ms} ms to {a.monitor}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr, chain, a.request_crash_p), daemon=True).start()

if __name__ == "__main__":
    main()
