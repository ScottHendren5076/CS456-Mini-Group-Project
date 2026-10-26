"""Heartbeat monitor (Task 4, push model). Separate process, separate UDP socket.

Every valid HEARTBEAT resets the timer. If N consecutive periods pass with no beat
(window W = N x T), the service is declared dead: a timestamped ALERT is printed and
appended to the incident log. All errors are caught so the monitor never crashes.
"""
import argparse, json, socket, time

def ts():
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t*1000)%1000:03d}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7000)
    ap.add_argument("--interval-ms", type=int, default=500, help="expected period T")
    ap.add_argument("--missed", type=int, default=3, help="N missed beats before alert")
    ap.add_argument("--log", default="incidents.log")
    ap.add_argument("--verbose", action="store_true", help="print every heartbeat")
    a = ap.parse_args()
    T = a.interval_ms / 1000
    W = a.missed * T

    def incident(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        try:
            with open(a.log, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"[{ts()}] could not write log: {e}", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", a.port))
    sock.settimeout(T / 4)
    print(f"[{ts()}] monitor on UDP {a.port}, T={a.interval_ms} ms, N={a.missed}, W={W:.2f}s", flush=True)

    last, alive, pid = None, False, None
    while True:
        try:
            data, src = sock.recvfrom(2048)
            hb = json.loads(data)
            if hb.get("type") != "HEARTBEAT":
                raise ValueError("not a heartbeat")
            last = time.time()
            if not alive or hb["pid"] != pid:
                pid = hb["pid"]
                incident(f"service UP: pid {pid} from {src[0]}:{src[1]}")
            elif a.verbose:
                print(f"[{ts()}] beat pid={pid} seq={hb['seq']} events={hb.get('events')}", flush=True)
            alive = True
        except socket.timeout:
            pass
        except (ValueError, KeyError, TypeError) as e:
            print(f"[{ts()}] ignored bad packet: {e}", flush=True)
        except OSError as e:
            print(f"[{ts()}] socket error ignored: {e}", flush=True)

        if alive and time.time() - last > W:
            alive = False
            incident(f"ALERT: service pid {pid} FAILED, no heartbeat for {time.time()-last:.2f}s ({a.missed} missed beats)")

if __name__ == "__main__":
    main()
