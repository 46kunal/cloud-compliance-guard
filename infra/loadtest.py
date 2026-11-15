"""Generate load against the dashboard to demonstrate Auto Scaling.

    python infra/loadtest.py https://dxxxx.cloudfront.net --seconds 600 --workers 60

Uses only the public sign-in page and /health, so it needs no credentials. The Auto Scaling policy
tracks 50% average CPU; small instances usually need several minutes of sustained load before a
new server launches, and several more minutes of calm before one is removed. Run it only against
your own deployment.
"""
import argparse
import threading
import time
import urllib.error
import urllib.request

counts = {"ok": 0, "error": 0}
lock = threading.Lock()


def worker(url, stop_at):
    paths = ["/login", "/health"]
    index = 0
    while time.time() < stop_at:
        target = url.rstrip("/") + paths[index % 2]
        index += 1
        try:
            with urllib.request.urlopen(target, timeout=10) as response:
                response.read()
            key = "ok"
        except (urllib.error.URLError, TimeoutError, OSError):
            key = "error"
        with lock:
            counts[key] += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url")
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--workers", type=int, default=60)
    args = parser.parse_args()
    stop_at = time.time() + args.seconds
    threads = [threading.Thread(target=worker, args=(args.url, stop_at), daemon=True) for _ in range(args.workers)]
    for thread in threads:
        thread.start()
    last = 0
    while time.time() < stop_at:
        time.sleep(10)
        with lock:
            total = counts["ok"] + counts["error"]
            print(f"{int(stop_at - time.time()):>4}s left  requests={total}  rate={(total - last) / 10:.0f}/s  errors={counts['error']}")
            last = total
    for thread in threads:
        thread.join(timeout=15)


if __name__ == "__main__":
    main()
