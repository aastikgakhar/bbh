"""Start the lab on 127.0.0.1. `python run_lab.py --port 5057 --reset`."""

import argparse
import os

import app as lab


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("LAB_PORT", "5057")))
    ap.add_argument("--reset", action="store_true", help="re-seed the database (default each start)")
    args = ap.parse_args()
    os.environ["LAB_PORT"] = str(args.port)
    lab.seed()
    print(f"lab on http://127.0.0.1:{args.port}  (alice/alice-pass, bob/bob-pass)")
    lab.app.run(host="127.0.0.1", port=args.port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
