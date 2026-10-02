#!/usr/bin/env python3
"""
stall_check.py - what were the stalled processes actually waiting for?

Reads the CSVs an incident_dump.py run already wrote, and answers the one
question the D-state signal cannot answer on its own: is this the local disk,
or something off the box (a network filesystem, a storage client)?

The discriminator is that cgroup/process IO counters here are BLOCK device
bytes (/proc/<pid>/io read_bytes/write_bytes and io.stat), so NFS or SMB
traffic never shows up in them. Processes stalled in D state with no block IO
of their own were waiting on something that is not this machine's disk.

  python3 stall_check.py <incident dir>

Three blocks:
  1. the busiest stall moments, and how many DIFFERENT users stalled together
     (several unrelated users at the same second = a shared dependency)
  2. per user: D state vs IO pressure vs their own block IO
  3. whole-box block IO next to the stall count, to test the competing
     explanation that one process saturated the local disk

Stdlib only.
"""
import csv
import json
import os
import sys
from datetime import datetime

D = sys.argv[1] if len(sys.argv) > 1 else "."
try:
    W = json.load(open(f"{D}/meta.json"))["window"]
except OSError:
    raise SystemExit(f"no meta.json in {D} - point this at an incident_dump.py output directory")
T0 = datetime.fromisoformat(W["start"]).timestamp()
T1 = datetime.fromisoformat(W["end"]).timestamp()


def hhmm(t):
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def load(qid, key="service", sub=None):
    """{series name: [(unix, value)]} from data/<qid>.csv; {} when absent."""
    path = f"{D}/data/{qid}.csv"
    out = {}
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                v, t = float(r["value"]), float(r["unix"])
            except (ValueError, KeyError, TypeError):
                continue
            name = r.get(key) or "-"
            if sub and r.get(sub):
                name = f"{name}/{r[sub]}"
            out.setdefault(name, []).append((t, v))
    return out


def peak(points, lo=T0, hi=T1):
    vals = [v for t, v in points if lo <= t <= hi]
    return max(vals) if vals else None


def totals(series):
    """{unix: sum across series}"""
    agg = {}
    for pts in series.values():
        for t, v in pts:
            agg[t] = agg.get(t, 0) + v
    return agg


dstate = load("cg_dstate", sub="comm")
if not dstate:
    raise SystemExit("data/cg_dstate.csv is empty or missing - nothing stalled, or cgroup-exporter had no data")

users = {}
for name, pts in dstate.items():
    u = name.split("/")[0]
    m = peak(pts)
    if m:
        users[u] = max(users.get(u, 0), m)

print("== 1. busiest stall moments (processes in D state) ==")
per_t = {}
for name, pts in dstate.items():
    for t, v in pts:
        if v > 0:
            per_t.setdefault(t, []).append((name, v))
if not per_t:
    print("  nothing in D state inside the window")
for t in sorted(per_t, key=lambda t: -sum(v for _, v in per_t[t]))[:8]:
    rows = sorted(per_t[t], key=lambda r: -r[1])
    users_here = len({n.split("/")[0] for n, _ in rows})
    inside = "  <-- inside the reported window" if T0 <= t <= T1 else ""
    print(f"  {hhmm(t)}  {users_here} user(s) / {len(rows)} command(s) / "
          f"{sum(v for _, v in rows):.0f} process(es){inside}")
    print(f"            {', '.join(n for n, _ in rows[:6])}")

print("\n== 2. per user: stalled on IO, but doing any block IO? ==")
psi_some, psi_full = load("cg_psi_io_some"), load("cg_psi_io_full")
read, write = load("cg_io_read"), load("cg_io_write")
print(f"  {'user':<16}{'D state':>9}{'io PSI some':>13}{'io PSI full':>13}{'block read':>13}{'block write':>13}")
for u, dmax in sorted(users.items(), key=lambda kv: -kv[1])[:12]:
    def col(src, unit, scale=1.0):
        m = peak(src.get(u, []))
        return "-" if m is None else f"{m / scale:.1f} {unit}"
    print(f"  {u:<16}{dmax:>9.0f}{col(psi_some, '%'):>13}{col(psi_full, '%'):>13}"
          f"{col(read, 'MB/s', 1e6):>13}{col(write, 'MB/s', 1e6):>13}")
print("  block read/write = real block-device bytes; NFS and SMB traffic is NOT counted here")

print("\n== 3. competing explanation: did the local disk saturate? ==")
io_all = totals(dict([(f"r:{k}", v) for k, v in read.items()]
                     + [(f"w:{k}", v) for k, v in write.items()]))
ds_all = totals(dstate)
rows = [(t, ds_all.get(t, 0), io_all.get(t, 0)) for t in sorted(set(ds_all) | set(io_all))
        if T0 - 900 <= t <= T1 + 900 and (ds_all.get(t, 0) or io_all.get(t, 0) > 50e6)]
if not rows:
    print("  no stalls and no heavy block IO around the window")
print(f"  {'time':<10}{'D state':>9}{'box-wide block IO':>20}")
for t, ds, io in rows:
    print(f"  {hhmm(t):<10}{ds:>9.0f}{io / 1e6:>16.1f} MB/s")
print("\n  stalls lining up with the IO peaks -> local disk contention;"
      "\n  stalls with the box quiet -> the wait is off this machine")
