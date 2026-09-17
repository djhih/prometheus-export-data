#!/usr/bin/env python3
"""
incident_dump.py - collect Prometheus evidence for one incident window and
draft a postmortem from it.

Given the window someone reported a slowdown in, this script:
  1. runs a fixed catalog of PromQL queries (ssh-probe latency, host and
     cgroup PSI, CPU/memory/IO attribution, OOM, D-state, containers, GPU
     faults, ffds-sync, alerts) over the window plus a baseline before it,
  2. saves every raw API response (JSON) and a flat CSV per query,
  3. compares the incident window against the baseline and lists the
     signals that moved, with the time they first crossed their threshold,
  4. fills postmortem-template.zh-tw.md with those facts (impact, detection,
     candidate timeline, data coverage, top offenders, Grafana links),
  5. writes collect-host-logs.sh: the journal/kernel/login evidence that
     Prometheus doesn't hold, pinned to the same window.

Everything lands in one directory, so the evidence outlives the Prometheus
retention (15d in the reference stack). Stdlib only.

Usage:
  # Prometheus binds 127.0.0.1 on the monitoring host - tunnel first:
  ssh -N -L 9090:localhost:9090 <monitoring-host> &
  python3 incident_dump.py --start "2026-09-10 14:00" --end "2026-09-10 16:00" \\
      --instance gpu-node-1
  # a copied TSDB mounted as a local Prometheus:
  python3 incident_dump.py ... --prom http://localhost:9091
  # print every PromQL expression without contacting Prometheus:
  python3 incident_dump.py --start ... --end ... --instance gpu-node-1 --list

Times without an offset are read in --tz (default: this machine's zone).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = HERE / "postmortem-template.zh-tw.md"
DEFAULT_HYPOTHESES = HERE / "hypotheses.zh-tw.json"

MAX_POINTS = 11000          # Prometheus rejects query_range above this per series
STEPS = (15, 30, 60, 120, 300, 600, 1800, 3600)
HIDDEN_LABELS = {"__name__", "uid", "uuid"}   # redundant with service / gpu
TABLE_HIDDEN = HIDDEN_LABELS | {"instance", "job"}
CMD_WIDTH = 90              # truncate command lines in markdown tables (CSV keeps them whole)
EVENTS_PER_QUERY = 3        # timeline candidates per query, strongest first
MAX_TIMELINE = 80

SECTIONS = {
    "coverage": "Data coverage",
    "experience": "User experience (ssh-probe)",
    "host": "Host (node-exporter)",
    "cgroup": "cgroups (cgroup-exporter)",
    "containers": "Containers (cAdvisor)",
    "gpu": "GPU (nvml / DCGM)",
    "ffds": "ffds-sync",
    "alerts": "Alerts",
    "top": "Top consumers",
}

# Dashboards worth opening for the window: (uid, title, variable holding the instance).
# uids/variables from the provisioned Grafana dashboard JSONs.
DASHBOARDS = [
    ("ssh-probe", "SSH Probe - Login & Command Latency", "host"),
    ("cgroup-host-detail", "cgroup - Host Detail", "instance"),
    ("cgroup-cluster-overview", "cgroup - Cluster Overview", None),
    ("cadvisor-container-detail", "Docker Container Detail (cAdvisor)", "instance"),
    ("gpu-dataflow", "GPU - Dataflow", "host"),
    ("nvml-host-detail", "NVML GPU Host Detail", "instance"),
    ("ffds-sync", "FFDS Sync - SMB to WEKA", "host"),
]


# ---------------------------------------------------------------- catalog --

@dataclass
class Query:
    id: str
    section: str
    title: str
    expr: str
    unit: str = ""
    kind: str = "range"         # range: series over the context window; table: one eval over the incident window
    floor: float | None = None  # timeline signal: absolute threshold (also >= 2x baseline p95); None = info only
    impact: bool = False        # user-facing, quoted in the Impact section


def build_catalog(inst: str, step: int, dur_s: float) -> list[Query]:
    # Jobs don't agree on the instance label: most keep Prometheus' default
    # host:port (a different port per exporter), some relabel to the bare
    # host. Match both - anchored, so node-1 never matches node-11.
    host_re = re.escape(inst).replace("\\", "\\\\")   # backslashes doubled inside a PromQL string
    im = f'instance=~"{host_re}(:[0-9]+)?"'

    def s(metric, *extra):
        return metric + "{" + ",".join((im,) + extra) + "}"

    # Gauges: at step >= 2 scrapes, take the max inside each step so spikes
    # between evaluation points survive; otherwise the plain read already
    # sees every sample.
    def peak(sel, scrape=15):
        return f"max_over_time({sel}[{step}s])" if step >= 2 * scrape else sel

    def low(sel, scrape=15):
        return f"min_over_time({sel}[{step}s])" if step >= 2 * scrape else sel

    # Grafana's $__rate_interval: >= 4 scrapes, and never skip samples between steps.
    def rw(scrape=15):
        return f"{max(4 * scrape, step + scrape)}s"

    D = f"{int(dur_s)}s"
    up_w = f"{max(step, 60)}s"
    probe_up = 'up{job="ssh-probe"}'   # the probe runs on the monitoring host; its up has no target instance
    idle = s("node_cpu_seconds_total", 'mode="idle"')
    iowait = s("node_cpu_seconds_total", 'mode="iowait"')
    disk = 'device!~"loop.*|ram.*|sr.*|fd.*"'
    net = 'device!~"lo|veth.*|docker.*|br-.*|cali.*|flannel.*|virbr.*"'
    fs = 'fstype!~"tmpfs|overlay|squashfs|nsfs|devtmpfs|ramfs|autofs"'
    named = 'name!=""'

    def ctr(metric):
        return s(metric, named)

    def label(expr, value):
        return f"label_replace({expr}, 'probe', '{value}', '', '')"

    return [
        Query("up", "coverage", "Scrape health (min up per window)",
              f"min_over_time({s('up')}[{up_w}]) or min_over_time({probe_up}[{up_w}])"),

        Query("ssh_connect", "experience", "SSH login time",
              f"max({peak(s('ssh_probe_connect_duration_seconds'), 5)})", "s", floor=1.0, impact=True),
        Query("ssh_logout", "experience", "SSH logout time",
              f"max({peak(s('ssh_probe_logout_duration_seconds'), 5)})", "s", floor=1.0, impact=True),
        Query("ssh_command", "experience", "Remote command latency",
              f"max by (command) ({peak(s('ssh_probe_command_duration_seconds'), 5)})", "s",
              floor=0.5, impact=True),
        Query("ssh_connect_failures", "experience", "SSH login failures",
              f"sum(increase({s('ssh_probe_connect_failures_total')}[{rw(5)}]))", "count",
              floor=0.5, impact=True),
        Query("ssh_command_failures", "experience", "Remote command failures",
              f"sum by (command) (increase({s('ssh_probe_command_failures_total')}[{rw(5)}]))", "count",
              floor=0.5, impact=True),

        Query("host_load", "host", "Load1 per CPU",
              f"{peak(s('node_load1'))} / scalar(count({idle}))", "x", floor=1.0),
        Query("host_cpu_busy", "host", "CPU busy",
              f"100 * (1 - avg(rate({idle}[{rw()}])))", "%", floor=85),
        Query("host_iowait", "host", "CPU iowait",
              f"100 * avg(rate({iowait}[{rw()}]))", "%", floor=10),
        Query("host_psi_cpu", "host", "Host CPU pressure (some)",
              f"100 * rate({s('node_pressure_cpu_waiting_seconds_total')}[{rw()}])", "%", floor=20),
        Query("host_psi_mem_some", "host", "Host memory pressure (some)",
              f"100 * rate({s('node_pressure_memory_waiting_seconds_total')}[{rw()}])", "%", floor=5),
        Query("host_psi_mem_full", "host", "Host memory pressure (full)",
              f"100 * rate({s('node_pressure_memory_stalled_seconds_total')}[{rw()}])", "%", floor=2),
        Query("host_psi_io_some", "host", "Host IO pressure (some)",
              f"100 * rate({s('node_pressure_io_waiting_seconds_total')}[{rw()}])", "%", floor=20),
        Query("host_psi_io_full", "host", "Host IO pressure (full)",
              f"100 * rate({s('node_pressure_io_stalled_seconds_total')}[{rw()}])", "%", floor=5),
        Query("host_mem_used", "host", "Memory used (1 - MemAvailable/MemTotal)",
              f"100 * (1 - {low(s('node_memory_MemAvailable_bytes'))} / {s('node_memory_MemTotal_bytes')})",
              "%", floor=90),
        Query("host_swap_in", "host", "Swap-in (pages/s)",
              f"rate({s('node_vmstat_pswpin')}[{rw()}])", "/s", floor=100),
        Query("host_disk_busy", "host", "Disk busy (io_time)",
              f"100 * rate({s('node_disk_io_time_seconds_total', disk)}[{rw()}])", "%", floor=80),
        Query("host_fs_used", "host", "Filesystem used",
              f"100 * (1 - {s('node_filesystem_avail_bytes', fs)} / {s('node_filesystem_size_bytes', fs)})",
              "%", floor=95),
        Query("host_net_rx", "host", "Network receive",
              f"rate({s('node_network_receive_bytes_total', net)}[{rw()}])", "Bps"),
        Query("host_net_tx", "host", "Network transmit",
              f"rate({s('node_network_transmit_bytes_total', net)}[{rw()}])", "Bps"),

        Query("cg_psi_cpu", "cgroup", "cgroup CPU pressure (some)",
              f"100 * rate({s('cgroup_psi_cpu_some_seconds_total')}[{rw()}])", "%", floor=20),
        Query("cg_psi_mem_some", "cgroup", "cgroup memory pressure (some)",
              f"100 * rate({s('cgroup_psi_memory_some_seconds_total')}[{rw()}])", "%", floor=5),
        Query("cg_psi_mem_full", "cgroup", "cgroup memory pressure (full)",
              f"100 * rate({s('cgroup_psi_memory_full_seconds_total')}[{rw()}])", "%", floor=2),
        Query("cg_psi_io_some", "cgroup", "cgroup IO pressure (some)",
              f"100 * rate({s('cgroup_psi_io_some_seconds_total')}[{rw()}])", "%", floor=20),
        Query("cg_psi_io_full", "cgroup", "cgroup IO pressure (full)",
              f"100 * rate({s('cgroup_psi_io_full_seconds_total')}[{rw()}])", "%", floor=5),
        Query("cg_cpu", "cgroup", "CPU used per cgroup",
              f"rate({s('cgroup_cpu_usage_usec_total')}[{rw()}]) / 1e6", "cores", floor=4),
        Query("cg_cpu_throttled", "cgroup", "CPU throttled per cgroup",
              f"rate({s('cgroup_cpu_throttled_usec_total')}[{rw()}]) / 1e6", "cores", floor=0.5),
        Query("cg_mem_anon", "cgroup", "Anonymous memory per cgroup",
              peak(s("cgroup_memory_anon_bytes")), "bytes", floor=8e9),
        Query("cg_mem_current", "cgroup", "memory.current per cgroup",
              peak(s("cgroup_memory_current_bytes")), "bytes"),
        Query("cg_refault", "cgroup", "File refaults (thrashing, pages/s)",
              f"rate({s('cgroup_memory_workingset_refault_file_total')}[{rw()}])", "/s", floor=1000),
        Query("cg_direct_reclaim", "cgroup", "Direct reclaim scans (pages/s)",
              f"rate({s('cgroup_memory_pgscan_direct_total')}[{rw()}])", "/s", floor=1000),
        Query("cg_mem_high", "cgroup", "memory.high breaches",
              f"increase({s('cgroup_memory_events_high_total')}[{rw()}])", "count", floor=0.5),
        Query("cg_oom_kill", "cgroup", "OOM kills",
              f"increase({s('cgroup_memory_events_oom_kill_total')}[{rw()}])", "count", floor=0.5),
        Query("cg_io_read", "cgroup", "Disk read per cgroup",
              f"sum by (service) (rate({s('cgroup_io_read_bytes_total')}[{rw()}]))", "Bps", floor=50e6),
        Query("cg_io_write", "cgroup", "Disk write per cgroup",
              f"sum by (service) (rate({s('cgroup_io_written_bytes_total')}[{rw()}]))", "Bps", floor=50e6),
        Query("cg_dstate", "cgroup", "Processes in D state",
              f"sum by (service, comm) ({peak(s('cgroup_process_dstate_count'))})", "count", floor=3),
        Query("cg_logged_in", "cgroup", "Logged-in users",
              peak(s("cgroup_logged_in_users")), "count", floor=1),

        Query("ctr_cpu", "containers", "CPU used per container",
              f"sum by (name) (rate({ctr('container_cpu_usage_seconds_total')}[{rw()}]))", "cores", floor=4),
        Query("ctr_throttled", "containers", "Throttled CFS periods per container",
              f"100 * sum by (name) (rate({ctr('container_cpu_cfs_throttled_periods_total')}[{rw()}]))"
              f" / sum by (name) (rate({ctr('container_cpu_cfs_periods_total')}[{rw()}]))", "%", floor=25),
        Query("ctr_mem", "containers", "Working set per container",
              f"sum by (name) ({peak(ctr('container_memory_working_set_bytes'))})", "bytes"),
        Query("ctr_oom", "containers", "Container OOM events",
              f"sum by (name) (increase({ctr('container_oom_events_total')}[{rw()}]))", "count", floor=0.5),

        Query("gpu_util", "gpu", "GPU utilization",
              f"100 * max by (gpu) ({peak(s('nvml_gpu_utilization_ratio'))})", "%"),
        Query("gpu_mem", "gpu", "GPU memory used",
              f"max by (gpu) ({peak(s('nvml_gpu_memory_used_bytes'))})", "bytes"),
        Query("gpu_user_mem", "gpu", "GPU memory per user",
              f"sum by (user) ({peak(s('nvml_user_gpu_memory_bytes'))})", "bytes"),
        Query("gpu_xid", "gpu", "GPU XID errors",
              f"sum by (gpu, xid) (increase({s('DCGM_EXP_XID_ERRORS_COUNT')}[{rw(5)}]))", "count", floor=0.5),
        Query("gpu_pcie_replay", "gpu", "PCIe replays",
              f"sum by (gpu) (increase({s('DCGM_FI_DEV_PCIE_REPLAY_COUNTER')}[{rw(5)}]))", "count", floor=0.5),

        Query("ffds_jobs", "ffds", "ffds-sync jobs running",
              f"sum by (job) ({peak(s('ffds_sync_jobs_running'))})", "count", floor=0.5),
        Query("ffds_read", "ffds", "ffds-sync read",
              f"sum by (job) ({peak(s('ffds_sync_job_io_read_bytes_per_second'))})", "Bps", floor=50e6),
        Query("ffds_write", "ffds", "ffds-sync write",
              f"sum by (job) ({peak(s('ffds_sync_job_io_write_bytes_per_second'))})", "Bps", floor=50e6),
        Query("ffds_dstate", "ffds", "ffds-sync processes in D state",
              f"sum by (job) ({peak(s('ffds_sync_job_dstate_processes'))})", "count", floor=0.5),

        Query("alerts", "alerts", "Firing alerts (all instances)", 'ALERTS{alertstate="firing"}'),

        Query("t_ssh_failures", "experience", "SSH probe failures in the window",
              label(f"sum(increase({s('ssh_probe_connect_failures_total')}[{D}]))", "connect")
              + " or " + label(f"sum(increase({s('ssh_probe_logout_failures_total')}[{D}]))", "logout")
              + " or " + label(f"sum by (command) (increase({s('ssh_probe_command_failures_total')}[{D}]))",
                               "command"),
              "count", kind="table"),
        Query("t_logged_in", "experience", "Most users logged in at once",
              f"max_over_time({s('cgroup_logged_in_users')}[{D}])", "count", kind="table"),
        Query("t_top_cpu_proc", "top", "Top processes by CPU% (peak in window)",
              f"topk(15, max by (service, pid, cmd) (max_over_time({s('cgroup_top_process_cpu_percent')}[{D}])))",
              "%", kind="table"),
        Query("t_top_mem_proc", "top", "Top processes by RSS (peak in window)",
              f"topk(15, max by (service, pid, cmd) (max_over_time({s('cgroup_top_process_memory_bytes')}[{D}])))",
              "bytes", kind="table"),
        Query("t_top_io_proc", "top", "Top processes by disk IO rate (peak in window)",
              f"topk(15, max by (service, pid, cmd) (max_over_time({s('cgroup_top_process_io_bytes_per_sec')}[{D}])))",
              "Bps", kind="table"),
        Query("t_cpu_service", "top", "CPU time consumed per cgroup",
              f"topk(15, sum by (service) (increase({s('cgroup_cpu_usage_usec_total')}[{D}])) / 1e6)",
              "cpus", kind="table"),
        Query("t_anon_service", "top", "Peak anonymous memory per cgroup",
              f"topk(15, max by (service) (max_over_time({s('cgroup_memory_anon_bytes')}[{D}])))",
              "bytes", kind="table"),
        Query("t_io_service", "top", "Disk bytes read + written per cgroup",
              f"topk(15, sum by (service) (increase({s('cgroup_io_read_bytes_total')}[{D}]))"
              f" + sum by (service) (increase({s('cgroup_io_written_bytes_total')}[{D}])))",
              "bytes", kind="table"),
        Query("t_dstate", "top", "Commands seen in D state",
              f"max by (service, comm) (max_over_time({s('cgroup_process_dstate_count')}[{D}])) > 0",
              "count", kind="table"),
        Query("t_oom", "top", "OOM kills per cgroup",
              f"sum by (service) (increase({s('cgroup_memory_events_oom_kill_total')}[{D}])) > 0",
              "count", kind="table"),
        Query("t_ctr_cpu", "top", "CPU time consumed per container",
              f"topk(10, sum by (name) (increase({ctr('container_cpu_usage_seconds_total')}[{D}])))",
              "cpus", kind="table"),
        Query("t_ctr_oom", "top", "OOM events per container",
              f"sum by (name) (increase({ctr('container_oom_events_total')}[{D}])) > 0",
              "count", kind="table"),
        Query("t_gpu_user_mem", "top", "Peak GPU memory per user",
              f"topk(10, max by (user, gpu) (max_over_time({s('nvml_user_gpu_memory_bytes')}[{D}])))",
              "bytes", kind="table"),
        Query("t_gpu_xid", "top", "GPU XID errors in the window",
              f"sum by (gpu, xid) (increase({s('DCGM_EXP_XID_ERRORS_COUNT')}[{D}])) > 0",
              "count", kind="table"),
    ]


# ----------------------------------------------------------------- time ----

def parse_offset(text: str) -> timezone:
    m = re.fullmatch(r"(?:UTC)?([+-])(\d{1,2}):?(\d{2})?", text.strip(), re.I)
    if not m:
        raise argparse.ArgumentTypeError(f"bad --tz {text!r}, expected e.g. +08:00")
    delta = timedelta(hours=int(m[2]), minutes=int(m[3] or 0))
    return timezone(-delta if m[1] == "-" else delta)


def parse_time(text: str, tz: timezone | None) -> datetime:
    t = text.strip()
    if re.fullmatch(r"\d{9,}(\.\d+)?", t):
        return datetime.fromtimestamp(float(t), tz or timezone.utc).astimezone(tz)
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        raise SystemExit(f"cannot parse time {text!r}; use 'YYYY-MM-DD HH:MM', RFC3339 or unix seconds")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz) if tz else dt.astimezone()   # naive: --tz, else this machine's zone
    return dt.astimezone(tz) if tz else dt


def parse_duration(text: str) -> float:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|[smhdwy])", text.strip())
    if not parts or "".join(n + u for n, u in parts) != text.strip():
        raise argparse.ArgumentTypeError(f"bad duration {text!r}, expected e.g. 30m, 1h, 1h30m")
    return sum(float(n) * (0.001 if u == "ms" else units[u]) for n, u in parts)


def tz_label(tz) -> str:
    off = datetime.now(tz).utcoffset() or timedelta(0)
    mins = int(off.total_seconds() // 60)
    return f"UTC{'+' if mins >= 0 else '-'}{abs(mins) // 60:02d}:{abs(mins) % 60:02d}"


def posix_tz(tz) -> str:
    """POSIX TZ string for a fixed offset (sign is inverted in POSIX)."""
    off = int((datetime.now(tz).utcoffset() or timedelta(0)).total_seconds() // 60)
    if off == 0:
        return "UTC0"
    name = f"<{'+' if off > 0 else '-'}{abs(off) // 60:02d}{abs(off) % 60:02d}>"
    return f"{name}{'-' if off > 0 else '+'}{abs(off) // 60:02d}:{abs(off) % 60:02d}"


@dataclass
class Window:
    start: float
    end: float
    ctx_start: float
    ctx_end: float
    step: int
    tz: timezone

    def dt(self, t: float) -> datetime:
        return datetime.fromtimestamp(t, self.tz)

    @property
    def multi_day(self) -> bool:
        return self.dt(self.ctx_start).date() != self.dt(self.ctx_end).date()

    def hms(self, t: float | None) -> str:
        if t is None:
            return "-"
        return self.dt(t).strftime("%m-%d %H:%M:%S" if self.multi_day else "%H:%M:%S")

    def full(self, t: float) -> str:
        return self.dt(t).strftime("%Y-%m-%d %H:%M:%S")


def pick_step(span_s: float) -> int:
    for st in STEPS:
        if span_s / st + 1 <= MAX_POINTS:
            return st
    return math.ceil(span_s / (MAX_POINTS - 1))


# ------------------------------------------------------------ prometheus ---

def http_json(url: str, form: dict | None = None, timeout: float = 120) -> dict:
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            return json.loads(body)
        except ValueError:
            return {"status": "error", "error": f"HTTP {e.code}: {body[:300]}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"status": "error", "error": f"request failed: {e}"}


@dataclass
class Series:
    labels: dict
    points: list    # [(unix, value)]


@dataclass
class Result:
    query: Query
    series: list = field(default_factory=list)   # range: [Series]; table: [(labels, value)]
    error: str = ""
    raw: dict = field(default_factory=dict)


def run_query(prom: str, q: Query, w: Window) -> Result:
    if q.kind == "range":
        form = {"query": q.expr, "start": f"{w.ctx_start:.3f}", "end": f"{w.ctx_end:.3f}", "step": f"{w.step}s"}
        resp = http_json(prom + "/api/v1/query_range", form)
    else:
        resp = http_json(prom + "/api/v1/query", {"query": q.expr, "time": f"{w.end:.3f}"})
    res = Result(q, raw=resp)
    if resp.get("status") != "success":
        res.error = str(resp.get("error") or resp)[:300]
        return res
    data = resp.get("data", {})
    for item in data.get("result", []):
        if q.kind == "range":
            pts = [(float(t), float(v)) for t, v in item.get("values", [])]
            res.series.append(Series(item.get("metric", {}), pts))
        else:
            res.series.append((item.get("metric", {}), float(item["value"][1])))
    if q.kind == "table":
        res.series.sort(key=lambda lv: lv[1] if math.isfinite(lv[1]) else -math.inf, reverse=True)
    return res


def save_result(res: Result, data_dir: Path, w: Window) -> None:
    q = res.query
    (data_dir / f"{q.id}.json").write_text(json.dumps({"query": q.expr, "response": res.raw}))
    if not res.series:
        return
    rows = res.series if q.kind == "table" else [(sr.labels, None) for sr in res.series]
    keys = ordered({k for labels, _ in rows for k in labels})
    with open(data_dir / f"{q.id}.csv", "w", newline="") as f:
        out = csv.writer(f)
        if q.kind == "table":
            out.writerow(keys + ["value"])
            for labels, v in res.series:
                out.writerow([labels.get(k, "") for k in keys] + [v])
        else:
            out.writerow(["time", "unix"] + keys + ["value"])
            for sr in res.series:
                lab = [sr.labels.get(k, "") for k in keys]
                for t, v in sr.points:
                    out.writerow([w.full(t), f"{t:.0f}"] + lab + [v])


# --------------------------------------------------------------- analysis --

@dataclass
class Stat:
    series: Series
    base_p95: float | None
    inc_avg: float | None
    inc_max: float | None
    inc_max_t: float | None
    threshold: float | None
    first: float | None = None       # first point above threshold anywhere in the context
    last: float | None = None
    peak: float | None = None        # max above threshold anywhere in the context
    peak_t: float | None = None
    above_s: float = 0.0             # time above threshold inside the incident window
    moved: bool = False

    @property
    def ratio(self) -> float:
        if not self.threshold or self.inc_max is None:
            return 0.0
        return self.inc_max / self.threshold


def p95(vals: list) -> float | None:
    if not vals:
        return None
    s = sorted(vals)
    return s[int(0.95 * (len(s) - 1))]


def analyze(sr: Series, q: Query, w: Window) -> Stat:
    pts = [(t, v) for t, v in sr.points if math.isfinite(v)]
    base = [v for t, v in pts if t < w.start]
    inc = [(t, v) for t, v in pts if w.start <= t <= w.end]
    b95 = p95(base)
    st = Stat(sr, b95,
              sum(v for _, v in inc) / len(inc) if inc else None,
              max((v for _, v in inc), default=None),
              max(inc, key=lambda tv: tv[1])[0] if inc else None,
              None)
    if q.floor is None:
        return st
    st.threshold = max(q.floor, 2 * b95) if b95 is not None else q.floor
    above = [(t, v) for t, v in pts if v > st.threshold]
    if above:
        st.first, st.last = above[0][0], above[-1][0]
        st.peak_t, st.peak = max(above, key=lambda tv: tv[1])
    st.above_s = sum(w.step for t, v in inc if v > st.threshold)
    st.moved = st.above_s > 0
    return st


KEY_ORDER = ["service", "name", "user", "gpu", "xid", "probe", "command", "comm", "pid", "cmd"]


def ordered(keys) -> list:
    return sorted(keys, key=lambda k: (KEY_ORDER.index(k) if k in KEY_ORDER else len(KEY_ORDER), k))


def label_keys(series_labels: list) -> list:
    """Labels worth printing: the ones that tell this query's series apart
    (or, for a lone series, whatever identifies it beyond the host)."""
    if len(series_labels) == 1:
        return ordered(set(series_labels[0]) - TABLE_HIDDEN - {"platform"})
    keys = {k for lab in series_labels for k in lab} - HIDDEN_LABELS
    return ordered(k for k in keys if len({lab.get(k) for lab in series_labels}) > 1)


def fmt_labels(labels: dict, keys: list) -> str:
    return ", ".join(f"{k}={labels.get(k, '')}" for k in keys) or "-"


def fmt(v: float | None, unit: str) -> str:
    if v is None or not math.isfinite(v):
        return "-"
    if unit == "s":
        return f"{v * 1000:.0f} ms" if abs(v) < 1 else f"{v:.2f} s"
    if unit == "%":
        return f"{v:.1f} %"
    if unit in ("bytes", "Bps"):
        n, u = abs(v), "B"
        for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
            if n < 1024 or u == "PiB":
                break
            n /= 1024
        body = f"{v:.0f} B" if u == "B" else f"{math.copysign(n, v):.1f} {u}"
        return body + ("/s" if unit == "Bps" else "")
    if unit == "cores":
        return f"{v:.2f} cores"
    if unit == "cpus":
        return f"{v:,.0f} CPU-s"
    if unit == "/s":
        return f"{v:,.0f}/s"
    if unit == "count":
        return f"{v:.0f}" if abs(v) >= 1 else f"{v:.2g}"
    if unit == "x":
        return f"{v:.2f}"
    return f"{int(v)}" if float(v).is_integer() else f"{v:.3g}"


def cell(text: str, width: int = CMD_WIDTH) -> str:
    text = str(text).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def runs(timestamps: list, step: int) -> list:
    """Group sorted timestamps into [first, last] runs of consecutive steps."""
    out = []
    for t in timestamps:
        if out and t - out[-1][1] <= step * 1.5:
            out[-1][1] = t
        else:
            out.append([t, t])
    return out


def span(a: float, b: float, w: Window) -> str:
    return f"{w.hms(a)} to {w.hms(b)} ({human_dur(b - a + w.step)})"


def human_dur(sec: float) -> str:
    sec = int(round(sec))
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m{sec % 60:02d}s" if sec % 60 else f"{sec // 60}m"
    return f"{sec // 3600}h{(sec % 3600) // 60:02d}m"


# ------------------------------------------------------------ host logs ----

# journalctl -o short-iso: 2026-09-14T14:32:05+0800 host kernel: ...
LOG_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-]\d{2}):?(\d{2})")


class LogScan:
    """host-logs.txt from collect-host-logs.sh: the evidence Prometheus has no
    metric for (OOM kills, hung tasks, XID, remote filesystem errors)."""

    SCANNED = re.compile(r"journal|kernel|dmesg|log", re.I)
    COVERAGE = re.compile(r"entries in window:\s*(\d+)")

    def __init__(self, path: Path):
        self.path = path
        self.covered = True      # False once we know the journal has nothing for the window
        self.lines, keep, saw_header = [], True, False
        for ln in path.read_text(errors="replace").splitlines():
            if ln.startswith("====="):
                # section headers name the very patterns we grep for, and inventory
                # sections (mount tables, sar) are not events - skip both
                saw_header, keep = True, bool(self.SCANNED.search(ln))
                continue
            m = self.COVERAGE.search(ln)
            if m:
                self.covered = int(m[1]) > 0
            if keep:
                self.lines.append(ln)
        if not saw_header:       # not our format: scan everything
            self.lines = path.read_text(errors="replace").splitlines()

    def hits(self, patterns: list) -> list:
        """[(pattern, count, first matching line)] - patterns are plain substrings."""
        out = []
        for pat in patterns:
            rx = re.compile(re.escape(pat), re.I)
            matched = [ln for ln in self.lines if rx.search(ln)]
            if matched:
                out.append((pat, len(matched), matched[0].strip()))
        return out

    @staticmethod
    def stamp(line: str) -> float | None:
        m = LOG_TS.match(line)
        if not m:
            return None
        try:
            return datetime.fromisoformat(f"{m[1]}{m[2]}:{m[3]}").timestamp()
        except ValueError:
            return None


# ------------------------------------------------------------- rendering ---

class Report:
    def __init__(self, results: dict, w: Window, inst: str, args, meta: dict):
        self.r = results
        self.w = w
        self.inst = inst
        self.args = args
        self.meta = meta
        self.stats = {}                                 # query id -> [Stat]
        for qid, res in results.items():
            if res.query.kind == "range" and qid not in ("up", "alerts"):
                self.stats[qid] = [analyze(sr, res.query, w) for sr in res.series]
        self.events = []                                # (t, text)
        self.coverage_issues = []                       # filled by coverage(), read by the hypotheses
        self.log_seen = set()                           # one timeline entry per log line, not per pattern

    # -- coverage ------------------------------------------------------------
    def coverage(self) -> str:
        w, res = self.w, self.r["up"]
        if res.error:
            self.coverage_issues.append(f"`up` query failed: {res.error}")
            return f"- `up` query failed: {res.error}"
        if not res.series:
            return (f"- **No `up` series for instance `{self.inst}` in the window.** Either the host is wrong "
                    "(compare with `count by (job, instance) (up)`) or the data has aged out.")
        expected = int((w.ctx_end - w.ctx_start) // w.step) + 1
        lines = ["| job | instance | samples present | target down | no samples (scrape gap) |",
                 "|---|---|---|---|---|"]
        for sr in sorted(res.series, key=lambda s: s.labels.get("job", "")):
            job = sr.labels.get("job", "?")
            present = {round((t - w.ctx_start) / w.step) for t, _ in sr.points}
            down = [t for t, v in sr.points if v < 1]
            missing = [w.ctx_start + i * w.step for i in range(expected) if i not in present]
            down_runs, gap_runs = runs(down, w.step), runs(missing, w.step)
            for a, b in down_runs:
                self.events.append((a, f"Scrape target down: job `{job}` until {w.hms(b)}"))
                self.coverage_issues.append(f"`{job}` down {span(a, b, w)}")
            for a, b in gap_runs:
                self.events.append((a, f"No samples from job `{job}` until {w.hms(b)}"))
                self.coverage_issues.append(f"`{job}` no samples {span(a, b, w)}")
            lines.append(f"| {job} | {sr.labels.get('instance', '')} | {100 * len(present) / expected:.1f} % | "
                         f"{'; '.join(span(a, b, w) for a, b in down_runs) or 'none'} | "
                         f"{'; '.join(span(a, b, w) for a, b in gap_runs) or 'none'} |")
        lines.append("")
        lines.append(f"Resolution: `min_over_time(up[{max(w.step, 60)}s])` every {w.step}s, so gaps and "
                     "outages shorter than about a minute can be blurred. A job that is missing from this "
                     "table was not scraped for this instance at all.")
        return "\n".join(lines)

    # -- alerts --------------------------------------------------------------
    def alert_intervals(self) -> list:
        res = self.r["alerts"]
        out = []
        for sr in res.series:
            lab = {k: v for k, v in sr.labels.items() if k not in ("__name__", "alertstate")}
            name = lab.pop("alertname", "?")
            desc = ", ".join(f"{k}={v}" for k, v in sorted(lab.items()))
            for a, b in runs([t for t, _ in sr.points], self.w.step):
                out.append((a, b, name, desc))
        return sorted(out)

    # -- moved signals -------------------------------------------------------
    def moved(self) -> list:
        out = []
        for qid, stats in self.stats.items():
            q = self.r[qid].query
            keys = label_keys([s.series.labels for s in stats])
            for st in stats:
                if st.moved:
                    out.append((q, st, keys))
        return sorted(out, key=lambda x: x[1].ratio, reverse=True)

    def signal_events(self) -> None:
        w = self.w
        for qid, stats in self.stats.items():
            q = self.r[qid].query
            keys = label_keys([s.series.labels for s in stats])
            hit = sorted((s for s in stats if s.moved), key=lambda s: s.ratio, reverse=True)
            for st in hit[:EVENTS_PER_QUERY]:
                who = f" [{fmt_labels(st.series.labels, keys)}]" if keys else ""
                self.events.append((st.first,
                    f"{q.title}{who} above {fmt(st.threshold, q.unit)} until {w.hms(st.last)}, "
                    f"peak {fmt(st.peak, q.unit)} at {w.hms(st.peak_t)} "
                    f"(baseline p95 {fmt(st.base_p95, q.unit)})"))
            if len(hit) > EVENTS_PER_QUERY:
                self.events.append((hit[EVENTS_PER_QUERY].first,
                    f"... {len(hit) - EVENTS_PER_QUERY} more series of '{q.title}' moved (see data/{qid}.csv)"))

    def moved_table(self) -> str:
        rows = self.moved()
        if not rows:
            return ("No signal crossed its threshold inside the reported window. Either the window is off "
                    "(widen --pad or move --start/--end), or the slowdown is outside what these exporters see "
                    "(network, client side, a remote filesystem): check the host logs and the overview below.")
        w = self.w
        lines = ["| signal | series | baseline p95 | threshold | incident max (at) | time above |",
                 "|---|---|---|---|---|---|"]
        for q, st, keys in rows[:40]:
            lines.append(f"| {q.title} | {cell(fmt_labels(st.series.labels, keys))} | "
                         f"{fmt(st.base_p95, q.unit)} | {fmt(st.threshold, q.unit)} | "
                         f"{fmt(st.inc_max, q.unit)} ({w.hms(st.inc_max_t)}) | {human_dur(st.above_s)} |")
        if len(rows) > 40:
            lines.append(f"\n{len(rows) - 40} more rows omitted; every series is in `data/*.csv`.")
        lines.append("")
        lines.append("Threshold = max(fixed floor, 2 x baseline p95). Baseline = the "
                     f"{human_dur(w.start - w.ctx_start)} before the reported start; if the problem began "
                     "earlier than reported, the baseline is contaminated and thresholds are too high.")
        return "\n".join(lines)

    # -- overview ------------------------------------------------------------
    def overview(self) -> str:
        w = self.w
        lines = ["| section | signal | series | top series | baseline p95 | incident max (at) | moved |",
                 "|---|---|---|---|---|---|---|"]
        for qid, res in self.r.items():
            q = res.query
            if q.kind != "range" or qid in ("up", "alerts"):
                continue
            sec = SECTIONS[q.section]
            if res.error:
                lines.append(f"| {sec} | {q.title} | - | query error: {cell(res.error, 60)} | | | |")
                continue
            stats = [s for s in self.stats[qid] if s.inc_max is not None]
            if not stats:
                lines.append(f"| {sec} | {q.title} | 0 | no data | | | |")
                continue
            keys = label_keys([s.series.labels for s in self.stats[qid]])
            top = max(stats, key=lambda s: s.inc_max)
            n_moved = sum(s.moved for s in stats)
            lines.append(f"| {sec} | {q.title} | {len(stats)} | {cell(fmt_labels(top.series.labels, keys), 50)} | "
                         f"{fmt(top.base_p95, q.unit)} | {fmt(top.inc_max, q.unit)} ({w.hms(top.inc_max_t)}) | "
                         f"{n_moved or ''} |")
        return "\n".join(lines)

    # -- tables --------------------------------------------------------------
    def table(self, qid: str, limit: int = 15) -> str:
        res = self.r[qid]
        q = res.query
        head = f"**{q.title}** (`data/{qid}.csv`)"
        if res.error:
            return f"{head}: query error: {res.error}"
        if not res.series:
            return f"{head}: none."
        keys = ordered({k for lab, _ in res.series for k in lab} - TABLE_HIDDEN)
        lines = [head, "", "| " + " | ".join(keys + ["value"]) + " |", "|" + "---|" * (len(keys) + 1)]
        for lab, v in res.series[:limit]:
            lines.append("| " + " | ".join(cell(lab.get(k, "")) for k in keys) + f" | {fmt(v, q.unit)} |")
        return "\n".join(lines)

    def top(self) -> str:
        ids = ["t_oom", "t_ctr_oom", "t_dstate", "t_gpu_xid", "t_top_cpu_proc", "t_top_mem_proc",
               "t_top_io_proc", "t_cpu_service", "t_anon_service", "t_io_service", "t_ctr_cpu", "t_gpu_user_mem"]
        return "\n\n".join(self.table(i) for i in ids)

    # -- impact / detection --------------------------------------------------
    def impact(self) -> str:
        w = self.w
        lines = []
        probe_seen = False
        for qid, stats in self.stats.items():
            q = self.r[qid].query
            if not q.impact:
                continue
            probe_seen |= any(s.inc_max is not None for s in stats)
            keys = label_keys([s.series.labels for s in stats])
            for st in stats:
                if not st.moved:
                    continue
                who = f" ({fmt_labels(st.series.labels, keys)})" if keys else ""
                lines.append(f"- {q.title}{who}: peak {fmt(st.inc_max, q.unit)} at {w.hms(st.inc_max_t)} "
                             f"vs baseline p95 {fmt(st.base_p95, q.unit)}; above {fmt(st.threshold, q.unit)} "
                             f"for {human_dur(st.above_s)} of the reported window "
                             f"(first {w.hms(st.first)}, last {w.hms(st.last)}).")
        fails = self.r["t_ssh_failures"]
        nonzero = [(lab, v) for lab, v in fails.series if v >= 0.5]
        if nonzero:
            lines.append("- Probe failures in the window: " + ", ".join(
                f"{lab.get('probe')}{'/' + lab['command'] if 'command' in lab else ''} x{v:.0f}"
                for lab, v in nonzero) + ".")
        if not probe_seen:
            lines.append(f"- ssh-probe has no data for `{self.inst}` in this window, so there is no objective "
                         "latency measurement; impact has to come from the user reports.")
        elif not lines:
            lines.append("- ssh-probe saw nothing abnormal: login and cd/ls/poetry latency stayed within their "
                         "thresholds. The slowdown was either not on the interactive path the probe exercises "
                         "(e.g. inside a job, on GPU, on a network filesystem) or outside the reported window.")
        users = self.r["t_logged_in"].series
        if users:
            lines.append(f"- Up to {users[0][1]:.0f} user accounts were logged in during the window "
                         "(upper bound of who could have noticed).")
        return "\n".join(lines)

    def detection(self) -> str:
        w = self.w
        lines = []
        alerts = [a for a in self.alert_intervals() if a[0] <= w.ctx_end and a[1] >= w.ctx_start]
        if alerts:
            for a, b, name, desc in alerts:
                lines.append(f"- Alert `{name}` ({desc}) firing {span(a, b, w)}.")
        else:
            lines.append(f"- No alert fired between {w.full(w.ctx_start)} and {w.full(w.ctx_end)}.")
        rules = self.meta.get("alert_rules")
        if rules is not None:
            lines.append(f"- Alerting rules loaded in Prometheus ({len(rules)}): "
                         + (", ".join(f"`{r}`" for r in rules) if rules else "none") + ".")
        firsts = [(st.first, q) for q, st, _ in self.moved() if st.first is not None]
        if firsts:
            t, q = min(firsts, key=lambda x: x[0])
            lines.append(f"- Earliest monitoring signal over threshold: {q.title} at {w.full(t)}. "
                         "Compare with when the user noticed and when it was reported (time to detect).")
        return "\n".join(lines)

    # -- timeline ------------------------------------------------------------
    def timeline(self) -> str:
        w = self.w
        self.signal_events()
        for a, b, name, desc in self.alert_intervals():
            self.events.append((a, f"ALERT `{name}` firing ({desc})"))
            if b < w.ctx_end - w.step:
                self.events.append((b + w.step, f"ALERT `{name}` resolved"))
        self.events.append((w.start, "**--- reported window starts ---**"))
        self.events.append((w.end, "**--- reported window ends ---**"))
        ev = sorted((e for e in self.events if e[0] is not None), key=lambda e: e[0])
        dropped = max(0, len(ev) - MAX_TIMELINE)
        if dropped:   # keep the markers, drop the tail
            keep = ev[:MAX_TIMELINE]
            ev = keep + [e for e in ev[MAX_TIMELINE:] if e[1].startswith("**")]
        lines = [f"{w.dt(w.ctx_start):%Y-%m-%d} (all times {tz_label(w.tz)}, "
                 f"{w.step}s resolution)", ""]
        lines += [f"- `{w.hms(t)}` {text}" for t, text in ev]
        if dropped:
            lines.append(f"- ... {dropped} more candidate events omitted.")
        return "\n".join(lines)

    # -- hypotheses ----------------------------------------------------------
    def _series_txt(self, qid: str, st: Stat) -> str:
        keys = label_keys([s.series.labels for s in self.stats.get(qid, [])])
        return f" [{fmt_labels(st.series.labels, keys)}]" if keys else ""

    def _rows_txt(self, qids: list, limit: int = 3) -> str:
        out = []
        for qid in qids:
            res = self.r.get(qid)
            if not res or res.error or not res.series:
                continue
            keys = ordered({k for lb, _ in res.series for k in lb} - TABLE_HIDDEN)
            for lb, v in res.series[:limit]:
                out.append(f"{cell(fmt_labels(lb, keys), 45)} {fmt(v, res.query.unit)}")
            break                                        # one table is enough for a summary cell
        return "; ".join(out)

    def judge(self, h: dict, lab: dict, ph: dict, log) -> tuple:
        """(verdict, evidence) for one hypothesis, from the data actually returned."""
        if h.get("kind") == "coverage":
            return ((lab["supported"], cell("; ".join(self.coverage_issues), 300))
                    if self.coverage_issues else (lab["ruled_out"], ph["coverage_ok"]))

        have, missing = [], []
        for qid in h.get("signals", []):
            res = self.r.get(qid)
            (missing if (res is None or res.error or not res.series) else have).append(qid)
        moved = sorted(((qid, st) for qid in have for st in self.stats.get(qid, []) if st.moved),
                       key=lambda x: x[1].ratio, reverse=True)
        events = []
        for qid in h.get("events", []):
            res = self.r.get(qid)
            if res and not res.error:
                events += [(qid, lb, v) for lb, v in res.series if v >= 0.5]
        usable = log if (log and log.covered) else None
        hits = usable.hits(h["log"]) if (usable and h.get("log")) else []
        for pat, _, line in hits:                        # kernel evidence belongs on the timeline
            at = LogScan.stamp(line)
            if at and self.w.ctx_start - 3600 <= at <= self.w.ctx_end + 3600 and line not in self.log_seen:
                self.log_seen.add(line)                  # several patterns can hit the same line
                self.events.append((at, f"host log ({pat}): {cell(line, 120)}"))

        bits = []
        for qid, st in moved[:2]:
            q = self.r[qid].query
            bits.append(ph["peak"].format(signal=qid, series=self._series_txt(qid, st),
                                          peak=fmt(st.peak if st.peak is not None else st.inc_max, q.unit),
                                          base=fmt(st.base_p95, q.unit), threshold=fmt(st.threshold, q.unit),
                                          time=self.w.hms(st.first)))
        for qid, lb, v in events[:2]:
            res = self.r[qid]
            keys = ordered(set(lb) - TABLE_HIDDEN)
            bits.append(ph["event"].format(signal=qid, series=f" [{fmt_labels(lb, keys)}]" if keys else "",
                                           value=fmt(v, res.query.unit)))
        for pat, n, _ in hits[:3]:
            bits.append(ph["log"].format(pattern=pat, count=n))

        if h.get("kind") == "usage":                     # high usage is not by itself a cause
            rows = self._rows_txt(h.get("tables", []))
            if not rows and not bits:
                return lab["undetermined"], self._nodata(ph, h, missing or h.get("tables", []))
            return lab["manual"], "; ".join(bits + ([ph["top"].format(rows=rows)] if rows else []))
        if bits:
            return lab["supported"], "; ".join(bits)
        if not have and not (h.get("log") and usable):
            gap = missing or h.get("signals", [])
            if h.get("log") and log and not log.covered:
                return lab["undetermined"], ph.get("log_gap", ph["nologs"])
            return lab["undetermined"], (ph["nologs"] if (h.get("log") and not log)
                                         else self._nodata(ph, h, gap))

        scored = [(qid, st) for qid in have for st in self.stats.get(qid, [])
                  if st.inc_max is not None and st.threshold]
        if not scored:
            # data exists but carries no threshold (informational signals): a human must look
            peaks = sorted(((qid, st) for qid in have for st in self.stats.get(qid, [])
                            if st.inc_max is not None), key=lambda x: x[1].inc_max, reverse=True)
            for qid, st in peaks[:2]:
                bits.append(ph["no_threshold"].format(signal=qid, series=self._series_txt(qid, st),
                                                      peak=fmt(st.inc_max, self.r[qid].query.unit)))
            return (lab["manual"], "; ".join(bits)) if bits else \
                   (lab["undetermined"], self._nodata(ph, h, missing or h.get("signals", [])))

        # data was there and nothing crossed its threshold: say how close it got
        best = max(scored, key=lambda x: x[1].ratio, default=None)
        if best:
            qid, st = best
            q = self.r[qid].query
            bits.append(ph["below"].format(signal=qid, series=self._series_txt(qid, st),
                                           max=fmt(st.inc_max, q.unit), threshold=fmt(st.threshold, q.unit)))
        if h.get("log") and usable and not hits:
            bits.append(ph["log_none"].format(patterns=", ".join(h["log"][:4])))
        if missing:
            bits.append(ph["missing"].format(signals=", ".join(f"`{m}`" for m in missing)))
        return lab["ruled_out"], "; ".join(bits) or ph["none"]

    @staticmethod
    def _nodata(ph: dict, h: dict, gap: list) -> str:
        txt = ph["nodata"].format(signals=", ".join(f"`{g}`" for g in gap[:6]))
        return f"{txt}({h['needs']})" if h.get("needs") else txt

    def hypotheses(self, spec: dict, log) -> str:
        lab, ph = spec["labels"], spec["phrases"]
        lines = ["| 分類 | 假設 | 若成立應該看到 | 實際資料 | 結論 |", "|---|---|---|---|---|"]
        tally = {}
        for h in spec["hypotheses"]:
            verdict, evidence = self.judge(h, lab, ph, log)
            tally[verdict] = tally.get(verdict, 0) + 1
            lines.append(f"| {h.get('group', '')} | {h['title']} | {cell(h['signature'], 120)} | "
                         f"{cell(evidence, 300)} | **{verdict}** |")
        counts = "、".join(f"{v} {n}" for v, n in ((lab[k], tally.get(lab[k], 0))
                                                   for k in ("ruled_out", "supported", "manual", "undetermined"))
                          if n)
        lines += ["", ph.get("tally", "{total}: {counts}").format(total=len(spec["hypotheses"]), counts=counts)]
        return "\n".join(lines)

    # -- links / files -------------------------------------------------------
    def links(self) -> str:
        base = self.args.grafana.rstrip("/")
        frm, to = int(self.w.ctx_start * 1000), int(self.w.ctx_end * 1000)
        out = []
        for uid, title, var in DASHBOARDS:
            params = {"orgId": 1, "from": frm, "to": to}
            if var:
                params[f"var-{var}"] = self.inst
            out.append(f"- [{title}]({base}/d/{uid}?{urllib.parse.urlencode(params)})")
        users = []
        for qid in ("t_top_cpu_proc", "t_top_mem_proc", "t_top_io_proc"):
            for lab, _ in self.r[qid].series[:5]:
                svc = lab.get("service")
                if svc and svc not in users:
                    users.append(svc)
        for svc in users[:6]:
            params = {"orgId": 1, "from": frm, "to": to, "var-user": svc}
            out.append(f"- [cgroup - User Processes: {svc}]({base}/d/cgroup-user-processes?"
                       f"{urllib.parse.urlencode(params)})")
        out.append("")
        out.append("Links are pinned to the window above. To keep the graphs after Prometheus drops the data: "
                   "open each one, Share -> Snapshot, expire = Never, and paste the snapshot URL here.")
        return "\n".join(out)

    def files(self, out_dir: Path) -> str:
        return "\n".join([
            f"- Raw API responses: `data/<query>.json`; flat CSV: `data/<query>.csv` "
            f"({sum(1 for _ in (out_dir / 'data').glob('*.csv'))} files). Every PromQL expression is in "
            "`meta.json`, so any number here can be re-derived.",
            f"- Host logs for the same window (journal, kernel OOM/hung-task/XID, logins, sysstat): run "
            f"`ssh {self.inst} 'bash -s' < collect-host-logs.sh > host-logs.txt` "
            "(system logs need root or the systemd-journal/adm group).",
        ])


# ---------------------------------------------------------------- host logs --

def host_logs_script(w: Window, inst: str) -> str:
    since, until = int(w.ctx_start), int(w.ctx_end)
    d0 = w.dt(w.ctx_start)
    d1 = w.dt(w.ctx_end)
    return f"""#!/usr/bin/env bash
# Host-side evidence for {w.full(w.ctx_start)} .. {w.full(w.ctx_end)} ({tz_label(w.tz)}),
# generated by incident_dump.py for {inst}. Run ON the target:
#   ssh {inst} 'bash -s' < collect-host-logs.sh > host-logs.txt
# Full system logs need root or membership in systemd-journal/adm.
set -u
SINCE=@{since}
UNTIL=@{until}
export TZ='{posix_tz(w.tz)}'   # print timestamps in the report's timezone
section() {{ printf '\\n===== %s =====\\n' "$*"; }}

section "host"
hostname; uname -r; uptime; id

section "journal coverage: does the journal even reach this window?"
echo "entries in window: $(journalctl --since "$SINCE" --until "$UNTIL" --no-pager -q 2>/dev/null | wc -l)"
echo -n "oldest journal entry: "; journalctl --no-pager -o short-iso -q 2>/dev/null | head -n 1
journalctl --disk-usage 2>&1

section "journal: priority warning and above"
journalctl --since "$SINCE" --until "$UNTIL" -p warning --no-pager -o short-iso 2>&1 | tail -n 2000

section "kernel: OOM, hung tasks, GPU XID, IO / network filesystem errors"
journalctl -k --since "$SINCE" --until "$UNTIL" --no-pager -o short-iso 2>&1 \\
  | grep -Ei 'out of memory|oom|blocked for more than|hung_task|xid|nvrm|i/o error|blk_update_request|nfs|cifs|smb|soft lockup' \\
  || echo "(no matches - if the journal is not persistent, see dmesg below)"

section "dmesg tail (ring buffer, may not reach back to the window)"
dmesg -T 2>&1 | tail -n 300

section "logins overlapping the window"
last -F -s '{d0:%Y-%m-%d %H:%M:%S}' -t '{d1:%Y-%m-%d %H:%M:%S}' 2>&1 | head -n 200

section "sysstat (if installed)"
if command -v sar >/dev/null; then
  for f in /var/log/sa/sa{d0:%d} /var/log/sysstat/sa{d0:%d} /var/log/sysstat/sa{d0:%Y%m%d}; do
    [ -f "$f" ] || continue
    echo "# $f"
    sar -u -q -r -W -B -d -p -s {d0:%H:%M:%S} -e {d1:%H:%M:%S} -f "$f" 2>&1
  done
else
  echo "(sar not installed)"
fi
"""


# ------------------------------------------------------------------- main ---

def fill_template(template: str, values: dict) -> str:
    out = template
    for k, v in values.items():
        out = out.replace("{{" + k + "}}", v)
    left = sorted(set(re.findall(r"\{\{([A-Z_]+)\}\}", out)))
    if left:
        print(f"warning: template placeholders not filled: {', '.join(left)}", file=sys.stderr)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump Prometheus evidence for an incident window and draft a postmortem.")
    ap.add_argument("--start", required=True, help="reported start, e.g. '2026-09-10 14:00' (or RFC3339 / unix)")
    ap.add_argument("--end", required=True, help="reported end")
    ap.add_argument("--instance", required=True, help="affected host as in its instance label, port optional (matches host and host:<port>)")
    ap.add_argument("--pad", type=parse_duration, default=parse_duration("1h"),
                    help="context before/after the window; the part before is the baseline (default 1h)")
    ap.add_argument("--tz", type=parse_offset, default=None, help="offset for naive times, e.g. +08:00")
    ap.add_argument("--prom", default="http://localhost:9090", help="Prometheus base URL")
    ap.add_argument("--grafana", default="http://localhost:3000", help="Grafana base URL (for links only)")
    ap.add_argument("--step", type=parse_duration, default=None, help="query resolution (default: auto, >= 15s)")
    ap.add_argument("--title", default=None, help="incident title for the draft")
    ap.add_argument("--out", type=Path, default=None, help="output directory (default: ./incident-<instance>-<start>)")
    ap.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    ap.add_argument("--hypotheses", type=Path, default=DEFAULT_HYPOTHESES,
                    help="root-cause checklist to judge against the data")
    ap.add_argument("--host-logs", type=Path, default=None,
                    help="host-logs.txt from collect-host-logs.sh; adds kernel evidence to the checklist")
    ap.add_argument("--force", action="store_true", help="write into an existing non-empty output directory")
    ap.add_argument("--list", action="store_true", help="print the query catalog and exit")
    args = ap.parse_args()

    args.instance = re.sub(r":[0-9]+$", "", args.instance)   # host:port -> host; queries match any port
    tz = args.tz or datetime.now().astimezone().tzinfo    # the report is written in one zone
    start = parse_time(args.start, args.tz).astimezone(tz)
    end = parse_time(args.end, args.tz).astimezone(tz)
    if end <= start:
        raise SystemExit("--end must be after --start")
    t0, t1 = start.timestamp(), end.timestamp()
    ctx0, ctx1 = t0 - args.pad, min(t1 + args.pad, datetime.now().timestamp())
    step = int(args.step) if args.step else pick_step(ctx1 - ctx0)
    ctx0 = t0 - math.ceil(args.pad / step) * step     # align so the reported start falls on a step
    w = Window(t0, t1, ctx0, max(ctx1, t1), step, tz)
    catalog = build_catalog(args.instance, step, t1 - t0)

    if args.list:
        for q in catalog:
            print(f"# {q.id} [{q.kind}] {q.title}\n{q.expr}\n")
        return 0

    prom = args.prom.rstrip("/")
    info = http_json(prom + "/api/v1/status/buildinfo", timeout=15)
    if info.get("status") != "success":
        raise SystemExit(f"cannot reach Prometheus at {prom}: {info.get('error')}\n"
                         "It binds 127.0.0.1 on the monitoring host; tunnel first: "
                         "ssh -N -L 9090:localhost:9090 <monitoring-host>")
    flags = http_json(prom + "/api/v1/status/flags", timeout=15).get("data", {})
    retention = flags.get("storage.tsdb.retention.time", "")
    rules_resp = http_json(prom + "/api/v1/rules?type=alert", timeout=15)
    alert_rules = None
    if rules_resp.get("status") == "success":
        alert_rules = sorted({r.get("name", "?") for g in rules_resp["data"].get("groups", [])
                              for r in g.get("rules", [])})

    expiry = "unknown"
    if retention and retention != "0s":
        try:
            exp = w.dt(t0 + parse_duration(retention))
            expiry = f"about {exp:%Y-%m-%d} (Prometheus retention {retention}; size-based retention may drop it sooner)"
            if exp.timestamp() < datetime.now().timestamp():
                print(f"warning: the window is older than the retention ({retention}); expect empty results",
                      file=sys.stderr)
        except argparse.ArgumentTypeError:
            expiry = f"retention {retention}"

    out = args.out or Path(f"incident-{re.sub(r'[^A-Za-z0-9._-]', '_', args.instance)}-{start:%Y%m%d-%H%M}")
    if out.exists() and any(out.iterdir()) and not args.force:
        raise SystemExit(f"{out} exists and is not empty (use --force to overwrite)")
    data_dir = out / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    print(f"window {w.full(t0)} .. {w.full(t1)} {tz_label(tz)}, context {w.full(w.ctx_start)} .. "
          f"{w.full(w.ctx_end)}, step {step}s -> {out}/", file=sys.stderr)
    results = {}
    for i, q in enumerate(catalog, 1):
        res = run_query(prom, q, w)
        save_result(res, data_dir, w)
        results[q.id] = res
        status = f"error: {res.error[:80]}" if res.error else f"{len(res.series)} series"
        print(f"  [{i:2d}/{len(catalog)}] {q.id:<22} {status}", file=sys.stderr)

    log = None
    if args.host_logs:
        if args.host_logs.exists():
            log = LogScan(args.host_logs)
            print(f"host logs: {len(log.lines)} lines from {args.host_logs}", file=sys.stderr)
        else:
            print(f"warning: --host-logs {args.host_logs} not found; kernel checks skipped", file=sys.stderr)
    spec = json.loads(args.hypotheses.read_text())

    meta = {
        "generated": datetime.now(tz).isoformat(timespec="seconds"),
        "args": {k: (str(v) if isinstance(v, (Path, timezone)) else v) for k, v in vars(args).items()},
        "window": {"start": w.dt(t0).isoformat(), "end": w.dt(t1).isoformat(),
                   "context_start": w.dt(w.ctx_start).isoformat(), "context_end": w.dt(w.ctx_end).isoformat(),
                   "step_seconds": step},
        "prometheus": {"url": prom, "build": info.get("data", {}), "retention": retention},
        "alert_rules": alert_rules,
        "host_logs": str(args.host_logs) if log else None,
        "queries": [{"id": q.id, "section": q.section, "title": q.title, "kind": q.kind, "expr": q.expr,
                     "unit": q.unit, "floor": q.floor, "series": len(results[q.id].series),
                     "error": results[q.id].error or None} for q in catalog],
    }

    rep = Report(results, w, args.instance, args, meta)
    coverage = rep.coverage()           # before timeline(): both add events
    title = args.title or f"{args.instance} slowdown {start:%Y-%m-%d %H:%M}"
    values = {
        "TITLE": title,
        "DATE": f"{start:%Y-%m-%d}",
        "INSTANCE": args.instance,
        "WINDOW": f"{w.full(t0)} to {w.full(t1)} ({tz_label(tz)})",
        "TZ": tz_label(tz),
        "EXPIRY": expiry,
        "GENERATED": f"incident_dump.py, {meta['generated']}, Prometheus {prom}",
        "AUTO_HYPOTHESES": rep.hypotheses(spec, log),
        "AUTO_IMPACT": rep.impact(),
        "AUTO_DETECTION": rep.detection(),
        "AUTO_TIMELINE": rep.timeline(),
        "AUTO_COVERAGE": coverage,
        "AUTO_MOVED": rep.moved_table(),
        "AUTO_TOP": rep.top(),
        "AUTO_OVERVIEW": rep.overview(),
        "AUTO_LINKS": rep.links(),
        "AUTO_FILES": rep.files(out),
    }
    (out / "postmortem.zh-tw.md").write_text(fill_template(args.template.read_text(), values))
    logs = out / "collect-host-logs.sh"
    logs.write_text(host_logs_script(w, args.instance))
    logs.chmod(0o755)
    (out / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    errors = [q.id for q in catalog if results[q.id].error]
    empty = [q.id for q in catalog if not results[q.id].error and not results[q.id].series]
    print(f"\nwrote {out}/postmortem.zh-tw.md, {out}/collect-host-logs.sh, {out}/meta.json, {out}/data/",
          file=sys.stderr)
    print(f"{len(rep.moved())} series moved vs baseline; {len(empty)} queries returned no data; "
          f"{len(errors)} failed{': ' + ', '.join(errors) if errors else ''}", file=sys.stderr)
    return 1 if len(errors) == len(catalog) else 0


if __name__ == "__main__":
    sys.exit(main())
