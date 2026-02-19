"""System metrics collection via psutil and vnstat."""

import asyncio
import json
import os
import platform
import shutil
import socket
import time
from collections import deque
from datetime import datetime, timezone

import psutil

from .config import get_config

# ---------------------------------------------------------------------------
# Caches
# ---------------------------------------------------------------------------
_vnstat_cache: dict = {}
_vnstat_cache_time: float = 0.0

# Rolling history for sparklines (last 150 samples = 5 min at 2s interval)
MAX_LIVE_SAMPLES = 150

_cpu_history: deque[float] = deque(maxlen=MAX_LIVE_SAMPLES)
_net_rx_history: deque[float] = deque(maxlen=MAX_LIVE_SAMPLES)
_net_tx_history: deque[float] = deque(maxlen=MAX_LIVE_SAMPLES)
_timestamps: deque[float] = deque(maxlen=MAX_LIVE_SAMPLES)

# Previous counters for rate calculation
_prev_net: dict | None = None
_prev_net_time: float = 0.0
_prev_disk: dict | None = None
_prev_disk_time: float = 0.0


def _detect_interfaces() -> list[str]:
    """Return list of active non-loopback interfaces."""
    ifaces = []
    stats = psutil.net_if_stats()
    for name, nic in stats.items():
        if nic.isup and name != "lo":
            ifaces.append(name)
    return ifaces


def get_interfaces() -> list[str]:
    cfg = get_config()["monitoring"].get("interfaces", [])
    return cfg if cfg else _detect_interfaces()


# ---------------------------------------------------------------------------
# System Metrics (psutil)
# ---------------------------------------------------------------------------
def collect_cpu() -> dict:
    per_core = psutil.cpu_percent(interval=0, percpu=True)
    freq = psutil.cpu_freq()
    load = psutil.getloadavg()

    temps = {}
    try:
        t = psutil.sensors_temperatures()
        if t:
            for chip, entries in t.items():
                for e in entries:
                    temps[e.label or chip] = round(e.current, 1)
    except (AttributeError, OSError):
        pass

    overall = sum(per_core) / len(per_core) if per_core else 0.0
    return {
        "overall": round(overall, 1),
        "per_core": [round(c, 1) for c in per_core],
        "core_count": psutil.cpu_count(logical=True),
        "frequency_mhz": round(freq.current, 0) if freq else None,
        "frequency_max_mhz": round(freq.max, 0) if freq and freq.max else None,
        "load_average": [round(x, 2) for x in load],
        "temperatures": temps,
    }


def collect_memory() -> dict:
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    return {
        "total": vm.total,
        "used": vm.used,
        "free": vm.free,
        "available": vm.available,
        "cached": getattr(vm, "cached", 0),
        "buffers": getattr(vm, "buffers", 0),
        "percent": vm.percent,
        "swap_total": sw.total,
        "swap_used": sw.used,
        "swap_free": sw.free,
        "swap_percent": sw.percent,
    }


def collect_disk() -> dict:
    global _prev_disk, _prev_disk_time

    partitions = []
    for p in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(p.mountpoint)
            partitions.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "fstype": p.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            })
        except PermissionError:
            continue

    # I/O rates
    try:
        io = psutil.disk_io_counters(perdisk=False)
    except Exception:
        io = None
    now = time.time()
    io_rates = {}
    if io and _prev_disk is not None:
        dt = now - _prev_disk_time
        if dt > 0:
            io_rates = {
                "read_bytes_sec": round((io.read_bytes - _prev_disk["rb"]) / dt),
                "write_bytes_sec": round((io.write_bytes - _prev_disk["wb"]) / dt),
                "read_iops": round((io.read_count - _prev_disk["rc"]) / dt),
                "write_iops": round((io.write_count - _prev_disk["wc"]) / dt),
            }
    if io:
        _prev_disk = {
            "rb": io.read_bytes, "wb": io.write_bytes,
            "rc": io.read_count, "wc": io.write_count,
        }
        _prev_disk_time = now

    return {"partitions": partitions, "io": io_rates}


def collect_network_psutil() -> dict:
    """Collect real-time network counters from psutil (for per-second rates)."""
    global _prev_net, _prev_net_time

    counters = psutil.net_io_counters(pernic=True)
    now = time.time()
    ifaces = get_interfaces()
    result = {}

    for iface in ifaces:
        if iface not in counters:
            continue
        c = counters[iface]
        rate = {}
        if _prev_net and iface in _prev_net:
            dt = now - _prev_net_time
            if dt > 0:
                prev = _prev_net[iface]
                rate = {
                    "rx_bytes_sec": round((c.bytes_recv - prev["rx"]) / dt),
                    "tx_bytes_sec": round((c.bytes_sent - prev["tx"]) / dt),
                    "rx_packets_sec": round((c.packets_recv - prev["rp"]) / dt),
                    "tx_packets_sec": round((c.packets_sent - prev["tp"]) / dt),
                }

        result[iface] = {
            "rx_bytes": c.bytes_recv,
            "tx_bytes": c.bytes_sent,
            "rx_packets": c.packets_recv,
            "tx_packets": c.packets_sent,
            "rx_errors": c.errin,
            "tx_errors": c.errout,
            "rx_drops": c.dropin,
            "tx_drops": c.dropout,
            **rate,
        }

    # Store for next delta
    _prev_net = {}
    for iface in ifaces:
        if iface in counters:
            c = counters[iface]
            _prev_net[iface] = {
                "rx": c.bytes_recv, "tx": c.bytes_sent,
                "rp": c.packets_recv, "tp": c.packets_sent,
            }
    _prev_net_time = now

    return result


# ---------------------------------------------------------------------------
# vnstat
# ---------------------------------------------------------------------------
async def _run_vnstat(*args: str) -> str | None:
    if not shutil.which("vnstat"):
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "vnstat", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        return stdout.decode() if proc.returncode == 0 else None
    except (asyncio.TimeoutError, OSError):
        return None


async def get_vnstat_json() -> dict | None:
    """Get vnstat JSON, cached for configured TTL."""
    global _vnstat_cache, _vnstat_cache_time

    ttl = get_config()["monitoring"].get("vnstat_cache_ttl", 1)
    now = time.time()
    if _vnstat_cache and (now - _vnstat_cache_time) < ttl:
        return _vnstat_cache

    raw = await _run_vnstat("--json")
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        _vnstat_cache = data
        _vnstat_cache_time = now
        return data
    except json.JSONDecodeError:
        return None


async def collect_vnstat() -> dict:
    """Parse vnstat JSON into structured bandwidth data."""
    data = await get_vnstat_json()
    if not data:
        return {"available": False}

    ifaces_data = {}
    interfaces = data.get("interfaces", [])
    monitored = get_interfaces()

    for iface in interfaces:
        name = iface.get("name", iface.get("id", "unknown"))
        if monitored and name not in monitored:
            continue

        traffic = iface.get("traffic", {})

        # Hourly (last 24)
        hours = []
        for h in traffic.get("hour", [])[-24:]:
            hours.append({
                "date": f"{h['date']['year']}-{h['date']['month']:02d}-{h['date']['day']:02d}",
                "hour": h["time"]["hour"],
                "rx": h["rx"],
                "tx": h["tx"],
            })

        # Daily (last 30)
        days = []
        for d in traffic.get("day", [])[-30:]:
            days.append({
                "date": f"{d['date']['year']}-{d['date']['month']:02d}-{d['date']['day']:02d}",
                "rx": d["rx"],
                "tx": d["tx"],
            })

        # Monthly (last 12)
        months = []
        for m in traffic.get("month", [])[-12:]:
            months.append({
                "date": f"{m['date']['year']}-{m['date']['month']:02d}",
                "rx": m["rx"],
                "tx": m["tx"],
            })

        # Totals
        total = traffic.get("total", {})

        ifaces_data[name] = {
            "hourly": hours,
            "daily": days,
            "monthly": months,
            "total_rx": total.get("rx", 0),
            "total_tx": total.get("tx", 0),
        }

    return {"available": True, "interfaces": ifaces_data}


async def collect_vnstat_live() -> dict:
    """Get 5-second traffic sample via vnstat."""
    raw = await _run_vnstat("--json", "s")
    if raw is None:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Combined snapshot
# ---------------------------------------------------------------------------
def collect_system_info() -> dict:
    boot = psutil.boot_time()
    uptime = int(time.time() - boot)
    hostname = socket.gethostname()

    # Get primary IP
    ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass

    uname = platform.uname()
    return {
        "hostname": hostname,
        "ip": ip,
        "uptime_seconds": uptime,
        "boot_time": boot,
        "process_count": len(psutil.pids()),
        "platform": f"{uname.system} {uname.release}",
    }


async def collect_all() -> dict:
    """Full metrics snapshot. Each collector fails independently."""
    cpu = {}
    mem = {}
    disk = {}
    net = {}
    vnstat_data = {"available": False}
    info = {}

    try:
        cpu = collect_cpu()
    except Exception as e:
        print(f"[XMonitor] CPU collection error: {e}")

    try:
        mem = collect_memory()
    except Exception as e:
        print(f"[XMonitor] Memory collection error: {e}")

    try:
        disk = collect_disk()
    except Exception as e:
        print(f"[XMonitor] Disk collection error: {e}")

    try:
        net = collect_network_psutil()
    except Exception as e:
        print(f"[XMonitor] Network collection error: {e}")

    try:
        vnstat_data = await collect_vnstat()
    except Exception as e:
        print(f"[XMonitor] vnstat collection error: {e}")

    try:
        info = collect_system_info()
    except Exception as e:
        print(f"[XMonitor] System info error: {e}")

    # Update live histories
    now = time.time()
    _cpu_history.append(cpu.get("overall", 0))
    _timestamps.append(now)

    total_rx = sum(v.get("rx_bytes_sec", 0) for v in net.values())
    total_tx = sum(v.get("tx_bytes_sec", 0) for v in net.values())
    _net_rx_history.append(total_rx)
    _net_tx_history.append(total_tx)

    return {
        "system": info,
        "cpu": cpu,
        "memory": mem,
        "disk": disk,
        "network": net,
        "vnstat": vnstat_data,
        "live_history": {
            "timestamps": list(_timestamps),
            "cpu": list(_cpu_history),
            "net_rx": list(_net_rx_history),
            "net_tx": list(_net_tx_history),
        },
    }


# Initialize cpu_percent baseline
psutil.cpu_percent(interval=0, percpu=True)
