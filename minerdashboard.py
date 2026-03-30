#!/usr/bin/env python3
"""
Home ASIC Miner Stats Monitoring Dashboard
Rewrite with auto-scan, config file, and setup wizard.
Based on original by options4good (V2.2.2).
"""

import socket
import json
import time
import requests
import re
import threading
import argparse
import ipaddress
import os
import sys
import tty
import termios
import select
import queue as _queue
from collections import deque
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Rich imports (checked at runtime) ---
try:
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.console import Console
    from rich.prompt import Prompt, Confirm, IntPrompt
except ImportError:
    print("Missing dependency: rich")
    print("Install with: pip install rich")
    sys.exit(1)

try:
    import requests as _req_check
except ImportError:
    print("Missing dependency: requests")
    print("Install with: pip install requests")
    sys.exit(1)

APP_VERSION = "V3.1.0"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "miners.json")
console = Console()


# =============================================================================
# Config Management
# =============================================================================

def load_config():
    """Load miners from config file. Returns list of miner dicts."""
    if not os.path.exists(CONFIG_FILE):
        return []
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
        miners = data if isinstance(data, list) else data.get("miners", [])
        # Validate entries
        valid = []
        for m in miners:
            if "ip" in m and "name" in m and "type_hint" in m:
                valid.append(m)
        return valid
    except (json.JSONDecodeError, IOError) as e:
        console.print(f"[red]Error reading {CONFIG_FILE}: {e}[/]")
        return []


def save_config(miners):
    """Save miners list to config file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(miners, f, indent=2)
        console.print(f"[green]Config saved to {CONFIG_FILE}[/]")
    except IOError as e:
        console.print(f"[red]Error saving config: {e}[/]")


# =============================================================================
# Network Scanner
# =============================================================================

def get_local_subnet():
    """Detect the local subnet by finding the default gateway interface."""
    try:
        # Connect to a public IP (doesn't actually send data) to find local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 subnet
        parts = local_ip.split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return subnet, local_ip
    except Exception:
        return None, None


def _cgminer_cmd(ip, command, parameter=None, port=4028, timeout=1.5):
    """Send a command (with optional parameter) to the cgminer API. Returns parsed JSON or None."""
    try:
        payload = {"command": command}
        if parameter is not None:
            payload["parameter"] = str(parameter)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(json.dumps(payload).encode())
            buf = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                buf += chunk
            raw = buf.decode('utf-8', errors='ignore').strip('\x00')
            return json.loads(raw)
    except Exception:
        return None


def probe_cgminer(ip, port=4028, timeout=1.5):
    """Probe cgminer API (Avalon, Antminer S9, etc). Returns summary dict or None."""
    data = _cgminer_cmd(ip, "summary", port=port, timeout=timeout)
    if data and 'SUMMARY' in data:
        return {"api": "cgminer", "data": data}
    return None


def probe_http_api(ip, timeout=1.5):
    """Probe HTTP API (NerdAxe, Bitaxe, Lucky Miner, Gamma, Antminer, etc). Returns info dict or None."""
    ports = [80, 8080]
    paths = ["/api/system/info", "/api/system"]
    for port in ports:
        for path in paths:
            try:
                r = requests.get(f"http://{ip}:{port}{path}", timeout=timeout)
                if r.status_code == 200:
                    data = r.json()
                    if any(k in data for k in ['hashRate', 'sharesAccepted', 'version', 'hostname']):
                        return {"api": "http", "data": data}
            except Exception:
                pass
    return None


def detect_miner_type(ip, result):
    """Identify miner model from scan results. Never hardcode names — fetch from device."""
    last = ip.split('.')[-1]

    if result["api"] == "cgminer":
        # Query version command — Avalon returns e.g. "Type": "Avalon Q" or "Avalon1246 aa-..."
        type_str = ""
        ver_data = _cgminer_cmd(ip, "version", timeout=2.0)
        if ver_data:
            ver_info = ver_data.get("VERSION", [{}])[0]
            # Prefer Type, then Miner (firmware string), then Description
            type_str = (
                ver_info.get("Type")
                or ver_info.get("Description")
                or ver_info.get("Miner")
                or ""
            ).strip()
        if not type_str:
            # Fallback: Description in summary
            type_str = result["data"].get("SUMMARY", [{}])[0].get("Description", "").strip()

        type_lower = type_str.lower()
        if "antminer" in type_lower or "bmminer" in type_lower:
            return "antminer", type_str or f"Antminer-{last}"
        if "avalon" in type_lower or type_str:
            # Use whatever the device reported; fallback to IP hint
            return "avalon", type_str or f"Avalon-{last}"
        # Nothing came back from the API — use IP hint
        return "avalon", f"Miner-{last}"

    elif result["api"] == "http":
        data = result["data"]
        # Pull the most descriptive name available from the device
        device_name = (
            data.get("hostname")
            or data.get("model")
            or data.get("deviceModel")
            or data.get("boardVersion")
            or ""
        ).strip()

        combined = " ".join([
            str(data.get("hostname", "")),
            str(data.get("boardVersion", data.get("board", ""))),
            str(data.get("model", data.get("deviceModel", ""))),
            str(data.get("version", "")),
        ]).lower()

        if "antminer" in combined:
            return "antminer", device_name or f"Antminer-{last}"
        if "lucky" in combined:
            return "lucky", device_name or f"Lucky-{last}"
        if "nerd" in combined:
            return "nerd", device_name or f"NerdAxe-{last}"
        if "gamma" in combined:
            return "nerd", device_name or f"Gamma-{last}"
        if "bitaxe" in combined:
            return "nerd", device_name or f"Bitaxe-{last}"
        return "nerd", device_name or f"Miner-{last}"

    return "unknown", f"Miner-{last}"


def scan_network(subnet=None, max_workers=100):
    """Scan a /24 subnet for ASIC miners. Returns list of discovered miners."""
    if subnet is None:
        subnet, local_ip = get_local_subnet()
        if subnet is None:
            console.print("[red]Could not detect local subnet. Specify with --subnet.[/]")
            return []
        console.print(f"[cyan]Detected local IP:[/] {local_ip}")
        console.print(f"[cyan]Scanning subnet:[/] {subnet}")
    else:
        console.print(f"[cyan]Scanning subnet:[/] {subnet}")

    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError as e:
        console.print(f"[red]Invalid subnet: {e}[/]")
        return []

    hosts = [str(ip) for ip in network.hosts()]
    discovered = []
    scanned = 0
    total = len(hosts)

    console.print(f"[dim]Probing {total} addresses (cgminer:4028 + HTTP:80)...[/]")

    def probe_host(ip):
        # Try cgminer first (Avalon, Antminer)
        result = probe_cgminer(ip)
        if result:
            return ip, result
        # Try HTTP API (NerdAxe, Bitaxe, Lucky, Gamma)
        result = probe_http_api(ip)
        if result:
            return ip, result
        return ip, None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            scanned += 1
            if scanned % 50 == 0 or scanned == total:
                console.print(f"  [dim]{scanned}/{total} scanned, {len(discovered)} found...[/]", end="\r")
            try:
                ip, result = future.result()
                if result:
                    type_hint, auto_name = detect_miner_type(ip, result)
                    discovered.append({
                        "ip": ip,
                        "name": auto_name,
                        "type_hint": type_hint,
                        "api": result["api"]
                    })
            except Exception:
                pass

    console.print(f"\n[green]Scan complete. Found {len(discovered)} miner(s).[/]")
    return discovered


# =============================================================================
# Auto Setup (zero-interaction first run)
# =============================================================================

def auto_setup(subnet=None):
    """Zero-interaction first run: scan LAN, add ALL found miners, launch dashboard."""
    console.print("[bold cyan]First run — scanning your LAN for miners...[/]")
    if subnet is None:
        subnet, local_ip = get_local_subnet()
        if subnet is None:
            console.print("[red]Could not detect subnet. Add miners manually: ./run.sh --add IP --name NAME[/]")
            return []
        console.print(f"[dim]Local IP: {local_ip}  |  Subnet: {subnet}[/]")
    discovered = scan_network(subnet)
    if not discovered:
        console.print("[yellow]No miners found on {subnet}.[/]")
        console.print("[dim]Add manually: ./run.sh --add IP --name NAME  |  or re-run: ./run.sh --setup[/]")
        return []
    miners = [{"ip": m["ip"], "name": m["name"], "type_hint": m["type_hint"]} for m in discovered]
    save_config(miners)
    console.print(f"[green]Added {len(miners)} miner(s) — launching dashboard...[/]")
    time.sleep(0.8)
    return miners


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_scan(args):
    """Scan network and add all new miners to config."""
    subnet = getattr(args, 'subnet', None)
    discovered = scan_network(subnet)
    if not discovered:
        return
    existing = load_config()
    existing_ips = {m['ip'] for m in existing}
    added = 0
    for m in discovered:
        if m['ip'] not in existing_ips:
            existing.append({"ip": m["ip"], "name": m["name"], "type_hint": m["type_hint"]})
            console.print(f"  [green]+[/] {m['ip']}  {m['name']}  ({m['type_hint']})")
            added += 1
        else:
            console.print(f"  [dim]=[/] {m['ip']}  already in config")
    save_config(existing)
    console.print(f"[green]Done — added {added} new miner(s).[/]")


def cmd_add(args):
    """Manually add a miner."""
    miners = load_config()
    existing_ips = {m['ip'] for m in miners}

    if args.ip in existing_ips:
        console.print(f"[yellow]{args.ip} is already in config.[/]")
        return

    # Auto-detect type if not specified
    type_hint = args.type
    if type_hint == "auto":
        console.print(f"[dim]Probing {args.ip}...[/]")
        result = probe_cgminer(args.ip)
        if result:
            type_hint, auto_name = detect_miner_type(args.ip, result)
            console.print(f"  [green]Detected: {auto_name} (cgminer API)[/]")
        else:
            result = probe_http_api(args.ip)
            if result:
                type_hint, auto_name = detect_miner_type(args.ip, result)
                console.print(f"  [green]Detected: {auto_name} (HTTP API)[/]")
            else:
                console.print(f"  [yellow]Could not auto-detect. Defaulting to 'avalon'.[/]")
                type_hint = "avalon"

    name = args.name or f"Miner-{len(miners)+1}"
    miners.append({"ip": args.ip, "name": name, "type_hint": type_hint})
    save_config(miners)
    console.print(f"[green]Added {name} ({args.ip}) as {type_hint}.[/]")


def cmd_remove(args):
    """Remove a miner by IP or name."""
    miners = load_config()
    target = args.target
    before = len(miners)
    miners = [m for m in miners if m['ip'] != target and m['name'] != target]
    after = len(miners)

    if before == after:
        console.print(f"[yellow]No miner found matching '{target}'.[/]")
    else:
        save_config(miners)
        console.print(f"[green]Removed {before - after} miner(s).[/]")


def cmd_rename(args):
    """Rename a miner by IP or current name."""
    miners = load_config()
    for m in miners:
        if m['ip'] == args.target or m['name'] == args.target:
            old_name = m['name']
            m['name'] = args.new_name
            save_config(miners)
            console.print(f"[green]Renamed [cyan]{old_name}[/] → [cyan]{args.new_name}[/][/]")
            return
    console.print(f"[yellow]No miner found matching '{args.target}'[/]")


def cmd_list(_args):
    """List configured miners."""
    miners = load_config()
    if not miners:
        console.print("[yellow]No miners configured. Run with --scan or --setup.[/]")
        return

    table = Table(title="Configured Miners", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="cyan")
    table.add_column("IP", style="bold white")
    table.add_column("Type", style="magenta")

    for i, m in enumerate(sorted(miners, key=lambda x: x['name']), 1):
        table.add_row(str(i), m['name'], m['ip'], m['type_hint'])

    console.print(table)


def cmd_setup(args):
    """Re-scan LAN and reset config."""
    subnet = getattr(args, 'subnet', None)
    auto_setup(subnet)


# =============================================================================
# Keyboard Input
# =============================================================================

_cmd_queue: _queue.Queue = _queue.Queue()


def _keyboard_reader() -> None:
    """Background thread: capture single keypresses and push to _cmd_queue."""
    if not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)          # single-char reads, Ctrl+C still works
        while True:
            if select.select([sys.stdin], [], [], 0.05)[0]:
                ch = sys.stdin.read(1)
                if ch in ('q', 'Q', 'a', 'A', 'r', 'R', 'd', 'D', 's', 'S', 'f', 'F', 'c', 'C', '\x03'):
                    _cmd_queue.put(ch.lower())
    except Exception:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass


# =============================================================================
# Monitor (original logic preserved)
# =============================================================================

class UniversalMonitor:
    def __init__(self, miners):
        self.miners = sorted(miners, key=lambda x: x['name'])
        self.acc_counts = {m['ip']: 0 for m in self.miners}
        self.rej_counts = {m['ip']: 0 for m in self.miners}
        self.block_counts = {m['ip']: 0 for m in self.miners}
        self.share_logs = deque(maxlen=100)
        self.avalon_modes = {"0": "ECO", "1": "STANDARD", "2": "SUPER"}

        self.miner_data = {m['ip']: {"online": False, "loading": True} for m in self.miners}
        self.log_lock = threading.Lock()
        self.start_threads()

    def start_threads(self):
        for miner in self.miners:
            t = threading.Thread(target=self._miner_worker, args=(miner,), daemon=True)
            t.start()

    def _miner_worker(self, miner):
        while True:
            data = self.fetch_data(miner)
            self.miner_data[miner['ip']] = data
            time.sleep(10)

    def _format_uptime(self, seconds):
        try:
            seconds = int(float(seconds))
            d, h, m = seconds // 86400, (seconds % 86400) // 3600, (seconds % 3600) // 60
            return f"{d}d {h}h {m}m" if d > 0 else f"{h}h {m}m"
        except:
            return "--"

    def _format_diff(self, val):
        if val is None or val == 0 or val == "":
            return "--"
        val_str = str(val).strip().upper()
        match = re.search(r'([0-9.]+)\s*([KMGTH]+)', val_str)
        if match:
            num_part = match.group(1)
            unit_char = match.group(2)[0]
            return f"{num_part} {unit_char}H"
        try:
            num = float(re.sub(r'[^0-9.]', '', val_str))
            if num >= 1e12: return f"{num / 1e12:.2f} TH"
            elif num >= 1e9: return f"{num / 1e9:.2f} GH"
            elif num >= 1e6: return f"{num / 1e6:.2f} MH"
            elif num >= 1e3: return f"{num / 1e3:.2f} KH"
            else: return f"{num:,.0f}"
        except:
            return str(val)

    def _avalon_cmd(self, ip, cmd):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((ip, 4028))
                s.sendall(json.dumps({"command": cmd}).encode())
                buffer = b""
                while True:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    buffer += chunk
                raw = buffer.decode('utf-8', errors='ignore').strip('\x00')
                try:
                    return json.loads(raw)
                except:
                    return raw
        except:
            return None

    def fetch_data(self, miner):
        ip = miner['ip']
        now_ts = datetime.now().strftime('%H:%M:%S')
        try:
            if miner['type_hint'] == "avalon":
                sum_d = self._avalon_cmd(ip, "summary")
                pool_d = self._avalon_cmd(ip, "pools")
                estats_raw = self._avalon_cmd(ip, "estats")
                if sum_d and pool_d:
                    s = sum_d.get('SUMMARY', [{}])[0]
                    p = pool_d.get('POOLS', [{}])[0]
                    parsed_estats = {k: v for k, v in re.findall(r'(\w+)\[([^\]]+)\]', str(estats_raw))}
                    ps = parsed_estats.get("PS", "").split()
                    mv = ps[1] if len(ps) > 1 else "0"
                    dc = float(ps[4]) if len(ps) > 4 else 0
                    ac = float(ps[6]) if len(ps) > 6 else 0
                    hash_th = (s.get('GHS 5s') or s.get('MHS 5s', 0) / 1000) / 1000
                    acc = int(s.get('Accepted', 0))
                    rej = int(s.get('Rejected', 0))
                    blocks = int(s.get('Found Blocks', 0))
                    self._update_activity_logs(miner['name'], ip, acc, rej, blocks, now_ts)
                    mode_label = self.avalon_modes.get(parsed_estats.get('WORKMODE', '1'), 'STD')
                    return {
                        "online": True, "hash": hash_th, "ver": mode_label,
                        "eff": f"{dc/hash_th:.2f} J/TH" if hash_th > 0 else "0.00 J/TH",
                        "temp": f"{parsed_estats.get('TAvg', s.get('Temperature', 0))}°C",
                        "pwr": f"{float(mv)/100:.2f}V - {dc:.1f}W/{ac:.1f}W",
                        "vf": f"{mv}mV/{parsed_estats.get('Freq','--')}MHz",
                        "fan": f"{parsed_estats.get('FanR','--')} RPM",
                        "up": self._format_uptime(s.get('Elapsed', 0)),
                        "bd": self._format_diff(s.get('Best Share', 0)), "sd": "--",
                        "sh": f"{acc}/{rej}",
                        "pd": f"{int(float(p.get('Diff', 0))):,}" if p.get('Diff') else "--",
                        "bl": blocks,
                        "p": p.get('URL', 'Unknown'),
                        "ping": f"{float(parsed_estats.get('PING', 0)):.1f}ms",
                        "u": p.get('User', 'N/A')
                    }
            else:
                r = requests.get(f"http://{ip}/api/system/info", timeout=3.0).json()
                st = r.get('stratum', {})
                h_th = r.get('hashRate', 0) / 1000
                dc = float(r.get('power', 0))
                v_core = float(r.get('voltage', 0)) / 1000
                mv_act = r.get('coreVoltageActual', 0)
                acc = int(r.get('sharesAccepted', 0))
                rej = int(r.get('sharesRejected', 0))
                blocks = int(r.get('foundBlocks', 0))
                self._update_activity_logs(miner['name'], ip, acc, rej, blocks, now_ts)

                ping = 0
                keys_to_check = ['responseTime', 'pingRtt', 'latency']
                pools = st.get('pools', [])
                if pools and isinstance(pools, list):
                    p0 = pools[0]
                    for k in keys_to_check:
                        if k in p0:
                            ping = p0[k]
                            break
                if ping == 0:
                    for k in keys_to_check:
                        if k in st:
                            ping = st[k]
                            break
                if ping == 0:
                    for k in keys_to_check:
                        if k in r:
                            ping = r[k]
                            break

                return {
                    "online": True, "hash": h_th, "ver": r.get('version', 'N/A'),
                    "eff": f"{dc/h_th:.2f} J/TH" if h_th > 0 else "0.00 J/TH",
                    "temp": f"{r.get('temp', 0):.1f}°/{r.get('vrTemp', 0)}°",
                    "pwr": f"{v_core:.2f}V - {dc:.1f}W/{dc/0.9:.1f}W",
                    "vf": f"{mv_act}mV/{r.get('frequency', 0)}MHz",
                    "fan": f"{r.get('fanspeed', 0):.0f}% ({r.get('fanrpm', 0)} RPM)",
                    "up": self._format_uptime(r.get('uptimeSeconds', 0)),
                    "bd": self._format_diff(r.get('bestDiff')),
                    "sd": self._format_diff(r.get('bestSessionDiff')),
                    "sh": f"{acc}/{rej}",
                    "pd": f"{r.get('poolDifficulty', 0):,}",
                    "bl": blocks,
                    "p": f"{r.get('stratumURL', st.get('url'))}:{r.get('stratumPort', st.get('port'))}",
                    "ping": f"{float(ping):.1f}ms",
                    "u": r.get('stratumUser', st.get('user'))
                }
        except:
            pass
        return {"online": False}

    def _update_activity_logs(self, name, ip, acc, rej, blocks, ts):
        with self.log_lock:
            if acc > self.acc_counts[ip] and self.acc_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] [bold green]\u2705[/] {name} Accepted")
            if rej > self.rej_counts[ip] and self.rej_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] [bold red]\u274c[/] {name} Rejected")
            if blocks > self.block_counts[ip] and self.block_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] \U0001f3c6 [bold gold1]BLOCK![/] {name}")
            self.acc_counts[ip] = acc
            self.rej_counts[ip] = rej
            self.block_counts[ip] = blocks

    def update_ui(self):
        total_hash, online_count = 0, 0
        header_style = "bold bright_white"

        perf_t = Table(expand=True, border_style="dim")
        perf_t.add_column("Miner", style="cyan", width=22, header_style=header_style)
        perf_t.add_column("Hashrate", justify="right", header_style=header_style)
        perf_t.add_column("Efficiency", justify="center", style="bold white", header_style=header_style)
        perf_t.add_column("Temp Asic/VR", justify="center", style="yellow", header_style=header_style)
        perf_t.add_column("Power Volt/DC/AC", justify="center", style="orange3", header_style=header_style)
        perf_t.add_column("Asic Volt/Freq", justify="center", style="magenta", header_style=header_style)
        perf_t.add_column("Fan", justify="right", style="bold cyan", header_style=header_style)

        luck_t = Table(expand=True, border_style="dim")
        luck_t.add_column("Miner", style="cyan", width=12, header_style=header_style)
        luck_t.add_column("Uptime", justify="center", style="bold blue", header_style=header_style)
        luck_t.add_column("Best Diff All-time", justify="right", style="bold green", header_style=header_style)
        luck_t.add_column("Best Diff Session", justify="right", style="green", header_style=header_style)
        luck_t.add_column("Accepted/Rejected", justify="center", style="bold white", header_style=header_style)
        luck_t.add_column("Pool Diff", justify="center", style="white", header_style=header_style)
        luck_t.add_column("Blocks", justify="center", style="bold gold1", header_style=header_style)

        pool_t = Table(expand=True, border_style="dim")
        pool_t.add_column("Miner", style="cyan", width=12, header_style=header_style)
        pool_t.add_column("IP Address", style="bold white", width=15, header_style=header_style)
        pool_t.add_column("Pool URL", style="bold yellow", header_style=header_style)
        pool_t.add_column("Ping", justify="right", style="green", header_style=header_style)
        pool_t.add_column("Username/Worker", style="white", header_style=header_style)

        for m in self.miners:
            st = self.miner_data.get(m['ip'], {"online": False})
            if st.get("online"):
                total_hash += st['hash']
                online_count += 1
                perf_t.add_row(
                    f"{m['name']} [dim]({st['ver']})[/]",
                    f"{st['hash']:.2f} TH/s", st['eff'], st['temp'],
                    st['pwr'], st['vf'], st['fan']
                )
                luck_t.add_row(
                    m['name'], st['up'], st['bd'], st['sd'],
                    st['sh'], st['pd'], str(st['bl'])
                )
                pool_t.add_row(m['name'], m['ip'], st['p'], st['ping'], st['u'])
            elif st.get("loading"):
                perf_t.add_row(m['name'], "[yellow]INIT...[/]", "-", "-", "-", "-", "-")
                luck_t.add_row(m['name'], "-", "-", "-", "-", "-", "-")
                pool_t.add_row(m['name'], m['ip'], "-", "-", "-")
            else:
                perf_t.add_row(m['name'], "[red]OFFLINE[/]", "-", "-", "-", "-", "-")
                luck_t.add_row(m['name'], "-", "-", "-", "-", "-", "-")
                pool_t.add_row(m['name'], m['ip'], "[red]Disconnected[/]", "-", "-")

        header = Table.grid(expand=True)
        header.add_column()
        header.add_column(justify="right")
        header.add_row(
            Text.from_markup(
                f"Total: [bold green]{total_hash:.2f} TH/s[/] | "
                f"Online: [bold cyan]{online_count}/{len(self.miners)}[/] | "
                f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]"
            ),
            Text.from_markup(f"[bold cyan]Version: {APP_VERSION}[/]")
        )

        controls = (
            "[bold dim]── Controls ──[/]\n"
            "[bold cyan]a[/] add miner\n"
            "[bold cyan]r[/] rename\n"
            "[bold cyan]d[/] delete\n"
            "[bold cyan]f[/] fan speed\n"
            "[bold cyan]s[/] rescan LAN\n"
            "[bold cyan]c[/] clear+rescan\n"
            "[bold cyan]q[/] quit\n"
            "[dim]Ctrl+C cancels[/]"
        )

        layout = Layout()
        layout.split_row(
            Layout(name="left", ratio=4),
            Layout(name="right", ratio=1)
        )
        layout["left"].split_column(
            Layout(Panel(header, title="[bold]Global Status[/]", border_style="bright_cyan"), size=3),
            Layout(Panel(perf_t, title="[bold]Performance[/]", border_style="bright_magenta"), ratio=1),
            Layout(Panel(luck_t, title="[bold]Mining[/]", border_style="bold bright_red"), ratio=1),
            Layout(Panel(pool_t, title="[bold]Connectivity[/]", border_style="bright_cyan"), ratio=1),
        )
        layout["right"].split_column(
            Layout(Panel("\n".join(self.share_logs), title="[bold]Activity[/]", border_style="bold bright_yellow"), ratio=4),
            Layout(Panel(controls, border_style="dim"), size=13),
        )
        return layout


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ASIC Miner Dashboard - Auto-scan, config, and monitoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 minerdashboard.py                  # Run dashboard (setup wizard on first run)
  python3 minerdashboard.py --scan           # Scan LAN for miners
  python3 minerdashboard.py --scan --subnet 10.0.0.0/24
  python3 minerdashboard.py --add 192.168.0.108 --name Avalon-Q --type avalon
  python3 minerdashboard.py --rename 192.168.0.108 --new-name Avalon-Q
  python3 minerdashboard.py --remove 192.168.0.108
  python3 minerdashboard.py --list           # Show configured miners
  python3 minerdashboard.py --setup          # Re-run setup wizard
        """
    )
    parser.add_argument('--scan', action='store_true', help='Scan LAN for miners')
    parser.add_argument('--subnet', type=str, help='Subnet to scan (e.g. 192.168.1.0/24)')
    parser.add_argument('--add', type=str, metavar='IP', help='Add a miner by IP')
    parser.add_argument('--name', type=str, help='Name for --add')
    parser.add_argument('--type', type=str, default='auto',
                        choices=['auto', 'avalon', 'nerd', 'lucky', 'antminer'],
                        help='Miner type for --add (default: auto-detect)')
    parser.add_argument('--remove', type=str, metavar='IP_OR_NAME', help='Remove a miner')
    parser.add_argument('--rename', type=str, metavar='IP_OR_NAME', help='Rename a miner')
    parser.add_argument('--new-name', type=str, metavar='NAME', help='New name for --rename')
    parser.add_argument('--list', action='store_true', help='List configured miners')
    parser.add_argument('--setup', action='store_true', help='Run interactive setup wizard')

    args = parser.parse_args()

    # Handle CLI commands
    if args.scan:
        cmd_scan(args)
        return

    if args.add:
        args.ip = args.add
        cmd_add(args)
        return

    if args.remove:
        args.target = args.remove
        cmd_remove(args)
        return

    if args.rename:
        if not args.new_name:
            console.print("[red]--rename requires --new-name NAME[/]")
            sys.exit(1)
        args.target = args.rename
        cmd_rename(args)
        return

    if args.list:
        cmd_list(args)
        return

    if args.setup:
        cmd_setup(args)
        return

    # Default: run dashboard
    miners = load_config()

    if not miners:
        miners = auto_setup()
        if not miners:
            console.print("[red]No miners found. Add one: ./run.sh --add IP --name NAME[/]")
            sys.exit(1)

    console.print(f"[cyan]Starting dashboard with {len(miners)} miner(s)...[/]")
    time.sleep(0.5)

    # Start keyboard reader thread
    kb = threading.Thread(target=_keyboard_reader, daemon=True)
    kb.start()

    mon = UniversalMonitor(miners)

    while True:
        cmd = None

        # Run live dashboard until a key is pressed
        with Live(mon.update_ui(), screen=True, refresh_per_second=4) as live:
            while True:
                try:
                    cmd = _cmd_queue.get_nowait()
                    break
                except _queue.Empty:
                    pass
                live.update(mon.update_ui())
                time.sleep(0.25)

        # Handle command outside Live context (terminal is restored here)
        if cmd in ('q', '\x03'):
            break

        elif cmd == 'a':
            console.print("\n[bold cyan]Add Miner[/]  [dim](Ctrl+C to cancel)[/]")
            try:
                ip = Prompt.ask("  IP address")
                last = ip.split('.')[-1]
                # Auto-detect type from device
                console.print(f"  [dim]Probing {ip}...[/]", end="")
                probe = probe_cgminer(ip) or probe_http_api(ip)
                if probe:
                    detected_type, detected_name = detect_miner_type(ip, probe)
                    console.print(f" found: [green]{detected_name}[/]")
                else:
                    detected_type, detected_name = "avalon", f"Miner-{last}"
                    console.print(" [yellow]no response, using defaults[/]")
                name = Prompt.ask("  Name", default=detected_name)
                type_hint = Prompt.ask("  Type", choices=["avalon", "nerd", "lucky", "antminer"], default=detected_type)
                existing = load_config()
                if not any(m['ip'] == ip for m in existing):
                    existing.append({"ip": ip, "name": name, "type_hint": type_hint})
                    save_config(existing)
                    console.print(f"[green]Added {name} ({ip})[/]")
                else:
                    console.print(f"[yellow]{ip} already in config[/]")
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled.[/]")
            time.sleep(0.5)
            mon = UniversalMonitor(load_config())

        elif cmd == 'r':
            console.print("\n[bold cyan]Rename Miner[/]  [dim](Ctrl+C to cancel)[/]")
            existing = load_config()
            console.print("  Miners: " + "  ".join(f"[cyan]{m['name']}[/] ({m['ip']})" for m in existing))
            try:
                target = Prompt.ask("  IP or current name")
                match = next((m for m in existing if m['ip'] == target or m['name'] == target), None)
                if match:
                    new_name = Prompt.ask("  New name", default=match['name'])
                    match['name'] = new_name
                    save_config(existing)
                    console.print(f"[green]Renamed → {new_name}[/]")
                else:
                    console.print(f"[yellow]Not found: {target}[/]")
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled.[/]")
            time.sleep(0.5)
            mon = UniversalMonitor(load_config())

        elif cmd == 'd':
            console.print("\n[bold cyan]Delete Miner[/]  [dim](Ctrl+C to cancel)[/]")
            existing = load_config()
            console.print("  Miners: " + "  ".join(f"[cyan]{m['name']}[/] ({m['ip']})" for m in existing))
            try:
                target = Prompt.ask("  IP or name to delete")
                before = len(existing)
                existing = [m for m in existing if m['ip'] != target and m['name'] != target]
                if len(existing) < before:
                    save_config(existing)
                    console.print(f"[green]Removed {target}[/]")
                    if not existing:
                        console.print("[yellow]No miners left.[/]")
                        break
                else:
                    console.print(f"[yellow]Not found: {target}[/]")
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled.[/]")
            time.sleep(0.5)
            mon = UniversalMonitor(load_config())

        elif cmd == 'f':
            console.print("\n[bold cyan]Fan Speed Control[/]  [dim](Ctrl+C to cancel)[/]")
            existing = load_config()
            avalon_miners = [m for m in existing if m['type_hint'] == 'avalon']
            if not avalon_miners:
                console.print("[yellow]No Avalon/cgminer miners in config (fan control uses cgminer API)[/]")
                time.sleep(1)
                mon = UniversalMonitor(load_config())
                continue
            console.print("  Miners: " + "  ".join(f"[cyan]{m['name']}[/] ({m['ip']})" for m in avalon_miners))
            try:
                target = Prompt.ask("  IP or name (or 'all')")
                speed = Prompt.ask("  Fan speed % (0-100)", default="60")
                try:
                    speed_val = max(0, min(100, int(speed)))
                except ValueError:
                    console.print("[red]Invalid value — must be 0-100[/]")
                    time.sleep(1)
                    mon = UniversalMonitor(load_config())
                    continue
                targets = avalon_miners if target.lower() == 'all' else [
                    m for m in avalon_miners if m['ip'] == target or m['name'] == target
                ]
                if not targets:
                    console.print(f"[yellow]Not found: {target}[/]")
                else:
                    for m in targets:
                        r = _cgminer_cmd(m['ip'], "ascset", parameter=f"0,fan,{speed_val}", timeout=3.0)
                        status = r.get("STATUS", [{}])[0].get("STATUS", "?") if r else "no response"
                        icon = "[green]✓[/]" if status == "S" else "[yellow]~[/]"
                        console.print(f"  {icon} {m['name']} ({m['ip']}) → fan {speed_val}%  ({status})")
            except KeyboardInterrupt:
                console.print("\n[dim]Cancelled.[/]")
            time.sleep(1)
            mon = UniversalMonitor(load_config())

        elif cmd == 's':
            console.print("\n[bold cyan]Rescanning LAN — adding new miners...[/]")
            subnet, _ = get_local_subnet()
            discovered = scan_network(subnet)
            if discovered:
                existing = load_config()
                existing_ips = {m['ip'] for m in existing}
                added = 0
                for d in discovered:
                    if d['ip'] not in existing_ips:
                        existing.append({"ip": d['ip'], "name": d['name'], "type_hint": d['type_hint']})
                        console.print(f"  [green]+[/] {d['ip']}  {d['name']}")
                        added += 1
                save_config(existing)
                console.print(f"[green]{added} new miner(s) added.[/]" if added else "[dim]No new miners found.[/]")
            else:
                console.print("[yellow]No miners found.[/]")
            time.sleep(1)
            mon = UniversalMonitor(load_config())

        elif cmd == 'c':
            console.print("\n[bold cyan]Clear config and rescan LAN...[/]")
            subnet, local_ip = get_local_subnet()
            if subnet:
                console.print(f"[dim]Local IP: {local_ip}  |  Subnet: {subnet}[/]")
            discovered = scan_network(subnet) if subnet else []
            if discovered:
                miners_new = [{"ip": d['ip'], "name": d['name'], "type_hint": d['type_hint']} for d in discovered]
                save_config(miners_new)
                for d in discovered:
                    console.print(f"  [green]✓[/] {d['ip']}  {d['name']}")
                console.print(f"[green]Config rebuilt with {len(miners_new)} miner(s).[/]")
            else:
                console.print("[yellow]No miners found — config unchanged.[/]")
            time.sleep(1)
            mon = UniversalMonitor(load_config())


if __name__ == "__main__":
    main()
