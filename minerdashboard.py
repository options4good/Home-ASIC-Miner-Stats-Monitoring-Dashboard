import socket
import json
import time
import requests
import re
import threading
import sys
from collections import deque
from datetime import datetime
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

# --- Configuration ---
MINERS_CONFIG = [
    {"ip": "10.0.0.3", "name": "AvaQ-01", "type_hint": "avalon"},
    {"ip": "10.0.0.23", "name": "Nerd-03", "type_hint": "nerd"},
    {"ip": "10.0.0.47", "name": "LM-LV07", "type_hint": "lucky"},
    {"ip": "10.0.0.53", "name": "Nerd-02", "type_hint": "nerd"},
    {"ip": "10.0.0.130", "name": "Nerd-01", "type_hint": "nerd"},
    {"ip": "10.0.0.147", "name": "Nerd-04", "type_hint": "nerd"},
    {"ip": "10.0.0.7", "name": "AvaN3S-01", "type_hint": "avalonnano"},
    {"ip": "10.0.0.51", "name": "Gamma-01", "type_hint": "nerd"},
    {"ip": "10.0.0.35", "name": "LM-LV08", "type_hint": "lucky"},
    {"ip": "10.0.0.111", "name": "Gamma-02", "type_hint": "nerd"},
    {"ip": "10.0.0.166", "name": "Gamma-03", "type_hint": "nerd"},
    {"ip": "10.0.0.22", "name": "Nerd-05", "type_hint": "nerd"}
]

MINERS = sorted(MINERS_CONFIG, key=lambda x: x['name'])

APP_VERSION = "V2.5.6"

class UniversalMonitor:
    def __init__(self):
        self.acc_counts = {m['ip']: 0 for m in MINERS}
        self.rej_counts = {m['ip']: 0 for m in MINERS}
        self.block_counts = {m['ip']: 0 for m in MINERS}
        self.share_logs = deque(maxlen=100) 
        self.avalon_modes = {"0": "ECO", "1": "STD", "2": "SUP"}
        self.nano_modes = {"0": "LOW", "1": "MED", "2": "HIGH"}
        
        self.miner_data = {m['ip']: {"online": False, "loading": True} for m in MINERS}
        self.log_lock = threading.Lock()
        self.start_threads()

    def start_threads(self):
        for miner in MINERS:
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
        except: return "--"

    def _format_diff(self, val):
        if val is None or val == 0 or val == "": return "--"
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
        except: return str(val)

    def _avalon_cmd(self, ip, cmd):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((ip, 4028))
                s.sendall(json.dumps({"command": cmd}).encode())
                buffer = b""
                while True:
                    chunk = s.recv(8192)
                    if not chunk: break
                    buffer += chunk
                raw = buffer.decode('utf-8', errors='ignore').strip('\x00')
                try: return json.loads(raw)
                except: return raw
        except: return None

    def fetch_data(self, miner):
        ip = miner['ip']
        now_ts = datetime.now().strftime('%H:%M:%S')
        try:
            if miner['type_hint'] in ["avalon", "avalonnano"]:
                sum_d = self._avalon_cmd(ip, "summary")
                pool_d = self._avalon_cmd(ip, "pools")
                estats_raw = self._avalon_cmd(ip, "estats")
                
                if sum_d and pool_d:
                    s = sum_d.get('SUMMARY', [{}])[0]
                    p = pool_d.get('POOLS', [{}])[0]
                    parsed_estats = {k: v for k, v in re.findall(r'(\w+)\[([^\]]+)\]', str(estats_raw))}
                    ps_data = parsed_estats.get("PS", "").split()
                    
                    # Avalon Pool Diff Calculation
                    diff_acc = float(s.get('Difficulty Accepted', 0))
                    acc = int(s.get('Accepted', 0))
                    avg_diff = diff_acc / acc if acc > 0 else 0
                    calc_pool_diff = f"{int(avg_diff):,}" if avg_diff > 0 else "NA"

                    if miner['type_hint'] == "avalonnano":
                        ac_pwr = float(ps_data[6]) if len(ps_data) > 6 else 0
                        dc_pwr = ac_pwr * 0.9      
                        pwr_display = f"NA - {dc_pwr:.1f}W/{ac_pwr:.1f}W"
                        vf_display = f"NA/{parsed_estats.get('Freq','--')}MHz"
                        wm_key = parsed_estats.get('WORKMODE','1')
                        wm = self.nano_modes.get(wm_key, 'MED')
                        eff_val = dc_pwr
                    else:
                        mv = ps_data[1] if len(ps_data) > 1 else "0"
                        dc = float(ps_data[4]) if len(ps_data) > 4 else 0
                        ac = float(ps_data[6]) if len(ps_data) > 6 else 0
                        pwr_display = f"{float(mv)/100:.2f}V - {dc:.1f}W/{ac:.1f}W"
                        vf_display = f"{mv}mV/{parsed_estats.get('Freq','--')}MHz"
                        wm = self.avalon_modes.get(parsed_estats.get('WORKMODE','1'), 'STD')
                        eff_val = dc

                    raw_ghs_5m = s.get('GHS 5m') or (s.get('MHS 5m', 0) / 1000)
                    hash_th = float(raw_ghs_5m) / 1000
                    
                    rej, blocks = int(s.get('Rejected', 0)), int(s.get('Found Blocks', 0))
                    self._update_activity_logs(miner['name'], ip, acc, rej, blocks, now_ts)
                    
                    best_diff = self._format_diff(s.get('Best Share', 0))
                    raw_pct = str(parsed_estats.get('FanR', '--')).replace('%', '')
                    fan_rpm = parsed_estats.get('Fan1', '--')
                    fan_display = f"{raw_pct}% ({fan_rpm} RPM)" if raw_pct != '--' else "--"
                    
                    rej_rate = (rej / acc * 100) if acc > 0 else 0.0

                    return {
                        "online": True, "hash": hash_th, "mode": wm,
                        "eff": f"{eff_val/hash_th:.2f} J/TH" if hash_th > 0 else "0.00 J/TH", 
                        "temp": f"{parsed_estats.get('TAvg', s.get('Temperature', 0))}°C",
                        "pwr": pwr_display, "vf": vf_display,
                        "fan": fan_display, "up": self._format_uptime(s.get('Elapsed', 0)),
                        "bd": best_diff, "sd": best_diff, "sh": f"{acc}/{rej} ({rej_rate:.2f})",
                        "pd": calc_pool_diff, "bl": blocks,
                        "p": p.get('URL', 'Unknown'), "ping": f"{float(parsed_estats.get('PING', 0)):.1f}ms", "u": p.get('User', 'N/A')
                    }
            else:
                # Nerd/Lucky Logic
                r = requests.get(f"http://{ip}/api/system/info", timeout=3.0).json()
                st = r.get('stratum', {})
                h_th = r.get('hashRate', 0) / 1000
                dc = float(r.get('power', 0))
                v_core, mv_act = float(r.get('voltage', 0))/1000, r.get('coreVoltageActual', 0)
                acc, rej, blocks = int(r.get('sharesAccepted', 0)), int(r.get('sharesRejected', 0)), int(r.get('foundBlocks', 0))
                self._update_activity_logs(miner['name'], ip, acc, rej, blocks, now_ts)
                
                ping_display = "NA"
                
                # Fix Lucky NA display
                if miner['type_hint'] == "lucky":
                    pool_diff = "NA"
                else:
                    pool_diff = f"{r.get('poolDifficulty', 0):,}"

                rej_rate = (rej / acc * 100) if acc > 0 else 0.0

                if miner['type_hint'] != "lucky":
                    ping_val = 0
                    keys = ['responseTime', 'pingRtt', 'latency']
                    pools = st.get('pools', [])
                    if pools and isinstance(pools, list):
                        for k in keys:
                            if k in pools[0]: ping_val = pools[0][k]; break
                    if ping_val == 0:
                        for k in keys:
                            if k in r: ping_val = r[k]; break
                            if k in st: ping_val = st[k]; break
                    ping_display = f"{float(ping_val):.1f}ms"

                return {
                    "online": True, "hash": h_th, "mode": None,
                    "eff": f"{dc/h_th:.2f} J/TH" if h_th > 0 else "0.00 J/TH", "temp": f"{r.get('temp', 0):.1f}°/{r.get('vrTemp', 0)}°",
                    "pwr": f"{v_core:.2f}V - {dc:.1f}W/{dc/0.9:.1f}W", "vf": f"{mv_act}mV/{r.get('frequency', 0)}MHz",
                    "fan": f"{r.get('fanspeed', 0):.0f}% ({r.get('fanrpm', 0)} RPM)", "up": self._format_uptime(r.get('uptimeSeconds', 0)),
                    "bd": self._format_diff(r.get('bestDiff')), "sd": self._format_diff(r.get('bestSessionDiff')), "sh": f"{acc}/{rej} ({rej_rate:.2f})",
                    "pd": pool_diff, "bl": blocks, "p": f"{r.get('stratumURL', st.get('url'))}:{r.get('stratumPort', st.get('port'))}",
                    "ping": ping_display, "u": r.get('stratumUser', st.get('user'))
                }
        except: pass
        return {"online": False}

    def _update_activity_logs(self, name, ip, acc, rej, blocks, ts):
        with self.log_lock:
            if acc > self.acc_counts[ip] and self.acc_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] [bold green]✅[/] {name} [bright_green]Accepted[/]")
            if rej > self.rej_counts[ip] and self.rej_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] [bold red]❌[/] {name} [bold red]Rejected[/]")
            if blocks > self.block_counts[ip] and self.block_counts[ip] != 0:
                self.share_logs.appendleft(f"[{ts}] [bold green]✅[/] {name} [bold blink grey11 on gold1] BLOCK FOUND!!! [/]\a")
            self.acc_counts[ip], self.rej_counts[ip], self.block_counts[ip] = acc, rej, blocks

    def update_ui(self):
        total_hash, online_count = 0, 0
        header_style = "bold bright_white"
        miner_name_style = "bold bright_cyan"
        mid_ground_style = "bright_white"

        perf_t = Table(expand=True, border_style="dim")
        perf_t.add_column("Miner", style=miner_name_style, width=22, header_style=header_style)
        perf_t.add_column("Hashrate", justify="right", style=mid_ground_style, header_style=header_style)
        perf_t.add_column("Efficiency", justify="center", style="bold white", header_style=header_style)
        perf_t.add_column("Temp ASIC/VR", justify="center", style="yellow", header_style=header_style)
        perf_t.add_column("Power Volt/DC/AC", justify="center", style="orange3", header_style=header_style)
        perf_t.add_column("ASIC Volt/Freq", justify="center", style="magenta", header_style=header_style)
        perf_t.add_column("Fan", justify="right", style="bold cyan", header_style=header_style)

        luck_t = Table(expand=True, border_style="dim")
        luck_t.add_column("Miner", style=miner_name_style, width=12, header_style=header_style)
        luck_t.add_column("Uptime", justify="center", style="bold blue", header_style=header_style)
        luck_t.add_column("Best Diff All-time", justify="right", style="bold green", header_style=header_style)
        luck_t.add_column("Best Diff Session", justify="right", style="green", header_style=header_style)
        luck_t.add_column("Accepted/Rejected/%", justify="center", style="bold white", header_style=header_style)
        luck_t.add_column("Pool Diff", justify="center", style="white", header_style=header_style)
        luck_t.add_column("Blocks", justify="center", style="bold gold1", header_style=header_style)

        pool_t = Table(expand=True, border_style="dim")
        pool_t.add_column("Miner", style=miner_name_style, width=12, header_style=header_style)
        pool_t.add_column("IP Address", style="bold white", width=15, header_style=header_style)
        pool_t.add_column("Pool URL", style="bold yellow", header_style=header_style)
        pool_t.add_column("Ping", justify="right", style="green", header_style=header_style)
        pool_t.add_column("Username/Worker", style=mid_ground_style, header_style=header_style)

        for m in MINERS:
            st = self.miner_data.get(m['ip'], {"online": False})
            if st.get("online"):
                total_hash += st['hash']; online_count += 1
                m_name = f"{m['name']} [dim]({st['mode']})[/]" if st.get('mode') else m['name']
                perf_t.add_row(m_name, f"{st['hash']:.2f} TH/s", st['eff'], st['temp'], st['pwr'], st['vf'], st['fan'])
                luck_t.add_row(m['name'], st['up'], st['bd'], st['sd'], st['sh'], st['pd'], str(st['bl']))
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
        header.add_column(); header.add_column(justify="right")
        header.add_row(
            Text.from_markup(f"Total: [bold green]{total_hash:.2f} TH/s[/] | Online: [bold cyan]{online_count}/{len(MINERS)}[/] | [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]"),
            Text.from_markup(f"[bold cyan]Version: {APP_VERSION}[/]")
        )

        layout = Layout()
        layout.split_row(Layout(name="left", ratio=4), Layout(name="right", ratio=1))
        layout["left"].split_column(
            Layout(Panel(header, title="[bold]Global Status[/]", border_style="bright_cyan"), size=3),
            Layout(Panel(perf_t, title="[bold]Performance[/]", border_style="bright_magenta"), ratio=1),
            Layout(Panel(luck_t, title="[bold]Mining[/]", border_style="bold bright_red"), ratio=1),
            Layout(Panel(pool_t, title="[bold]Connectivity[/]", border_style="bright_cyan"), ratio=1)
        )
        layout["right"].update(Panel("\n".join(self.share_logs), title="[bold]Activity[/]", border_style="bold bright_yellow"))
        
        return layout

if __name__ == "__main__":
    mon = UniversalMonitor()
    with Live(mon.update_ui(), screen=True, refresh_per_second=4) as live:
        while True:
            live.update(mon.update_ui())
            time.sleep(0.25)
