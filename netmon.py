#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netmon — Monitoring réseau avec alertes Telegram (pensé pour Termux)

Fonctionnalités :
  - Scan du réseau local (nmap -sn) et détection des nouveaux appareils
  - Scan de ports/services (nmap -sV) sur les appareils inconnus détectés
  - Reconnaissance d'OS (nmap -O) optionnelle sur les nouveaux hôtes
  - Baseline persistante (devices.json) : la mémoire des appareils connus
  - Historique des scans (history.jsonl) consultable sur le dashboard web
  - Alertes Telegram (API officielle, via urllib — zéro dépendance)
  - Dashboard web intégré (http.server stdlib, aucune dépendance)
  - Mode daemon : scan régulier en boucle

Utilisation :
  python3 netmon.py --scan           # un scan, affiche le résultat
  python3 netmon.py --baseline       # sauvegarde l'état actuel comme référence
  python3 netmon.py --daemon         # boucle : scan + alertes à chaque intervalle
  python3 netmon.py --web            # dashboard web intégré (http://localhost:8080)
  python3 netmon.py --daemon --web   # charme absolu : daemon + dashboard
  python3 netmon.py --test-telegram  # envoie un message de test
"""

import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
BASELINE_FILE = BASE_DIR / "devices.json"
HISTORY_FILE = BASE_DIR / "history.jsonl"

# ---------------------------------------------------------------- config


def load_config():
    if not CONFIG_FILE.exists():
        sys.exit(
            "[!] config.json introuvable.\n"
            "    Copie le modèle :  cp config.example.json config.json\n"
            "    puis renseigne ta clé Telegram et ton réseau."
        )
    return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))


def load_baseline():
    if BASELINE_FILE.exists():
        return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    return {}


def save_baseline(devices):
    BASELINE_FILE.write_text(
        json.dumps(devices, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def append_history(entry):
    """Ajoute une ligne à history.jsonl dans l'ordre...";
    une ligne = un scan."""
    with HISTORY_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_history(limit=200):
    if not HISTORY_FILE.exists():
        return []
    lines = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.reverse()  # plus récent en premier
    return out


# ---------------------------------------------------------------- scan


def parse_nmap(output):
    """Parse la sortie de `nmap -sn` → {mac: {"ip":..., "vendor":...}}."""
    hosts = {}
    blocks = output.split("Nmap scan report for ")
    for block in blocks[1:]:
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", block)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        mac_match = re.search(
            r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?", block
        )
        if mac_match:
            mac = mac_match.group(1).upper()
            vendor = (mac_match.group(2) or "").strip()
        else:
            # Appareil sur le même segment (pas de MAC vu par nmap) :
            # on utilise l'IP comme identifiant de secours.
            mac = f"IP:{ip}"
            vendor = ""
        hosts[mac] = {"ip": ip, "vendor": vendor}
    return hosts


def scan_network(network):
    """Scan passif (ping sweep) du réseau avec nmap."""
    nmap = shutil.which("nmap")
    if not nmap:
        sys.exit(
            "[!] nmap est introuvable.\n"
            "    Sur Termux :  pkg install nmap"
        )
    # -sn : ping sweep seulement (pas de scan de ports) → rapide et discret
    result = subprocess.run(
        [nmap, "-sn", network],
        capture_output=True,
        text=True,
        timeout=180,
    )
    return parse_nmap(result.stdout)


# ---------------------------------------------------------------- ports


def parse_nmap_ports(output):
    """Parse la sortie `nmap -sV` → [(port, service, version)]."""
    ports = []
    for line in output.splitlines():
        m = re.match(r"^\s*(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m:
            port, service, version = m.groups()
            ports.append((port, service, version.strip()))
    return ports


def parse_nmap_os(output):
    """Récupère la conjecture d'OS dans la sortie `nmap -O`."""
    details = re.search(r"OS details:\s*(.+)", output)
    if details:
        return details.group(1).strip()
    running = re.search(r"Running:\s*(.+)", output)
    if running:
        return running.group(1).strip()
    return ""


def port_scan(ip, args, timeout):
    """Scan de ports (+ OS éventuel) sur une cible → (ports, os_guess)."""
    nmap = shutil.which("nmap")
    if not nmap:
        return [], ""
    try:
        result = subprocess.run(
            [nmap, *args, ip],
            capture_output=True, text=True, timeout=timeout
        )
        return parse_nmap_ports(result.stdout), parse_nmap_os(result.stdout)
    except Exception as exc:
        print(f"[!] Scan de ports échoué sur {ip} : {exc}")
        return [], ""


def format_port_line(entry):
    port, service, version = entry
    detail = f" ({version})" if version else ""
    return f"   • <code>{port}/tcp</code> {service}{detail}"


def build_scan_args(config):
    """Construit les arguments du scan d'enrichissement (ports + OS)."""
    ports_cfg = config.get("port_scan", {})
    args = ports_cfg.get("args", ["-sV", "--top-ports", "100"])
    if config.get("os_detection", False):
        args = args + ["-O"]
    return args, ports_cfg.get("timeout_sec", 120)


# ---------------------------------------------------------------- telegram


def send_telegram(config, message):
    telegram = config.get("telegram", {})
    token = telegram.get("bot_token", "")
    chat_id = telegram.get("chat_id", "")
    if not token or not chat_id:
        print("[i] Telegram non configuré — message ignoré :")
        print(message)
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
        }
    ).encode()
    try:
        with urllib.request.urlopen(url, data=payload, timeout=15) as resp:
            resp.read()
        return True
    except Exception as exc:
        print(f"[!] Erreur Telegram : {exc}")
        return False


# ---------------------------------------------------------------- logique


def compare(baseline, current, notify_vanished=False):
    """Retourne les listes de nouveaux appareils et d'appareils disparus."""
    new_devices = {mac: info for mac, info in current.items() if mac not in baseline}
    vanished = (
        {mac: info for mac, info in baseline.items() if mac not in current}
        if notify_vanished
        else {}
    )
    return new_devices, vanished


def describe(mac, info):
    vendor = info.get("vendor") or "fabricant inconnu"
    return f"📱 <code>{mac}</code> @ <code>{info['ip']}</code> ({vendor})"


def run_scan(config, baseline):
    network = config["network"]
    print(f"[*] Scan de {network} ...")
    current = scan_network(network)
    print(f"[*] {len(current)} appareil(s) en ligne.")

    new_devices, vanished = compare(baseline, current, config.get("notify_vanished", False))

    messages = []
    history_entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "online": len(current),
        "new": [],
        "vanished": [info["ip"] for info in vanished.values()],
    }

    if new_devices:
        lines = "\n".join(describe(mac, info) for mac, info in new_devices.items())
        messages.append(f"🚨 <b>Nouveaux appareils sur le réseau</b>\n{lines}")
        for mac, info in new_devices.items():
            print(f"  [+] NOUVEAU : {mac} @ {info['ip']} ({info['vendor'] or '?'})")

        # Scan d'enrichissement (ports, services, OS) sur les nouveaux appareils
        ports_cfg = config.get("port_scan", {})
        if ports_cfg.get("enabled", False):
            args, timeout = build_scan_args(config)
            for mac, info in new_devices.items():
                ip = info["ip"]
                print(f"  [*] Scan de ports sur {ip} ...")
                entries, os_guess = port_scan(ip, args, timeout)
                device_record = {
                    "mac": mac,
                    "ip": ip,
                    "vendor": info.get("vendor", ""),
                    "ports": [f"{p}/tcp {s}" for p, s, _ in entries[:15]],
                    "os": os_guess,
                }
                history_entry["new"].append(device_record)

                if entries:
                    print(f"      {len(entries)} port(s) ouvert(s).")
                    details = "\n".join(format_port_line(e) for e in entries[:15])
                    msg = f"🔍 <b>{ip}</b> — {len(entries)} port(s) ouvert(s)\n{details}"
                else:
                    msg = f"🔍 <b>{ip}</b> — aucun port ouvert détecté"

                if os_guess:
                    msg += f"\n💻 OS probable : {os_guess}"
                    print(f"      OS : {os_guess}")
                messages.append(msg)

    if vanished:
        lines = "\n".join(describe(mac, info) for mac, info in vanished.items())
        messages.append(f"💤 <b>Appareils absents</b>\n{lines}")

    append_history(history_entry)

    for msg in messages:
        send_telegram(config, msg)

    baseline.update(current)
    save_baseline(baseline)

    print(f"[*] Baseline mise à jour ({time.strftime('%H:%M:%S')}).")
    return current


def run_daemon(config):
    interval = config.get("interval_sec", 300)
    print(f"[*] Mode daemon : scan toutes les {interval} s. Ctrl+C pour arrêter.")
    baseline = load_baseline()
    while True:
        try:
            run_scan(config, baseline)
        except Exception as exc:
            print(f"[!] Erreur pendant le scan : {exc}")
        time.sleep(interval)


# ---------------------------------------------------------------- web


def local_ips():
    """IPs où le dashboard est joignable (pour l'affichage de l'URL)."""
    ips = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ("127.0.0.1", "0.0.0.0") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


PAGE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netmon 🛡️</title>
<meta http-equiv="refresh" content="30">
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background:#0d1117; color:#e6edf3;
         margin: 0; padding: 1.2rem; }
  h1 { font-size: 1.3rem; }  h2 { font-size: 1.05rem; margin-bottom: .3rem; }
  .muted { color:#8b949e; font-size:.85rem; }
  table { width:100%; border-collapse: collapse; margin: .6rem 0 1.4rem;
          font-size:.9rem; }
  th, td { text-align:left; padding:.45rem .55rem; border-bottom:1px solid #21262d; }
  th { color:#8b949e; font-weight:600; }
  .card { background:#161b22; border:1px solid #21262d; border-radius:10px;
          padding:1rem; margin-bottom:1rem; }
  .badge { background:#1f6feb22; color:#58a6ff; border-radius:6px;
           padding:.1rem .45rem; font-size:.8rem; }
  .ports { color:#7ee787; } .os { color:#ffa657; }
  a { color:#58a6ff; }
</style>
</head>
<body>
<h1>🛡️ netmon — dashboard</h1>
<p class="muted">Appareils connus : __DEVICES_COUNT__ · Rafraîchissement auto : 30 s</p>

<div class="card">
<h2>📱 Appareils connus</h2>
<table id="devices">
  <tr><th>MAC</th><th>IP</th><th>Fabricant</th></tr>
</table>
</div>

<div class="card">
<h2>📜 Historique des scans</h2>
<table id="history">
  <tr><th>Quand</th><th>En ligne</th><th>Nouveaux</th><th>Détails</th></tr>
</table>
</div>

<p class="muted">API JSON : <a href="/api/state">/api/state</a></p>

<script>
const table = (id, rowsHtml) => { document.getElementById(id)
  .insertAdjacentHTML("beforeend", rowsHtml); };

fetch("/api/state").then(r => r.json()).then(state => {
  const devRows = Object.entries(state.devices).map(([mac, d]) =>
    `<tr><td><code>${mac}</code></td><td>${d.ip}</td><td>${d.vendor || "?"}</td></tr>`
  ).join("");
  table("devices", devRows);

  const histRows = state.history.map(h => {
    const news = h.new.map(n =>
      `<div><span class="badge">${n.ip}</span>
       ${n.vendor || "?"}
       <span class="ports">${n.ports.length ? n.ports.join(", ") : ""}</span>
       ${n.os ? `<div class="os">OS : ${n.os}</div>` : ""}</div>`
    ).join("") || "<span class='muted'>—</span>";
    return `<tr><td>${h.ts}</td><td>${h.online}</td><td>${h.new.length}</td>
            <td>${news}</td></tr>`;
  }).join("");
  table("history", histRows);
});
</script>
</body>
</html>"""


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/state":
            state = {
                "devices": load_baseline(),
                "history": load_history(),
            }
            body = json.dumps(state, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/":
            body = PAGE.replace(
                "__DEVICES_COUNT__", str(len(load_baseline()))
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):  # on silencie les logs HTTP
        pass


def start_web_server(config, foreground=False):
    web_cfg = config.get("web", {})
    port = web_cfg.get("port", 8080)
    bind = web_cfg.get("bind", "0.0.0.0")
    server = ThreadingHTTPServer((bind, port), WebHandler)
    urls = [f"http://<ton-ip>:{port}"] + [
        f"http://{ip}:{port}" for ip in local_ips()
    ]
    print(f"[*] Dashboard web : {', '.join(urls)}")
    if foreground:
        print("[*] Ctrl+C pour arrêter.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Arrêt du dashboard.")
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server


# ---------------------------------------------------------------- cli


def main():
    parser = argparse.ArgumentParser(description="netmon — monitoring réseau + Telegram")
    parser.add_argument("--scan", action="store_true", help="un simple scan")
    parser.add_argument("--baseline", action="store_true",
                        help="déclare l'état actuel comme référence")
    parser.add_argument("--daemon", action="store_true",
                        help="boucle de surveillance continue")
    parser.add_argument("--web", action="store_true",
                        help="dashboard web intégré")
    parser.add_argument("--test-telegram", action="store_true",
                        help="envoie un message de test Telegram")
    args = parser.parse_args()

    if not any([args.scan, args.baseline, args.daemon, args.web, args.test_telegram]):
        parser.print_help()
        return

    config = load_config()

    if args.test_telegram:
        ok = send_telegram(config, "✅ <b>netmon</b> est bien connecté à Telegram !")
        sys.exit(0 if ok else 1)

    if args.baseline:
        current = scan_network(config["network"])
        save_baseline(current)
        print(f"[*] Baseline enregistrée : {len(current)} appareil(s) connus.")
        for mac, info in current.items():
            print(f"    - {mac} @ {info['ip']} ({info['vendor'] or '?'})")
        if not args.daemon and not args.web:
            return

    daemon = args.daemon
    web = args.web

    if web:
        start_web_server(config, foreground=not daemon)

    if daemon:
        run_daemon(config)   # s'arrête jamais : Ctrl+C


if __name__ == "__main__":
    main()
