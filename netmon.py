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
  - Mode bot : contrôle à distance via Telegram (/scan, /status...)

Utilisation :
  python3 netmon.py --scan           # un scan, affiche le résultat
  python3 netmon.py --baseline       # sauvegarde l'état actuel comme référence
  python3 netmon.py --daemon         # boucle : scan + alertes à chaque intervalle
  python3 netmon.py --bot            # scans automatiques + commandes Telegram
  python3 netmon.py --web            # dashboard web intégré (http://localhost:8080)
  python3 netmon.py --daemon --web   # charme absolu : daemon + dashboard
  python3 netmon.py --test-telegram  # envoie un message de test
"""

import argparse
import html
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
ALIAS_FILE = BASE_DIR / "aliases.json"
PORTS_FILE = BASE_DIR / "ports.json"
GWSTATE_FILE = BASE_DIR / "gw.json"

# État partagé entre le daemon de scan et le bot Telegram
SCAN_LOCK = threading.Lock()
LAST_STATE = {"ts": "", "online": 0}
TP_OFFSET = 0  # offset de lecture des updates Telegram
SCAN_CYCLE = 0  # compteur de cycles pour l'IDS

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


def load_aliases():
    """Alias lisibles des appareils : {mac: "TV du salon", ...}."""
    if ALIAS_FILE.exists():
        return json.loads(ALIAS_FILE.read_text(encoding="utf-8"))
    return {}


def save_aliases(aliases):
    ALIAS_FILE.write_text(
        json.dumps(aliases, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def alias_of(mac):
    return load_aliases().get(mac, "")


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


# ---------------------------------------------------------------- ids


def load_ports_base():
    """Baseline des ports ouverts par appareil : {mac: {"ts":..., "ports":[...]}}."""
    if PORTS_FILE.exists():
        return json.loads(PORTS_FILE.read_text(encoding="utf-8"))
    return {}


def save_ports_base(ports_base):
    PORTS_FILE.write_text(
        json.dumps(ports_base, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _get_gateway_mac():
    """(ip, mac) de la passerelle. None si indéterminable."""
    gw_ip, gw_mac = None, None
    try:
        route = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        gw_m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", route)
        if gw_m:
            gw_ip = gw_m.group(1)
    except Exception:
        pass
    if not gw_ip:
        # offshore : /proc/net/route (destination 00000000 = passerelle)
        try:
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000":
                    raw = fields[2]
                    gw_ip = ".".join(
                        str(int(raw[i:i + 2], 16)) for i in (6, 4, 2, 0)
                    )
                    break
        except Exception:
            pass
    if not gw_ip:
        return None
    try:
        neigh = subprocess.run(
            ["ip", "neigh", "show", gw_ip],
            capture_output=True, text=True, timeout=10,
        ).stdout
        mac_m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", neigh)
        if mac_m:
            gw_mac = mac_m.group(1).upper()
    except Exception:
        pass
    if not gw_mac:
        # fallback : /proc/net/arp
        try:
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                target, hw_flags, hw_addr = line.split()[0], line.split()[2], line.split()[3]
                if target == gw_ip and len(hw_addr.split(":")) == 6 and hw_addr != "00:00:00:00:00:00":
                    gw_mac = hw_addr.upper()
                    break
        except Exception:
            pass
    return (gw_ip, gw_mac) if gw_mac else None


def ids_gateway_guard(config, ids_events):
    """Gardien ARP : alerte si la MAC de la passerelle change (spoofing)."""
    cfg = config.get("ids", {})
    if not cfg.get("gateway_watch", True):
        return
    gw = _get_gateway_mac()
    if not gw:
        return
    ip, mac = gw
    state = {}
    if GWSTATE_FILE.exists():
        state = json.loads(GWSTATE_FILE.read_text(encoding="utf-8"))
    old_mac = state.get("mac", "")
    if old_mac and old_mac != mac:
        ids_events.append({
            "level": "CRIT",
            "type": "arp_change",
            "msg": (f"MAC de la passerelle {ip} a changé : "
                    f"{old_mac} → {mac} (attaque ARP-spoofing possible ?)"),
        })
    state.update(ip=ip, mac=mac)
    GWSTATE_FILE.write_text(json.dumps(state, indent=2))


def ids_check_ports(config, ip, mac, entries, prior_ports, ids_events, warn_new=True):
    """Diff les ports + détecte les ports suspects. Retourne l'état actuel."""
    cfg = config.get("ids", {})
    suspicious = cfg.get("suspicious_ports", [21, 23, 445, 3389, 5555, 5060])
    alias = alias_of(mac)

    ports_now = []
    for port, service, _version in entries:
        ports_now.append(f"{port}/tcp {service}")
        if int(port) in suspicious:
            ids_events.append({
                "level": "CRIT",
                "type": "suspicious_port",
                "msg": (f"port suspect {port}/tcp ({service}) ouvert sur {ip}"
                        + (f" ({alias})" if alias else "")),
            })
    if warn_new:
        for ref in ports_now:
            if ref not in prior_ports:
                ids_events.append({
                    "level": "WARN",
                    "type": "new_port",
                    "msg": (f"nouveau port ouvert sur {ip}"
                            + (f" ({alias})" if alias else "") + f" : {ref}"),
                })
    return ports_now


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
    line = f"📱 <code>{mac}</code> @ <code>{info['ip']}</code> ({vendor})"
    alias = alias_of(mac)
    if alias:
        line += f"\n   👤 <b>{html.escape(alias)}</b>"
    return line


def run_scan(config, baseline):
    """Point d'entrée de scan : thread-safe (daemon et bot cohabitent)."""
    with SCAN_LOCK:
        return _scan_inner(config, baseline)


def _scan_inner(config, baseline):
    network = config["network"]
    print(f"[*] Scan de {network} ...")
    current = scan_network(network)
    print(f"[*] {len(current)} appareil(s) en ligne.")

    new_devices, vanished = compare(baseline, current, config.get("notify_vanished", False))

    messages = []
    ids_events = []
    history_entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "online": len(current),
        "new": [],
        "vanished": [info["ip"] for info in vanished.values()],
        "ids": ids_events,
    }

    ids_cfg = config.get("ids", {})
    global SCAN_CYCLE
    SCAN_CYCLE += 1
    if ids_cfg.get("enabled", True):
        ids_gateway_guard(config, ids_events)

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

                # IDS : premier état des ports d'un nouvel appareil
                if entries:
                    ports_base = load_ports_base()
                    ports_now = ids_check_ports(
                        config, ip, mac, entries, [], ids_events, warn_new=False
                    )
                    ports_base[mac] = {"ts": history_entry["ts"], "ports": ports_now}
                    save_ports_base(ports_base)

        # IDS : refresh périodique des appareils CONNUS (ports qui changent)
        if ids_cfg.get("watch_known", True):
            every = max(int(ids_cfg.get("rescan_every", 2)), 1)
            if SCAN_CYCLE % every == 1:
                args_known = ids_cfg.get(
                    "known_scan_args", ["-sT", "--top-ports", "100"]
                )
                timeout = int(ids_cfg.get("timeout_sec", 120))
                ports_base = load_ports_base()
                for mac, info in current.items():
                    if mac not in baseline:  # nouveaux : déjà traités au-dessus
                        continue
                    ip_known = info["ip"]
                    prior = ports_base.get(mac, {}).get("ports", [])
                    print(f"  [*] IDS pulse sur {ip_known} ...")
                    entries_k, _ = port_scan(ip_known, args_known, timeout)
                    if not entries_k:
                        continue  # scan vide (éteint/bloqué) : on ne casse pas la base
                    ports_now = ids_check_ports(
                        config, ip_known, mac, entries_k, prior, ids_events
                    )
                    ports_base[mac] = {"ts": history_entry["ts"], "ports": ports_now}
                    save_ports_base(ports_base)

    if vanished:
        lines = "\n".join(describe(mac, info) for mac, info in vanished.items())
        messages.append(f"💤 <b>Appareils absents</b>\n{lines}")

    for ev in ids_events:
        icon = "🔴" if ev["level"] == "CRIT" else "🟠"
        print(f"  ⚠️ IDS [{ev['level']}] {ev['msg']}")
        messages.append(f"🛡️ <b>netmon IDS</b>\n{icon} <b>{ev['level']}</b> — {ev['msg']}")

    append_history(history_entry)

    for msg in messages:
        send_telegram(config, msg)

    baseline.update(current)
    save_baseline(baseline)

    LAST_STATE.update(ts=history_entry["ts"], online=len(current))
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


# ---------------------------------------------------------------- bot telegram


def telegram_get_updates(config, wait=15):
    """Récupère les messages reçus par le bot (polling). → tokens safe"""
    global TP_OFFSET
    t = config.get("telegram", {})
    url = (
        f"https://api.telegram.org/bot{t['bot_token']}/getUpdates"
        f"?timeout={wait}&offset={TP_OFFSET}"
    )
    try:
        with urllib.request.urlopen(url, timeout=wait + 10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"[!] getUpdates : {exc}")
        return []
    out = []
    for upd in data.get("result", []):
        TP_OFFSET = max(TP_OFFSET, upd["update_id"] + 1)
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat_id = (msg.get("chat") or {}).get("id")
        if text and chat_id:
            out.append((chat_id, text))
    return out


def bot_respond(config, chat_id, text):
    """Traite une commande Telegram (/scan, /status...) et répond."""
    cmd = text.split()[0].split("@")[0].lower()

    if cmd in ("/start", "/help", "/commands"):
        send_telegram(config, (
            "🤖 <b>netmon — commandes</b>\n"
            "/status — dernier scan (heure, nb en ligne)\n"
            "/scan — lancer un scan immédiatement\n"
            "/devices — appareils connus\n"
            "/name <ip> <nom> — renommer un appareil (ex : /name 192.168.1.42 TV salon)\n"
            "/unknown — nouveaux du dernier scan\n"
            "/recent — 5 derniers scans\n"
            "/events — dernières alertes IDS"
        ))
    elif cmd == "/status":
        if LAST_STATE["ts"]:
            send_telegram(config, (
                f"📊 <b>Dernier scan</b>\n"
                f"🕐 {html.escape(LAST_STATE['ts'])}\n"
                f"📶 {LAST_STATE['online']} appareil(s) en ligne"
            ))
        else:
            send_telegram(config, "⏳ Aucun scan effectué — attends le premier scan.")
    elif cmd == "/scan":
        send_telegram(config, "⏳ Scan en cours...")
        run_scan(config, load_baseline())
    elif cmd == "/name":
        parts = text.split(maxsplit=2)
        if len(parts) < 3:
            send_telegram(config,
                          "💡 Usage : /name <ip_ou_mac> <petit nom>\n"
                          "ex : /name 192.168.1.42 TV du salon")
            return
        target, label = parts[1], parts[2].strip()
        devices = load_baseline()
        mac = None
        if target.upper() in devices:
            mac = target.upper()
        else:
            for m, info in devices.items():
                if info["ip"] == target:
                    mac = m
                    break
        if not mac:
            send_telegram(config, f"🤔 {target} introuvable — regarde /devices")
            return
        aliases = load_aliases()
        aliases[mac] = label
        save_aliases(aliases)
        info = devices[mac]
        send_telegram(config, (
            f"🏷️ Alias enregistré !\n"
            f"<code>{html.escape(info['ip'])}</code> → "
            f"<b>{html.escape(label)}</b>"
        ))
    elif cmd == "/devices":
        devices = load_baseline()
        if not devices:
            send_telegram(config, "📭 Baseline vide — lance d'abord /scan")
            return
        aliases = load_aliases()
        lines = []
        for info in list(devices.values())[:15]:
            ip = html.escape(info["ip"])
            vendor = html.escape(info.get("vendor") or "inconnu")
            alias = next(
                (a for m, a in aliases.items() if devices[m]["ip"] == info["ip"]),
                ""
            )
            tag = f" 👤 <b>{html.escape(alias)}</b>" if alias else ""
            lines.append(f"• <code>{ip}</code> {vendor}{tag}")
        more = f"\n... et {len(devices) - 15} autres" if len(devices) > 15 else ""
        send_telegram(config, f"📱 <b>{len(devices)} appareil(s) connu(s)</b>\n" + "\n".join(lines) + more)
    elif cmd == "/events":
        evts = [e for h in load_history(10) for e in h.get("ids", [])]
        if not evts:
            send_telegram(config, "✅ Aucun événement IDS — réseau calme.")
            return
        lines = []
        for e in evts[:10]:
            icon = "🔴" if e["level"] == "CRIT" else "🟠"
            lines.append(f"{icon} <b>{e['level']}</b> — {html.escape(e['msg'])}")
        send_telegram(config, "🛡️ <b>Alertes IDS récentes</b>\n" + "\n".join(lines))
    elif cmd == "/unknown":
        hist = load_history(1)
        news = hist[0]["new"] if hist else []
        if news:
            lines = []
            for n in news:
                os_part = f" · OS: {n['os']}" if n.get("os") else ""
                lines.append(
                    f"🚨 <code>{html.escape(n['ip'])}</code> "
                    f"{html.escape(n['vendor'] or '?')}{os_part}"
                )
            send_telegram(config,
                          f"🔍 <b>Appareils du dernier scan</b>\n" + "\n".join(lines))
        else:
            send_telegram(config, "✅ Aucun nouvel appareil au dernier scan.")
    elif cmd == "/recent":
        hist = load_history(5)
        if not hist:
            send_telegram(config, "📭 Aucun historique pour l'instant.")
            return
        lines = "\n".join(
            f"• {html.escape(h['ts'])} — {h['online']} en ligne — "
            f"{len(h['new'])} nouveau(x)"
            for h in hist
        )
        send_telegram(config, f"📜 <b>5 derniers scans</b>\n{lines}")
    else:
        send_telegram(config, "🤔 Commande inconnue — /help pour la liste")


def run_bot(config):
    """Mode bot : scans périodiques en tâche de fond + commandes Telegram."""
    interval = config.get("interval_sec", 300)

    def periodic():
        baseline = load_baseline()
        while True:
            try:
                run_scan(config, baseline)
            except Exception as exc:
                print(f"[!] Scan périodique : {exc}")
            time.sleep(interval)

    threading.Thread(target=periodic, daemon=True).start()

    allowed_chat = str(config["telegram"]["chat_id"])
    print("[*] Bot Telegram lancé — envoie /help dans ton chat !")
    while True:
        for chat_id, text in telegram_get_updates(config):
            if str(chat_id) != allowed_chat:
                print(f"[!] Commande refuse de champ {chat_id} (non autorise).")
                continue
            print(f"[*] Commande Telegram : {text}")
            bot_respond(config, chat_id, text)


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
    parser.add_argument("--bot", action="store_true",
                        help="daemon + commandes Telegram (/scan, /status...)")
    parser.add_argument("--web", action="store_true",
                        help="dashboard web intégré")
    parser.add_argument("--test-telegram", action="store_true",
                        help="envoie un message de test Telegram")
    args = parser.parse_args()

    if not any([args.scan, args.baseline, args.daemon, args.bot, args.web,
                args.test_telegram]):
        parser.print_help()
        return

    config = load_config()

    if args.test_telegram:
        ok = send_telegram(config, "✅ <b>netmon</b> est bien connecté à Telegram !")
        if ok:
            print("✅ Message envoyé — va voir ton téléphone !")
        else:
            print("[!] Échec de l'envoi — regarde les logs au-dessus.")
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
        start_web_server(config, foreground=not (daemon or args.bot))

    if args.bot:
        run_bot(config)      # s'arrête jamais : Ctrl+C
        return

    if daemon:
        run_daemon(config)   # s'arrête jamais : Ctrl+C


if __name__ == "__main__":
    main()
