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
  - Dossier enrichi des appareils (v4) : hostname rDNS, TTL OS, bannière HTTP,
    classification heuristique (box, TV, imprimante, NAS, smartphone...)
  - Traces de présence : first_seen / last_seen / compteur de scans (v4)
  - Dossier détaillé par Telegram (/info) + export CSV/JSON (/export) (v4)
  - Dashboard web avec graphique de présence (v4)
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
import csv
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
import uuid
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
EXPORT_DIR = BASE_DIR / "export"

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


# ---------------------------------------------------------------- enrich
# Dossier d'identité des appareils (v4) : hostname rDNS, TTL OS, bannière
# HTTP, classification heuristique — la partie « agent fédéral » 🕵️

OUI_EXTRA = {
    # Repli quand nmap ne fournit pas le vendeur (préfixes MAC connus)
    "00:09:B0": "Nintendo", "00:16:32": "Sony", "00:17:88": "Philips Hue",
    "00:1A:11": "Google", "3C:5A:B4": "Xiaomi", "50:C7:BF": "TP-Link",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
}

WELL_KNOWN = {
    21: "FTP", 22: "SSH (admin distante)", 23: "Telnet (⚠ non chiffré)",
    25: "SMTP (mail)", 53: "DNS", 80: "Web", 111: "RPC/NFS",
    135: "RPC Windows", 139: "NetBIOS (partage Windows)", 443: "HTTPS",
    445: "SMB (partage Windows)", 515: "Impression LPD",
    548: "Partage Apple (AFP)", 554: "RTSP (flux caméra)",
    631: "Impression IPP", 1900: "UPnP", 3389: "RDP (bureau distant)",
    5000: "NAS Synology", 5555: "ADB (⚠ Android)",
    5900: "VNC", 7000: "AirPlay", 8008: "Google Cast",
    8009: "Google Cast/Chromecast", 9100: "Impression brute (JetDirect)",
    62078: "usbmuxd (iPhone/iPad)",
}


def vendor_of(mac, nmap_vendor):
    """Vendeur : nmap en priorité, sinon banque OUI offline."""
    if nmap_vendor:
        return nmap_vendor
    return OUI_EXTRA.get(mac[:8], "")


def reverse_dns(ip):
    """Nom d'hôte (reverse DNS) d'une IP. '' si rien trouvé."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.rstrip(".")
    except Exception:
        return ""


def ttl_os_family(ttl):
    """Conjecture d'OS via le TTL ICMP (sur un LAN, pas de saut de routeur)."""
    if not ttl:
        return ""
    ttl = int(ttl)
    if ttl >= 240:
        return f"équipement réseau / Unix (TTL {ttl})"
    if ttl >= 120:
        return f"Windows (TTL {ttl})"
    if ttl >= 55:
        return f"Linux / Android / macOS (TTL {ttl})"
    return f"OS inconnu (TTL {ttl})"


def ping_ttl(ip):
    """TTL mesuré avec 1 ping ICMP → None si ping indisponible/échec."""
    ping = shutil.which("ping")
    if not ping:
        return None
    try:
        out = subprocess.run(
            [ping, "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"ttl[= ](\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def http_banner(ip, port):
    """Entête HTTP « Server » / auth d'un service web. '' si rien."""
    if int(port) not in (80, 8080):
        return ""
    try:
        req = urllib.request.Request(
            f"http://{ip}:{port}/", headers={"User-Agent": "netmon/4"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            return (
                resp.headers.get("Server", "")
                or resp.headers.get("WWW-Authenticate", "")
            )
    except Exception:
        return ""


GW_CACHE = {"ip": ""}


def gateway_ip():
    """IP de la passerelle locale (détectée une fois puis mise en cache)."""
    if not GW_CACHE["ip"]:
        gw = _get_gateway_mac()
        if gw:
            GW_CACHE["ip"] = gw[0]
    return GW_CACHE["ip"]


def classify_device(ip, gw_ip, vendor, hostname, port_entries, os_guess):
    """Heuristique de classification → (type, confiance %, notes)."""
    apset = {int(p) for p, _s, _v in port_entries if str(p).isdigit()}
    vend = (vendor or "").lower()
    host = (hostname or "").lower()
    osl = (os_guess or "").lower()
    notes = []

    if gw_ip and ip == gw_ip:
        notes.append("c'est l'IP de la passerelle")
        return "Box / routeur", 98, notes

    if os_guess:
        notes.append(f"OS nmap : {os_guess}")

    # ---------- Apple
    if "apple" in vend:
        if 7000 in apset:
            return "Apple TV (AirPlay)", 92, notes
        if 62078 in apset:
            return "iPhone / iPad", 90, notes
        if apset & {22, 548}:
            return "Mac (SSH / partage)", 85, notes
        return "Appareil Apple (iPhone / iPad / Mac probable)", 60, notes

    # ---------- Raspberry Pi
    if "raspberry" in vend:
        return "Raspberry Pi", 95, notes

    # ---------- imprimante
    if apset & {9100, 631, 515}:
        return "Imprimante / serveur d'impression", 85, notes

    # ---------- TV / clés multimédia
    if apset & {8008, 8009}:
        if "chromecast" in host:
            return "Chromecast", 90, notes
        return "Clé HDMI / Google Cast (probable)", 75, notes
    if "roku" in vend or 9060 in apset:
        return "Box TV (Roku)", 85, notes
    if apset & {8001, 8002}:
        return "TV connectée (LG / Samsung)", 80, notes

    # ---------- caméra
    if 554 in apset:
        return "Caméra IP / NVR", 80, notes

    # ---------- NAS
    if apset & {5000, 5001, 9000}:
        return "NAS", 80, notes
    if apset & {445, 139} and "linux" in osl:
        return "Serveur / NAS Linux (Samba)", 70, notes

    # ---------- PC Windows
    if "windows" in osl:
        return "PC Windows", 85, notes
    if apset & {135, 3389}:
        return "PC Windows (RPC / RDP)", 75, notes

    # ---------- smartphones Android génériques
    if any(k in vend for k in (
            "xiaomi", "huawei", "honor", "oppo", "realme", "oneplus",
            "vivo", "motorola", "alcatel")):
        return "Smartphone / tablette Android (probable)", 70, notes

    # ---------- indices de nom d'hôte
    HOST_KEYWORDS = (
        ("iphone", "iPhone"), ("ipad", "iPad"),
        ("galaxy", "Smartphone Samsung"), ("pixel", "Smartphone Google"),
        ("android", "Smartphone Android"), ("chromecast", "Chromecast"),
        ("nest", "Enceinte / hub Google"), ("echo", "Enceinte Amazon"),
        ("syno", "NAS"), ("nas", "NAS"), ("printer", "Imprimante"),
        ("shelly", "Objet domotique (Shelly)"), ("esp-", "Objet domotique (ESP)"),
        ("hue", "Pont Hue / domotique"), ("tv", "TV / appareil multimédia"),
    )
    for kw, label in HOST_KEYWORDS:
        if kw in host:
            notes.append(f"hostname contient « {kw} »")
            return label, 80, notes

    return "À identifier (pas assez d'indices)", 15, notes


def enrich_device(ip, mac, vendor, port_entries, os_guess, enrich_cfg=None):
    """Construit le « dossier » d'un appareil (hostname, TTL, OS, type...)."""
    enrich_cfg = enrich_cfg or {}
    if not enrich_cfg.get("enabled", True):
        return {}
    host = reverse_dns(ip) if enrich_cfg.get("reverse_dns", True) else ""
    ttl = ping_ttl(ip) if enrich_cfg.get("ping_ttl", True) else None
    server = ""
    for port, _svc, _ver in port_entries:
        if int(port) in (80, 8080):
            server = http_banner(ip, int(port))
            if server:
                break
    ptype, conf, notes = classify_device(
        ip, gateway_ip() if enrich_cfg.get("compare_gateway", True) else "",
        vendor, host, port_entries, os_guess,
    )
    if server:
        notes.append(f"bannière HTTP : {server}")
    rec = {
        "hostname": host,
        "ttl": ttl,
        "os_family": ttl_os_family(ttl) if ttl else "",
        "type": ptype,
        "confidence": conf,
        "notes": notes,
    }
    if os_guess:
        rec["os"] = os_guess
    if server:
        rec["banner"] = server
    return rec




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


def send_telegram_document(config, path, caption=""):
    """Envoie un fichier au chat (multipart/form-data, stdlib uniquement)."""
    t = config.get("telegram", {})
    if not t.get("bot_token") or not t.get("chat_id"):
        print("[i] Telegram non configuré — document non envoyé :", path)
        return False
    boundary = f"----netmon{uuid.uuid4().hex}"
    parts = []
    for key, value in (("chat_id", t["chat_id"]), ("caption", caption)):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f"name=\"{key}\"\r\n\r\n{value}\r\n".encode()
        )
    mime = "text/csv" if path.suffix == ".csv" else "application/json"
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; "
        f"filename=\"{path.name}\"\r\nContent-Type: {mime}\r\n\r\n".encode()
    )
    parts.append(path.read_bytes() + f"\r\n--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{t['bot_token']}/sendDocument",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return bool(result.get("ok"))
    except Exception as exc:
        print(f"[!] Envoi document Telegram : {exc}")
        return False


def export_devices_csv(path):
    """Baseline + dossiers enrichis → tableau CSV lisible."""
    devices = load_baseline()
    aliases = load_aliases()
    ports_base = load_ports_base()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["mac", "ip", "alias", "fabricant", "hostname", "type",
                         "confiance", "os", "premier_contact",
                         "dernier_apercu", "vus", "ports"])
        for mac, rec in devices.items():
            writer.writerow([
                mac, rec.get("ip", ""), aliases.get(mac, ""),
                rec.get("vendor", ""), rec.get("hostname", ""),
                rec.get("type", ""), rec.get("confidence", ""),
                rec.get("os_family", "") or rec.get("os", ""),
                rec.get("first_seen", ""), rec.get("last_seen", ""),
                rec.get("seen", ""),
                "; ".join(ports_base.get(mac, {}).get("ports", [])),
            ])
    return path


def export_devices_json(path):
    """« Dossier complet » JSON : baseline + alias + baseline ports."""
    payload = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "aliases": load_aliases(),
        "ports": load_ports_base(),
        "devices": load_baseline(),
    }
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path


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
    typ = info.get("type", "")
    extra = f" · {typ}" if typ else ""
    line = f"📱 <code>{mac}</code> @ <code>{info['ip']}</code> ({vendor}){extra}"
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
                dossier = enrich_device(
                    ip, mac, info.get("vendor", ""), entries, os_guess,
                    config.get("enrich", {}),
                )
                baseline.setdefault(mac, {}).update(dossier)
                device_record = {
                    "mac": mac,
                    "ip": ip,
                    "vendor": info.get("vendor", ""),
                    "ports": [f"{p}/tcp {s}" for p, s, _ in entries[:15]],
                    "os": os_guess,
                    **dossier,
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

        else:
            # Scan de ports désactivé : dossier léger (rDNS, TTL, classification)
            for mac, info in new_devices.items():
                dossier = enrich_device(
                    info["ip"], mac, info.get("vendor", ""), [], "",
                    config.get("enrich", {}),
                )
                baseline.setdefault(mac, {}).update(dossier)

    # IDS : pulse périodique sur les appareils CONNUS, même sans nouveaux
    # (diff des ports + rafraîchissement du dossier d'identité)
    if ids_cfg.get("watch_known", True):
        every = max(int(ids_cfg.get("rescan_every", 2)), 1)
        if SCAN_CYCLE % every == 1:
            args_known = ids_cfg.get(
                "known_scan_args", ["-sT", "--top-ports", "100"]
            )
            timeout = int(ids_cfg.get("timeout_sec", 120))
            ports_base = load_ports_base()
            for mac, info in current.items():
                if mac not in baseline:  # nouveaux : déjà traités ci-dessus
                    continue
                ip_known = info["ip"]
                print(f"  [*] IDS pulse sur {ip_known} ...")
                entries_k, os_k = port_scan(ip_known, args_known, timeout)
                if not entries_k:
                    continue  # scan vide (éteint/bloqué) : on ne casse pas la base
                prior = ports_base.get(mac, {}).get("ports", [])
                ports_now = ids_check_ports(
                    config, ip_known, mac, entries_k, prior, ids_events
                )
                ports_base[mac] = {"ts": history_entry["ts"], "ports": ports_now}
                save_ports_base(ports_base)
                # le dossier d'identité se rafraîchit au même rythme
                baseline.setdefault(mac, {}).update(
                    enrich_device(
                        ip_known, mac, info.get("vendor", ""), entries_k, os_k,
                        config.get("enrich", {}),
                    )
                )

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

    # Suivi de présence : first_seen / last_seen / compteur, sans écraser
    # les dossiers enrichis déjà enregistrés.
    now_ts = history_entry["ts"]
    for mac, info in current.items():
        rec = baseline.setdefault(mac, {})
        rec["ip"] = info["ip"]
        rec["vendor"] = info.get("vendor", "") or rec.get("vendor", "")
        rec.setdefault("first_seen", now_ts)
        rec["last_seen"] = now_ts
        rec["seen"] = int(rec.get("seen", 0)) + 1
        rec.setdefault("ports", [])
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
            "/events — dernières alertes IDS\n"
            "/info <ip> — dossier détaillé d'un appareil 🕵️\n"
            "/export — récupérer la base en document (csv ou json)"
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
            typ = f" · {html.escape(str(info['type']))}" if info.get("type") else ""
            last_seen = info.get("last_seen", "")
            last = f" ({html.escape(last_seen)})" if last_seen else ""
            lines.append(f"• <code>{ip}</code> {vendor}{typ}{tag}{last}")
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
    elif cmd == "/info":
        parts = text.split()
        if len(parts) < 2:
            send_telegram(config, "💡 Usage : /info <ip_ou_mac>")
            return
        target = parts[1]
        devices = load_baseline()
        mac = next(
            (m for m in devices
             if devices[m].get("ip") == target or m == target.upper()),
            None,
        )
        if not mac:
            send_telegram(config,
                          f"🤔 {html.escape(target)} inconnu — regarde /devices")
            return
        rec = devices[mac]
        alias = alias_of(mac)
        ports_base = load_ports_base().get(mac, {}).get("ports", [])
        lines = [
            f"🕵️ <b>Dossier : {html.escape(rec.get('ip', '?'))}</b>",
            f"• MAC : <code>{mac}</code>",
        ]
        if alias:
            lines.append(f"• 👤 Alias : <b>{html.escape(alias)}</b>")
        if rec.get("vendor"):
            lines.append(f"• Fabricant : {html.escape(rec['vendor'])}")
        if rec.get("hostname"):
            lines.append(f"• Hostname : {html.escape(rec['hostname'])}")
        if rec.get("type"):
            lines.append(
                f"• Type : <b>{html.escape(str(rec['type']))}</b>"
                f" (confiance {rec.get('confidence', '?')}%)"
            )
        if rec.get("os_family"):
            lines.append(f"• OS : {html.escape(rec['os_family'])}")
        if rec.get("os"):
            lines.append(f"• OS nmap : {html.escape(rec['os'])}")
        if rec.get("banner"):
            lines.append(f"• Bannière HTTP : {html.escape(str(rec['banner']))}")
        if rec.get("first_seen"):
            lines.append(
                f"• 1er contact : {html.escape(str(rec['first_seen']))} · dernier : "
                f"{html.escape(str(rec.get('last_seen', '')))} · vu "
                f"{rec.get('seen', '?')} fois"
            )
        if ports_base:
            lines.append("• Ports ouverts : " +
                         html.escape(" , ".join(ports_base[:10])))
        for note in rec.get("notes", [])[:5]:
            lines.append(f"   ℹ️ {html.escape(str(note))}")
        send_telegram(config, "\n".join(lines))
    elif cmd == "/export":
        kind = "json" if "json" in text.lower() else "csv"
        EXPORT_DIR.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = EXPORT_DIR / f"netmon_{stamp}.{kind}"
        if kind == "json":
            export_devices_json(path)
        else:
            export_devices_csv(path)
        ok = send_telegram_document(config, path, caption="📦 Export netmon v4")
        if not ok:
            send_telegram(config, f"📄 Export écrit ici : {path}")
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
  <tr><th>Alias</th><th>Type</th><th>Fabricant</th><th>IP</th><th>Hostname</th>
      <th>OS</th><th>Dernier aperçu</th></tr>
</table>
</div>

<div class="card">
<h2>📈 Appareils en ligne par scan</h2>
<canvas id="chart" width="640" height="180" style="width:100%"></canvas>
</div>

<div class="card">
<h2>📜 Historique des scans</h2>
<table id="history">
  <tr><th>Quand</th><th>En ligne</th><th>Nouveaux</th><th>Détails</th></tr>
</table>
</div>

<p class="muted">API : <a href="/api/state">/api/state</a> ·
<a href="/api/export">📦 export CSV</a> ·
<a href="/api/export?kind=json">📦 export JSON</a></p>

<script>
const table = (id, rowsHtml) => { document.getElementById(id)
  .insertAdjacentHTML("beforeend", rowsHtml); };

fetch("/api/state").then(r => r.json()).then(state => {
  const devRows = Object.entries(state.devices).map(([mac, d]) =>
    `<tr><td><strong>${d.alias || "&mdash;"}</strong></td>
     <td>${d.type || "?"}${d.confidence ? ` <span class="badge">${d.confidence}%</span>` : ""}</td>
     <td>${d.vendor || "?"}</td>
     <td><code>${d.ip}</code></td>
     <td>${d.hostname || ""}</td>
     <td class="os">${d.os_family || d.os || ""}</td>
     <td class="muted">${d.last_seen || ""}</td></tr>`
  ).join("");
  table("devices", devRows);

  // 📈 graphique de présence : nb d'appareils par scan (60 derniers)
  const pts = state.history.slice(0, 60).reverse();
  const cvs = document.getElementById("chart");
  const ctx = cvs.getContext("2d");
  ctx.fillStyle = "#0d1117";
  ctx.fillRect(0, 0, cvs.width, cvs.height);
  ctx.strokeStyle = "#58a6ff";
  ctx.lineWidth = 2;
  ctx.beginPath();
  const maxY = Math.max(1, ...pts.map(h => h.online || 0));
  pts.forEach((h, i) => {
    const x = 10 + i * (cvs.width - 20) / Math.max(pts.length - 1, 1);
    const y = cvs.height - 15 - (h.online || 0) * (cvs.height - 30) / maxY;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();

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
            aliases = load_aliases()
            devices = {
                mac: {**rec, "alias": aliases.get(mac, "")}
                for mac, rec in load_baseline().items()
            }
            state = {"devices": devices, "history": load_history()}
            body = json.dumps(state, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/export"):
            kind = "json" if "kind=json" in self.path else "csv"
            EXPORT_DIR.mkdir(exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            if kind == "json":
                path = EXPORT_DIR / f"netmon_{stamp}.json"
                ctype = "application/json"
                export_devices_json(path)
            else:
                path = EXPORT_DIR / f"netmon_{stamp}.csv"
                ctype = "text/csv; charset=utf-8"
                export_devices_csv(path)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header(
                "Content-Disposition", f'attachment; filename="{path.name}"'
            )
            self.end_headers()
            self.wfile.write(path.read_bytes())
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
