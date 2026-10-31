# netmon 🛡️📡

**Monitoring réseau personnel avec alertes Telegram — conçu pour Termux (Android).**

netmon scanne ton réseau local, mémorise les appareils connus (baseline) et te prévient
sur Telegram dès qu'un **nouvel appareil** se connecte (nouveau smartphone, voisin sur
tx Wi-Fi, box piratée...). Idéal pour surveiller son réseau domestique.

- ✅ Python pur (stdlib) — **aucun `pip install` nécessaire**
- ✅ Alertes Telegram (API officielle)
- ✅ Baseline persistante dans `devices.json`
- ✅ Mode daemon : scan automatique toutes les X secondes
- ✅ (v4) Dossier enrichi par appareil + graphique de présence + export CSV/JSON

---

## ⚠️ Éthique & légal

Ce projet est prévu pour surveiller **ton propre réseau** (chez toi).
Scanner un réseau sans autorisation explicite est illégal dans la plupart des pays.
Utilise-le comme outil de défense (blue team), pas d'intrusion.

---

## 📲 Installation sous Termux

```bash
pkg update -y
pkg install -y git nmap python
git clone <ton-repo> netmon && cd netmon
bash install.sh
```

## 🔑 Configuration Telegram (5 minutes)

1. Sur Telegram, cherche **@BotFather** → `/newbot` → choisis un nom → tu reçois un
   **token** (`123456:ABC-DEF...`).
2. Envoie un message quelconque à ton nouveau bot (il ne peut pas t'écrire en premier).
3. Ouvre `https://api.telegram.org/bot<TOKEN>/getUpdates` dans ton navigateur
   → dans le JSON, récupère `"chat":{"id": 123456789}` (ton **chat_id**).
4. Édite `config.json` :

```json
{
  "network": "192.168.1.0/24",
  "interval_sec": 300,
  "notify_vanished": false,
  "telegram": {
    "bot_token": "123456:ABC-DEF...",
    "chat_id": "123456789"
  }
}
```

> 💡 Ton réseau : tape `ip route` dans Termux, la ligne `default via ...` indique
> ta passerelle ; le masque est souvent `/24` (192.168.1.0/24 ou 192.168.0.0/24).

- `[args]` : les options passées à nmap. `--top-ports 100` = les 100 ports les plus
  courants, avec détection de service/version (`-sV`). Pour plus de précision :
  `["-sV", "-p", "1-65535"]` (scan complet, beaucoup plus long).

## 🚀 Utilisation

```bash
python3 netmon.py --test-telegram   # vérifier la connexion Telegram
python3 netmon.py --baseline        # enregistrer tes appareils actuels comme norme
python3 netmon.py --scan            # scan unique + diff par rapport à la baseline
python3 netmon.py --daemon          # surveillance continue
python3 netmon.py --bot             # daemon + télécommande par messages Telegram
```

## 🤖 Contrôle à distance par Telegram (`--bot`)

Le mode bot lance les scans automatiques **et** traite tes messages — ton outil se pilote donc entièrement depuis Telegram, même à des kilomètres :

## 🛡️ Détections IDS intégrées (v3)

Au-delà des **nouveaux appareils**, netmon surveille les comportements anormaux :

| Détection | Ligne d'alerte | Ce que ça dévoie |
|---|---|---|
| Appareil inconnu | 🚨 **Nouveau appareil** | intrus (voisin, attaqu physique...) |
| Nouveau **port ouvert** sur un appareil connu | 🟠 **WARN — nouveau port** | logiciel hébergé suspect installé |
| **Port suspect** ouvert (telnet 23, SMB 445, RDP 3389, ADB 5555…) | 🔴 **CRIT — port suspect** | service dangereux exposé |
| MAC de la **passerelle a changé** | 🔴 **CRIT — ARP-spoofing possible ?** | un pirate se fait passer pour ta box (MITM) |

- Les alertes sont aussi dans `history.jsonl` (champ `ids`) et consultables via `/events`.
- La baseline des ports viv dans `ports.json` (diff automatique à chaque pulse).
- Configurable dans la section `ids` du `config.json` (désactiver casuellement `watch_known`,
  ajouter des ports suspects, fixer `rescan_every` : 1 = pulse à chaque cycle, 3 = un cycle sur trois).

**Limiter les faux positifs** : après un changement légitime (mise à jour de la box, service que tu installes toi-même), les alertes `/events` te préviennent à tort. La méthode pro : tu **vérifies** que l'événement est bénin puis tu effaces la baseline concernée (`rm ports.json` → le prochain scan la recrée) — c'est le classique cycle IDS « alerte → investigation → triage ». Réseau calme = pas d'events ; un changement inexplicable = une vraie piste d'intrusion.

## 🕵️ Dossiers enrichis (v4)

Chaque appareil obtient un vrai dossier d'identité dans `devices.json` :

| Info | Comment ça s'obtient |
|---|---|
| **Hostname** | reverse DNS de l'IP |
| **OS (TTL)** | 1 ping ICMP : TTL 128 → Windows, 64 → Linux/Android/macOS, 255 → équipement réseau |
| **Bannière HTTP** | entêtes `Server` / auth des ports 80/8080 (révèle souvent le modèle exact de la TV/box !) |
| **Type** | heuristique fabricant + ports + hostname : Box/routeur, TV, Chromecast, Apple TV, iPhone, imprimante, NAS, caméra IP, PC Windows, Raspberry Pi, domotique… avec un **% de confiance** |
| **Présence** | `first_seen` (1er contact), `last_seen`, compteur de scans où il était là |

Le tout configurable dans `config.json` :

```json
"enrich": {
  "enabled": true,
  "reverse_dns": true,
  "ping_ttl": true,
  "compare_gateway": true
}
```

> Remarque : le « pulse » IDS périodique tourne désormais sur **tous** les appareils
> connus (pas seulement quand un inconnu apparaît) — ports **et** dossier se
> rafraîchissent au rythme de `rescan_every`.

| Commande | Effet |
|---|---|
| `/info <ip>` | dossier complet d'un appareil : fabricant, hostname, type (confiance), OS, ports, bannière HTTP, 1er/dernier contact |
| `/export` | reçois `devices` en **CSV** ; `/export json` pour le dossier complet en JSON |
| `/events` | dernières alertes IDS |

| Commande | Effet |
|---|---|
| `/help` | liste des commandes |
| `/status` | heure du dernier scan + nombre d'appareils en ligne |
| `/scan` | déclenche un scan immédiat (+ alertes habituelles) |
| `/devices` | liste des appareils connus (baseline) + leurs alias |
| `/name <ip> <nom>` | renomme un appareil (ex: `/name 192.168.1.42 TV salon`) — enregistré dans `aliases.json` |
| `/unknown` | appareils détectés lors du dernier scan |
| `/recent` | les 5 derniers scans |
| `/events` | dernières alertes IDS |
| `/info <ip>` | dossier détaillé d'un appareil 🕵️ (v4) |
| `/export` | base envoyée en document : CSV (`/export`) ou JSON (`/export json`) (v4) |

🛡️ Sécurité intégrée : **seul le chat configuré** (`chat_id` du `config.json`) obtient une réponse — les autres sont ignorés.

Résultat sur Telegram quand un inconnu apparaît :

```
🚨 Nouveaux appareils sur le réseau
📱 3C:5A:B4:XX:XX:XX @ 192.168.1.42 (Xiaomi Communications)

🔍 192.168.1.42 — 3 port(s) ouvert(s)
   • 22/tcp ssh (OpenSSH 8.2)
   • 80/tcp http (nginx 1.18.0)
   • 443/tcp https
```

## ⏰ Lancer au démarrage (Termux:Boot)

1. Installe l'app **Termux:Boot** (F-Droid) et ouvre-la une fois.
2. Puis :

```bash
pkg install termux-services
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/netmon.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd ~/netmon && python3 netmon.py --daemon >> log.txt 2>&1 &
EOF
chmod +x ~/.termux/boot/netmon.sh
```

## 🧠 Idées d'évolution (pour aller plus loin)

- [x] Scan de ports sur les nouveaux appareils (`nmap -sV`) ✅
- [x] Dossiers enrichis : hostname, TTL OS, bannière HTTP, classification ✅ (v4)
- [x] Export CSV / JSON + graphique de présence dans le dashboard ✅ (v4)
- [ ] Notification avec capture d'écran / image du scan
- [ ] Alertes automatiques Telegram sur changement sans ta commande (déjà actif en mode daemon/bot via les scans périodiques 🎉)

---
Projet éducatif — apprendre la cybersécurité défensive sur mobile. 🐍
