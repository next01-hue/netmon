# netmon 🛡️📡

**Monitoring réseau personnel avec alertes Telegram — conçu pour Termux (Android).**

netmon scanne ton réseau local, mémorise les appareils connus (baseline) et te prévient
sur Telegram dès qu'un **nouvel appareil** se connecte (nouveau smartphone, voisin sur
tx Wi-Fi, box piratée...). Idéal pour surveiller son réseau domestique.

- ✅ Python pur (stdlib) — **aucun `pip install` nécessaire**
- ✅ Alertes Telegram (API officielle)
- ✅ Baseline persistante dans `devices.json`
- ✅ Mode daemon : scan automatique toutes les X secondes

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

| Commande | Effet |
|---|---|
| `/help` | liste des commandes |
| `/status` | heure du dernier scan + nombre d'appareils en ligne |
| `/scan` | déclenche un scan immédiat (+ alertes habituelles) |
| `/devices` | liste des appareils connus (baseline) + leurs alias |
| `/name <ip> <nom>` | renomme un appareil (ex: `/name 192.168.1.42 TV salon`) — enregistré dans `aliases.json` |
| `/unknown` | appareils détectés lors du dernier scan |
| `/recent` | les 5 derniers scans |

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
- [ ] Notification avec capture d'écran / image du scan
- [ ] Interface web légère (Flask) consultable depuis le téléphone
- [ ] Export CSV / graphique de présence des appareils
- [ ] Reconnaissance OS des nouveaux hôtes

---
Projet éducatif — apprendre la cybersécurité défensive sur mobile. 🐍
