#!/data/data/com.termux/files/usr/bin/bash
# install.sh — installation de netmon sous Termux
# Utilisation : bash install.sh

set -e

echo "[*] Mise à jour des paquets..."
pkg update -y && pkg upgrade -y

echo "[*] Installation des dépendances (python, nmap, git)..."
pkg install -y python nmap git

echo "[*] Copie de la configuration..."
if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "[i] config.json créé — ouvre-le et renseigne Telegram + ton réseau."
fi

chmod +x netmon.py

echo ""
echo "✅ Installation terminée !"
echo "   1) Configure Telegram :  nano config.json"
echo "   2) Message de test    :  python3 netmon.py --test-telegram"
echo "   3) Reference de départ:  python3 netmon.py --baseline"
echo "   4) Surveille en boucle:  python3 netmon.py --daemon"
