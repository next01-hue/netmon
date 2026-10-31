#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests unitaires v4 — 100 % offline : TLS/TTL, classification, OUI, export
(zéro réseau, zéro Telegram). Lance :  python3 test_netmon.py"""

import tempfile
import unittest
from pathlib import Path

import netmon


class IsolateFiles(unittest.TestCase):
    """Les tests écrivent dans un dossier temporaire, jamais dans le repo."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        tmp = Path(self.tmp.name)
        netmon.BASELINE_FILE = tmp / "devices.json"
        netmon.ALIAS_FILE = tmp / "aliases.json"
        netmon.PORTS_FILE = tmp / "ports.json"
        netmon.HISTORY_FILE = tmp / "history.jsonl"
        netmon.GWSTATE_FILE = tmp / "gw.json"
        netmon.EXPORT_DIR = tmp / "export"

    def tearDown(self):
        self.tmp.cleanup()


class TestTtlOs(unittest.TestCase):
    def test_windows(self):
        self.assertIn("Windows", netmon.ttl_os_family(128))

    def test_linux(self):
        self.assertIn("Linux", netmon.ttl_os_family(64))

    def test_reseau(self):
        self.assertIn("équipement réseau", netmon.ttl_os_family(255))

    def test_vide(self):
        self.assertEqual("", netmon.ttl_os_family(None))


class TestClassify(unittest.TestCase):
    def test_box_passerelle(self):
        t, c, _ = netmon.classify_device(
            "192.168.1.1", "192.168.1.1", "", "", [], "")
        self.assertEqual("Box / routeur", t)
        self.assertGreater(c, 90)

    def test_imprimante(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.9", "192.168.1.1", "", "",
            [("9100", "jetdirect", "")], "")
        self.assertIn("Imprimante", t)

    def test_apple_airplay(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.5", "192.168.1.1", "Apple Inc.", "",
            [("7000", "airtunes", "")], "")
        self.assertIn("Apple TV", t)

    def test_iphone(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.6", "192.168.1.1", "Apple Inc.", "",
            [("62078", "usbmuxd", "")], "")
        self.assertIn("iPhone", t)

    def test_chromecast_hostname(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.30", "192.168.1.1", "", "chromecast-salon-ab",
            [("8009", "cast", "")], "")
        self.assertEqual("Chromecast", t)

    def test_raspberry(self):
        t, c, _ = netmon.classify_device(
            "192.168.1.20", "192.168.1.1", "Raspberry Pi Trading", "", [], "")
        self.assertEqual("Raspberry Pi", t)
        self.assertGreater(c, 90)

    def test_pc_windows_via_rdp(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.40", "192.168.1.1", "", "", [("3389", "ms-wbt", "")], "")
        self.assertIn("Windows", t)

    def test_a_identifier(self):
        t, _, _ = netmon.classify_device(
            "192.168.1.66", "192.168.1.1", "", "", [], "")
        self.assertIn("À identifier", t)


class TestOui(unittest.TestCase):
    def test_repli_oui(self):
        self.assertEqual("Raspberry Pi",
                         netmon.vendor_of("B8:27:EB:11:22:33", ""))

    def test_nmap_prioritaire(self):
        self.assertEqual("Xiaomi Communications",
                         netmon.vendor_of("B8:27:EB:11:22:33",
                                          "Xiaomi Communications"))


class TestPresence(IsolateFiles):
    def test_premier_puis_deuxieme_scan(self):
        netmon.save_baseline({})
        ts1 = "2026-10-30 10:00:00"
        ts2 = "2026-10-30 10:05:00"
        # simule la boucle finale d'_scan_inner
        base = netmon.load_baseline()
        for ts in (ts1, ts2):
            rec = base.setdefault("AA:BB:CC:DD:EE:FF", {})
            rec["ip"] = "192.168.1.77"
            rec.setdefault("first_seen", ts)
            rec["last_seen"] = ts
            rec["seen"] = int(rec.get("seen", 0)) + 1
        netmon.save_baseline(base)
        rec = netmon.load_baseline()["AA:BB:CC:DD:EE:FF"]
        self.assertEqual(ts1, rec["first_seen"])
        self.assertEqual(ts2, rec["last_seen"])
        self.assertEqual(2, rec["seen"])


class TestExport(IsolateFiles):
    def test_csv_complet(self):
        netmon.save_baseline({
            "AA:11:22:33:44:55": {
                "ip": "192.168.1.7", "vendor": "Samsung", "type": "TV",
                "confidence": 80, "seen": 3, "hostname": "salon-tv",
                "first_seen": "2026-10-30 09:00:00",
                "last_seen": "2026-10-30 15:00:00",
            },
        })
        path = netmon.export_devices_csv(
            netmon.EXPORT_DIR / "netmon_test.csv")
        content = Path(path).read_text(encoding="utf-8")
        for attendu in ("192.168.1.7", "Samsung", "TV", "salon-tv"):
            self.assertIn(attendu, content)

    def test_json_complet(self):
        netmon.save_baseline({"AA:BB:CC:DD:EE:01": {"ip": "192.168.1.2"}})
        path = netmon.export_devices_json(
            netmon.EXPORT_DIR / "netmon_test.json")
        import json
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertIn("devices", data)
        self.assertIn("aliases", data)
        self.assertIn("ports", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
