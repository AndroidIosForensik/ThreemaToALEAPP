**Deutsch** | [English](README.md)

# ThreemaToALEAPP

Wandelt eine **Threema-Datensicherung** (`threema-backup_<Zeitstempel>_1.zip`, passwortgeschützt) in eine Pseudo-Extraktion um, die [ALEAPP](https://github.com/abrignoni/ALEAPP) mit seinem Threema-Parser (`scripts/artifacts/Threema.py`) direkt einlesen kann.

Damit lassen sich Threema-Chats auswerten, auch wenn kein Dateisystem-Abbild des Android-Geräts vorliegt, sondern nur die in der App erstellte Datensicherung.

> **Hinweis:** Die erzeugte `threema4.db` ist eine **Rekonstruktion** aus dem Backup und keine Originaldatei vom Gerät. Das ist im Bericht und in der Datenbank selbst (Tabelle `backup_conversion_info`) dokumentiert.

---

## Download

Die fertige Windows-Version (keine Python-Installation nötig) gibt es unter **[Releases](../../releases/latest)**:

- `ThreemaBackup_zu_ALEAPP.exe` – Doppelklick genügt, es öffnet sich ein Fenster.

## Bedienung

### Mit Fenster (Standard)

1. `ThreemaBackup_zu_ALEAPP.exe` starten (oder `python threema_backup_zu_aleapp.py`).
2. Threema-Backup-ZIP wählen.
3. Passwort der Datensicherung eingeben.
4. Ausgabeordner wählen (leer = `ALEAPP_Threema_Export` neben dem Backup).
5. **Konvertieren für ALEAPP** klicken.

### Kommandozeile

```bash
python threema_backup_zu_aleapp.py threema-backup_1790790557634_1.zip "Passwort" C:\Auswertung\Threema
```

oder mit benannten Parametern:

```bash
python threema_backup_zu_aleapp.py threema-backup_1790790557634_1.zip --passwort "Passwort" --out C:\Auswertung\Threema
```

| Parameter | Bedeutung |
|---|---|
| `backup` | Pfad zur Threema-Backup-ZIP |
| `passwort` / `--passwort` / `--password` | Passwort der Datensicherung |
| `ausgabe` / `--out` | Ausgabeordner |
| `--nogui` | kein Fenster; fehlende Angaben werden in der Konsole abgefragt (Passwort unsichtbar) |

Alternativ können `PASSWORT`, `BACKUP_DATEI` und `AUSGABE_ORDNER` oben im Skript eingetragen werden.

### In ALEAPP

ALEAPP starten, als Eingabe `ALEAPP_Threema.zip` wählen (Typ **zip**) und den Threema-Parser ausführen. ALEAPP benötigt dafür das Python-Paket `sqlcipher3`.

## Ausgabe

```
<Ausgabeordner>/
├── ALEAPP_Threema.zip                ← Eingabe für ALEAPP
│   └── data/data/ch.threema.app/
│       ├── databases/threema4.db                         (SQLCipher 4, wie auf dem Gerät)
│       ├── files/key.dat                                 (Schlüsseldatei, Version 1, ohne Passphrase)
│       └── shared_prefs/ch.threema.app_preferences.xml   (eigene Threema-ID)
├── backup_entschluesselt/            ← alle Dateien des Backups im Klartext (CSVs, Medien, Avatare)
├── medien/                           ← Mediendateien mit erkannter Endung, nach Chat sortiert
└── report.txt                        ← Konvertierungsbericht mit SHA-256-Hashwerten und Statistik
```

## Was wird übernommen?

| Inhalt | in `threema4.db` | von ALEAPP angezeigt |
|---|---|---|
| Eigene Threema-ID und Public Key | ✔ | ✔ (Account) |
| Kontakte | ✔ | ✔ |
| Einzelchats | ✔ | ✔ |
| Gruppen und Gruppennachrichten | ✔ (`m_group`, `m_group_message`) | ✘ (Stand Sept. 2026) |
| Verteilerlisten und Nachrichten | ✔ (`distribution_list*`) | ✘ |
| Emoji-Reaktionen | ✔ (`*_emoji_reaction`) | ✘ |
| Medien, Thumbnails, Avatare | – | ✘ → liegen unter `medien/` |

Was ALEAPP nicht anzeigt, steht trotzdem in der Datenbank und im Klartext unter `backup_entschluesselt/`.

## Technischer Hintergrund

- **Backup-ZIP:** WinZip-AES (AE-1/AE-2, PBKDF2-SHA1) bzw. ZipCrypto wird selbst entschlüsselt, inklusive HMAC-Prüfung jedes Eintrags.
- **ID-Backup (`identity`):** Base32 → PBKDF2-SHA256 (100 000 Iterationen) → XSalsa20; daraus werden Threema-ID und Public Key abgeleitet. Der **private Schlüssel wird nicht exportiert**.
- **Datenbank:** Schema mit Tabellen und Spalten wie in Threema-Android (`ch.threema.storage.factories`). Die Datenbank wird wie von Threema verschlüsselt: SQLCipher 4, Passphrase als String `x"<hex>"`, `kdf_iter = 1`, HMAC-SHA512, 4096-Byte-Seiten. Nach der Verschlüsselung wird jede Seite gegengeprüft.
- **key.dat:** Version 1 ohne Passphrase (XOR-Maske + SHA-1-Prüfsumme), so wie ALEAPP sie erwartet. Der Datenbankschlüssel wird bei jedem Lauf zufällig neu erzeugt.

## Forensische Hinweise

- `threema4.db` ist eine Rekonstruktion, keine Gerätedatei. Der Schlüssel in `key.dat` ist nicht der des Originalgeräts.
- Die Hashwerte von Quelle, ALEAPP-ZIP, Datenbank und allen Mediendateien stehen in `report.txt`.
- Nicht im Backup enthalten (und daher auch nicht in der Ausgabe): Datum „Date Added“ der Kontakte, Nickname und Telefonnummer des Kontoinhabers sowie Nachrichten, die vor der Sicherung gelöscht wurden.
- Der Backup-Zeitpunkt wird aus dem Dateinamen gelesen und in der lokalen Zeit des auswertenden Rechners angegeben.

## Aus dem Quellcode ausführen / selbst bauen

Voraussetzung: Python 3.9 oder neuer.

```bash
pip install -r requirements.txt
```

```bash
python threema_backup_zu_aleapp.py
```

Eigene Windows-Exe bauen:

```bash
pip install pyinstaller
```

```bash
pyinstaller --onefile --name ThreemaBackup_zu_ALEAPP threema_backup_zu_aleapp.py
```

Die Exe liegt danach unter `dist/`.

## Lizenz

[MIT](LICENSE) – das Tool darf frei verwendet, verändert und weitergegeben werden (auch dienstlich und kommerziell), solange der Lizenzhinweis erhalten bleibt. Nutzung ohne Gewähr.
