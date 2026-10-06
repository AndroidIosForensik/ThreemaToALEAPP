**English** | [Deutsch](README.de.md)

# ThreemaToALEAPP

Converts a **Threema data backup** (`threema-backup_<timestamp>_1.zip`, password protected) into a pseudo extraction that [ALEAPP](https://github.com/abrignoni/ALEAPP) can read directly with its Threema parser (`scripts/artifacts/Threema.py`).

This lets you analyse Threema chats even when no file system image of the Android device is available, only the backup created inside the app.

> **Note:** The generated `threema4.db` is a **reconstruction** from the backup, not an original file from the device. This is documented in the report and in the database itself (table `backup_conversion_info`).

> The user interface, log messages and output folder names of the tool are in German.

---

## Download

A ready-to-use Windows build (no Python installation required) is available under **[Releases](../../releases/latest)**:

- `ThreemaBackup_zu_ALEAPP.exe` – just double-click it and a window opens.

## Usage

### With the window (default)

1. Start `ThreemaBackup_zu_ALEAPP.exe` (or `python threema_backup_zu_aleapp.py`).
2. Select the Threema backup ZIP (*Threema-Backup (ZIP)*).
3. Enter the backup password (*Passwort*).
4. Select an output folder (*Ausgabeordner*; empty = `ALEAPP_Threema_Export` next to the backup).
5. Click **Konvertieren für ALEAPP** (convert for ALEAPP).

### Command line

```bash
python threema_backup_zu_aleapp.py threema-backup_1790790557634_1.zip "password" C:\Cases\Threema
```

or with named parameters:

```bash
python threema_backup_zu_aleapp.py threema-backup_1790790557634_1.zip --password "password" --out C:\Cases\Threema
```

| Parameter | Meaning |
|---|---|
| `backup` | Path to the Threema backup ZIP |
| `passwort` / `--password` / `--passwort` | Backup password |
| `ausgabe` / `--out` | Output folder |
| `--nogui` | No window; missing values are prompted in the console (password hidden) |

Alternatively, `PASSWORT`, `BACKUP_DATEI` and `AUSGABE_ORDNER` can be filled in at the top of the script.

### In ALEAPP

Start ALEAPP, select `ALEAPP_Threema.zip` as input (type **zip**) and run the Threema parser. ALEAPP needs the Python package `sqlcipher3` for this.

## Output

```
<output folder>/
├── ALEAPP_Threema.zip                ← input for ALEAPP
│   └── data/data/ch.threema.app/
│       ├── databases/threema4.db                         (SQLCipher 4, as on the device)
│       ├── files/key.dat                                 (key file, version 1, no passphrase)
│       └── shared_prefs/ch.threema.app_preferences.xml   (own Threema ID)
├── backup_entschluesselt/            ← all backup files in plain text (CSVs, media, avatars)
├── medien/                           ← media files with detected extension, sorted by chat
└── report.txt                        ← conversion report with SHA-256 hashes and statistics
```

## What is converted?

| Content | in `threema4.db` | shown by ALEAPP |
|---|---|---|
| Own Threema ID and public key | ✔ | ✔ (account) |
| Contacts | ✔ | ✔ |
| One-to-one chats | ✔ | ✔ |
| Groups and group messages | ✔ (`m_group`, `m_group_message`) | ✘ (as of Sept. 2026) |
| Distribution lists and messages | ✔ (`distribution_list*`) | ✘ |
| Emoji reactions | ✔ (`*_emoji_reaction`) | ✘ |
| Media, thumbnails, avatars | – | ✘ → stored under `medien/` |

Anything ALEAPP does not display is still in the database and in plain text under `backup_entschluesselt/`.

## Technical background

- **Backup ZIP:** WinZip AES (AE-1/AE-2, PBKDF2-SHA1) or ZipCrypto is decrypted by the tool itself, including the HMAC check of every entry.
- **ID backup (`identity`):** Base32 → PBKDF2-SHA256 (100,000 iterations) → XSalsa20; the Threema ID and public key are derived from it. The **private key is not exported**.
- **Database:** schema with tables and columns as in Threema Android (`ch.threema.storage.factories`). The database is encrypted the same way Threema does it: SQLCipher 4, passphrase as the string `x"<hex>"`, `kdf_iter = 1`, HMAC-SHA512, 4096-byte pages. Every page is verified after encryption.
- **key.dat:** version 1 without passphrase (XOR mask + SHA-1 checksum), as expected by ALEAPP. The database key is randomly generated on every run.

## Forensic notes

- `threema4.db` is a reconstruction, not a device file. The key in `key.dat` is not the one from the original device.
- Hashes of the source, the ALEAPP ZIP, the database and all media files are listed in `report.txt`.
- Not contained in the backup (and therefore not in the output): the contacts' "Date Added", the account owner's nickname and phone number, and messages deleted before the backup was made.
- The backup time is taken from the file name and shown in the local time of the analysing computer.

## Run from source / build it yourself

Requirement: Python 3.9 or newer.

```bash
pip install -r requirements.txt
```

```bash
python threema_backup_zu_aleapp.py
```

Build your own Windows exe:

```bash
pip install pyinstaller
```

```bash
pyinstaller --onefile --name ThreemaBackup_zu_ALEAPP threema_backup_zu_aleapp.py
```

The exe is then located in `dist/`.

## License

[MIT](LICENSE) – the tool may be freely used, modified and redistributed (including for official and commercial purposes) as long as the license notice is retained. Provided without warranty.
