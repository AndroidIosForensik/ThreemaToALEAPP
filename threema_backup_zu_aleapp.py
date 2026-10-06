#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
threema_backup_zu_aleapp.py
===========================
Wandelt ein Threema-Datensicherungs-Backup (threema-backup_<Zeit>_1.zip, passwortgeschützt)
in eine Pseudo-Extraktion um, die ALEAPP mit seinem Threema-Parser (scripts/artifacts/Threema.py)
einlesen kann:

    <Ausgabe>/ALEAPP_Threema.zip
        data/data/ch.threema.app/databases/threema4.db          (SQLCipher 4, wie auf dem Gerät)
        data/data/ch.threema.app/files/key.dat                  (Schlüsseldatei, ungeschützt, Version 1)
        data/data/ch.threema.app/shared_prefs/ch.threema.app_preferences.xml  (eigene Threema-ID)
    <Ausgabe>/backup_entschluesselt/   (alle Dateien des Backups im Klartext: CSVs, Medien, Avatare)
    <Ausgabe>/medien/                  (Mediendateien mit erkannter Endung und Originalnamen)
    <Ausgabe>/report.txt               (Hashwerte, Statistik, Mapping-Hinweise)

In ALEAPP dann: Input = ALEAPP_Threema.zip (Typ "zip"). ALEAPP benötigt dafür das Paket sqlcipher3.

Benötigt: Python 3.9+   ->   pip install cryptography
Start:    Doppelklick bzw.  python threema_backup_zu_aleapp.py        (öffnet ein Fenster)
          oder  python threema_backup_zu_aleapp.py <backup.zip> "<Passwort>" <Ausgabeordner>

WICHTIG: Die erzeugte threema4.db ist eine REKONSTRUKTION aus dem Backup, keine Originaldatei vom Gerät.
Der Datenbankschlüssel wird bei jedem Lauf zufällig neu erzeugt (steht verschleiert in key.dat).
"""

# =====================================================================================
#  HIER EINTRAGEN (optional). Leer lassen = das Programm fragt per Fenster nach.
# =====================================================================================
PASSWORT       = ""   # Passwort der Threema-Datensicherung
BACKUP_DATEI   = ""   # z.B. r"C:\Users\Max\Downloads\threema-backup_1790790557634_1.zip"
AUSGABE_ORDNER = ""   # leer = Ordner "ALEAPP_Threema_Export" neben dem Backup
# =====================================================================================

import argparse, base64, csv, datetime, getpass, hashlib, hmac, io, json, os, re, shutil, sqlite3
import struct, sys, tempfile, zipfile, zlib
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Fehlendes Paket. Bitte installieren:\n    pip install cryptography")
    sys.exit(1)

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

PKG = "ch.threema.app"
VERSION = "1.0 (2026-09-30)"
csv.field_size_limit(2 ** 31 - 1)


class Abbruch(Exception):
    pass


# ------------------------------------------------------------------ ZIP mit WinZip-AES (AE-1/AE-2) oder ZipCrypto lesen
class BackupZip:
    def __init__(self, path, password):
        self.path = Path(path)
        self.pw = password.encode("utf-8")
        self.zf = zipfile.ZipFile(self.path)
        self.infos = {i.filename: i for i in self.zf.infolist() if not i.is_dir()}

    def names(self):
        return list(self.infos)

    def _raw(self, info):
        with open(self.path, "rb") as f:
            f.seek(info.header_offset)
            h = f.read(30)
            if h[:4] != b"PK\x03\x04":
                raise Abbruch(f"Beschädigter ZIP-Eintrag: {info.filename}")
            n, m = struct.unpack("<HH", h[26:30])
            f.seek(info.header_offset + 30 + n + m)
            return f.read(info.compress_size)

    @staticmethod
    def _aes_extra(info):
        ex = info.extra
        i = 0
        while i + 4 <= len(ex):
            hid, ln = struct.unpack("<HH", ex[i:i + 4])
            if hid == 0x9901:
                d = ex[i + 4:i + 4 + ln]
                return d[4], struct.unpack("<H", d[5:7])[0]      # strength, eigentliche Methode
            i += 4 + ln
        raise Abbruch(f"AES-Eintrag ohne 0x9901-Feld: {info.filename}")

    def read(self, name):
        info = self.infos[name]
        if info.compress_type != 99:
            try:
                return self.zf.read(info, pwd=self.pw if info.flag_bits & 1 else None)
            except RuntimeError as e:
                raise Abbruch("Falsches Passwort (ZipCrypto).") from e
        strength, method = self._aes_extra(info)
        klen = {1: 16, 2: 24, 3: 32}[strength]
        slen = klen // 2
        raw = self._raw(info)
        salt, pwv, data, auth = raw[:slen], raw[slen:slen + 2], raw[slen + 2:-10], raw[-10:]
        km = hashlib.pbkdf2_hmac("sha1", self.pw, salt, 1000, 2 * klen + 2)
        ekey, hkey, check = km[:klen], km[klen:2 * klen], km[2 * klen:]
        if check != pwv:
            raise Abbruch("Falsches Passwort für das Threema-Backup.")
        if hmac.new(hkey, data, hashlib.sha1).digest()[:10] != auth:
            raise Abbruch(f"Authentifizierung fehlgeschlagen (Datei beschädigt): {name}")
        # AES-CTR mit Little-Endian-Zähler ab 1 (WinZip-Spezifikation)
        nblocks = (len(data) + 15) // 16
        ctrs = b"".join((i + 1).to_bytes(16, "little") for i in range(nblocks))
        enc = Cipher(algorithms.AES(ekey), modes.ECB()).encryptor()
        ks = enc.update(ctrs) + enc.finalize()
        plain = (int.from_bytes(data, "big") ^ int.from_bytes(ks[:len(data)], "big")).to_bytes(len(data), "big") if data else b""
        if method == 8:
            plain = zlib.decompress(plain, -15)
        elif method != 0:
            raise Abbruch(f"Nicht unterstützte Kompression {method}: {name}")
        return plain


# ------------------------------------------------------------------ Threema-ID-Backup (identity) entschlüsseln
def _rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _salsa_core(inp, hsalsa=False):
    x = list(inp)
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (5, 9, 13, 1), (10, 14, 2, 6), (15, 3, 7, 11),
                           (0, 1, 2, 3), (5, 6, 7, 4), (10, 11, 8, 9), (15, 12, 13, 14)):
            x[b] ^= _rotl((x[a] + x[d]) & 0xffffffff, 7)
            x[c] ^= _rotl((x[b] + x[a]) & 0xffffffff, 9)
            x[d] ^= _rotl((x[c] + x[b]) & 0xffffffff, 13)
            x[a] ^= _rotl((x[d] + x[c]) & 0xffffffff, 18)
    if hsalsa:
        return struct.pack("<8I", *(x[i] for i in (0, 5, 10, 15, 6, 7, 8, 9)))
    return struct.pack("<16I", *((x[i] + inp[i]) & 0xffffffff for i in range(16)))


def _salsa_state(key, n16):
    s = struct.unpack("<4I", b"expand 32-byte k")
    k = struct.unpack("<8I", key)
    n = struct.unpack("<4I", n16)
    return [s[0], k[0], k[1], k[2], k[3], s[1], n[0], n[1], n[2], n[3], s[2], k[4], k[5], k[6], k[7], s[3]]


def xsalsa20_xor(key, nonce24, data):
    sub = _salsa_core(_salsa_state(key, nonce24[:16]), hsalsa=True)
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _salsa_core(_salsa_state(sub, nonce24[16:] + struct.pack("<Q", i // 64)))
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def decode_identity_backup(text, password):
    """Threema-ID-Export: Base32(Salt[8] | XSalsa20(PBKDF2-SHA256(pw, salt, 100000))(ID[8] | PrivKey[32] | SHA256[:2]))"""
    s = re.sub(r"[^A-Z2-7]", "", text.upper())
    raw = base64.b32decode(s + "=" * (-len(s) % 8))
    if len(raw) != 50:
        return None
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw[:8], 100000, 32)
    pt = xsalsa20_xor(key, b"\x00" * 24, raw[8:])
    ident, priv, chk = pt[:8], pt[8:40], pt[40:42]
    if hashlib.sha256(ident + priv).digest()[:2] != chk:
        return None
    pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return ident.decode("ascii"), pub.hex()


# ------------------------------------------------------------------ SQLCipher 4 (Threema: Passphrase x"hex", kdf_iter 1, HMAC-SHA512)
PAGE_SIZE, RESERVE = 4096, 80          # IV(16) + HMAC-SHA512(64)


def empty_sqlite_with_reserve(path):
    h = bytearray(PAGE_SIZE)
    h[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", h, 16, PAGE_SIZE)
    h[18] = h[19] = 1
    h[20], h[21], h[22], h[23] = RESERVE, 64, 32, 32
    for off, val in ((24, 1), (28, 1), (44, 4), (56, 1), (92, 1), (96, 3045000)):
        struct.pack_into(">I", h, off, val)
    h[100] = 0x0D
    struct.pack_into(">H", h, 105, PAGE_SIZE - RESERVE)
    Path(path).write_bytes(bytes(h))


def _sqlcipher_keys(raw_key, salt):
    """Wie Threema-Android: Passphrase ist der STRING  x"<hex>"  (keine SQLCipher-Rohschlüssel-Syntax),
    abgeleitet mit PBKDF2-HMAC-SHA512 und kdf_iter = 1; HMAC-Key wie bei SQLCipher 4 üblich."""
    passphrase = ('x"' + raw_key.hex() + '"').encode("ascii")
    key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, 1, 32)
    return key, hashlib.pbkdf2_hmac("sha512", key, bytes(b ^ 0x3A for b in salt), 2, 32)


def sqlcipher4_encrypt(plain, raw_key):
    salt = os.urandom(16)
    key, hkey = _sqlcipher_keys(raw_key, salt)
    out = bytearray()
    for i in range(len(plain) // PAGE_SIZE):
        pg = i + 1
        page = plain[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        s = 16 if pg == 1 else 0
        iv = os.urandom(16)
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = e.update(page[s:PAGE_SIZE - RESERVE]) + e.finalize()
        mac = hmac.new(hkey, ct + iv + pg.to_bytes(4, "little"), hashlib.sha512).digest()
        out += (salt if pg == 1 else b"") + ct + iv + mac
    return bytes(out)


def sqlcipher4_verify(enc, raw_key, plain):
    key, hkey = _sqlcipher_keys(raw_key, enc[:16])
    for i in range(len(enc) // PAGE_SIZE):
        pg = i + 1
        page = enc[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        s, e = (16 if pg == 1 else 0), PAGE_SIZE - RESERVE
        iv, mac = page[e:e + 16], page[e + 16:e + 80]
        if not hmac.compare_digest(hmac.new(hkey, page[s:e + 16] + pg.to_bytes(4, "little"), hashlib.sha512).digest(), mac):
            return False
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        if d.update(page[s:e]) + d.finalize() != plain[i * PAGE_SIZE + s:i * PAGE_SIZE + e]:
            return False
    return True


KEY_DAT_XOR_MASK = bytes([149, 13, 38, 122, 136, 234, 119, 16, 156, 80, 231, 63, 71, 224, 105, 114,
                          218, 196, 57, 124, 153, 234, 126, 103, 175, 253, 221, 50, 218, 53, 247, 12])


def make_key_dat(raw_key):
    """key.dat Version 1, ohne Passphrase: Flag(0) | Key XOR Maske | 8 Byte Salt (ungenutzt) | SHA1(Key)[:4]"""
    return b"\x00" + bytes(a ^ b for a, b in zip(raw_key, KEY_DAT_XOR_MASK)) + b"\x00" * 8 + hashlib.sha1(raw_key).digest()[:4]


# ------------------------------------------------------------------ Schema (Spalten wie Threema-Android, ch.threema.storage.factories)
SCHEMA = """
CREATE TABLE `contacts` (`identity` VARCHAR ,`publicKey` BLOB ,`firstName` VARCHAR ,`lastName` VARCHAR ,
 `publicNickName` VARCHAR ,`verificationLevel` INTEGER ,`state` VARCHAR DEFAULT 'ACTIVE' NOT NULL ,
 `androidContactId` VARCHAR ,`featureLevel` INTEGER DEFAULT 0 NOT NULL ,`idColorIndex` INTEGER ,`avatarExpires` BIGINT,
 `isWork` TINYINT DEFAULT 0,`type` INT DEFAULT 0,`profilePicBlobID` BLOB DEFAULT NULL,`dateCreated` BIGINT DEFAULT 0,
 `lastUpdateAt` INTEGER,`acquaintanceLevel` TINYINT DEFAULT 0 NOT NULL,`isRestored` TINYINT DEFAULT 0,
 `conversationVisibility` INTEGER DEFAULT 0 NOT NULL,`readReceipts` TINYINT DEFAULT 0,`typingIndicators` TINYINT DEFAULT 0,
 `forwardSecurityState` TINYINT DEFAULT 0,`syncState` INTEGER NOT NULL DEFAULT 0,`jobTitle` VARCHAR DEFAULT NULL,
 `department` VARCHAR DEFAULT NULL,`isArchived` TINYINT DEFAULT 0, `identityId` VARCHAR, PRIMARY KEY (`identity`) );
CREATE TABLE `message`(`id` INTEGER PRIMARY KEY AUTOINCREMENT , `uid` VARCHAR , `apiMessageId` VARCHAR , `identity` VARCHAR ,
 `outbox` SMALLINT , `type` INTEGER , `body` VARCHAR , `correlationId` VARCHAR , `caption` VARCHAR , `isRead` SMALLINT ,
 `isSaved` SMALLINT , `isQueued` TINYINT , `state` VARCHAR , `postedAtUtc` BIGINT , `createdAtUtc` BIGINT ,
 `modifiedAtUtc` BIGINT , `isStatusMessage` SMALLINT ,`quotedMessageId` VARCHAR ,`messageContentsType` TINYINT ,
 `messageFlags` INT ,`deliveredAtUtc` DATETIME ,`readAtUtc` DATETIME ,`forwardSecurityMode` TINYINT DEFAULT 0 ,
 `displayTags` TINYINT DEFAULT 0 ,`editedAtUtc` DATETIME ,`deletedAtUtc` DATETIME );
CREATE TABLE `m_group` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `apiGroupId` VARCHAR , `name` VARCHAR ,
 `creatorIdentity` VARCHAR , `createdAt` BIGINT , `lastUpdateAt` INTEGER, `synchronizedAt` BIGINT ,
 `conversationVisibility` INTEGER DEFAULT 0 NOT NULL, `groupDesc` VARCHAR DEFAULT NULL,
 `changedGroupDescTimestamp` BIGINT DEFAULT NULL, `colorIndex` INTEGER DEFAULT 0 NOT NULL,
 `userState` INTEGER DEFAULT 0 NOT NULL, `backupGroupUid` VARCHAR);
CREATE TABLE `group_member` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `identity` VARCHAR , `groupId` INTEGER);
CREATE TABLE `m_group_message`(`id` INTEGER PRIMARY KEY AUTOINCREMENT , `uid` VARCHAR , `apiMessageId` VARCHAR ,
 `groupId` INTEGER NOT NULL , `identity` VARCHAR , `outbox` SMALLINT , `type` INTEGER ,`correlationId` VARCHAR ,
 `body` VARCHAR ,`caption` VARCHAR ,`isRead` SMALLINT ,`isSaved` SMALLINT ,`isQueued` TINYINT ,`state` VARCHAR ,
 `postedAtUtc` BIGINT , `createdAtUtc` BIGINT , `modifiedAtUtc` BIGINT , `isStatusMessage` SMALLINT ,
 `quotedMessageId` VARCHAR ,`messageContentsType` TINYINT ,`messageFlags` INT ,`deliveredAtUtc` DATETIME ,
 `readAtUtc` DATETIME ,`forwardSecurityMode` TINYINT DEFAULT 0 ,`groupMessageStates` VARCHAR ,
 `displayTags` TINYINT DEFAULT 0 ,`editedAtUtc` DATETIME ,`deletedAtUtc` DATETIME );
CREATE TABLE `distribution_list` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `name` VARCHAR, `createdAt` BIGINT,
 `lastUpdate` BIGINT, `isArchived` TINYINT DEFAULT 0);
CREATE TABLE `distribution_list_member` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `identity` VARCHAR,
 `distributionListId` INTEGER, `isActive` TINYINT DEFAULT 1);
CREATE TABLE `distribution_list_message` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `uid` VARCHAR, `apiMessageId` VARCHAR,
 `distributionListId` INTEGER, `identity` VARCHAR, `outbox` SMALLINT, `type` INTEGER, `body` VARCHAR, `caption` VARCHAR,
 `isRead` SMALLINT, `isSaved` SMALLINT, `state` VARCHAR, `postedAtUtc` BIGINT, `createdAtUtc` BIGINT,
 `modifiedAtUtc` BIGINT, `isStatusMessage` SMALLINT, `quotedMessageId` VARCHAR, `deliveredAtUtc` DATETIME,
 `readAtUtc` DATETIME, `editedAtUtc` DATETIME, `deletedAtUtc` DATETIME);
CREATE TABLE `contact_emoji_reaction` (`messageId` INTEGER, `apiMessageId` VARCHAR, `senderIdentity` VARCHAR,
 `emojiSequence` VARCHAR, `reactedAt` BIGINT);
CREATE TABLE `group_emoji_reaction` (`messageId` INTEGER, `apiMessageId` VARCHAR, `senderIdentity` VARCHAR,
 `emojiSequence` VARCHAR, `reactedAt` BIGINT);
CREATE TABLE `backup_conversion_info` (`key` TEXT PRIMARY KEY, `value` TEXT);
"""

# ch.threema.storage.models.MessageType (serializedValue) – Backup-Typnamen -> DB-Wert
MSG_TYPE = {"TEXT": 0, "LOCATION": 4, "STATUS": 6, "POLL": 7, "BALLOT": 7, "FILE": 8, "VOIP_STATUS": 9,
            "DATE_SEPARATOR": 10, "GROUP_CALL_STATUS": 11, "FORWARD_SECURITY_STATUS": 12, "GROUP_STATUS": 13,
            "IMAGE": 8, "VIDEO": 8, "VOICEMESSAGE": 8, "CONTACT": 0}
VERIFICATION = {"UNVERIFIED": 0, "SERVER_VERIFIED": 1, "FULLY_VERIFIED": 2}


def sniff_ext(data):
    for magic, ext in ((b"\xff\xd8\xff", ".jpg"), (b"\x89PNG\r\n\x1a\n", ".png"), (b"GIF8", ".gif"),
                       (b"%PDF", ".pdf"), (b"OggS", ".ogg"), (b"ID3", ".mp3"), (b"\x1aE\xdf\xa3", ".webm"),
                       (b"PK\x03\x04", ".zip")):
        if data.startswith(magic):
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if data[4:8] == b"ftyp":
        return ".m4a" if data[8:11] == b"M4A" else ".mp4"
    if data[:6] in (b"#!AMR\n",):
        return ".amr"
    return ".bin"


def file_body_info(body):
    """Dateiname/MIME/Größe aus dem FILE-Body (positionales JSON-Array bzw. Legacy-JSON-Objekt)."""
    try:
        j = json.loads(body)
    except Exception:
        return None, None, None
    if isinstance(j, list):
        mime = next((p for p in j if isinstance(p, str) and "/" in p and len(p) < 100), None)
        name = j[4] if len(j) > 4 and isinstance(j[4], str) else None
        size = j[3] if len(j) > 3 and isinstance(j[3], int) else None
        return name, mime, size
    if isinstance(j, dict):
        return j.get("n"), j.get("m"), j.get("s")
    return None, None, None


def ival(v, default=None):
    try:
        return int(v) if v not in (None, "") else default
    except ValueError:
        return default


def read_csv(data):
    text = data.decode("utf-8-sig", errors="replace")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    head = rows[0]
    return [dict(zip(head, r)) for r in rows[1:] if r]


# ------------------------------------------------------------------ Konvertierung
def convert(backup_file, password, out_dir, log=print):
    backup_file = Path(backup_file).expanduser()
    if not backup_file.is_file():
        raise Abbruch(f"Backup-Datei nicht gefunden: {backup_file}")
    if not password:
        raise Abbruch("Kein Passwort angegeben.")
    bz = BackupZip(backup_file, password)
    names = bz.names()
    if "identity" not in names or "contacts.csv" not in names:
        raise Abbruch("Das sieht nicht nach einer Threema-Datensicherung aus (identity/contacts.csv fehlen).")
    log(f"Backup: {backup_file.name} ({len(names)} Einträge)")

    files = {}
    for n in names:
        files[n] = bz.read(n)
    log("Alle Einträge entschlüsselt (Passwort ok, AES-Authentifizierung ok).")

    ident = decode_identity_backup(files["identity"].decode("ascii", "replace"), password)
    own_id, own_pub = ident if ident else (None, None)
    log(f"Eigene Threema-ID: {own_id or 'nicht entschlüsselbar'}")
    settings = dict(r for r in csv.reader(io.StringIO(files.get("settings", b"").decode("utf-8", "replace"))) if len(r) == 2)

    out_dir = Path(out_dir).expanduser().resolve()
    stage = out_dir / "ALEAPP_Threema"
    for p in (stage, out_dir / "backup_entschluesselt", out_dir / "medien"):
        if p.exists():
            shutil.rmtree(p)
    app = stage / "data" / "data" / PKG
    for sub in ("databases", "files", "shared_prefs"):
        (app / sub).mkdir(parents=True)
    (out_dir / "backup_entschluesselt").mkdir(parents=True)
    (out_dir / "medien").mkdir(parents=True)

    for n, data in files.items():
        tgt = out_dir / "backup_entschluesselt" / n
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_bytes(data if n != "identity" else b"(ID-Backup, verschluesselt - private Schluessel nicht exportiert)\n")

    tmp = Path(tempfile.mkdtemp(prefix="threema2aleapp_"))
    try:
        plain_path = tmp / "threema4_plain.db"
        empty_sqlite_with_reserve(plain_path)
        db = sqlite3.connect(plain_path)
        db.executescript(SCHEMA)
        st = {k: 0 for k in ("contacts", "messages", "groups", "group_messages", "dlists", "dlist_messages",
                             "reactions", "media", "media_orphan")}

        # Kontakte
        contacts = read_csv(files["contacts.csv"])
        idid_to_identity = {}
        for c in contacts:
            identity = c.get("identity")
            if not identity:
                continue
            if c.get("identity_id"):
                idid_to_identity[c["identity_id"]] = identity
            pk = bytes.fromhex(c["publickey"]) if re.fullmatch(r"[0-9a-fA-F]{64}", c.get("publickey", "")) else None
            db.execute("INSERT OR REPLACE INTO contacts (identity, publicKey, firstName, lastName, publicNickName, "
                       "verificationLevel, androidContactId, dateCreated, lastUpdateAt, acquaintanceLevel, isRestored, "
                       "isArchived, identityId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (identity, pk, c.get("firstname") or None, c.get("lastname") or None, c.get("nick_name") or None,
                        VERIFICATION.get(c.get("verification", ""), 0), c.get("acid") or None, None,
                        ival(c.get("last_update")), 1 if c.get("hidden") == "1" else 0, 1,
                        1 if c.get("archived") == "1" else 0, c.get("identity_id") or None))
            st["contacts"] += 1

        def msg_values(r):
            typ = r.get("type", "TEXT")
            return dict(uid=r.get("uid") or None, apiMessageId=r.get("apiid") or None,
                        outbox=1 if r.get("isoutbox") == "1" else 0, type=MSG_TYPE.get(typ, 0),
                        body=r.get("body"), caption=r.get("caption") or None,
                        isRead=1 if r.get("isread") == "1" else 0, isSaved=1 if r.get("issaved") == "1" else 0,
                        state=r.get("messagestae") or r.get("messagestate") or None,
                        postedAtUtc=ival(r.get("posted_at")), createdAtUtc=ival(r.get("created_at")),
                        modifiedAtUtc=ival(r.get("modified_at")),
                        isStatusMessage=1 if r.get("isstatusmessage") == "1" else 0,
                        quotedMessageId=r.get("quoted_message_apiid") or None,
                        deliveredAtUtc=ival(r.get("delivered_at")), readAtUtc=ival(r.get("read_at")),
                        displayTags=ival(r.get("display_tags"), 0), editedAtUtc=ival(r.get("edited_at")),
                        deletedAtUtc=ival(r.get("deleted_at")))

        def insert(table, vals):
            cols = ",".join(f"`{k}`" for k in vals)
            return db.execute(f"INSERT INTO `{table}` ({cols}) VALUES ({','.join('?' * len(vals))})",
                              list(vals.values())).lastrowid

        media_index = {}          # uid -> (conv-label, body)

        # Einzelchats
        for n in sorted(names):
            m = re.fullmatch(r"message_(.+)\.csv", n)
            if not m:
                continue
            key = m.group(1)
            identity = idid_to_identity.get(key, key)
            for r in read_csv(files[n]):
                v = msg_values(r)
                v["identity"] = identity
                if v["type"] == 8 and v["body"]:
                    v["messageContentsType"] = 1 if (file_body_info(v["body"])[1] or "").startswith("image/") else None
                insert("message", v)
                media_index[v["uid"]] = (identity, v["body"])
                st["messages"] += 1

        # Gruppen
        group_uid_to_id = {}
        for g in read_csv(files.get("groups.csv", b"")):
            gid = insert("m_group", dict(apiGroupId=g.get("id") or None, name=g.get("groupname") or None,
                                         creatorIdentity=g.get("creator") or None, createdAt=ival(g.get("created_at")),
                                         lastUpdateAt=ival(g.get("last_update")), groupDesc=g.get("groupDesc") or None,
                                         changedGroupDescTimestamp=ival(g.get("groupDescTimestamp")),
                                         userState=ival(g.get("user_state"), 0),
                                         conversationVisibility=1 if g.get("archived") == "1" else 0,
                                         backupGroupUid=g.get("group_uid") or None))
            for mem in [x for x in (g.get("members") or "").split(";") if x]:
                insert("group_member", dict(identity=mem, groupId=gid))
            for k in (g.get("group_uid"), g.get("id")):
                if k:
                    group_uid_to_id[k] = gid
            st["groups"] += 1
        for n in sorted(names):
            m = re.fullmatch(r"group_message_(.+)\.csv", n)
            if not m:
                continue
            gid = group_uid_to_id.get(m.group(1))
            if gid is None:
                gid = insert("m_group", dict(name=f"(Gruppe {m.group(1)} – nicht in groups.csv)", backupGroupUid=m.group(1)))
                group_uid_to_id[m.group(1)] = gid
            for r in read_csv(files[n]):
                v = msg_values(r)
                v["groupId"] = gid
                v["identity"] = r.get("identity") or (own_id if v["outbox"] else None)
                v["groupMessageStates"] = r.get("g_msg_states") or None
                insert("m_group_message", v)
                media_index[v["uid"]] = (f"gruppe_{gid}", v["body"])
                st["group_messages"] += 1

        # Verteilerlisten
        dl_map = {}
        for d in read_csv(files.get("distribution_list.csv", b"")):
            did = insert("distribution_list", dict(name=d.get("distribution_list_name") or None,
                                                   createdAt=ival(d.get("created_at")), lastUpdate=ival(d.get("last_update")),
                                                   isArchived=1 if d.get("archived") == "1" else 0))
            for mem in [x for x in (d.get("distribution_members") or "").split(";") if x]:
                insert("distribution_list_member", dict(identity=mem, distributionListId=did))
            dl_map[d.get("id")] = did
            st["dlists"] += 1
        for n in sorted(names):
            m = re.fullmatch(r"distribution_list_message_(.+)\.csv", n)
            if not m:
                continue
            did = dl_map.get(m.group(1).split("-")[0])
            for r in read_csv(files[n]):
                v = msg_values(r)
                v.pop("displayTags", None)
                v["distributionListId"] = did
                v["identity"] = r.get("identity") or None
                insert("distribution_list_message", v)
                media_index[v["uid"]] = (f"verteiler_{did}", v["body"])
                st["dlist_messages"] += 1

        # Reaktionen
        for fname, table in (("contact_reactions.csv", "contact_emoji_reaction"), ("group_reactions.csv", "group_emoji_reaction")):
            for r in read_csv(files.get(fname, b"")):
                src = "message" if table == "contact_emoji_reaction" else "m_group_message"
                mid = db.execute(f"SELECT id FROM `{src}` WHERE apiMessageId=?", (r.get("api_message_id"),)).fetchone()
                insert(table, dict(messageId=mid[0] if mid else None, apiMessageId=r.get("api_message_id"),
                                   senderIdentity=r.get("sender_identity"), emojiSequence=r.get("emoji_sequence"),
                                   reactedAt=ival(r.get("reacted_at"))))
                st["reactions"] += 1

        # Medien exportieren (im Backup unverschlüsselt, auf dem Gerät nur mit Master-Key lesbar -> ALEAPP zeigt sie nicht)
        media_rows = []
        for n in sorted(names):
            m = re.fullmatch(r"(message|group_message|distribution_list_message)_(media|thumbnail)_(.+)", n) or \
                re.fullmatch(r"(distribution_list)_(thumbnail)_(.+)", n)
            if not m:
                continue
            kind, part, uid = m.group(1), m.group(2), m.group(3)
            data = files[n]
            conv, body = media_index.get(uid, (None, None))
            fname, mime, _ = file_body_info(body) if body else (None, None, None)
            ext = sniff_ext(data)
            base = re.sub(r'[\\/:*?"<>|]', "_", fname) if (fname and part == "media") else f"{uid}{ext}"
            if fname and part == "media" and "." not in fname:
                base += ext
            tgt = out_dir / "medien" / (conv or "ohne_nachricht") / (f"{uid[:8]}_thumb_{base}" if part == "thumbnail" else f"{uid[:8]}_{base}")
            tgt.parent.mkdir(parents=True, exist_ok=True)
            tgt.write_bytes(data)
            media_rows.append((n, str(tgt.relative_to(out_dir)), len(data), hashlib.sha256(data).hexdigest()))
            st["media"] += 1
            if conv is None:
                st["media_orphan"] += 1
        for n in sorted(names):
            if n.startswith(("contact_avatar_", "contact_profile_pic_", "group_avatar_")):
                data = files[n]
                tgt = out_dir / "medien" / "avatare" / (n + sniff_ext(data))
                tgt.parent.mkdir(parents=True, exist_ok=True)
                tgt.write_bytes(data)
                media_rows.append((n, str(tgt.relative_to(out_dir)), len(data), hashlib.sha256(data).hexdigest()))

        bsha = hashlib.sha256(backup_file.read_bytes()).hexdigest()
        info = {"hinweis": "Rekonstruiert aus Threema-Datensicherung, NICHT die Original-threema4.db des Geräts",
                "tool": f"threema_backup_zu_aleapp.py {VERSION}",
                "konvertiert_am_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "quelle": backup_file.name, "sha256_quelle": bsha, "backup_version": settings.get("version", ""),
                "eigene_id": own_id or "", "eigener_public_key": own_pub or ""}
        db.executemany("INSERT INTO backup_conversion_info VALUES (?,?)", info.items())
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise Abbruch("Interner Fehler: Integritätsprüfung der Datenbank fehlgeschlagen.")
        db.execute("VACUUM")
        db.close()

        plain = plain_path.read_bytes()
        if plain[20] != RESERVE or len(plain) % PAGE_SIZE:
            raise Abbruch("Interner Fehler: unerwartetes Seitenlayout.")
        raw_key = os.urandom(32)
        enc = sqlcipher4_encrypt(plain, raw_key)
        if not sqlcipher4_verify(enc, raw_key, plain):
            raise Abbruch("Interner Fehler: SQLCipher-Gegenprüfung fehlgeschlagen.")
        (app / "databases" / "threema4.db").write_bytes(enc)
        (app / "files" / "key.dat").write_bytes(make_key_dat(raw_key))
        prefs = ["<?xml version='1.0' encoding='utf-8' standalone='yes' ?>", "<map>"]
        if own_id:
            prefs.append(f'    <string name="identity">{own_id}</string>')
        prefs.append('    <string name="backup_conversion_note">Rekonstruiert aus Threema-Datensicherung</string>')
        prefs.append("</map>")
        (app / "shared_prefs" / "ch.threema.app_preferences.xml").write_text("\n".join(prefs) + "\n", encoding="utf-8")
        log(f"threema4.db erzeugt ({len(enc) // PAGE_SIZE} Seiten, SQLCipher-4-Gegenprüfung ok).")

        zip_path = out_dir / "ALEAPP_Threema.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(stage.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(stage).as_posix())

        ts = ""
        mt = re.search(r"threema-backup_(\d{13})", backup_file.name)
        if mt:
            ts = datetime.datetime.fromtimestamp(int(mt.group(1)) / 1000).strftime("%d.%m.%Y %H:%M:%S")
        rep = [
            "Threema-Datensicherung -> ALEAPP  |  Konvertierungsbericht",
            "=" * 60,
            f"Tool:                 threema_backup_zu_aleapp.py {VERSION}",
            f"Konvertiert (UTC):    {info['konvertiert_am_utc']}",
            f"Quelle:               {backup_file}",
            f"SHA-256 Quelle:       {bsha}",
            f"Backup-Zeitpunkt:     {ts or '?'} (aus Dateiname, lokale Zeit dieses Rechners)",
            f"Backup-Formatversion: {settings.get('version', '?')}",
            f"Eigene Threema-ID:    {own_id or 'nicht entschlüsselbar'}",
            f"Eigener Public Key:   {own_pub or '-'}",
            "",
            f"Kontakte:             {st['contacts']}",
            f"Einzelnachrichten:    {st['messages']}",
            f"Gruppen:              {st['groups']}  (Nachrichten: {st['group_messages']})",
            f"Verteilerlisten:      {st['dlists']}  (Nachrichten: {st['dlist_messages']})",
            f"Reaktionen:           {st['reactions']}",
            f"Mediendateien:        {st['media']} (davon ohne zugehörige Nachricht: {st['media_orphan']})",
            "",
            "Ausgabe:",
            f"  {zip_path}",
            f"  SHA-256 ALEAPP_Threema.zip: {hashlib.sha256(zip_path.read_bytes()).hexdigest()}",
            f"  SHA-256 threema4.db:        {hashlib.sha256(enc).hexdigest()}",
            "",
            "Hinweise zur Auswertung:",
            "  * threema4.db ist eine Rekonstruktion (Tabellen/Spalten wie Threema-Android), keine Gerätedatei.",
            "  * Schlüssel in key.dat ist bei jedem Lauf neu und zufällig (nicht der des Originalgeräts).",
            "  * ALEAPP (Stand Sept. 2026) wertet nur Account, Kontakte und EINZELchats aus. Gruppen-, Verteiler-",
            "    nachrichten und Reaktionen stehen in threema4.db (m_group_message, distribution_list_message,",
            "    *_emoji_reaction) sowie im Klartext unter backup_entschluesselt/.",
            "  * Mediendateien zeigt ALEAPP bei Threema nicht an; sie liegen unter medien/ (nach Chat sortiert).",
            "  * 'Date Added' der Kontakte ist im Backup nicht enthalten (ALEAPP-Spalte bleibt leer).",
            "  * Nickname und verknüpfte Telefonnummer des Kontoinhabers enthält das Backup nicht.",
            "  * Der private Schlüssel aus dem ID-Backup wird bewusst NICHT exportiert.",
            "  * Nachrichten, die vor der Sicherung gelöscht wurden, enthält auch das Backup nicht.",
        ]
        if media_rows:
            rep += ["", "Mediendateien (Backup-Eintrag | Ausgabe | Größe | SHA-256):"]
            rep += [f"  {a} | {b} | {c} | {d}" for a, b, c, d in media_rows]
        (out_dir / "report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
        for line in rep[2:rep.index("Hinweise zur Auswertung:") - 1]:
            log(line)
        log(f"\nFERTIG. In ALEAPP als Eingabe wählen (Typ zip):\n  {zip_path}")
        return zip_path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ Oberfläche
def run_gui():
    import threading
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox

    w = tk.Tk()
    w.title("Threema-Backup -> ALEAPP")
    w.geometry("760x520")
    frm = tk.Frame(w, padx=10, pady=10)
    frm.pack(fill="both", expand=True)
    v_src, v_pw, v_out = tk.StringVar(value=BACKUP_DATEI), tk.StringVar(value=PASSWORT), tk.StringVar(value=AUSGABE_ORDNER)

    def pick_zip():
        p = filedialog.askopenfilename(title="Threema-Backup (ZIP) wählen", filetypes=[("Threema-Backup", "*.zip"), ("Alle", "*.*")])
        if p:
            v_src.set(p)
            if not v_out.get():
                v_out.set(str(Path(p).parent / "ALEAPP_Threema_Export"))

    def pick_out():
        p = filedialog.askdirectory(title="Ausgabeordner wählen")
        if p:
            v_out.set(p)

    tk.Label(frm, text="Threema-Backup (ZIP):").grid(row=0, column=0, sticky="w", pady=4)
    tk.Entry(frm, textvariable=v_src, width=70).grid(row=0, column=1, sticky="we", padx=6)
    tk.Button(frm, text="Wählen …", command=pick_zip).grid(row=0, column=2, sticky="we")
    tk.Label(frm, text="Passwort:").grid(row=1, column=0, sticky="w", pady=4)
    pw_entry = tk.Entry(frm, textvariable=v_pw, width=70, show="•")
    pw_entry.grid(row=1, column=1, sticky="we", padx=6)
    v_show = tk.BooleanVar(value=False)
    tk.Checkbutton(frm, text="anzeigen", variable=v_show,
                   command=lambda: pw_entry.config(show="" if v_show.get() else "•")).grid(row=2, column=1, sticky="w")
    tk.Label(frm, text="Ausgabeordner:").grid(row=3, column=0, sticky="w", pady=4)
    tk.Entry(frm, textvariable=v_out, width=70).grid(row=3, column=1, sticky="we", padx=6)
    tk.Button(frm, text="Wählen …", command=pick_out).grid(row=3, column=2, sticky="we")
    frm.columnconfigure(1, weight=1)
    logbox = scrolledtext.ScrolledText(frm, height=18, font=("Consolas", 9))
    logbox.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
    frm.rowconfigure(5, weight=1)

    def log(msg):
        w.after(0, lambda: (logbox.insert("end", str(msg) + "\n"), logbox.see("end")))

    def start():
        src, pw, out = v_src.get().strip(), v_pw.get(), v_out.get().strip()
        if not src:
            messagebox.showwarning("Fehlt", "Bitte die Threema-Backup-ZIP wählen."); return
        if not out:
            out = str(Path(src).parent / "ALEAPP_Threema_Export"); v_out.set(out)
        btn.config(state="disabled")
        logbox.delete("1.0", "end")

        def work():
            try:
                convert(src, pw, out, log)
                w.after(0, lambda: messagebox.showinfo("Fertig", f"ALEAPP-Eingabe erstellt:\n{Path(out) / 'ALEAPP_Threema.zip'}"))
            except Abbruch as e:
                log(f"FEHLER: {e}")
                w.after(0, lambda: messagebox.showerror("Fehler", str(e)))
            except Exception as e:  # noqa
                import traceback
                log(traceback.format_exc())
                w.after(0, lambda: messagebox.showerror("Fehler", repr(e)))
            finally:
                w.after(0, lambda: btn.config(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    btn = tk.Button(frm, text="Konvertieren für ALEAPP", command=start, bg="#05a63f", fg="white", padx=10, pady=4)
    btn.grid(row=4, column=1, sticky="w", pady=8)
    w.mainloop()


def _hide_own_console():
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        procs = (ctypes.c_uint * 8)()
        n = k32.GetConsoleProcessList(procs, 8)
        own = 2 if getattr(sys, "frozen", False) else 1
        if 0 < n <= own:
            ctypes.windll.user32.ShowWindow(k32.GetConsoleWindow(), 0)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Threema-Datensicherung in ALEAPP-Eingabe umwandeln")
    ap.add_argument("backup", nargs="?", help="threema-backup_....zip")
    ap.add_argument("pw_pos", nargs="?", metavar="passwort", help="Passwort der Datensicherung (in Anführungszeichen)")
    ap.add_argument("out_pos", nargs="?", metavar="ausgabe", help="Ausgabeordner")
    ap.add_argument("--password", "--passwort", dest="password", help="Passwort der Datensicherung")
    ap.add_argument("--out", help="Ausgabeordner")
    ap.add_argument("--nogui", action="store_true", help="kein Fenster, Abfrage in der Konsole")
    a = ap.parse_args()

    src = a.backup or BACKUP_DATEI
    pw = a.password or a.pw_pos or PASSWORT
    out = a.out or a.out_pos or AUSGABE_ORDNER
    if not a.backup and not a.nogui:
        _hide_own_console()
    if not (src and pw) and not a.nogui:
        try:
            run_gui()
            return
        except Exception as e:
            print(f"(Fenster nicht verfügbar: {e}) – weiter in der Konsole.")
    if not src:
        src = input("Pfad zur Threema-Backup-ZIP: ").strip().strip('"')
    if not pw:
        pw = getpass.getpass("Passwort der Datensicherung (Eingabe unsichtbar): ")
    out = out or str(Path(src).expanduser().parent / "ALEAPP_Threema_Export")
    try:
        convert(src, pw, out)
    except Abbruch as e:
        sys.exit(f"FEHLER: {e}")
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
