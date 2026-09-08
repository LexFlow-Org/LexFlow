#!/usr/bin/env python3
"""Offline LexFlow license manager; never persists private signing keys.

Registry v3 uses AES-256-GCM/Scrypt and atomic writes. Authenticated v2
registries migrate on the next save. Local withdrawal cannot revoke a
token on another offline computer. Existing command names are retained.
"""
import argparse
import base64
import binascii
from contextlib import contextmanager
import csv
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import uuid
import warnings

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    raise SystemExit("Manca cryptography: installala con python3 -m pip install cryptography.")

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
LOCAL_KEY_DIR = Path.home() / "Library/Application Support/LexFlow License Keys"
REGISTRY_FILE = SCRIPT_DIR / ".lexflow-issued-keys.enc"
REGISTRY_SALT_FILE = SCRIPT_DIR / ".lexflow-registry-salt"
MAGIC = b"LEXFLOW-REGISTRY-V3\0"
MAX_REGISTRY_BYTES = 16 * 1024 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_REGISTRY_ENTRIES = 100_000
DAY_MS = 86_400_000


def read_private_file(path, limit):
    """Read a bounded regular file without following Unix symlinks."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("I file sensibili non possono essere link simbolici.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("È richiesto un file regolare.")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File troppo grande; operazione interrotta.")
    return data


def atomic_private_write(path, data, *, replace=True):
    """Publish a complete owner-only file; never truncate old contents."""
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Destinazione non valida o link simbolico.")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".lexflow-stage-", delete=False) as stream:
            temporary = Path(stream.name)
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Fails if destination already exists.
            temporary.unlink()
        temporary = None
        if os.name != "nt":
            fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def registry_lock():
    """Serialize read-modify-write commands across processes, including prompts."""
    path = REGISTRY_FILE.parent / ".lexflow-license-manager.lock"
    if path.is_symlink():
        raise ValueError("File di blocco non valido.")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "r+b") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("File di blocco non regolare.")
        if os.name == "nt":
            import msvcrt
            if os.fstat(stream.fileno()).st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise ValueError("Il registro è già aperto in un altro processo.") from exc
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Il registro è già aperto in un altro processo.") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def normalize_b64(raw):
    value = raw.strip()
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Base64 non valido.") from exc


def derive_registry_key(password, salt):
    if len(salt) != 32:
        raise ValueError("Salt del registro non valido.")
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())


def _entries_from_plaintext(plaintext, salt, legacy):
    try:
        wrapper = json.loads(plaintext)
        entries = wrapper["entries"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Registro decifrato ma non valido; originali conservati.") from exc
    if not isinstance(entries, list) or len(entries) > MAX_REGISTRY_ENTRIES or any(not isinstance(e, dict) for e in entries):
        raise ValueError("Struttura del registro non valida.")
    if legacy and wrapper.get("hmac"):
        # This old field was a checksum; AEAD supplies authentication.
        encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(salt + b":INTEGRITY:" + encoded).hexdigest()
        if not isinstance(wrapper["hmac"], str) or not hmac.compare_digest(wrapper["hmac"], expected):
            raise ValueError("Checksum storico del registro non valido; originali conservati.")
    return entries


def load_registry(password):
    if not REGISTRY_FILE.exists() and not REGISTRY_FILE.is_symlink():
        return []
    data = read_private_file(REGISTRY_FILE, MAX_REGISTRY_BYTES)
    candidates = []
    if data.startswith(MAGIC):
        offset = len(MAGIC)
        if len(data) < offset + 60:
            raise ValueError("Registro incompleto; originali conservati.")
        candidates.append((data[offset:offset+32], data[offset+32:offset+44], data[offset+44:], MAGIC, False))
    else:
        if len(data) >= 60:
            candidates.append((data[:32], data[32:44], data[44:], None, True))
    for salt, nonce, ciphertext, aad, legacy in candidates:
        try:
            plaintext = AESGCM(derive_registry_key(password, salt)).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            continue
        return _entries_from_plaintext(plaintext, salt, legacy)
    # Read a historical split salt only after the self-contained layout failed
    # authentication. A stale/corrupt salt cannot block a valid embedded file.
    if not data.startswith(MAGIC) and len(data) >= 28 and (REGISTRY_SALT_FILE.exists() or REGISTRY_SALT_FILE.is_symlink()):
        salt = read_private_file(REGISTRY_SALT_FILE, 32)
        try:
            plaintext = AESGCM(derive_registry_key(password, salt)).decrypt(data[:12], data[12:], None)
        except InvalidTag:
            pass
        else:
            return _entries_from_plaintext(plaintext, salt, True)
    raise ValueError("Password errata o registro danneggiato. Nessun file modificato: conserva gli originali.")


def save_registry(password, entries):
    if not isinstance(entries, list) or len(entries) > MAX_REGISTRY_ENTRIES or any(not isinstance(e, dict) for e in entries):
        raise ValueError("Struttura del registro non valida.")
    salt, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    plaintext = json.dumps({"version": 3, "entries": entries}, ensure_ascii=False, separators=(",", ":")).encode()
    if len(plaintext) > MAX_REGISTRY_BYTES - len(MAGIC) - 60:
        raise ValueError("Registro troppo grande.")
    ciphertext = AESGCM(derive_registry_key(password, salt)).encrypt(nonce, plaintext, MAGIC)
    atomic_private_write(REGISTRY_FILE, MAGIC + salt + nonce + ciphertext)
    # Preserve historical salt: old encrypted backups may still require it.


def secret_prompt(label):
    # getpass otherwise falls back to potentially echoed input on some terminals.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(label)
        except getpass.GetPassWarning as exc:
            raise ValueError("Terminale senza input nascosto: apri un terminale interattivo per inserire i segreti.") from exc


def get_password():
    exists = REGISTRY_FILE.exists() or REGISTRY_FILE.is_symlink()
    password = secret_prompt("Password registro: " if exists else "Nuova password registro (minimo 12 caratteri): ")
    if not exists:
        if len(password) < 12:
            raise ValueError("Servono almeno 12 caratteri per il nuovo registro.")
        if password != secret_prompt("Conferma password: "):
            raise ValueError("Le password non corrispondono.")
    return password


def expected_public_key():
    """Read only public constants; fail if runtime/build keys are inconsistent."""
    runtime = (PROJECT_DIR / "src-tauri/src/license.rs").read_text()
    build = (PROJECT_DIR / "src-tauri/build.rs").read_text()
    runtime_key = re.search(r"const PUBLIC_KEY_BYTES:\s*\[u8;\s*32\]\s*=\s*\[([^]]+)\]", runtime)
    build_key = re.search(r"PUBLIC_KEY_BYTES.*?extend_from_slice\(&\[([^]]+)\]", build, re.S)
    if not runtime_key or not build_key:
        raise ValueError("Impossibile leggere le chiavi pubbliche dell'app; controllare i sorgenti.")
    values = [bytes(int(x) for x in re.findall(r"(\d+)u8", match[1])) for match in (runtime_key, build_key)]
    if len(values[0]) != 32 or values[0] != values[1]:
        raise ValueError("Chiavi pubbliche diverse fra app e build; generazione interrotta.")
    return values[0]


def _parse_private_key(raw):
    raw = raw.strip()
    if raw.startswith("-----BEGIN"):
        private = serialization.load_pem_private_key(raw.encode(), password=None)
    else:
        data = bytes.fromhex(raw) if re.fullmatch(r"[a-fA-F0-9]{64}", raw) else normalize_b64(raw)
        private = ed25519.Ed25519PrivateKey.from_private_bytes(data) if len(data) == 32 else serialization.load_der_private_key(data, password=None)
    if not isinstance(private, ed25519.Ed25519PrivateKey):
        raise ValueError("È richiesta una chiave Ed25519.")
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def configured_private_key_path():
    """Resolve the explicitly requested local issuer without exposing its secret."""
    base = LOCAL_KEY_DIR
    if base.is_symlink() or base.resolve() != base:
        raise ValueError("La cartella della chiave locale non può essere un link simbolico.")
    metadata = json.loads(read_private_file(base / "active-license-key.json", 8192))
    if not isinstance(metadata, dict) or metadata.get("public_key_hex") != expected_public_key().hex():
        raise ValueError("La chiave locale configurata non corrisponde a questa versione dell'app.")
    value = metadata.get("private_key_file")
    if not isinstance(value, str) or not value:
        raise ValueError("Percorso della chiave locale mancante.")
    path = Path(value)
    if not path.is_absolute() or path.resolve() != path or base not in path.parents:
        raise ValueError("La chiave locale deve restare nella cartella privata configurata.")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("La chiave locale deve essere un file regolare.")
    if os.name != "nt" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("La chiave locale deve appartenere all'utente ed essere leggibile solo da lui (0600).")
    return path


def _text(value, name, maximum, required=True):
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"Campo {name} non valido (massimo {maximum} caratteri, senza controlli).")
    return value.strip()


def validate_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("Payload licenza non valido.")
    _text(payload.get("c"), "studio", 500)
    _text(payload.get("id"), "ID", 128)
    for field in ("a", "s", "t", "h", "n"):
        if field in payload:
            _text(payload[field], field, 500, required=False)
    expiry, grace = payload.get("e"), payload.get("g", 0)
    if type(expiry) is not int or not 0 < expiry <= 253_402_300_799_999:
        raise ValueError("Scadenza non valida.")
    if type(grace) is not int or not 0 <= grace <= 3650:
        raise ValueError("Grace Period non valido: usare da 0 a 3650 giorni.")
    return payload


def sign_token(private, public, payload):
    actual = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(actual, public):
        raise ValueError("La chiave privata non corrisponde alla chiave pubblica di questa versione dell'app.")
    validate_payload(payload)
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(private.sign(encoded.encode())).decode().rstrip("=")
    token = f"LXFW.{encoded}.{signature}"
    verify_token(token, public)
    return token


def verify_token(token, public):
    if len(token) > MAX_TOKEN_BYTES:
        raise ValueError("Token troppo lungo.")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "LXFW" or any(not re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts[1:]):
        raise ValueError("Formato atteso: LXFW.<payload>.<firma>.")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(normalize_b64(parts[2]), parts[1].encode())
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Firma non valida: token alterato o chiave diversa dall'app.") from exc
    try:
        return validate_payload(json.loads(normalize_b64(parts[1])))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Dati del token non validi.") from exc


def _parse_expiry(value):
    date = datetime.strptime(value, "%Y-%m-%d").date() if value else (datetime.now(timezone.utc) + timedelta(days=365)).date()
    end = datetime(date.year, date.month, date.day, tzinfo=timezone.utc) + timedelta(days=1)
    return int(end.timestamp() * 1000) - 1, date.isoformat()


def compute_key_hash(token):
    return hashlib.sha256(f"BURN-GLOBAL-V2:{token}".encode()).hexdigest()


def create_backup():
    if REGISTRY_FILE.exists():
        suffix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(4)
        backup = REGISTRY_FILE.parent / f".lexflow-registry-{suffix}.bak.enc"
        atomic_private_write(backup, read_private_file(REGISTRY_FILE, MAX_REGISTRY_BYTES), replace=False)
        return backup
    return None


def cmd_generate(args):
    public = expected_public_key()
    key_file = configured_private_key_path() if getattr(args, "local_key", False) else args.private_key_file
    raw = read_private_file(key_file, 16_384).decode() if key_file else secret_prompt("Chiave privata Ed25519 (Hex/Base64): ")
    try:
        private, actual = _parse_private_key(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("Chiave privata non valida; usare seed Hex/Base64 o file PEM/PKCS8.") from exc
    finally:
        del raw
    if not hmac.compare_digest(actual, public):
        raise ValueError("Chiave privata diversa da quella dell'app: non verrà emessa una licenza inutilizzabile.")
    studio = _text(input("Nome studio: ").strip(), "studio", 500)
    lawyer = _text(input("Nome e cognome avvocato: ").strip(), "avvocato", 500)
    title = input("Titolo [Avv. / Praticante, predefinito Avv.]: ").strip() or "Avv."
    if title not in ("Avv.", "Praticante"):
        raise ValueError("Titolo non valido.")
    key_id = _text(input("ID licenza [automatico]: ").strip() or str(uuid.uuid4()), "ID", 128)
    expiry, label = _parse_expiry(input("Scadenza AAAA-MM-GG, inclusa fino a fine giornata UTC [1 anno]: ").strip())
    if expiry <= int(datetime.now(timezone.utc).timestamp() * 1000):
        raise ValueError("La scadenza deve essere futura.")
    grace = int(input("Giorni dopo scadenza [0]: ").strip() or "0")
    hardware = input("ID dispositivo obbligatorio [vuoto = nessun vincolo nel token]: ").strip()
    payload = {"c": studio, "s": studio, "a": lawyer, "t": title, "e": expiry, "id": key_id, "n": secrets.token_hex(16)}
    if grace:
        payload["g"] = grace
    if hardware:
        payload["h"] = hardware
    token = sign_token(private, public, payload)
    del private
    password = get_password()
    entries = load_registry(password)
    if any(entry.get("id") == key_id for entry in entries):
        raise ValueError("ID già usato nel registro. Scegli un nuovo ID.")
    entries.append({"id": key_id, "studio": studio, "studio_name": studio, "lawyer_name": lawyer, "lawyer_title": title, "issued_at": datetime.now(timezone.utc).isoformat(), "expires_at": label, "expiry_ms": expiry, "burn_hash": compute_key_hash(token), "status": "issued", "nonce": payload["n"], "grace_days": grace, "hardware_id": hardware})
    save_registry(password, entries)
    print("Licenza firmata e registrata. Invia al destinatario solo il token seguente:")
    print(token)
    print("La chiave privata e il registro devono restare sul tuo computer.")


def cmd_verify(args):
    token = args.token.strip() if args.token else secret_prompt("Token da verificare: ").strip()
    payload = verify_token(token, expected_public_key())
    now = int(datetime.now(timezone.utc).timestamp() * 1000)
    expired = now > payload["e"] + payload.get("g", 0) * DAY_MS
    status = "SCADUTA" if expired else ("IN GRACE PERIOD" if now > payload["e"] else "VALIDA")
    print(f"Firma Ed25519 verificata. Licenza {status}.")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if payload.get("h"):
        print("Licenza vincolata a dispositivo: questo comando non verifica l'ID del destinatario.")
    print("La verifica è locale e non conferma attivazioni o revoche su altri computer.")
    return 1 if expired else 0


def csv_cell(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value


def cmd_registry(args):
    password = get_password()
    entries = load_registry(password)
    if args.command == "list":
        print(json.dumps(entries, ensure_ascii=False, indent=2))
    elif args.command == "stats":
        withdrawn = sum(e.get("status") == "burned" for e in entries)
        print(f"Licenze registrate: {len(entries)}; ritirate nel registro locale: {withdrawn}.")
        print("Un'app offline non comunica al generatore lo stato di attivazione.")
    elif args.command == "export":
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        fields = ("id", "studio", "lawyer_name", "issued_at", "expires_at", "status", "hardware_id", "grace_days")
        writer.writerow(fields)
        writer.writerows([csv_cell(entry.get(field, "")) for field in fields] for entry in entries)
        path = Path(args.output) if args.output else REGISTRY_FILE.parent / "lexflow-keys-export.csv"
        atomic_private_write(path, output.getvalue().encode("utf-8-sig"), replace=False)
        print(f"CSV in chiaro creato: {path}. Conserva il file in una destinazione appropriata.")
    elif args.command == "burn":
        target = args.id or input("ID da ritirare nel registro locale: ").strip()
        found = [entry for entry in entries if entry.get("id") == target and entry.get("status") != "burned"]
        if len(found) != 1:
            raise ValueError("ID assente, duplicato o già ritirato.")
        print("Il ritiro cambia solo questo registro: il token già distribuito continua a funzionare offline.")
        if input("Digita BURN per confermare: ").strip() != "BURN":
            print("Annullato.")
            return
        create_backup()
        found[0]["status"] = "burned"
        found[0]["burned_at"] = datetime.now(timezone.utc).isoformat()
        save_registry(password, entries)
        print("Ritiro registrato. Hash del token conservato per riconoscerlo.")
    elif args.command == "nuke":
        print("Elimina il registro corrente, conservandone un backup cifrato. Non revoca i token distribuiti.")
        if input("Digita NUKE per confermare: ").strip() != "NUKE":
            print("Annullato.")
            return
        if not REGISTRY_FILE.exists():
            raise ValueError("Nessun registro da eliminare.")
        backup = create_backup()
        REGISTRY_FILE.unlink()
        print(f"Registro rimosso; backup cifrato: {backup}. La cancellazione fisica su SSD non è garantita.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Licenze LexFlow offline: firma Ed25519 e registro cifrato locale.")
    sub = parser.add_subparsers(dest="command")
    generate = sub.add_parser("generate", help="Genera una licenza compatibile con la chiave pubblica del progetto")
    key_source = generate.add_mutually_exclusive_group()
    key_source.add_argument("--private-key-file", type=Path, help="File privato Hex/Base64/PEM; il contenuto non viene stampato")
    key_source.add_argument("--local-key", action="store_true", help="Usa la chiave locale configurata in Application Support, fuori da iCloud")
    verify = sub.add_parser("verify", help="Verifica realmente la firma, senza aprire il registro")
    verify.add_argument("token", nargs="?", help="Preferire il prompt per evitare token nella cronologia/processi")
    for command in ("list", "stats", "nuke"):
        sub.add_parser(command)
    burn = sub.add_parser("burn", help="Ritiro nel solo registro locale; nessuna revoca remota")
    burn.add_argument("id", nargs="?")
    export = sub.add_parser("export", help="Esporta un nuovo CSV in chiaro senza sovrascrivere file")
    export.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        if args.command == "verify":
            return cmd_verify(args)
        with registry_lock():
            if args.command == "generate":
                cmd_generate(args)
            else:
                cmd_registry(args)
        return 0
    except (OSError, ValueError) as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nOperazione annullata.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
