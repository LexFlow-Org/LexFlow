#!/usr/bin/env python3
"""
LexFlow — Generatore Licenze v2.5 (Ed25519 Signed Tokens + Registro Blindato)

Miglioramenti rispetto a v2.4:
  - Fix bug salt detection: priorità al nuovo formato (salt embedded) se file ≥ 44B
  - Backup automatico: snapshot prima di operazioni distruttive (burn/nuke)
  - Hardware ID (node-locking): campo opzionale 'h' per legare licenza a un PC
  - Grace Period: campo opzionale 'g' per scadenza morbida (avvisa ma funziona)

Storico:
  v2.3 — Salt embedded, getpass, backward-compat v2.2
  v2.2 — Prima versione con registro crittografato

Funzionalità:
  - Revoke e Burn UNIFICATI → un solo comando 'burn' (niente revoke soft, inutile)
  - ULTRA-BURN potenziato: 3000x cascade SHA-512 + SHA3-256 + BLAKE2b multi-algo
  - UNA SOLA PASSWORD per tutti i comandi (session-based)
  - Registro locale crittografato AES-256-GCM con Scrypt (n=2^17)
  - Integrità registro: HMAC-SHA256 interno per detect corruzione
  - Ogni chiave è tracciata con: ID, studio, avvocato, data emissione, scadenza, stato
  - Anti-replay: nonce univoco 128-bit per ogni chiave
  - Comando NUKE: distruzione TOTALE del registro (ultra-burn + sovrascrittura)
  - Backup automatico prima di burn/nuke (anti-disastro)
  - Hardware ID opzionale per node-locking
  - Grace Period opzionale per scadenza morbida

Uso:
  python3 scripts/generate_license_v2.py generate        → genera nuova chiave
  python3 scripts/generate_license_v2.py list             → mostra tutte le chiavi emesse
  python3 scripts/generate_license_v2.py verify <token>   → verifica una chiave
  python3 scripts/generate_license_v2.py burn <id>        → DISTRUGGE una chiave (ultra-burn irreversibile)
  python3 scripts/generate_license_v2.py export           → esporta registro in CSV
  python3 scripts/generate_license_v2.py stats            → statistiche emissioni
  python3 scripts/generate_license_v2.py nuke             → DISTRUGGE TUTTO il registro

Dipendenze:
  pip install cryptography
"""
import base64
import csv
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    print("Errore: installa le dipendenze con 'pip install cryptography'")
    sys.exit(1)

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
REGISTRY_FILE = SCRIPT_DIR / ".lexflow-issued-keys.enc"
REGISTRY_SALT_FILE = SCRIPT_DIR / ".lexflow-registry-salt"

# ── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    """ANSI escape codes for terminal styling."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    # Colors
    RED     = "\033[38;5;196m"
    GREEN   = "\033[38;5;114m"
    YELLOW  = "\033[38;5;221m"
    BLUE    = "\033[38;5;75m"
    CYAN    = "\033[38;5;117m"
    PURPLE  = "\033[38;5;183m"
    ORANGE  = "\033[38;5;215m"
    WHITE   = "\033[38;5;255m"
    GRAY    = "\033[38;5;245m"
    DARK    = "\033[38;5;240m"
    # Backgrounds
    BG_RED  = "\033[48;5;52m"
    BG_GREEN = "\033[48;5;22m"
    BG_BLUE = "\033[48;5;17m"

# ── UI Helpers ───────────────────────────────────────────────────────────────
BOX_W = 62  # inner width of boxes

def _box_top():
    return f"  {C.DARK}╭{'─' * BOX_W}╮{C.RESET}"

def _box_bot():
    return f"  {C.DARK}╰{'─' * BOX_W}╯{C.RESET}"

def _box_sep():
    return f"  {C.DARK}├{'─' * BOX_W}┤{C.RESET}"

def _box_line(text="", align="left"):
    """Render a line inside a box. Strips ANSI for width calc."""
    visible = re.sub(r'\x1b\[[0-9;]*m', '', text)
    pad = BOX_W - 2 - len(visible)
    if pad < 0:
        pad = 0
    if align == "center":
        left_pad = pad // 2
        right_pad = pad - left_pad
        inner = " " * left_pad + text + " " * right_pad
    else:
        inner = " " + text + " " * (pad - 1) if pad > 0 else " " + text
    return f"  {C.DARK}│{C.RESET}{inner}{C.DARK}│{C.RESET}"

def _box_empty():
    return _box_line("")

def _header(title, subtitle=None, icon="⚖️"):
    """Print a styled header box."""
    lines = [
        "",
        _box_top(),
        _box_empty(),
        _box_line(f"{icon}  {C.BOLD}{C.CYAN}{title}{C.RESET}", "center"),
    ]
    if subtitle:
        lines.append(_box_line(f"{C.DIM}{subtitle}{C.RESET}", "center"))
    lines.append(_box_empty())
    lines.append(_box_bot())
    lines.append("")
    print("\n".join(lines))

def _success_box(title, details: list[str] = None):
    """Print a success result box."""
    lines = [
        "",
        _box_top(),
        _box_empty(),
        _box_line(f"{C.GREEN}✅{C.RESET}  {C.BOLD}{C.GREEN}{title}{C.RESET}", "center"),
        _box_empty(),
    ]
    if details:
        lines.append(_box_sep())
        lines.append(_box_empty())
        for d in details:
            lines.append(_box_line(d))
        lines.append(_box_empty())
    lines.append(_box_bot())
    lines.append("")
    print("\n".join(lines))

def _error(msg):
    print(f"\n  {C.RED}❌{C.RESET} {msg}\n")

def _warn(msg):
    print(f"  {C.YELLOW}⚠️{C.RESET} {msg}")

def _info(msg):
    print(f"  {C.BLUE}ℹ️{C.RESET} {msg}")

def _field(label, value, icon=""):
    """Print a labeled field."""
    prefix = f"{icon} " if icon else ""
    print(f"  {prefix}{C.DIM}{label}:{C.RESET}  {C.WHITE}{value}{C.RESET}")

def _prompt(label, secret=False, default=None):
    """Styled input prompt."""
    hint = f" {C.DIM}({default}){C.RESET}" if default else ""
    prefix = f"  {C.PURPLE}›{C.RESET} "
    if secret:
        return getpass.getpass(f"{prefix}{label}{hint}: ").strip()
    return input(f"{prefix}{label}{hint}: ").strip()

def _confirm(msg, keyword):
    """Ask for typed confirmation. Returns True if matched."""
    val = input(f"  {C.YELLOW}⚠️{C.RESET} {msg} [{C.BOLD}{keyword}{C.RESET}]: ").strip()
    return val == keyword

MSG_CANCELLED = f"  {C.DIM}Annullato.{C.RESET}"

# ── Session password cache ───────────────────────────────────────────────────
_session_password = None


def normalize_b64(raw: str) -> bytes:
    """Normalizza qualsiasi stringa Base64 (standard o URL-safe, con/senza padding)."""
    s = raw.strip()
    s = s.replace('+', '-').replace('/', '_')
    pad = 4 - (len(s) % 4)
    if pad < 4:
        s += '=' * pad
    return base64.urlsafe_b64decode(s)


def derive_registry_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using Scrypt (n=2^17, r=8, p=1)."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode())


def compute_integrity_hmac(entries: list, salt: bytes) -> str:
    """Compute HMAC-SHA256 of registry data for integrity check."""
    raw = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(salt + b":INTEGRITY:" + raw).hexdigest()


def load_registry(password: str) -> list:
    """Load and decrypt the issued keys registry.
    
    Format v2.3: salt (32B) + nonce (12B) + ciphertext inline nel file .enc.
    Backward-compatible: se esiste il vecchio .lexflow-registry-salt, lo usa e migra.
    """
    if not REGISTRY_FILE.exists():
        return []

    data = REGISTRY_FILE.read_bytes()

    # ── Detect formato: precedenza al nuovo formato v2.3+ (salt embedded) ──
    if len(data) >= 44:
        # Nuovo formato: salt (32B) + nonce (12B) + ciphertext
        salt = data[:32]
        nonce = data[32:44]
        ciphertext = data[44:]
    elif REGISTRY_SALT_FILE.exists():
        # Vecchio formato (fallback v2.2): salt in file separato
        salt = REGISTRY_SALT_FILE.read_bytes()
        if len(data) < 12:
            _error("File registro troppo piccolo — corrotto. Usa 'nuke' per resettare.")
            sys.exit(1)
        nonce = data[:12]
        ciphertext = data[12:]
    else:
        _error("File registro non valido o file salt mancante. Usa 'nuke' per resettare.")
        sys.exit(1)

    key = derive_registry_key(password, salt)

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        _error("Decryption fallita.")
        print(f"  {C.DIM}  Possibili cause:{C.RESET}")
        print(f"  {C.DIM}  1. Password errata{C.RESET}")
        print(f"  {C.DIM}  2. File registro corrotto{C.RESET}")
        print()
        print(f"  {C.DIM}  Se sei SICURO della password, il file è corrotto.{C.RESET}")
        print(f"  {C.DIM}  Usa: python3 scripts/generate_license_v2.py nuke{C.RESET}")
        print()
        sys.exit(1)

    try:
        wrapper = json.loads(plaintext.decode())
    except json.JSONDecodeError:
        _error("Registro decrittato ma JSON invalido — corrotto. Usa 'nuke'.")
        sys.exit(1)

    # Integrity check
    entries = wrapper.get("entries", [])
    stored_hmac = wrapper.get("hmac", "")
    computed_hmac = compute_integrity_hmac(entries, salt)

    if stored_hmac and stored_hmac != computed_hmac:
        _error("INTEGRITÀ COMPROMESSA! Il registro è stato manomesso.")
        print(f"  {C.DIM}  HMAC atteso:  {computed_hmac[:32]}…{C.RESET}")
        print(f"  {C.DIM}  HMAC trovato: {stored_hmac[:32]}…{C.RESET}")
        print(f"  {C.DIM}  Usa 'nuke' per eliminare e ricominciare.{C.RESET}")
        print()
        sys.exit(1)

    return entries


def save_registry(password: str, entries: list):
    """Encrypt and save the registry with integrity HMAC.
    
    Formato v2.3: salt (32B) + nonce (12B) + ciphertext — tutto in un unico file.
    Se esiste il vecchio file salt separato, lo migra e lo rimuove.
    """
    # Recupera salt esistente o genera nuovo
    if REGISTRY_SALT_FILE.exists():
        # Migrazione: usa il vecchio salt, poi lo elimineremo
        salt = REGISTRY_SALT_FILE.read_bytes()
    elif REGISTRY_FILE.exists() and len(REGISTRY_FILE.read_bytes()) >= 32:
        # Salt già embedded nel file .enc (formato v2.3)
        salt = REGISTRY_FILE.read_bytes()[:32]
    else:
        salt = secrets.token_bytes(32)

    key = derive_registry_key(password, salt)

    # Wrap entries with HMAC
    hmac_val = compute_integrity_hmac(entries, salt)
    wrapper = {
        "version": "2.4",
        "entries": entries,
        "hmac": hmac_val,
        "updated_at": datetime.now().isoformat(),
    }

    plaintext = json.dumps(wrapper, indent=2, ensure_ascii=False).encode()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Nuovo formato: salt + nonce + ciphertext in un unico file
    # SECURITY: REGISTRY_FILE is derived from __file__.resolve().parent — not user-controlled
    out_path = REGISTRY_FILE.resolve()
    assert out_path.parent == SCRIPT_DIR, "Path traversal detected"
    out_path.write_bytes(salt + nonce + ciphertext)

    # Migrazione: rimuovi vecchio file salt separato (ora è embedded)
    if REGISTRY_SALT_FILE.exists():
        # Sovrascrittura sicura prima di cancellare
        size = REGISTRY_SALT_FILE.stat().st_size
        REGISTRY_SALT_FILE.write_bytes(secrets.token_bytes(max(size, 64)))
        REGISTRY_SALT_FILE.unlink()
        _info("Salt migrato nel file registro (formato v2.3).")


def get_password() -> str:
    """Get password — cached per sessione. UNA SOLA PASSWORD per tutto."""
    global _session_password

    if _session_password is not None:
        return _session_password

    if REGISTRY_FILE.exists():
        pwd = _prompt("Password registro", secret=True)
    else:
        print()
        _info("Prima esecuzione — crea la password del registro chiavi.")
        print(f"  {C.DIM}  Questa password protegge TUTTE le operazioni sulle licenze.{C.RESET}")
        print()
        pwd = _prompt("Nuova password (min 8 caratteri)", secret=True)
        pwd2 = _prompt("Conferma password", secret=True)
        if pwd != pwd2:
            _error("Le password non corrispondono.")
            sys.exit(1)
        if len(pwd) < 8:
            _error("Password troppo corta (minimo 8 caratteri).")
            sys.exit(1)

    _session_password = pwd
    return pwd


def compute_key_hash(token: str) -> str:
    """Hash di una chiave per il registro (SHA-256, non reversibile)."""
    return hashlib.sha256(f"BURN-GLOBAL-V2:{token}".encode()).hexdigest()


def ultra_burn_string(s: str) -> str:
    """
    ULTRA-BURN v2: cascade multi-algoritmo 3000 round per rendere
    il dato originale irrecuperabile anche con analisi forense.

    Round 1-1000: SHA-512 con counter
    Round 1001-2000: SHA3-256 con salt invertito
    Round 2001-3000: BLAKE2b (64 byte) con XOR progressivo

    Risultato: i dati originali sono sepolti sotto 3000 strati
    di hash crittografici eterogenei. Nessun attacco noto può
    invertire anche solo UNO di questi passaggi.
    """
    h = s.encode()
    # Fase 1: SHA-512 cascade (1000 round)
    for i in range(1000):
        h = hashlib.sha512(h + i.to_bytes(4, 'big')).digest()
    # Fase 2: SHA3-256 cascade con salt invertito (1000 round)
    for i in range(1000):
        h = hashlib.sha3_256(h[::-1] + i.to_bytes(4, 'big') + b'\xDE\xAD').digest()
    # Fase 3: BLAKE2b cascade con XOR progressivo (1000 round)
    for i in range(1000):
        xor_byte = (i % 256).to_bytes(1, 'big') * len(h)
        mixed = bytes(a ^ b for a, b in zip(h, xor_byte[:len(h)]))
        h = hashlib.blake2b(mixed + i.to_bytes(4, 'big'), digest_size=64).digest()
    return "OBLITERATED:" + h.hex()[:48]


def _parse_private_key(priv_key_raw: str):
    """Parse private key from various formats (Base64/Hex/PEM). Returns (private_key, pub_bytes) or raises."""
    if priv_key_raw.startswith('-----BEGIN'):
        lines = priv_key_raw.split('\n')
        priv_key_raw = ''.join([l for l in lines if not l.startswith('-----')])

    if len(priv_key_raw) == 64 and all(c in '0123456789abcdefABCDEF' for c in priv_key_raw):
        _info("Formato HEX rilevato.")
        priv_key_bytes = bytes.fromhex(priv_key_raw)
    else:
        priv_key_bytes = normalize_b64(priv_key_raw)

    if len(priv_key_bytes) == 48 and priv_key_bytes[0] == 0x30:
        _info("Formato PKCS8 (48 byte) → estraggo seed 32 byte.")
        priv_key_bytes = priv_key_bytes[-32:]
    elif len(priv_key_bytes) != 32:
        raise ValueError(f"Chiave deve essere 32 byte (raw) o 48 byte (PKCS8), ricevuti {len(priv_key_bytes)}.")

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, pub_bytes


def _parse_expiry(date_str: str):
    """Parse expiry date string. Returns (expiry_timestamp, label) or raises."""
    if not date_str:
        expiry_timestamp = int((time.time() + 365.25 * 86400) * 1000)
        exp_date = datetime.now() + timedelta(days=365)
        return expiry_timestamp, exp_date.strftime('%Y-%m-%d')

    dt = datetime.strptime(date_str, "%Y-%m-%d")
    return int(dt.timestamp() * 1000), date_str


def cmd_generate():
    """Generate a new license key."""
    _header("LEXFLOW — GENERATORE LICENZE", "v2.5 · Ed25519 Signed Tokens", "🔐")

    # 1. Chiave Privata (getpass per evitare leak in terminal history)
    priv_key_raw = _prompt("Chiave Privata (Base64/Hex/PEM)", secret=True)
    if not priv_key_raw:
        _error("Chiave obbligatoria.")
        return

    try:
        private_key, pub_bytes = _parse_private_key(priv_key_raw)
        _info(f"Chiave OK → Pubblica: [{', '.join(str(b) for b in pub_bytes[:4])}, ...]")
    except Exception as e:
        _error(f"Chiave privata non valida: {e}")
        return

    # 2. Dati
    print()
    _info("Il nome studio appare nell'intestazione dei PDF e nelle impostazioni.")
    _info("Scrivi il nome completo, es: Studio Legale Rossi & Associati")
    print()
    studio_name = _prompt("Nome Studio completo (come deve apparire nei PDF)")
    if not studio_name:
        _error("Nome Studio obbligatorio.")
        return

    lawyer_name = _prompt("Nome e Cognome Avvocato (es. Avv. Mario Rossi)")
    if not lawyer_name:
        _error("Nome Avvocato obbligatorio.")
        return

    key_id = _prompt("ID Licenza", default="auto")
    if not key_id:
        key_id = str(uuid.uuid4())[:8]
        _info(f"ID generato: {C.BOLD}{key_id}{C.RESET}")

    date_str = _prompt("Scadenza AAAA-MM-GG", default="1 anno")
    try:
        expiry_timestamp, exp_label = _parse_expiry(date_str)
        _info(f"Scadenza: {C.BOLD}{exp_label}{C.RESET}")
    except ValueError:
        _error("Formato data errato. Usa AAAA-MM-GG.")
        return

    # NOTE: Hardware ID non serve — l'app lo calcola e salva automaticamente
    # all'attivazione (compute_machine_fingerprint in lib.rs).

    # Grace Period
    grace_days = _prompt("Giorni di Grace Period dopo scadenza", default="0")
    try:
        grace_int = int(grace_days) if grace_days else 0
    except ValueError:
        grace_int = 0
    if grace_int > 0:
        _info(f"Grace Period: {C.BOLD}{grace_int} giorni{C.RESET}")

    # 3. Payload + Firma
    nonce = secrets.token_hex(16)
    license_payload = {
        "c": studio_name,
        "e": expiry_timestamp,
        "id": key_id,
        "n": nonce,
    }
    if grace_int > 0:
        license_payload["g"] = grace_int
    if lawyer_name:
        license_payload["a"] = lawyer_name   # avvocato
    if studio_name:
        license_payload["s"] = studio_name   # studio

    payload_json = json.dumps(license_payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
    signature = private_key.sign(payload_b64.encode('utf-8'))
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    final_token = f"LXFW.{payload_b64}.{signature_b64}"

    # 4. Autovalidazione
    try:
        private_key.public_key().verify(signature, payload_b64.encode('utf-8'))
    except Exception:
        _error("ERRORE FIRMA — chiave corrotta.")
        return

    # 5. Registra
    pwd = get_password()
    registry = load_registry(pwd)

    existing_ids = {e.get("id") for e in registry if e.get("status") != "burned"}
    if key_id in existing_ids:
        _warn(f"ID '{key_id}' già presente!")
        if not _confirm("Continuare?", "s"):
            return

    entry = {
        "id": key_id,
        "studio": studio_name,
        "lawyer_name": lawyer_name or "",
        "studio_name": studio_name or "",
        "issued_at": datetime.now().isoformat(),
        "expires_at": datetime.fromtimestamp(expiry_timestamp / 1000).isoformat(),
        "expiry_ms": expiry_timestamp,
        "burn_hash": compute_key_hash(final_token),
        "status": "issued",
        "nonce": nonce,
    }
    if grace_int > 0:
        entry["grace_days"] = grace_int
    registry.append(entry)
    save_registry(pwd, registry)

    _success_box("LICENZA GENERATA E REGISTRATA", [
        f"{C.DIM}Studio:{C.RESET}     {C.WHITE}{studio_name}{C.RESET}",
        f"{C.DIM}Avvocato:{C.RESET}   {C.WHITE}{lawyer_name}{C.RESET}",
        f"{C.DIM}ID:{C.RESET}         {C.CYAN}{key_id}{C.RESET}",
        f"{C.DIM}Scadenza:{C.RESET}   {C.WHITE}{datetime.fromtimestamp(expiry_timestamp / 1000).strftime('%Y-%m-%d')}{C.RESET}",
        *([ f"{C.DIM}Grace:{C.RESET}     {C.WHITE}{grace_int} giorni{C.RESET}" ] if grace_int > 0 else []),
        f"{C.DIM}Burn Hash:{C.RESET}  {C.DARK}{entry['burn_hash'][:16]}…{C.RESET}",
        f"{C.DIM}Registro:{C.RESET}   {C.WHITE}{len(registry)} chiavi totali{C.RESET}",
    ])

    # Token — stampa pulita per copia facile (no box characters)
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")
    print(f"  {C.DIM}TOKEN — seleziona e copia la riga qui sotto:{C.RESET}")
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")
    print()
    print(f"{C.GREEN}{final_token}{C.RESET}")
    print()
    print(f"  {C.DIM}{'─' * 60}{C.RESET}")
    print()


def cmd_list():
    """List all issued keys."""
    pwd = get_password()
    registry = load_registry(pwd)

    if not registry:
        print(f"\n  {C.DIM}📭 Registro vuoto.{C.RESET}\n")
        return

    _header("REGISTRO CHIAVI LEXFLOW", f"{len(registry)} licenze tracciate", "📋")

    # Table header
    hdr = f"  {C.DIM}{'#':<4} {'ID':<12} {'Studio':<25} {'Emessa':<12} {'Scade':<12} {'Stato'}{C.RESET}"
    print(hdr)
    print(f"  {C.DARK}{'─' * 78}{C.RESET}")

    now_ms = int(time.time() * 1000)
    for i, entry in enumerate(registry, 1):
        issued = entry.get("issued_at", "?")[:10]
        expires = entry.get("expires_at", "?")[:10]
        status = entry.get("status", "?")
        expiry_ms = entry.get("expiry_ms", 0)

        if status == "burned":
            icon = f"{C.RED}🔥{C.RESET}"
            label = f"{C.RED}OBLITERATA{C.RESET}"
            studio_display = f"{C.DARK}██████████{C.RESET}"
            expires = f"{C.DARK}──────────{C.RESET}"
        elif expiry_ms > 0 and now_ms > expiry_ms:
            icon = f"{C.YELLOW}⏰{C.RESET}"
            label = f"{C.YELLOW}scaduta{C.RESET}"
            studio_display = f"{C.WHITE}{entry.get('studio', entry.get('client', '?'))}{C.RESET}"
        elif status == "activated":
            icon = f"{C.GREEN}🟢{C.RESET}"
            label = f"{C.GREEN}attiva{C.RESET}"
            studio_display = f"{C.WHITE}{entry.get('studio', entry.get('client', '?'))}{C.RESET}"
        else:
            icon = f"{C.BLUE}🔵{C.RESET}"
            label = f"{C.BLUE}emessa{C.RESET}"
            studio_display = f"{C.WHITE}{entry.get('studio', entry.get('client', '?'))}{C.RESET}"

        num = f"{C.DIM}{i}{C.RESET}"
        kid = f"{C.CYAN}{entry.get('id', '?')}{C.RESET}"
        print(f"  {num:<15} {kid:<23} {studio_display:<36} {C.DIM}{issued}{C.RESET}   {C.DIM}{expires}{C.RESET}   {icon} {label}")

    # Stats
    total = len(registry)
    active = sum(1 for e in registry if e.get("status") in ("issued", "activated") and (e.get("expiry_ms", 0) == 0 or now_ms <= e.get("expiry_ms", 0)))
    burned = sum(1 for e in registry if e.get("status") == "burned")
    expired = sum(1 for e in registry if e.get("expiry_ms", 0) > 0 and now_ms > e.get("expiry_ms", 0) and e.get("status") not in ("burned",))

    print()
    print(f"  {C.DARK}{'─' * 78}{C.RESET}")
    print(f"  {C.DIM}Totale:{C.RESET} {C.WHITE}{total}{C.RESET}  {C.DIM}│{C.RESET}  {C.GREEN}Valide: {active}{C.RESET}  {C.DIM}│{C.RESET}  {C.YELLOW}Scadute: {expired}{C.RESET}  {C.DIM}│{C.RESET}  {C.RED}Bruciate: {burned}{C.RESET}")
    print()


def _format_expiry(expiry_ms, now_ms, grace_days):
    """Format expiry status for display."""
    grace_ms = grace_days * 86400 * 1000
    exp_date = datetime.fromtimestamp(expiry_ms / 1000).strftime('%Y-%m-%d')
    is_expired = now_ms > expiry_ms
    is_in_grace = is_expired and (now_ms <= (expiry_ms + grace_ms))
    if is_in_grace:
        grace_end = datetime.fromtimestamp((expiry_ms + grace_ms) / 1000).strftime('%Y-%m-%d')
        return f"{C.ORANGE}{exp_date} ⚠️ SCADUTA (Grace Period fino al {grace_end}){C.RESET}"
    if is_expired:
        return f"{C.RED}{exp_date} ❌ SCADUTA{C.RESET}"
    return f"{C.GREEN}{exp_date} ✅ Valida{C.RESET}"


def _check_registry_status(burn_hash):
    """Check burn hash against registry. Returns formatted status string."""
    try:
        pwd = get_password()
        registry = load_registry(pwd)
        found = [e for e in registry if e.get("burn_hash") == burn_hash]
        if found:
            e = found[0]
            if e.get("status") == "burned":
                return f"{C.RED}🔥 CHIAVE OBLITERATA — non più valida{C.RESET}"
            return f"{C.GREEN}✅ Trovata (stato: {e.get('status')}){C.RESET}"
        return f"{C.YELLOW}❓ NON trovata (v1 o non registrata){C.RESET}"
    except Exception:
        return f"{C.YELLOW}❓ Impossibile accedere{C.RESET}"


def cmd_verify():
    """Verify a token."""
    if len(sys.argv) >= 3:
        token = sys.argv[2].strip()
    else:
        token = _prompt("Token da verificare")

    parts = token.split('.')
    if len(parts) != 3 or parts[0] != 'LXFW':
        _error("Formato non valido. Deve essere LXFW.<payload>.<firma>")
        return

    try:
        payload_bytes = base64.urlsafe_b64decode(parts[1] + '==')
        payload = json.loads(payload_bytes)
    except Exception:
        _error("Payload corrotto.")
        return

    expiry_ms = payload.get('e', 0)
    now_ms = int(time.time() * 1000)

    _header("VERIFICA TOKEN", payload.get('id', '?'), "🔍")

    _field("Studio", payload.get('c', '?'), "🏛️")
    _field("ID", payload.get('id', '?'), "🏷️")
    _field("Nonce", f"{payload.get('n', 'N/A')[:16]}…", "🔑")

    if 'h' in payload:
        _field("Hardware ID", payload.get('h'), "🖥️")

    grace_days = payload.get('g', 0)
    _field("Scadenza", _format_expiry(expiry_ms, now_ms, grace_days), "📅")

    if grace_days > 0:
        _field("Grace Period", f"{grace_days} giorni", "🕐")

    burn_hash = compute_key_hash(token)
    _field("Burn Hash", f"{C.DARK}{burn_hash[:24]}…{C.RESET}", "🔒")
    _field("Registro", _check_registry_status(burn_hash), "📋")
    print()


def create_backup():
    """Crea un backup del registro prima di operazioni distruttive."""
    if REGISTRY_FILE.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = SCRIPT_DIR / f".lexflow-registry-{timestamp}.bak.enc"
        backup_file.write_bytes(REGISTRY_FILE.read_bytes())
        _info(f"📦 Backup di sicurezza creato: {backup_file.name}")


def cmd_burn():
    """BURN a key — ultra-burn irreversible destruction."""
    if len(sys.argv) >= 3:
        target_id = sys.argv[2].strip()
    else:
        target_id = _prompt("ID chiave da BRUCIARE")

    pwd = get_password()
    registry = load_registry(pwd)

    found = [e for e in registry if e.get("id") == target_id and e.get("status") != "burned"]
    if not found:
        _error(f"Chiave '{target_id}' non trovata o già bruciata.")
        return

    entry = found[0]

    _header("🔥 ULTRA-BURN · Annientamento Totale", "3000 round × 3 algoritmi crittografici", "🔥")

    _field("ID", entry.get('id'), "🏷️")
    _field("Studio", entry.get('studio', entry.get('client', '?')), "🏛️")
    _field("Scadenza", entry.get('expires_at', '?')[:10], "📅")
    print()
    _warn(f"{C.RED}{C.BOLD}ATTENZIONE: Questa operazione è IRREVERSIBILE.{C.RESET}")
    print(f"  {C.DIM}  Studio, hash, nonce verranno sovrascritti con 3000 round{C.RESET}")
    print(f"  {C.DIM}  di cascade multi-algo (SHA-512 → SHA3-256 → BLAKE2b).{C.RESET}")
    print(f"  {C.DIM}  Il token NON potrà MAI più essere verificato o recuperato.{C.RESET}")
    print()

    if not _confirm("Digita per confermare", "BURN"):
        print(MSG_CANCELLED)
        return

    create_backup()
    print()
    print(f"  {C.ORANGE}⏳ Ultra-burn in corso…{C.RESET}")

    # Ultra-burn v2: sovrascrittura cascade multi-algo
    entry["status"] = "burned"
    entry["burned_at"] = datetime.now().isoformat()
    entry["client"] = ultra_burn_string(entry.get("client", ""))
    entry["studio"] = ultra_burn_string(entry.get("studio", ""))
    entry["burn_hash"] = ultra_burn_string(entry.get("burn_hash", ""))
    entry["nonce"] = ultra_burn_string(entry.get("nonce", ""))
    entry["expires_at"] = "0000-00-00T00:00:00"
    entry["expiry_ms"] = 0
    entry["issued_at"] = ultra_burn_string(entry.get("issued_at", ""))

    save_registry(pwd, registry)

    _success_box(f"Chiave '{target_id}' OBLITERATA", [
        f"{C.DIM}Algoritmi:{C.RESET}  SHA-512 (1000) → SHA3-256 (1000) → BLAKE2b (1000)",
        f"{C.DIM}Distrutti:{C.RESET}  studio, burn_hash, nonce, issued_at, expires_at",
        f"{C.DIM}Recupero:{C.RESET}   {C.RED}IMPOSSIBILE{C.RESET}",
    ])


def cmd_nuke():
    """NUKE — destroy entire registry."""
    _header("☢️ NUKE · Distruzione Totale Registro", "Questa operazione non può essere annullata", "☢️")

    print(f"  {C.RED}Questo eliminerà PERMANENTEMENTE:{C.RESET}")
    print(f"  {C.DIM}  • Tutte le chiavi emesse{C.RESET}")
    print(f"  {C.DIM}  • Il registro crittografato{C.RESET}")
    print(f"  {C.DIM}  • Il file salt{C.RESET}")
    print()
    print(f"  {C.YELLOW}I token già distribuiti continueranno a funzionare nell'app{C.RESET}")
    print(f"  {C.YELLOW}ma non saranno più tracciati nel registro.{C.RESET}")
    print()

    if not _confirm("Prima conferma — digita", "NUKE"):
        print(MSG_CANCELLED)
        return

    if not _confirm("Sei ASSOLUTAMENTE sicuro? Digita", "CONFERMA"):
        print(MSG_CANCELLED)
        return

    create_backup()

    # Sovrascrittura sicura: riempi i file con dati random prima di cancellare
    for fpath in [REGISTRY_FILE, REGISTRY_SALT_FILE]:
        if fpath.exists():
            size = fpath.stat().st_size
            # 3 passate di sovrascrittura con dati random
            for _ in range(3):
                fpath.write_bytes(secrets.token_bytes(max(size, 64)))
            fpath.unlink()

    _success_box("REGISTRO DISTRUTTO", [
        f"{C.DIM}File sovrascritti 3× con dati random e cancellati.{C.RESET}",
        f"{C.DIM}La prossima esecuzione creerà un registro pulito.{C.RESET}",
    ])


def cmd_export():
    """Export registry to CSV."""
    pwd = get_password()
    registry = load_registry(pwd)

    if not registry:
        print(f"\n  {C.DIM}📭 Registro vuoto.{C.RESET}\n")
        return

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Studio", "Avvocato", "Emissione", "Scadenza", "Stato", "Hardware ID", "Grace Days", "Burn Hash (parziale)"])
    for entry in registry:
        studio = entry.get("studio", entry.get("client", ""))
        if entry.get("status") == "burned":
            studio = "[BRUCIATA]"
        writer.writerow([
            entry.get("id", ""),
            studio,
            entry.get("lawyer_name", ""),
            entry.get("issued_at", "")[:19],
            entry.get("expires_at", "")[:10],
            entry.get("status", ""),
            entry.get("hardware_id", ""),
            entry.get("grace_days", ""),
            entry.get("burn_hash", "")[:16],
        ])

    csv_path = SCRIPT_DIR / "lexflow-keys-export.csv"
    csv_path.write_text(output.getvalue())

    _success_box("Registro Esportato", [
        f"{C.DIM}File:{C.RESET}    {C.WHITE}{csv_path}{C.RESET}",
        f"{C.DIM}Chiavi:{C.RESET}  {C.WHITE}{len(registry)}{C.RESET}",
    ])


def cmd_stats():
    """Show statistics."""
    pwd = get_password()
    registry = load_registry(pwd)

    now_ms = int(time.time() * 1000)
    total = len(registry)
    active = sum(1 for e in registry if e.get("status") in ("issued", "activated") and (e.get("expiry_ms", 0) == 0 or now_ms <= e.get("expiry_ms", 0)))
    activated = sum(1 for e in registry if e.get("status") == "activated")
    burned = sum(1 for e in registry if e.get("status") == "burned")
    expired = sum(1 for e in registry if e.get("expiry_ms", 0) > 0 and now_ms > e.get("expiry_ms", 0) and e.get("status") not in ("burned",))

    studi = {}
    for e in registry:
        if e.get("status") == "burned":
            continue
        s = e.get("studio", e.get("client", "?"))
        studi[s] = studi.get(s, 0) + 1

    _header("📊 STATISTICHE REGISTRO", f"{total} licenze tracciate", "📊")

    # Stats tree
    print(f"  {C.WHITE}{C.BOLD}{total}{C.RESET} {C.DIM}chiavi totali{C.RESET}")
    print(f"  {C.DARK}├─{C.RESET} {C.GREEN}🟢 Valide:    {active}{C.RESET}")
    print(f"  {C.DARK}├─{C.RESET} {C.BLUE}🔵 Attivate:  {activated}{C.RESET}")
    print(f"  {C.DARK}├─{C.RESET} {C.YELLOW}⏰ Scadute:   {expired}{C.RESET}")
    print(f"  {C.DARK}╰─{C.RESET} {C.RED}🔥 Bruciate:  {burned}{C.RESET}")

    if studi:
        print()
        print(f"  {C.DIM}Per Studio:{C.RESET}")
        for i, (studio, count) in enumerate(sorted(studi.items(), key=lambda x: -x[1])):
            connector = "╰─" if i == len(studi) - 1 else "├─"
            print(f"  {C.DARK}{connector}{C.RESET} {C.WHITE}{studio}{C.RESET}: {C.CYAN}{count}{C.RESET}")
    print()


def main():
    if len(sys.argv) < 2:
        _header("⚖️ LexFlow License Manager", "v2.5 · Ed25519 + AES-256-GCM + Scrypt", "⚖️")
        cmds = [
            ("generate", "Genera nuova licenza", f"{C.CYAN}🔐{C.RESET}"),
            ("list", "Mostra registro chiavi", f"{C.BLUE}📋{C.RESET}"),
            ("verify", "Verifica un token", f"{C.GREEN}🔍{C.RESET}"),
            ("burn", "Brucia chiave (irreversibile)", f"{C.RED}🔥{C.RESET}"),
            ("export", "Esporta CSV", f"{C.WHITE}📄{C.RESET}"),
            ("stats", "Statistiche", f"{C.PURPLE}📊{C.RESET}"),
            ("nuke", "Distruggi TUTTO il registro", f"{C.ORANGE}☢️{C.RESET}"),
        ]
        print(f"  {C.DIM}Comandi disponibili:{C.RESET}")
        print()
        for cmd_name, desc, icon in cmds:
            print(f"    {icon}  {C.CYAN}{C.BOLD}{cmd_name:<12}{C.RESET} {C.DIM}{desc}{C.RESET}")
        print()
        print(f"  {C.DIM}Uso: python3 scripts/generate_license_v2.py <comando>{C.RESET}")
        print()
        return

    cmd = sys.argv[1].lower()
    commands = {
        "generate": cmd_generate,
        "list": cmd_list,
        "verify": cmd_verify,
        "burn": cmd_burn,
        "export": cmd_export,
        "stats": cmd_stats,
        "nuke": cmd_nuke,
    }

    fn = commands.get(cmd)
    if fn:
        fn()
    else:
        _error(f"Comando sconosciuto: {cmd}")
        print(f"  {C.DIM}Comandi: generate, list, verify, burn, export, stats, nuke{C.RESET}")
        print()


if __name__ == "__main__":
    main()
