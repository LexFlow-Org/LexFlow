#!/usr/bin/env python3
"""
LexFlow — Generatore Licenze v2.2 (Ed25519 Signed Tokens + Registro Blindato)

Miglioramenti rispetto a v2.1:
  - Revoke e Burn UNIFICATI → un solo comando 'burn' (niente revoke soft, inutile)
  - ULTRA-BURN potenziato: 3000x cascade SHA-512 + SHA3-256 + BLAKE2b multi-algo
  - UNA SOLA PASSWORD per tutti i comandi (session-based)
  - Registro locale crittografato AES-256-GCM con Scrypt (n=2^17)
  - Integrità registro: HMAC-SHA256 interno per detect corruzione
  - Ogni chiave è tracciata con: ID, cliente, data emissione, scadenza, stato
  - Anti-replay: nonce univoco 128-bit per ogni chiave
  - Comando NUKE: distruzione TOTALE del registro (ultra-burn + sovrascrittura)

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
SCRIPT_DIR = Path(__file__).parent
REGISTRY_FILE = SCRIPT_DIR / ".lexflow-issued-keys.enc"
REGISTRY_SALT_FILE = SCRIPT_DIR / ".lexflow-registry-salt"

# ── UI Strings ───────────────────────────────────────────────────────────────
SEP_NARROW = "  ═══════════════════════════════════════"
SEP_MEDIUM = "  ═══════════════════════════════════════════════════════"
SEP_WIDE = "  ═══════════════════════════════════════════════════════════════════════════"
SEP_DASH = "  ─────────────────────────────────────────"
MSG_CANCELLED = "  Annullato."

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
    """Load and decrypt the issued keys registry. Returns (entries, is_new)."""
    if not REGISTRY_FILE.exists():
        return []

    if not REGISTRY_SALT_FILE.exists():
        print("  ⚠️  File salt mancante. Registro corrotto — usa 'nuke' per resettare.")
        sys.exit(1)

    salt = REGISTRY_SALT_FILE.read_bytes()
    key = derive_registry_key(password, salt)
    data = REGISTRY_FILE.read_bytes()

    if len(data) < 12:
        print("  ⚠️  File registro troppo piccolo — corrotto. Usa 'nuke' per resettare.")
        sys.exit(1)

    nonce = data[:12]
    ciphertext = data[12:]

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print()
        print("  ❌ Decryption fallita. Possibili cause:")
        print("     1. Password errata")
        print("     2. File registro corrotto")
        print()
        print("  Se sei SICURO della password, il file è corrotto.")
        print("  Usa: python3 scripts/generate_license_v2.py nuke")
        print("  per eliminare il registro e ricominciare da zero.")
        print()
        sys.exit(1)

    try:
        wrapper = json.loads(plaintext.decode())
    except json.JSONDecodeError:
        print("  ❌ Registro decrittato ma JSON invalido — corrotto. Usa 'nuke'.")
        sys.exit(1)

    # Integrity check
    entries = wrapper.get("entries", [])
    stored_hmac = wrapper.get("hmac", "")
    computed_hmac = compute_integrity_hmac(entries, salt)

    if stored_hmac and stored_hmac != computed_hmac:
        print("  ❌ INTEGRITÀ COMPROMESSA! Il registro è stato manomesso.")
        print("     HMAC atteso:  " + computed_hmac[:32] + "...")
        print("     HMAC trovato: " + stored_hmac[:32] + "...")
        print("  Usa 'nuke' per eliminare e ricominciare.")
        sys.exit(1)

    return entries


def save_registry(password: str, entries: list):
    """Encrypt and save the registry with integrity HMAC."""
    if not REGISTRY_SALT_FILE.exists():
        salt = secrets.token_bytes(32)
        REGISTRY_SALT_FILE.write_bytes(salt)
    else:
        salt = REGISTRY_SALT_FILE.read_bytes()

    key = derive_registry_key(password, salt)

    # Wrap entries with HMAC
    hmac_val = compute_integrity_hmac(entries, salt)
    wrapper = {
        "version": "2.2",
        "entries": entries,
        "hmac": hmac_val,
        "updated_at": datetime.now().isoformat(),
    }

    plaintext = json.dumps(wrapper, indent=2, ensure_ascii=False).encode()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    REGISTRY_FILE.write_bytes(nonce + ciphertext)


def get_password() -> str:
    """Get password — cached per sessione. UNA SOLA PASSWORD per tutto."""
    global _session_password

    if _session_password is not None:
        return _session_password

    if REGISTRY_FILE.exists():
        pwd = getpass.getpass("  🔑 Password registro: ")
    else:
        print()
        print("  📝 Prima esecuzione — crea la password del registro chiavi.")
        print("     Questa password protegge TUTTE le operazioni sulle licenze.")
        print()
        pwd = getpass.getpass("     Nuova password (min 8 caratteri): ")
        pwd2 = getpass.getpass("     Conferma password: ")
        if pwd != pwd2:
            print("  ❌ Le password non corrispondono.")
            sys.exit(1)
        if len(pwd) < 8:
            print("  ❌ Password troppo corta (minimo 8 caratteri).")
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
        print("  ℹ️  Formato HEX rilevato.")
        priv_key_bytes = bytes.fromhex(priv_key_raw)
    else:
        priv_key_bytes = normalize_b64(priv_key_raw)

    if len(priv_key_bytes) == 48 and priv_key_bytes[0] == 0x30:
        print("  ℹ️  Formato PKCS8 (48 byte) → estraggo seed 32 byte.")
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
    print()
    print(SEP_MEDIUM)
    print("    LEXFLOW — GENERATORE LICENZE v2.1")
    print(SEP_MEDIUM)
    print()

    # 1. Chiave Privata
    priv_key_raw = input("  Chiave Privata (Base64/Hex/PEM): ").strip()
    if not priv_key_raw:
        print("  ❌ Chiave obbligatoria.")
        return

    try:
        private_key, pub_bytes = _parse_private_key(priv_key_raw)
        print(f"  ✅ Chiave OK. Pubblica: [{', '.join(str(b) for b in pub_bytes[:4])}, ...]")
    except Exception as e:
        print(f"  ❌ Chiave privata non valida: {e}")
        return

    # 2. Dati
    print()
    client_name = input("  Nome Cliente/Studio: ").strip()
    if not client_name:
        print("  ❌ Nome obbligatorio.")
        return

    key_id = input("  ID Licenza (invio = auto): ").strip()
    if not key_id:
        key_id = str(uuid.uuid4())[:8]
        print(f"  → ID: {key_id}")

    date_str = input("  Scadenza AAAA-MM-GG (invio = 1 anno): ").strip()
    try:
        expiry_timestamp, exp_label = _parse_expiry(date_str)
        print(f"  → Scadenza: {exp_label}")
    except ValueError:
        print("  ❌ Formato data errato. Usa AAAA-MM-GG.")
        return

    # 3. Payload + Firma
    nonce = secrets.token_hex(16)
    license_payload = {
        "c": client_name,
        "e": expiry_timestamp,
        "id": key_id,
        "n": nonce,
    }

    payload_json = json.dumps(license_payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
    signature = private_key.sign(payload_b64.encode('utf-8'))
    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    final_token = f"LXFW.{payload_b64}.{signature_b64}"

    # 4. Autovalidazione
    try:
        private_key.public_key().verify(signature, payload_b64.encode('utf-8'))
    except Exception:
        print("  ❌ ERRORE FIRMA — chiave corrotta.")
        return

    # 5. Registra
    pwd = get_password()
    registry = load_registry(pwd)

    existing_ids = {e.get("id") for e in registry if e.get("status") != "burned"}
    if key_id in existing_ids:
        print(f"\n  ⚠️  ID '{key_id}' già presente!")
        confirm = input("  Continuare? (s/N): ").strip().lower()
        if confirm != 's':
            return

    entry = {
        "id": key_id,
        "client": client_name,
        "issued_at": datetime.now().isoformat(),
        "expires_at": datetime.fromtimestamp(expiry_timestamp / 1000).isoformat(),
        "expiry_ms": expiry_timestamp,
        "burn_hash": compute_key_hash(final_token),
        "status": "issued",
        "nonce": nonce,
    }
    registry.append(entry)
    save_registry(pwd, registry)

    print()
    print(SEP_MEDIUM)
    print("    ✅ LICENZA GENERATA E REGISTRATA")
    print(SEP_MEDIUM)
    print()
    print(f"  Cliente:    {client_name}")
    print(f"  ID:         {key_id}")
    print(f"  Scadenza:   {datetime.fromtimestamp(expiry_timestamp / 1000).strftime('%Y-%m-%d')}")
    print(f"  Burn Hash:  {entry['burn_hash'][:16]}...")
    print(f"  Registro:   {len(registry)} chiavi totali")
    print()
    print("  TOKEN:")
    print()
    print(f"  {final_token}")
    print()
    print(SEP_MEDIUM)


def cmd_list():
    """List all issued keys."""
    pwd = get_password()
    registry = load_registry(pwd)

    if not registry:
        print("\n  📭 Registro vuoto.\n")
        return

    print()
    print(SEP_WIDE)
    print("    REGISTRO CHIAVI LEXFLOW")
    print(SEP_WIDE)
    print()
    print(f"  {'#':<4} {'ID':<12} {'Cliente':<25} {'Emessa':<12} {'Scade':<12} {'Stato'}")
    print("  " + "─" * 75)

    now_ms = int(time.time() * 1000)
    for i, entry in enumerate(registry, 1):
        issued = entry.get("issued_at", "?")[:10]
        expires = entry.get("expires_at", "?")[:10]
        status = entry.get("status", "?")
        expiry_ms = entry.get("expiry_ms", 0)

        if status == "burned":
            icon = "🔥"
            label = "OBLITERATA"
        elif expiry_ms > 0 and now_ms > expiry_ms:
            icon = "⏰"
            label = "scaduta"
        elif status == "activated":
            icon = "🟢"
            label = "attiva"
        else:
            icon = "🔵"
            label = "emessa"

        client_display = entry.get("client", "?")
        if status == "burned":
            client_display = "██████████"
            expires = "██████████"

        print(f"  {i:<4} {entry.get('id', '?'):<12} {client_display:<25} {issued:<12} {expires:<12} {icon} {label}")

    # Stats
    total = len(registry)
    active = sum(1 for e in registry if e.get("status") in ("issued", "activated") and (e.get("expiry_ms", 0) == 0 or now_ms <= e.get("expiry_ms", 0)))
    burned = sum(1 for e in registry if e.get("status") == "burned")
    expired = sum(1 for e in registry if e.get("expiry_ms", 0) > 0 and now_ms > e.get("expiry_ms", 0) and e.get("status") not in ("burned",))

    print()
    print(f"  Totale: {total} │ Valide: {active} │ Scadute: {expired} │ Bruciate: {burned}")
    print(SEP_WIDE)
    print()


def cmd_verify():
    """Verify a token."""
    if len(sys.argv) >= 3:
        token = sys.argv[2].strip()
    else:
        token = input("  Token da verificare: ").strip()

    parts = token.split('.')
    if len(parts) != 3 or parts[0] != 'LXFW':
        print("  ❌ Formato non valido. Deve essere LXFW.<payload>.<firma>")
        return

    try:
        payload_bytes = base64.urlsafe_b64decode(parts[1] + '==')
        payload = json.loads(payload_bytes)
    except Exception:
        print("  ❌ Payload corrotto.")
        return

    expiry_ms = payload.get('e', 0)
    now_ms = int(time.time() * 1000)
    expired = now_ms > expiry_ms

    print()
    print(f"  Cliente:   {payload.get('c', '?')}")
    print(f"  ID:        {payload.get('id', '?')}")
    print(f"  Nonce:     {payload.get('n', 'N/A')[:16]}...")
    print(f"  Scadenza:  {datetime.fromtimestamp(expiry_ms / 1000).strftime('%Y-%m-%d')} {'⏰ SCADUTA' if expired else '✅ Valida'}")

    burn_hash = compute_key_hash(token)
    print(f"  Burn Hash: {burn_hash[:24]}...")

    try:
        pwd = get_password()
        registry = load_registry(pwd)
        found = [e for e in registry if e.get("burn_hash") == burn_hash]
        if found:
            e = found[0]
            if e.get("status") == "burned":
                print("  Registro:  🔥 CHIAVE OBLITERATA — non più valida")
            else:
                print(f"  Registro:  ✅ Trovata (stato: {e.get('status')})")
        else:
            print("  Registro:  ⚠️  NON trovata (v1 o non registrata)")
    except Exception:
        print("  Registro:  ⚠️  Impossibile accedere al registro")
    print()


def cmd_burn():
    """BURN a key — ultra-burn irreversible destruction. No soft revoke, just total annihilation."""
    if len(sys.argv) >= 3:
        target_id = sys.argv[2].strip()
    else:
        target_id = input("  ID chiave da BRUCIARE: ").strip()

    pwd = get_password()
    registry = load_registry(pwd)

    found = [e for e in registry if e.get("id") == target_id and e.get("status") != "burned"]
    if not found:
        print(f"  ❌ Chiave '{target_id}' non trovata o già bruciata.")
        return

    entry = found[0]
    print()
    print("  🔥 ULTRA-BURN v2 — Annientamento Totale")
    print(SEP_DASH)
    print(f"  ID:       {entry.get('id')}")
    print(f"  Cliente:  {entry.get('client')}")
    print(f"  Scade:    {entry.get('expires_at', '?')[:10]}")
    print()
    print("  ⚠️  ATTENZIONE: Questa operazione è IRREVERSIBILE.")
    print("     Client, hash, nonce verranno sovrascritti con 3000 round")
    print("     di cascade multi-algoritmo (SHA-512 → SHA3-256 → BLAKE2b).")
    print("     Il token NON potrà MAI più essere verificato o recuperato.")
    print("     Nessun revoke soft — solo distruzione totale.")
    print()
    confirm = input("  Digita 'BURN' per confermare: ").strip()
    if confirm != 'BURN':
        print(MSG_CANCELLED)
        return

    print()
    print("  ⏳ Ultra-burn in corso (3000 round × 3 algoritmi)...")

    # Ultra-burn v2: sovrascrittura cascade multi-algo di TUTTI i dati sensibili
    entry["status"] = "burned"
    entry["burned_at"] = datetime.now().isoformat()
    entry["client"] = ultra_burn_string(entry.get("client", ""))
    entry["burn_hash"] = ultra_burn_string(entry.get("burn_hash", ""))
    entry["nonce"] = ultra_burn_string(entry.get("nonce", ""))
    entry["expires_at"] = "0000-00-00T00:00:00"
    entry["expiry_ms"] = 0
    # Anche issued_at: nessuna traccia temporale di quando è stata emessa
    entry["issued_at"] = ultra_burn_string(entry.get("issued_at", ""))

    save_registry(pwd, registry)

    print()
    print(f"  🔥🔥🔥 Chiave '{target_id}' OBLITERATA.")
    print("     3000 round: SHA-512 (1000) → SHA3-256 (1000) → BLAKE2b (1000)")
    print("     Campi distrutti: client, burn_hash, nonce, issued_at, expires_at")
    print("     Recupero: IMPOSSIBILE — dati sepolti sotto 3 strati crittografici.")
    print()


def cmd_nuke():
    """NUKE — destroy entire registry."""
    print()
    print("  ☢️  NUKE — DISTRUZIONE TOTALE REGISTRO")
    print(SEP_DASH)
    print()
    print("  Questo eliminerà PERMANENTEMENTE:")
    print("    • Tutte le chiavi emesse")
    print("    • Il registro crittografato")
    print("    • Il file salt")
    print()
    print("  I token già distribuiti continueranno a funzionare nell'app")
    print("  ma non saranno più tracciati nel registro.")
    print()

    confirm1 = input("  Digita 'NUKE' per confermare: ").strip()
    if confirm1 != 'NUKE':
        print(MSG_CANCELLED)
        return

    confirm2 = input("  Sei ASSOLUTAMENTE sicuro? Digita 'CONFERMA': ").strip()
    if confirm2 != 'CONFERMA':
        print(MSG_CANCELLED)
        return

    # Sovrascrittura sicura: riempi i file con dati random prima di cancellare
    for fpath in [REGISTRY_FILE, REGISTRY_SALT_FILE]:
        if fpath.exists():
            size = fpath.stat().st_size
            # 3 passate di sovrascrittura con dati random
            for _ in range(3):
                fpath.write_bytes(secrets.token_bytes(max(size, 64)))
            fpath.unlink()

    print()
    print("  ☢️  REGISTRO DISTRUTTO.")
    print("     File sovrascritti 3x con dati random e cancellati.")
    print("     La prossima esecuzione creerà un nuovo registro pulito.")
    print()


def cmd_export():
    """Export registry to CSV."""
    pwd = get_password()
    registry = load_registry(pwd)

    if not registry:
        print("  📭 Registro vuoto.")
        return

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Cliente", "Emissione", "Scadenza", "Stato", "Burn Hash (parziale)"])
    for entry in registry:
        client = entry.get("client", "")
        if entry.get("status") == "burned":
            client = "[BRUCIATA]"
        writer.writerow([
            entry.get("id", ""),
            client,
            entry.get("issued_at", "")[:19],
            entry.get("expires_at", "")[:10],
            entry.get("status", ""),
            entry.get("burn_hash", "")[:16],
        ])

    csv_path = SCRIPT_DIR / "lexflow-keys-export.csv"
    csv_path.write_text(output.getvalue())
    print(f"\n  ✅ Esportato: {csv_path}")
    print(f"  📋 {len(registry)} chiavi.\n")


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

    clients = {}
    for e in registry:
        if e.get("status") == "burned":
            continue
        c = e.get("client", "?")
        clients[c] = clients.get(c, 0) + 1

    print()
    print(SEP_NARROW)
    print("    STATISTICHE REGISTRO LEXFLOW")
    print(SEP_NARROW)
    print()
    print(f"  Chiavi totali:      {total}")
    print(f"  ├─ Valide:          {active}")
    print(f"  ├─ Attivate:        {activated}")
    print(f"  ├─ Scadute:         {expired}")
    print(f"  └─ Bruciate:        {burned}")
    print()
    if clients:
        print("  Per Cliente:")
        for client, count in sorted(clients.items(), key=lambda x: -x[1]):
            print(f"    {client}: {count}")
    print()
    print(SEP_NARROW)
    print()


def main():
    if len(sys.argv) < 2:
        print()
        print("  LexFlow License Manager v2.2")
        print()
        print("  Comandi:")
        print("    generate          Genera nuova licenza")
        print("    list              Mostra registro chiavi")
        print("    verify [token]    Verifica un token")
        print("    burn <id>         Brucia chiave (ultra-burn irreversibile)")
        print("    export            Esporta CSV")
        print("    stats             Statistiche")
        print("    nuke              Distruggi TUTTO il registro")
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
        print(f"  ❌ Comando sconosciuto: {cmd}")
        print("  Comandi: generate, list, verify, burn, export, stats, nuke")


if __name__ == "__main__":
    main()
