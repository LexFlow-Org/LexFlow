# Scripts - LexFlow

## File disponibili

### `generate_license_v2.py`
Generatore di licenze LexFlow v2 con registro cifrato, chiavi monouso (burn-hash) e anti-tampering.

```bash
python3 scripts/generate_license_v2.py
```

Requisiti: `pip3 install cryptography`

### `generate-icons.py`
Genera tutte le icone dell'app da `assets/icon-master.png`.

```bash
python3 scripts/generate-icons.py
```

Requisiti: `pip3 install Pillow`

## Sicurezza

1. **Chiave privata**: non committare mai la chiave privata Ed25519. Conservala in un password manager o HSM.
2. **Registro licenze**: il file `license_registry.enc` viene cifrato con AES-256-GCM. Non eliminarlo o le licenze emesse non saranno verificabili.
3. **Rotazione**: se la chiave privata viene compromessa, genera una nuova coppia, aggiorna `PUBLIC_KEY_BYTES` in `lib.rs` e rilascia una nuova versione.
