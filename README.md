# LexFlow

> Gestionale Studio Legale con Crittografia Zero-Knowledge

**Versione:** 3.7.0  
**Piattaforma:** Tauri v2 (macOS, Windows, Android)  
**Bundle ID:** `com.pietrolongo.lexflow`

---

## Funzionalità

- **Gestione Pratiche** -- crea, archivia e monitora fascicoli legali
- **Agenda** -- calendario con viste giorno/settimana/mese, drag-and-drop, notifiche
- **Scadenzario** -- deadline, udienze, termini processuali con briefing giornalieri
- **Time Tracking** -- timer live, inserimento manuale, griglia settimanale
- **Fatturazione** -- CRUD fatture con CPA 4% + IVA 22%, generazione PDF
- **Rubrica Contatti** -- clienti, controparti, CTU, avvocati con pratiche collegate
- **Conflict Check** -- ricerca conflitto di interessi su tutte le parti
- **Crittografia Zero-Knowledge** -- AES-256-GCM + Argon2id, dati cifrati localmente
- **Biometria** -- Touch ID (macOS) / Windows Hello per sblocco rapido
- **Notifiche native** -- avvisi scadenze anche ad app chiusa (cron desktop / AOT mobile)
- **System Tray** -- resta attiva in background con scheduler notifiche
- **Licenza Ed25519** -- firma crittografica offline, chiavi monouso (burn-hash)

## Stack Tecnologico

| Layer | Tecnologia |
|---|---|
| Frontend | React 19 + Vite 7 + Tailwind CSS 4 |
| Backend | Rust (Tauri v2.10) |
| Dati | Vault cifrato AES-256-GCM (file locale) |
| Crypto | Argon2id (KDF) + Ed25519 (licenze) + HMAC-SHA256 |
| PDF | jsPDF + jspdf-autotable |

## Struttura Progetto

```
LexFlow/
├── assets/              ← Sorgente icone e branding
│   └── icon-master.png
├── scripts/             ← Automazione
│   ├── generate-icons.py
│   └── generate_license_v2.py
├── client/              ← Frontend React + Vite
│   ├── src/
│   │   ├── components/  ← LoginScreen, Sidebar, PracticeDetail, ...
│   │   ├── pages/       ← Dashboard, Agenda, Settings, Billing, ...
│   │   ├── utils/       ← pdfGenerator.js
│   │   └── tauri-api.js ← Bridge ESM centralizzato
│   └── index.html
├── src-tauri/           ← Backend Rust + Tauri v2
│   ├── src/lib.rs       ← 3000+ righe: vault, crypto, licenze, notifiche
│   ├── icons/           ← Generate (NON editare)
│   └── tauri.conf.json
└── CHANGELOG.md
```

## Sviluppo

```bash
npm run dev          # Avvia dev (Tauri + Vite)
npm run build        # Build macOS Universal
npm run build:me     # Build + deploy in Applicazioni
npm run icons        # Rigenera icone da assets/icon-master.png
```

