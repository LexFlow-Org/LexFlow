"""Publish the verified replacement EXE, retaining the other three installers."""
from pathlib import Path
import datetime,hashlib,json,os,re,shutil
root=Path(__file__).resolve().parents[3]
evidence=Path(__file__).resolve().parent
release=root/'releases/2026-09-07'
candidate=Path('/private/tmp/lexflow-nohello-windows-2026-09-07/candidate-nohello')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
previous=json.loads((evidence/'previous-installer-sha256.json').read_text())
assert all(sha(release/p)==h for p,h in previous.items()),'Existing installer changed unexpectedly'
assert sha(root/'scripts/.lexflow-issued-keys.enc')=='bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4'
assert '13 passed; 0 failed' in (evidence/'biometric-tests.log').read_text()
assert '60 passed' in (evidence/'frontend-tests.log').read_text()
for relative,digest in json.loads((evidence/'changed-build-inputs.json').read_text()).items():assert sha(root/relative)==digest,relative
name='LexFlow_1.0.1_x64-setup.exe';source=candidate/name
receipt=json.loads((candidate/'BUILD-VERIFICATION.json').read_text())
assert sha(source)==receipt['sha256']
assert source.stat().st_size==receipt['installer_bytes']
assert receipt['verification']['installer_7z_test']=='passed'
assert receipt['verification']['current_project_matches_frozen_snapshot']
assert receipt['verification']['public_key_sha256']=='4ff69b87240948576d916234273c2468e0906c1468e190f2b9a2ac3a5230672f'
old=evidence/'previous-release-receipts';old.mkdir(exist_ok=True)
for relative in ['pacchetti.json','LEGGIMI.txt','Windows/BUILD-VERIFICATION.json','Windows/LEGGIMI.txt','Windows/SHA256SUMS.txt']:
 p=old/relative;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(release/relative,p)
new=evidence/'Windows';new.mkdir(exist_ok=True)
for p in candidate.iterdir():
 if p.is_file() and p.suffix.lower()!='.exe':shutil.copy2(p,new/p.name)
destination=release/'Windows'/name;staged=destination.with_name('.'+name+'.new')
assert not staged.exists();shutil.copy2(source,staged);assert sha(staged)==receipt['sha256'];os.replace(staged,destination)
for name in ['BUILD-VERIFICATION.json','SOURCE-SHA256.json','frontend-source-sha256.json']:
 p=candidate/name
 if p.is_file():shutil.copy2(p,release/'Windows'/name)
# Human-readable consequences accompany the installer, including the preserved password requirement.
(release/'Windows/LEGGIMI.txt').write_text('''LexFlow 1.0.1 — Windows x64 — aggiornamento dell’8 settembre 2026

Windows Hello è stato rimosso. L’accesso all’archivio usa la Master Password.
Non occorre generare una nuova licenza: l’emittente è lo stesso della precedente 1.0.1.

PRIMA DI INSTALLARE: verifica di conoscere la Master Password dell’archivio.
All’avvio l’app elimina la vecchia credenziale biometrica LexFlow dell’utente.
Se la password è stata dimenticata, non sarà più possibile usare il vecchio
sblocco Hello. Il vault e la sua password non vengono modificati.

Esegui LexFlow_1.0.1_x64-setup.exe per aggiornare la copia precedente.
Windows Hello non può più essere configurato né invocato. Se la pulizia della
vecchia credenziale fallisce, le Impostazioni mostrano un avviso: riavvia l’app
per riprovare. L’accesso con password resta disponibile.

WebView2 Fixed è incluso per l’uso offline. Installer non firmato Authenticode.
Verificati compilazione, architettura x64, contenuto del pacchetto, risorse e
chiave pubblica; superati 60 test frontend e 13 test Rust mirati con dati
sintetici. Il collaudo dell’aggiornamento e del Credential Manager su un PC
Windows reale resta da eseguire: il pacchetto è stato compilato sul Mac.

Rapporto nel progetto: docs/RIMOZIONE-WINDOWS-HELLO-2026-09-08.md.
''')
meta=json.loads((release/'pacchetti.json').read_text())
for a in meta['artifacts']:
 if a['file'].startswith('Windows/'):
  a.update({'sha256':receipt['sha256'],'bytes':receipt['installer_bytes'],'updated_at':datetime.datetime.now().astimezone().isoformat(),'source_manifest':'Windows/SOURCE-SHA256.json'})
meta.update({'updated_at':datetime.datetime.now().astimezone().isoformat(),'windows_hello_removed':True,'windows_legacy_bio_credential_deleted_on_startup':True,'windows_master_password_required_before_update':True,'windows_frontend_tests':60,'windows_removal_and_existing_macos_bio_targeted_tests':13,'windows_native_execution':False,'macos_android_artifacts_unchanged_since_settings_fix':True,'root_source_freeze_scope':'Previous macOS package build; Windows uses its own SOURCE-SHA256.json. Android uses Android/source-fingerprint.json.','windows_source_files_checked':receipt['verification']['source_files_compared']})
save(release/'pacchetti.json',meta)
(release/'SHA256SUMS.txt').write_text(''.join(f"{a['sha256']}  {a['file']}\n" for a in meta['artifacts']))
(release/'Windows/SHA256SUMS.txt').write_text(f"{receipt['sha256']}  LexFlow_1.0.1_x64-setup.exe\n")
p=release/'LEGGIMI.txt';t=p.read_text();t=t.replace('LexFlow 1.0.1 — pacchetti aggiornati il 7 settembre 2026','LexFlow 1.0.1 — Mac/Android aggiornati il 7 settembre, Windows l’8 settembre 2026')
t=t.replace('Windows: installer e applicazione non hanno firma Authenticode.','Windows: Windows Hello rimosso, accesso con Master Password. Prima di aggiornare\nverifica di conoscere la password: all’avvio viene eliminata la vecchia\ncredenziale biometrica LexFlow, senza modificare il vault. Leggi Windows/LEGGIMI.txt.\nInstaller e applicazione non hanno firma Authenticode.')
t+='\nAggiornamento Windows dell’8 settembre: 60 test frontend e 13 test Rust mirati\nsuperati; eliminati i controlli PowerShell di Hello. Mac e Android invariati.\nRapporto: docs/RIMOZIONE-WINDOWS-HELLO-2026-09-08.md.\n';p.write_text(t)
for a in meta['artifacts']:assert sha(release/a['file'])==a['sha256']
assert all(sha(release/p)==h for p,h in previous.items() if not p.startswith('Windows/'))
assert sha(Path('/Applications/LexFlow.app/Contents/MacOS/lexflow'))=='84d3937fda76e98490ee51f7e0a86395490b01d9d3c10604fc2901ce3f6f5c80'
save(evidence/'publication.json',{'updated_at':datetime.datetime.now().astimezone().isoformat(),'windows_installer_sha256':receipt['sha256'],'other_three_installers_unchanged':True,'installed_mac_unchanged':True,'license_registry_unchanged':True,'new_license_generated':False})
print(json.dumps({'published':str(destination),'sha256':receipt['sha256'],'bytes':receipt['installer_bytes']}))
