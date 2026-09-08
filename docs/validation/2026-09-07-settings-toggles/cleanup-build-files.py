from pathlib import Path
import datetime,hashlib,json,os,plistlib,shutil,subprocess
root=Path('/Users/pielongo/Library/Mobile Documents/com~apple~CloudDocs/Scrivania/sviluppo applicazioni/LexFlow')
evidence=root/'docs/validation/2026-09-07-settings-toggles'
report=evidence/'cleanup.json'
scratch=[Path('/private/tmp')/name for name in ['lexflow-validation-2026-09-07','lexflow-windows-rebuild-2026-09-07','lexflow-toggle-validation-2026-09-07','lexflow-ui-update-2026-09-07']]
generated=[root/name for name in ['node_modules','client/node_modules','client/dist','src-tauri/gen']]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
release=root/'releases/2026-09-07'
meta=json.loads((release/'pacchetti.json').read_text())
assert len(meta['artifacts'])==4
assert all(sha(release/a['file'])==a['sha256'] for a in meta['artifacts'])
assert sha(Path('/Applications/LexFlow.app/Contents/MacOS/lexflow'))==meta['installed_app_main_sha256']
registry=root/'scripts/.lexflow-issued-keys.enc'
assert sha(registry)=='bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4'
assert (evidence/'source-freeze.json').is_file() and (evidence/'installed-app-update.json').is_file()
assert (root/'docs/validation/2026-09-07-macos/final-rust-tests.log').is_file()
assert (evidence/'build/Windows/BUILD-VERIFICATION.json').is_file()
assert (evidence/'build/Android/verifica-pacchetto.json').is_file()
# Never remove tracked source or follow an unexpected top-level symbolic link.
assert not subprocess.run(['git','ls-files','node_modules','client/node_modules','client/dist','src-tauri/gen'],cwd=root,capture_output=True,text=True,check=True).stdout.strip()
for p in scratch+generated:assert p.exists() and p.is_dir() and not p.is_symlink(),str(p)
# Detach only disk images whose image path or mount belongs to this task's scratch.
info=plistlib.loads(subprocess.run(['hdiutil','info','-plist'],capture_output=True,check=True).stdout)
detached=[]
for image in info.get('images',[]):
 path=image.get('image-path','');ents=image.get('system-entities',[])
 owned=any(path.startswith(str(p)+'/') for p in scratch) or any(any(v.get('mount-point','').startswith(str(p)+'/') for p in scratch) for v in ents)
 if owned:
  dev=next((v['dev-entry'] for v in ents if v.get('mount-point')),None)
  if dev:subprocess.run(['hdiutil','detach',dev],check=True,capture_output=True);detached.append(dev)
# Read open-file inventory, return only matches rather than unrelated paths.
preflight=json.loads((evidence/'build/Android/final-open-files-check.json').read_text())
allowed_provider_paths={item['path'] for item in preflight['generated_open_files']}
assert len(allowed_provider_paths)==7
provider_command='/System/Library/PrivateFrameworks/FileProvider.framework/Support/fileproviderd'
lsof=subprocess.run(['/usr/sbin/lsof','-nP','+c','0','-Fpcn'],capture_output=True,text=True)
assert lsof.returncode==0 and not lsof.stderr.strip(), 'Could not verify open files'
opened=[];provider_handles=[];pid=None;command=None
for line in lsof.stdout.splitlines():
 if line.startswith('p'):pid=int(line[1:]);command=None
 elif line.startswith('c'):command=line[1:]
 elif line.startswith('n') and any(line[1:]==str(p) or line[1:].startswith(str(p)+'/') for p in scratch+generated):
  file=line[1:]
  if pid==680 and command=='fileproviderd' and file in allowed_provider_paths:
   actual=subprocess.run(['ps','-p','680','-o','comm='],capture_output=True,text=True,check=True).stdout.strip()
   assert actual==provider_command
   provider_handles.append(file)
  else:opened.append({'pid':pid,'command':command,'file':file})
assert not opened,'Task build directories still have open files: '+repr(opened[:5])
# Validate parked profiles as synthetic, after successful restoration. Never touch user-created vault.
parked=[];holds=Path.home()/'Library/Application Support/LexFlow Validation Sessions'
for name in ['20260907-091600','20260907-101447']:
 session=holds/name
 assert session.is_dir() and not session.is_symlink() and not (session/'session.json').exists()
 ledger=json.loads((session/'restored.json').read_text())
 assert ledger['phase']=='restored' and ledger['session']==str(session)
 assert not any(session.glob('original-*'))
 assert (session/'synthetic-0/.lexflow-qa-session').read_text().strip()==str(session)
 for p in session.glob('synthetic-*'):
  assert not p.is_symlink() and p.name.split('-')[1].isdigit()
  assert int(p.name.split('-')[1])<len(ledger['entries'])
  parked.append(p)
removed=[]
for p in scratch+generated+parked:
 if p.is_dir():shutil.rmtree(p)
 else:p.unlink()
 removed.append(str(p));print('Removed',p,flush=True)
# Remove Python bytecode caches belonging to project validation scripts only.
for p in (root/'scripts').rglob('__pycache__'):
 if p.is_dir() and not p.is_symlink():shutil.rmtree(p);removed.append(str(p))
assert sha(registry)=='bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4'
assert (holds/'20260907-091600/user-created-during-validation').is_dir()
assert (Path.home()/'Library/Application Support/com.pietrolongo.lexflow').is_dir()
assert (root/'Crea licenza LexFlow.command').is_file()
private=Path.home()/'Library/Application Support/LexFlow License Keys/license-2026-09-06-cd568eaaebf8/private-key.pem'
assert private.is_file() and private.stat().st_mode&0o777==0o600
result={'completed_at':datetime.datetime.now().astimezone().isoformat(),'removed_paths':removed,'detached_owned_disks':detached,'removed_obsolete_windows_zip':True,'four_installer_checksums_verified_before_cleanup':True,'installed_app_preserved':True,'real_profile_preserved':True,'user_created_validation_vault_preserved':True,'issuer_and_generator_preserved':True,'license_registry_unchanged':True,'shared_global_tool_caches_removed':False,'global_adb_keys_removed':False,'global_adb_key_note':'No initial fingerprint was recorded; preserve rather than remove potentially reused keys.','keychain_items_bulk_deleted':False,'icloud_service_preserved':True,'generated_locks_held_by_fileprovider_before_cleanup':provider_handles,'fileprovider_handles_were_read_only':False}
report.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n');print('Cleanup verified; evidence saved.',flush=True)
