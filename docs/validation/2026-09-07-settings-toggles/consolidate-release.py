from pathlib import Path
import json,hashlib,shutil,os,datetime
root=Path.cwd();release=root/'releases/2026-09-07';evidence=root/'docs/validation/2026-09-07-settings-toggles';scratch=Path('/private/tmp/lexflow-ui-update-2026-09-07')
mac=Path('/private/tmp/lexflow-validation-2026-09-07/macos/candidate-toggle');win=Path('/private/tmp/lexflow-windows-rebuild-2026-09-07/candidate-toggle');android=Path('/private/tmp/lexflow-validation-2026-09-07/android/candidate-toggle')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def save(p,d):p.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
freeze=scratch/'source-freeze.json';sources=json.loads(freeze.read_text());assert len(sources)==132
assert all(sha(root/name)==digest for name,digest in sources.items())
assert sha(root/'scripts/.lexflow-issued-keys.enc')=='bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4'
items=[(mac/'LexFlow-1.0.1-macOS-Apple-Silicon.dmg','macOS','376369c34358d8069ac10f03497c51d89e90fc94f317aed48fa745c8a7692222'),(mac/'LexFlow-1.0.1-macOS-Intel.dmg','macOS','b45686c13f73813d01646c09283e20d1607aaa9cc9b5948fd56ad6e8d051110e'),(win/'LexFlow_1.0.1_x64-setup.exe','Windows','a6d543a59f60b084521d1f12dc415cd5294c45cd77262721aa36f2a8b404916a'),(android/'LexFlow-1.0.1-Android-arm64.apk','Android','cc9d24a85cb40a5716a0fe45cea31d855092217b077a43538b769ab2736c2445')]
assert all(sha(p)==h for p,_,h in items)
# Preserve small preceding receipts, never old installers or private material.
previous=evidence/'previous-package-receipts';previous.mkdir(parents=True,exist_ok=True)
for p in release.rglob('*'):
 if p.is_file() and p.suffix.lower() in ('.txt','.md','.json'):
  out=previous/p.relative_to(release);out.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,out)
artifacts=[]
for source,platform,digest in items:
 destination=release/platform/source.name;temporary=destination.with_name('.'+destination.name+'.new')
 assert not temporary.exists();shutil.copy2(source,temporary);assert sha(temporary)==digest;os.replace(temporary,destination)
 artifacts.append({'file':str(destination.relative_to(release)),'bytes':destination.stat().st_size,'sha256':digest})
for source,platform in [(mac,'macOS'),(win,'Windows'),(android,'Android')]:
 out=evidence/'build'/platform;out.mkdir(parents=True,exist_ok=True)
 for p in source.iterdir():
  if p.is_file() and p.suffix.lower() not in ('.dmg','.exe','.apk'):
   shutil.copy2(p,out/p.name)
 for name in {'macOS':['verifica-pacchetto.json'],'Windows':['BUILD-VERIFICATION.json','LEGGIMI.txt'],'Android':['verifica-pacchetto.json','source-fingerprint.json','INSTALLAZIONE.md','CERTIFICATO-FIRMA.txt']}[platform]:shutil.copy2(source/name,release/platform/name)
# Old runtime report concerns APK252, keep its historical evidence outside current package metadata.
oldruntime=release/'Android/verifica-avvio-emulatore.json'
if oldruntime.exists():oldruntime.unlink()
for p in scratch.iterdir():
 if p.is_file() and p.suffix in ('.log','.json','.py'):shutil.copy2(p,evidence/p.name)
shutil.copy2(freeze,release/'source-freeze.json')
macreceipt=json.loads((release/'macOS/verifica-pacchetto.json').read_text());macreceipt['rust_full_suite_428_precedes_status_diagnostic']=True;macreceipt['latest_biometric_targeted_tests_passed']=8;macreceipt['native_gui_intermediate_arm_does_not_cover_latest_toggle_binary']=True
save(release/'macOS/verifica-pacchetto.json',macreceipt);save(evidence/'build/macOS/verifica-pacchetto.json',macreceipt)
metadata=json.loads((release/'pacchetti.json').read_text());metadata.update({'updated_at':datetime.datetime.now().astimezone().isoformat(),'android_version_code':253,'artifacts':artifacts,'source_freeze_sha256':sha(freeze),'source_files_checked':132,'settings_toggle_geometry_fixed':True,'settings_visual_geometric_checks':120,'settings_visual_interaction_profiles':24,'latest_biometric_targeted_tests':8,'rust_full_suite_428_precedes_status_diagnostic':True,'installed_app_updated':True,'installed_app_main_sha256':'84d3937fda76e98490ee51f7e0a86395490b01d9d3c10604fc2901ce3f6f5c80','license_registry_modified':False,'license_registry_real_record_count_verified':False,'android_253_runtime_tested':False})
save(release/'pacchetti.json',metadata)
(release/'SHA256SUMS.txt').write_text(''.join(f"{a['sha256']}  {a['file']}\n" for a in artifacts))
for platform in ['macOS','Windows','Android']:
 (release/platform/'SHA256SUMS.txt').write_text(''.join(f"{a['sha256']}  {Path(a['file']).name}\n" for a in artifacts if a['file'].startswith(platform+'/')))
save(evidence/'registry-check.json',{'registry_sha256_unchanged':'bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4','format':'encrypted V3','owner_only_permissions':'0600','real_records_decrypted':False,'real_count_verified':False,'issuer_changed':False,'synthetic_generator_tests':{'passed':19,'seconds':11.914,'exit_code':0,'source':'tool session89978; stdout only, no original log file'}})
print(json.dumps({'published':artifacts,'source_files_verified':len(sources),'installed_mac_updated':True},indent=2))
