from pathlib import Path
import hashlib,json,os,plistlib,shutil,subprocess,datetime
scratch=Path('/private/tmp/lexflow-ui-update-2026-09-07')
dmg=Path('/private/tmp/lexflow-validation-2026-09-07/macos/candidate-toggle/LexFlow-1.0.1-macOS-Apple-Silicon.dmg')
installed=Path('/Applications/LexFlow.app')
staging=Path('/Applications/.LexFlow-update-20260907.app')
rollback=scratch/'replaced-installed.app'
mount=scratch/'install-mount'
expected='84d3937fda76e98490ee51f7e0a86395490b01d9d3c10604fc2901ce3f6f5c80'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
def closed():assert subprocess.run(['pgrep','-xi','lexflow'],capture_output=True).returncode==1,'LexFlow is running; no update made'
def validate(p):
 assert p.is_dir() and not p.is_symlink()
 meta=plistlib.loads((p/'Contents/Info.plist').read_bytes())
 assert meta['CFBundleIdentifier']=='com.pietrolongo.lexflow' and meta['CFBundleExecutable']=='lexflow'
 return meta
closed();validate(installed)
assert not staging.exists() and not rollback.exists() and not mount.exists()
assert sha(dmg)=='376369c34358d8069ac10f03497c51d89e90fc94f317aed48fa745c8a7692222'
oldsha=sha(installed/'Contents/MacOS/lexflow')
mount.mkdir();mounted=False;replaced=False
try:
 run('hdiutil','attach',str(dmg),'-readonly','-nobrowse','-mountpoint',str(mount));mounted=True
 source=mount/'LexFlow.app';meta=validate(source);assert meta['CFBundleShortVersionString']=='1.0.1'
 assert sha(source/'Contents/MacOS/lexflow')==expected
 run('/usr/bin/ditto',str(source),str(staging))
 run('/usr/bin/codesign','--verify','--deep','--strict',str(staging))
 assert sha(staging/'Contents/MacOS/lexflow')==expected
 closed();os.rename(installed,rollback)
 try:
  os.rename(staging,installed);replaced=True
  run('/usr/bin/codesign','--verify','--deep','--strict',str(installed))
  assert sha(installed/'Contents/MacOS/lexflow')==expected
 except BaseException:
  if installed.exists():os.rename(installed,staging)
  os.rename(rollback,installed);replaced=False
  raise
 receipt={'updated_at':datetime.datetime.now().astimezone().isoformat(),'path':str(installed),'version':'1.0.1','old_main_sha256':oldsha,'new_main_sha256':expected,'source_dmg_sha256':sha(dmg),'codesign_strict_verified':True,'signature':'ad hoc','user_profile_modified':False,'license_registry_modified':False,'application_launched':False}
 (scratch/'installed-app-update.json').write_text(json.dumps(receipt,indent=2)+'\n')
 shutil.rmtree(rollback)
 print(json.dumps(receipt))
finally:
 if mounted:run('hdiutil','detach',str(mount))
 if mount.exists():mount.rmdir()
 if staging.exists() and not replaced:shutil.rmtree(staging)
