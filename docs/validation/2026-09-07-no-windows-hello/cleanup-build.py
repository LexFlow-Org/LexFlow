from pathlib import Path
import hashlib,json,shutil,subprocess,datetime
root=Path(__file__).resolve().parents[3];evidence=Path(__file__).resolve().parent
plan=json.loads((evidence/'cleanup-plan.json').read_text());paths=[Path(p) for p in plan['scratch']+plan['generated']]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
release=root/'releases/2026-09-07';meta=json.loads((release/'pacchetti.json').read_text())
assert (evidence/'publication.json').is_file() and meta.get('windows_hello_removed') is True
assert len(meta['artifacts'])==4 and all(sha(release/a['file'])==a['sha256'] for a in meta['artifacts'])
for p in paths:assert p.is_dir() and not p.is_symlink(),str(p)
assert not subprocess.run(['git','ls-files','node_modules','client/node_modules','client/dist','src-tauri/gen'],cwd=root,capture_output=True,text=True,check=True).stdout.strip()
# A running build prevents cleanup. iCloud may hold generated project files;
# those files are deliberately removed, without stopping that system service.
r=subprocess.run(['/usr/sbin/lsof','-nP','+c','0','-Fpcn'],capture_output=True,text=True)
assert r.returncode==0 and not r.stderr.strip(),'Open-file preflight unavailable'
process=None;command=None;busy=[];icloud=[]
for line in r.stdout.splitlines():
 if line.startswith('p'):process=int(line[1:]);command=None
 elif line.startswith('c'):command=line[1:]
 elif line.startswith('n') and any(line[1:]==str(p) or line[1:].startswith(str(p)+'/') for p in paths):
  file=line[1:]
  if command=='fileproviderd' and any(file.startswith(p+'/') for p in plan['generated']):icloud.append(file)
  else:busy.append({'pid':process,'command':command,'file':file})
assert not busy,'Task build files are still open: '+repr(busy[:5])
registry=root/'scripts/.lexflow-issued-keys.enc';expected_registry='bd183bb6bc19e626113610473c14814bcc0f9b6470b0b6d88015e29ac303b0c4'
assert sha(registry)==expected_registry
removed=[]
for p in paths:
 shutil.rmtree(p);removed.append(str(p));print('Removed',p,flush=True)
assert sha(registry)==expected_registry
assert all(not p.exists() for p in paths)
assert (root/'Crea licenza LexFlow.command').is_file()
private=Path.home()/'Library/Application Support/LexFlow License Keys/license-2026-09-06-cd568eaaebf8/private-key.pem'
assert private.is_file() and private.stat().st_mode&0o777==0o600
assert sha(Path('/Applications/LexFlow.app/Contents/MacOS/lexflow'))=='84d3937fda76e98490ee51f7e0a86395490b01d9d3c10604fc2901ce3f6f5c80'
(evidence/'cleanup.json').write_text(json.dumps({'completed_at':datetime.datetime.now().astimezone().isoformat(),'removed':removed,'icloud_generated_files_observed':icloud,'system_services_stopped':False,'real_user_profiles_touched':False,'license_registry_unchanged':True,'generator_and_private_issuer_preserved':True,'installed_mac_unchanged':True},indent=2)+'\n')
print('Verified cleanup complete.',flush=True)
