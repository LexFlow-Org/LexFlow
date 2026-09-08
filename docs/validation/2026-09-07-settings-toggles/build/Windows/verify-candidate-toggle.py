from pathlib import Path
import hashlib,json,struct,subprocess,shutil,re,datetime
root=Path(__file__).resolve().parent
project=root/'project'
release=root/'target/x86_64-pc-windows-msvc/release'
installers=list((release/'bundle/nsis').glob('*-setup.exe'))
assert len(installers)==1,installers
installer=installers[0]
output=root/'candidate-toggle';output.mkdir(exist_ok=True)
extracted=root/'extracted-toggle'
assert not extracted.exists(),'Use a fresh extraction directory for each candidate'
check=subprocess.run(['7z','t',str(installer)],capture_output=True,text=True)
(root/'installer-7z-test-toggle.log').write_text(check.stdout+check.stderr)
assert check.returncode==0,check.stdout+check.stderr
extract=subprocess.run(['7z','x',str(installer),'-o'+str(extracted),'-y'],capture_output=True,text=True)
(root/'installer-extract-toggle.log').write_text(extract.stdout+extract.stderr)
assert extract.returncode==0,extract.stdout+extract.stderr
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
expected={}
backend=project/'src-tauri'
for directory in ['templates','fonts','licenses']:
 for file in (backend/directory).rglob('*'):
  if file.is_file():expected[str(file.relative_to(backend))]=sha(file)
for file in (backend/'binaries/windows-qpdf').glob('*.dll'):expected[file.name]=sha(file)
for file in (backend/'binaries/windows-webview2').rglob('*'):
 if file.is_file():expected[str(file.relative_to(backend))]=sha(file)
for name in ['typst','qpdf']:expected[name+'.exe']=sha(backend/'binaries'/f'{name}-x86_64-pc-windows-msvc.exe')
expected['lexflow.exe']=sha(release/'lexflow.exe')
for relative,digest in expected.items():
 file=extracted/relative
 assert file.is_file(),f'Missing extracted resource: {relative}'
 assert sha(file)==digest,f'Mismatch: {relative}'
assert len(list(extracted.glob('*.dll')))==9
runtime_files=[p for p in (extracted/'binaries/windows-webview2').rglob('*') if p.is_file()]
assert len(runtime_files)==548

def pe_info(path):
 data=path.read_bytes()
 assert data[:2]==b'MZ'
 base=struct.unpack_from('<I',data,0x3c)[0]
 assert data[base:base+4]==b'PE\0\0'
 machine,sections=struct.unpack_from('<HH',data,base+4)
 size=struct.unpack_from('<H',data,base+20)[0];optional=base+24
 magic=struct.unpack_from('<H',data,optional)[0]
 directories=optional+(112 if magic==0x20b else 96)
 resource_rva=struct.unpack_from('<I',data,directories+16)[0]
 tables=[]
 for i in range(sections):
  offset=optional+size+i*40
  vsize,va,raw_size,raw=struct.unpack_from('<IIII',data,offset+8)
  tables.append((va,max(vsize,raw_size),raw))
 def file_offset(rva):
  for va,size,raw in tables:
   if va<=rva<va+size:return raw+rva-va
  raise AssertionError(f'Unmapped RVA {rva:x}')
 versions=[]
 if resource_rva:
  resource=file_offset(resource_rva)
  def entries(relative):
   offset=resource+relative;n_named,n_id=struct.unpack_from('<HH',data,offset+12)
   return [struct.unpack_from('<II',data,offset+16+i*8) for i in range(n_named+n_id)]
  def visit(relative):
   for name,target in entries(relative):
    if target&0x80000000:visit(target&0x7fffffff)
    else:
     rva,length=struct.unpack_from('<II',data,resource+target)
     offset=file_offset(rva);end=offset+length
     value_len=struct.unpack_from('<H',data,offset+2)[0];pos=offset+6
     while data[pos:pos+2]!=b'\0\0':pos+=2
     pos=(pos+2+3)&~3
     if pos+52<=end and value_len>=52:
      signature,structure,ms,ls=struct.unpack_from('<IIII',data,pos)
      assert signature==0xfeef04bd
      versions.append([ms>>16,ms&65535,ls>>16,ls&65535])
  for name,target in entries(0):
   if name==16 and target&0x80000000:visit(target&0x7fffffff)
 return {'machine':hex(machine),'fixed_file_versions':versions}

pe={name:pe_info(extracted/name) for name in ['lexflow.exe','typst.exe','qpdf.exe','qpdf30.dll','binaries/windows-webview2/msedgewebview2.exe']}
assert all(p['machine']=='0x8664' for p in pe.values())
assert [1,0,1,0] in pe['lexflow.exe']['fixed_file_versions']
public_key=bytes([174,48,245,149,58,105,117,189,197,166,82,54,39,166,166,194,189,248,121,72,199,249,194,97,34,165,16,49,44,16,222,13])
assert public_key in (extracted/'lexflow.exe').read_bytes()
assert hashlib.sha256(public_key).hexdigest()=='4ff69b87240948576d916234273c2468e0906c1468e190f2b9a2ac3a5230672f'
source=json.loads((root/'source-snapshot-sha256.json').read_text())
for name,digest in source.items():assert sha(project/name)==digest,name
nsis_files=list((release/'nsis').glob('*.nsi'))+list(release.glob('**/installer.nsi'))
receipt={
 'date':'2026-09-07','product':'LexFlow','version':'1.0.1','target':'x86_64-pc-windows-msvc',
 'installer':installer.name,'installer_bytes':installer.stat().st_size,'sha256':sha(installer),
 'build':{'host':'macOS ARM64 Apple M5','cargo_xwin':'0.23.1','llvm':'22.1.8','nsis':'3.12','jobs':2,'cargo_locked':True,'signed':False,'snapshot':str(project),'frontend_build':'Frozen client/dist, no frontend rebuild during cross compilation'},
 'verification':{'installer_7z_test':'passed','installer_extraction':'passed','extracted_files':sum(p.is_file() for p in extracted.rglob('*')),'application_resource_files_compared_sha256':len(expected),'webview2_fixed_runtime_files_compared_sha256':len(runtime_files),'vendor_qpdf_dlls':9,'pe':pe,'executable_sha256':expected['lexflow.exe'],'public_key_sha256':hashlib.sha256(public_key).hexdigest(),'public_key_bytes_present':True,'native_windows_execution':False,'windows_network_capture':False,'webview2_appcontainer_acl_hook':{'source':'src-tauri/windows/installer-hooks.nsh','sha256':sha(backend/'windows/installer-hooks.nsh'),'scope':'$INSTDIR\\binaries\\windows-webview2','grants':['S-1-15-2-2:(OI)(CI)(RX)','S-1-15-2-1:(OI)(CI)(RX)'],'failure_handling':'MessageBox + SetErrorLevel1 + Abort on command/exit failure','validation':'NSIS installer compiled; icacls and Windows app were not executed on macOS'}},
 'source_sha256_at_build':source,
 'frontend_source_sha256_at_build':json.loads((root/'frontend-toggle-source-sha256.json').read_text()),
 'change_scope':'Settings toggle event semantics, biometric availability diagnostics and native bridge updates; Android versionCode253 config carried in frozen source, Windows version unchanged1.0.1',
 'vendor_provenance':'Same preserved vendor files as previous build: Typst0.15.1, qpdf12.4.1, Fixed WebView2152.0.4191.62. Per-file hashes checked between snapshot and extracted new installer. Original archive hashes and Microsoft CAB signature verification are recorded in 2026-09-06 receipt.',
 'limitations':['Unsigned LexFlow binary/installer','No native Windows launch, license activation, vault, WebView rendering or network test','Source fixes validated in separate test reports; their inclusion proven by frozen source manifest and rebuilt executable']
}
shutil.copy2(installer,output/installer.name)
(output/'BUILD-VERIFICATION.json').write_text(json.dumps(receipt,indent=2)+'\n')
(output/'SOURCE-SHA256.json').write_text(json.dumps(source,indent=2)+'\n')
(output/'RESOURCES-SHA256.json').write_text(json.dumps(expected,indent=2)+'\n')
(output/'SHA256SUMS.txt').write_text(sha(installer)+'  '+installer.name+'\n')
print(json.dumps({'candidate':str(output/installer.name),'bytes':installer.stat().st_size,'sha256':sha(installer),'compared_files':len(expected),'pe':pe},indent=2))
