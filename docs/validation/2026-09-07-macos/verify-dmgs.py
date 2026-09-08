from pathlib import Path
import subprocess,json,plistlib,hashlib
root=Path('/private/tmp/lexflow-validation-2026-09-07/macos')
artifacts=[]
def run(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
for label,arch in [('Apple-Silicon','arm64'),('Intel','x86_64')]:
    dmg=root/'candidate'/f'LexFlow-1.0.1-macOS-{label}.dmg'
    mount=root/f'verify-{arch}'
    mount.mkdir(exist_ok=True)
    run(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-mountpoint',str(mount),str(dmg)])
    try:
        app=mount/'LexFlow.app';info=plistlib.loads((app/'Contents/Info.plist').read_bytes());assert info['CFBundleShortVersionString']=='1.0.1'
        run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)])
        binaries={}
        for name in ['lexflow','qpdf','typst']:
            p=app/'Contents/MacOS'/name;b=p.read_bytes();slices=run(['/usr/bin/lipo','-archs',str(p)]).strip();assert slices==arch
            links=run(['/usr/bin/otool','-L',str(p)]);assert '/opt/homebrew' not in links and '/usr/local/' not in links
            binaries[name]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'architecture':slices,'dependencies':links.splitlines()[1:]}
        b=(app/'Contents/MacOS/lexflow').read_bytes();assert b'/usr/bin/swift' not in b
        assert bytes.fromhex('5a0721069b92eee3db40d1b21545b15ab57fe7e99001365b5e71bcf4a8221f0e') not in b
        pubfound=bytes.fromhex('ae30f5953a6975bdc5a6523627a6a6c2bdf87948c7f9c26122a510312c10de0d') in b
        if arch=='arm64':assert pubfound
        artifacts.append({'file':dmg.name,'sha256':hashlib.sha256(dmg.read_bytes()).hexdigest(),'bytes':dmg.stat().st_size,'version':'1.0.1','codesign_strict_verified':True,'signature':'ad hoc; not notarized','binaries':binaries,'runtime_swift_reference_absent':True,'new_license_key_contiguous_in_main':pubfound,'intel_key_note':'Optimized Intel may synthesize constants as immediates; source freeze and tests verify issuer, contiguous scan alone is not validation.' if arch=='x86_64' else None,'biometrics_available_with_current_signature':False,'native_full_suite_on_exact_packaged_binary':False})
    finally:run(['/usr/bin/hdiutil','detach',str(mount)])
(root/'candidate'/'verifica-pacchetto.json').write_text(json.dumps({'date':'2026-09-07','artifacts':artifacts,'source_freeze_sha256':hashlib.sha256((root.parent/'source-freeze.json').read_bytes()).hexdigest(),'rust_tests_passed':428,'native_gui_intermediate_arm_tested':True,'intel_native_hardware_tested':False},indent=2)+'\n')
print(json.dumps([{'file':x['file'],'sha256':x['sha256'],'bytes':x['bytes']} for x in artifacts]))
