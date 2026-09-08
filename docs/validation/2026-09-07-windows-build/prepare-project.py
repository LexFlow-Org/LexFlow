from pathlib import Path
import hashlib, json, shutil, sys
source = Path(sys.argv[1]).resolve()
root = Path(__file__).resolve().parent
project = root / 'project'
project.mkdir(exist_ok=False)
backend = project / 'src-tauri'
backend.mkdir()
# Explicit source/resource allowlist: no root .env, license registry, private
# signing key, live vault, installed application or unrelated user files.
for name in ['src','icons','fonts','licenses','templates','windows','capabilities','permissions','native']:
    folder = source / 'src-tauri' / name
    if folder.is_dir(): shutil.copytree(folder, backend/name)
for name in ['Cargo.toml','Cargo.lock','build.rs','tauri.conf.json','tauri.windows.conf.json','Info.plist','entitlements.mac.plist']:
    file = source / 'src-tauri' / name
    if file.is_file(): shutil.copy2(file,backend/name)
binaries=backend/'binaries';binaries.mkdir()
for name in ['typst-x86_64-pc-windows-msvc.exe','qpdf-x86_64-pc-windows-msvc.exe']:
    shutil.copy2(source/'src-tauri/binaries'/name,binaries/name)
for name in ['windows-qpdf','windows-webview2']:
    shutil.copytree(source/'src-tauri/binaries'/name,binaries/name)
shutil.copytree(source/'client/dist',project/'client/dist')
for name in ['package.json','package-lock.json']:
    shutil.copy2(source/name,project/name)
(project/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
config={'build':{'beforeBuildCommand':'','frontendDist':'../client/dist'},'bundle':{'targets':['nsis']}}
(root/'cross-build-config.json').write_text(json.dumps(config,indent=2)+'\n')
manifest={}
for prefix in ['src-tauri/src','src-tauri/capabilities','client/dist']:
    for file in sorted((project/prefix).rglob('*')):
        if file.is_file():manifest[str(file.relative_to(project))]=hashlib.sha256(file.read_bytes()).hexdigest()
for name in ['Cargo.toml','Cargo.lock','build.rs','tauri.conf.json','tauri.windows.conf.json']:
    file=backend/name;manifest[str(file.relative_to(project))]=hashlib.sha256(file.read_bytes()).hexdigest()
(root/'source-snapshot-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(project)
