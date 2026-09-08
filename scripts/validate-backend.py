#!/usr/bin/env python3
"""Offline, synthetic validation of LexFlow's production Rust core.

No app data directory, keychain, private issuer key or real vault is opened.
The global Cargo cache is read-only input: selected archives/index are copied.
Generated source and build output live only in an explicitly owned scratch dir.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SCRATCH = Path("/private/tmp/lexflow-validation-2026-09-07/backend.noindex")
DEPENDENCIES = {
    "aes-gcm": "0.10", "aes-gcm-siv": "0.11", "argon2": "0.5", "base64": "0.22",
    "chrono": "0.4", "hex": "0.4", "hmac": "0.12", "libc": "0.2", "rand": "0.8",
    "rmp-serde": "1.3", "serde": "1.0", "serde_json": "1.0", "sha2": "0.10",
    "zeroize": "1.", "zstd": "0.13", "tempfile": "3.",
}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def prepare(work):
    marker = work / ".lexflow-validation-owned"
    if work.exists() and not marker.is_file():
        raise ValueError("Scratch directory exists and is not owned by this validation harness")
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker.write_text("Synthetic validation only. No user data.\n")
    source = work / "src"
    source.mkdir(exist_ok=True)
    lock = tomllib.loads((REPO / "src-tauri/Cargo.lock").read_text())
    packages = lock["package"]
    deps = []
    for name, prefix in DEPENDENCIES.items():
        candidates = [p for p in packages if p["name"] == name and p["version"].startswith(prefix)]
        if len(candidates) != 1:
            raise ValueError(f"Cannot identify locked core dependency: {name}")
        version = candidates[0]["version"]
        if name == "serde":
            deps.append(f'{name} = {{version="={version}", features=["derive"]}}')
        elif name == "zeroize":
            deps.append(f'{name} = {{version="={version}", features=["derive", "alloc"]}}')
        else:
            deps.append(f'{name} = "={version}"')
    (work / "Cargo.toml").write_text(
        '[package]\nname="lexflow-backend-validation"\nversion="0.0.0"\nedition="2021"\n'
        '[dependencies]\n' + "\n".join(deps) +
        '\n[profile.release]\nopt-level=3\nlto="thin"\ncodegen-units=1\ndebug=false\nstrip=true\n')
    if not (work / "Cargo.lock").exists():
        shutil.copyfile(REPO / "src-tauri/Cargo.lock", work / "Cargo.lock")

    cargo = work / "cargo-home"
    cargo.mkdir(exist_ok=True)
    original_registry = Path.home() / ".cargo/registry"
    index = cargo / "registry/index"
    if not index.exists():
        shutil.copytree(original_registry / "index", index)
    locked_archives = {f'{p["name"]}-{p["version"]}.crate' for p in packages}
    copied_bytes = 0
    for archive in (original_registry / "cache").glob("*/*.crate"):
        if archive.name not in locked_archives:
            continue
        target = cargo / "registry/cache" / archive.parent.name / archive.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(archive, target)
            copied_bytes += target.stat().st_size

    modules = []
    provenance = {}
    for name in ("constants", "io", "crypto", "security", "vault_engine"):
        path = REPO / f"src-tauri/src/{name}.rs"
        modules.append(f"#[path = {json.dumps(str(path))}] mod {name};")
        provenance[str(path.relative_to(REPO))] = digest(path)

    # Keep the production record decoder and its focused unit test verbatim.
    vault_path = REPO / "src-tauri/src/vault.rs"
    vault_decoder = vault_path.read_text().split("fn decode_indexed_record(", 1)[1].split("/// Write full vault data.", 1)[0]
    (source / "vault_decode.rs").write_text("use crate::vault_engine;\nuse serde_json::{json, Value};\nfn decode_indexed_record(" + vault_decoder)
    modules.append("mod vault_decode;")
    provenance[str(vault_path.relative_to(REPO))] = digest(vault_path)

    # Keep function bodies verbatim. Exclude only IPC wrappers/state imports.
    search_path = REPO / "src-tauri/src/search.rs"
    full_search = search_path.read_text()
    search = full_search.split("#[tauri::command]", 1)[0]
    search = "\n".join(line for line in search.splitlines()
        if line not in ("use crate::state::{get_vault_dek, get_vault_version, AppState};", "use tauri::State;"))
    search += '\npub(crate) fn fixture_searchable_text(v: &Value) -> String { extract_searchable_text(v, "practices") }\n'
    search += '''
pub(crate) fn fixture_consistent_index(directory: &std::path::Path, dek: &[u8], vault: &vault_engine::VaultData) -> SearchIndex {
    let entries = vault_engine::decrypt_index(dek, &vault.index).unwrap();
    ensure_index_consistent(directory, dek, &entries, vault)
}
'''
    # Compile the real search unit tests too; they contain no Tauri wrappers.
    search += '\n#[cfg(test)]\nmod tests {' + full_search.split('#[cfg(test)]\nmod tests {', 1)[1].split('/// Rebuild the entire search index', 1)[0]
    (source / "search.rs").write_text(search)
    modules.append("mod search;")
    provenance[str(search_path.relative_to(REPO))] = digest(search_path)
    backup_path = REPO / "src-tauri/src/backup.rs"
    backup = backup_path.read_text().split("#[tauri::command]", 1)[0]
    backup = "\n".join(line for line in backup.splitlines()
        if line not in ("use crate::state::AppState;", "use tauri::State;"))
    backup += '''
pub(crate) fn verify_fixture_backup(path: &std::path::Path) -> bool {
    let data = fs::read(path).unwrap();
    let mut sidecar = path.as_os_str().to_os_string(); sidecar.push(".hmac");
    fs::read_to_string(std::path::PathBuf::from(sidecar)).unwrap() == compute_backup_hmac(&data)
}
'''
    (source / "backup.rs").write_text(backup)
    modules.append("mod backup;")
    provenance[str(backup_path.relative_to(REPO))] = digest(backup_path)
    modules.append('''// Explicit test fixture: OS identity/keychain integration is NOT exercised.
mod platform {
    pub(crate) fn get_local_encryption_key() -> Vec<u8> { vec![0x7b; 32] }
    pub(crate) fn get_or_create_machine_id() -> String { "SYNTHETIC-VALIDATION-MACHINE".into() }
}''')
    main = (REPO / "scripts/validation/backend_main.rs").read_text().replace("#![allow(dead_code, unused_imports)]", "")
    (source / "main.rs").write_text("#![allow(dead_code, unused_imports)]\n" + "\n".join(modules) + "\n" + main)
    for relative in ("scripts/validate-backend.py", "scripts/validation/backend_main.rs", "scripts/validation/crash_interpose.c"):
        provenance[relative] = digest(REPO / relative)
    (work / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return cargo, provenance, copied_bytes


def run_case(binary, args, work, timeout):
    started = time.monotonic()
    try:
        child = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=timeout,
                               cwd=work, env=dict(os.environ, TMPDIR=str(work / "temporary")))
        try:
            result = json.loads(child.stdout.splitlines()[-1]) if child.returncode == 0 else {}
        except (ValueError, IndexError):
            result = {}
        return {"arguments":list(map(str,args)), "exit_code":child.returncode,
                "wall_seconds":time.monotonic()-started, "result":result,
                "stderr":child.stderr[-8000:]}
    except subprocess.TimeoutExpired:
        return {"arguments":list(map(str,args)), "timeout_seconds":timeout,
                "wall_seconds":time.monotonic()-started, "result":{}}


def crash_cases(binary, work):
    if platform.system() != "Darwin":
        return [{"kind":"crash","status":"not-run","reason":"macOS syscall interposer; requires native platform implementation elsewhere"}]
    dylib = work / "crash-interpose.dylib"
    subprocess.run(["/usr/bin/clang", "-dynamiclib", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(REPO / "scripts/validation/crash_interpose.c"), "-o", str(dylib)], check=True)
    fixture = work / "crash-fixture"
    if fixture.exists():
        shutil.rmtree(fixture)
    prepared = run_case(binary, ["prepare-crash", fixture], work, 90)
    if prepared.get("exit_code") != 0:
        return [{"kind":"crash","status":"failed-fixture","details":prepared}]
    results = []
    for phase in ("mid_write", "after_temp_close", "before_rename", "after_rename"):
        directory = work / ("crash-" + phase)
        if directory.exists():
            shutil.rmtree(directory)
        shutil.copytree(fixture, directory)
        marker = directory / "checkpoint"
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(dylib),
                   LEXFLOW_VALIDATION_TARGET=str(directory / "vault.lex"),
                   LEXFLOW_VALIDATION_MARKER=str(marker), LEXFLOW_VALIDATION_PHASE=phase,
                   TMPDIR=str(work / "temporary"))
        child = subprocess.Popen([str(binary), "write-crash", str(directory)], env=env,
                                 cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 15
        reached = False
        try:
            while time.monotonic() < deadline and child.poll() is None:
                if marker.exists():
                    reached = marker.read_text() == phase
                    break
                time.sleep(0.005)
            if child.poll() is None:
                child.kill()
            stdout, stderr = child.communicate(timeout=10)
            verified = run_case(binary, ["verify-crash", directory], work, 90) if reached else None
            expected = "new" if phase == "after_rename" else "old"
            okay = reached and child.returncode == -signal.SIGKILL and verified.get("exit_code") == 0 and verified["result"].get("generation") == expected
            results.append({"kind":"crash","phase":phase,"checkpoint_observed":reached,
                "child_exit_code":child.returncode,"status":"passed" if okay else "failed",
                "verified":verified,"stderr":stderr[-2000:],
                "orphan_staging_files":len(list(directory.glob(".vault.lex.tmp.*")))})
        finally:
            if child.poll() is None:
                child.kill(); child.wait()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, default=DEFAULT_SCRATCH)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000,10000,50000])
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--prepare-only", action="store_true")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--unit-tests-only", action="store_true")
    actions.add_argument("--crash-only", action="store_true")
    actions.add_argument("--gui-fixture", type=int, metavar="RECORDS",
                         help="Create a V8 fixture with the same password prehash as the UI; retains scratch")
    parser.add_argument("--skip-crash", action="store_true")
    parser.add_argument("--keep-scratch", action="store_true")
    args = parser.parse_args()
    work = args.scratch.expanduser().resolve()
    allowed = Path("/private/tmp/lexflow-validation-2026-09-07").resolve()
    if not work.is_relative_to(allowed) or work == allowed:
        parser.error("Scratch must be a dedicated child of /private/tmp/lexflow-validation-2026-09-07")
    if any(size < 1 or size > 50000 for size in args.sizes):
        parser.error("Sizes must be between 1 and 50000")
    if args.gui_fixture is not None and not 1 <= args.gui_fixture <= 50000:
        parser.error("Fixture size must be between 1 and 50000")
    if args.gui_fixture:
        args.keep_scratch = True
    cargo, provenance, copied = prepare(work)
    print(f"Scratch ready; copied {copied} bytes of cached archives; no downloads.", flush=True)
    if args.prepare_only:
        return 0
    results = {"machine":{"system":platform.system(),"release":platform.release(),"architecture":platform.machine(),
        "logical_cpus":os.cpu_count()},"source_sha256":provenance,"cases":[],
        "fidelity":"Production core source; search/backup bodies exclude IPC wrappers. Backup OS identity uses explicit synthetic fixtures. No app/installer integration."}
    try:
        (work / "temporary").mkdir(exist_ok=True)
        env = dict(os.environ, CARGO_HOME=str(cargo), CARGO_TARGET_DIR=str(work / "target"), TMPDIR=str(work / "temporary"))
        with (work / "build.log").open("w") as log:
            command = ["cargo", "test" if args.unit_tests_only else "build", "--release", "--offline", "--jobs", "2", "--manifest-path", str(work / "Cargo.toml")]
            if args.unit_tests_only:
                command.extend(["--", "--test-threads=1"])
            built = subprocess.run(command,
                                   cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
        if built.returncode:
            print((work / "build.log").read_text()[-12000:], file=sys.stderr)
            return built.returncode
        if args.unit_tests_only:
            log = (work / "build.log").read_text()
            summary = re.search(r'test result:.*', log)
            results["unit_tests"] = {"exit_code":built.returncode, "summary":summary.group(0) if summary else log[-4000:]}
            print(json.dumps(results["unit_tests"]), flush=True)
            if args.results:
                args.results.write_text(json.dumps(results,indent=2)+"\n")
            return 0
        binary = work / "target/release/lexflow-backend-validation"
        operations = [["reliability",work / "reliability"],
                          *[["vault",work / f"vault-{size}",size] for size in args.sizes],
                          *[["search",size] for size in args.sizes],
                          ["search-snapshot",work / f"vault-{max(args.sizes)}",max(args.sizes)]]
        if args.crash_only:
            operations = []
        if args.gui_fixture:
            size = args.gui_fixture
            output = work / f"gui-vault-{size}"
            if output.exists():
                raise ValueError("GUI fixture already exists; refusing to overwrite")
            operations = [["vault",work / f"vault-{size}",size],
                          ["gui-fixture",work / f"vault-{size}",output,size]]
        for operation in operations:
            if operation[0] in ("reliability", "vault") and operation[1].exists():
                if not operation[1].resolve().is_relative_to(work):
                    raise ValueError("Refusing to replace a fixture outside owned scratch")
                shutil.rmtree(operation[1])
            result = run_case(binary, operation, work, args.timeout)
            results["cases"].append(result)
            print(json.dumps(result), flush=True)
            if args.results:
                args.results.write_text(json.dumps(results,indent=2)+"\n")
        results["crash_cases"] = [] if args.skip_crash or args.gui_fixture else crash_cases(binary, work)
        print(json.dumps({"crash_cases":results["crash_cases"]}), flush=True)
        if args.results:
            args.results.write_text(json.dumps(results,indent=2)+"\n")
        return int(any(case.get("exit_code") != 0 for case in results["cases"]) or
                   any(case.get("status") != "passed" for case in results["crash_cases"]))
    finally:
        if not args.keep_scratch:
            shutil.rmtree(work)


if __name__ == "__main__":
    sys.exit(main())
