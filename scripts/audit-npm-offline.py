#!/usr/bin/env python3
"""Match local npm lockfiles against a previously downloaded OSV npm ZIP.

No network requests are made. The dependency graph is passed only to a local
Node process using the project's installed semver implementation. All lockfile
locations, including nested and optional/platform packages, are examined.
Exit 0: no matches; 1: matches; 2: incomplete/unsupported or invalid inputs.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

MATCHER = r'''
const fs = require('fs');
const semver = require(process.argv[1]);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const findings = [], unsupported = [];
function valid(value) {
  const parsed = semver.valid(value);
  if (parsed === null) throw new Error(`Invalid SEMVER boundary: ${value}`);
  return parsed;
}
function contains(version, range) {
  if (range.type !== 'SEMVER') throw new Error(`Unsupported range type: ${range.type}`);
  let lower = null, opened = false, matched = false;
  if (!Array.isArray(range.events) || range.events.length === 0) throw new Error('Missing range events');
  for (const event of range.events) {
    const keys = Object.keys(event);
    if (keys.length !== 1) throw new Error('Invalid range event');
    const kind = keys[0], boundary = event[kind];
    if (kind === 'introduced') {
      if (opened) throw new Error('Two introduced events without an interval end');
      lower = boundary === '0' ? null : valid(boundary); opened = true;
    } else if (['fixed', 'last_affected', 'limit'].includes(kind)) {
      if (!opened) throw new Error('Interval end without introduced event');
      const upper = valid(boundary);
      if (lower !== null && semver.gt(lower, upper)) throw new Error('Reversed interval');
      const above = lower === null || semver.gte(version, lower);
      const below = kind === 'last_affected' ? semver.lte(version, upper) : semver.lt(version, upper);
      matched ||= above && below;
      lower = null; opened = false;
    } else throw new Error(`Unsupported event: ${kind}`);
  }
  return matched || (opened && (lower === null || semver.gte(version, lower)));
}
for (const pkg of input.packages) {
  let version;
  try { version = valid(pkg.version); }
  catch (error) { unsupported.push({ ...pkg, reason: error.message }); continue; }
  for (const advisory of input.advisories) {
    if (advisory.withdrawn) continue;
    let affected = false;
    const fixed = new Set();
    for (const entry of advisory.affected || []) {
      if (entry.package?.ecosystem !== 'npm' || entry.package.name !== pkg.name) continue;
      for (const known of entry.versions || []) {
        try { affected ||= semver.eq(version, valid(known)); }
        catch (error) { unsupported.push({ id: advisory.id, ...pkg, reason: error.message }); }
      }
      for (const range of entry.ranges || []) {
        try { const match = contains(version, range); affected ||= match; }
        catch (error) { unsupported.push({ id: advisory.id, ...pkg, reason: error.message }); }
        for (const event of range.events || []) if (event.fixed) fixed.add(event.fixed);
      }
      if (!(entry.versions?.length || entry.ranges?.length))
        unsupported.push({ id: advisory.id, ...pkg, reason: 'Missing affected versions/ranges' });
    }
    if (affected) findings.push({ ...pkg, id: advisory.id, aliases: advisory.aliases || [],
      summary: advisory.summary || '', modified: advisory.modified, published: advisory.published,
      severity: advisory.database_specific?.severity || null,
      fixed_boundaries: [...fixed], url: `https://osv.dev/vulnerability/${advisory.id}` });
  }
}
process.stdout.write(JSON.stringify({ findings, unsupported }));
'''


def lock_packages(path):
    lock = json.loads(path.read_text())
    if lock.get("lockfileVersion", 0) < 2 or not isinstance(lock.get("packages"), dict):
        raise ValueError(f"{path}: package-lock v2/v3 required")
    packages = []
    for location, entry in lock["packages"].items():
        if not location or entry.get("link"):
            continue
        if not entry.get("version"):
            raise ValueError(f"{path}: missing version for {location}")
        name = entry.get("name") or location.rsplit("node_modules/", 1)[-1]
        packages.append({
            "lockfile": str(path), "path": location, "name": name,
            "version": entry["version"], "dev": entry.get("dev", False),
            "optional": entry.get("optional", False), "dev_optional": entry.get("devOptional", False),
            "installed_on_audit_host": (path.parent / location).is_dir(),
            "scope": "development" if entry.get("dev", False) else "runtime_or_optional",
        })
    return packages


def matching_advisories(archive, names):
    advisories = []
    total = 0
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            if not member.filename.endswith(".json"):
                continue
            total += 1
            if member.file_size > 32 * 1024 * 1024:
                raise ValueError(f"Oversized OSV record: {member.filename}")
            advisory = json.loads(source.read(member))
            if any(a.get("package", {}).get("ecosystem") == "npm" and a.get("package", {}).get("name") in names for a in advisory.get("affected", [])):
                advisories.append(advisory)
    return advisories, total


def run_matcher(packages, advisories, semver_path, node="node"):
    process = subprocess.run([node, "-e", MATCHER, str(semver_path.resolve())],
                             input=json.dumps({"packages": packages, "advisories": advisories}),
                             capture_output=True, text=True, check=True)
    return json.loads(process.stdout)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--lock", action="append", type=Path)
    parser.add_argument("--semver", type=Path, default=Path("client/node_modules/semver"))
    parser.add_argument("--node", default="node")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        locks = args.lock or [Path("package-lock.json"), Path("client/package-lock.json")]
        packages = [package for path in locks for package in lock_packages(path)]
        advisories, total = matching_advisories(args.archive, {p["name"] for p in packages})
        matched = run_matcher(packages, advisories, args.semver, args.node)
        findings = sorted(matched["findings"], key=lambda f: (f["scope"], f["name"], f["version"], f["id"], f["path"]))
        report = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": "Local OSV archive + exact SEMVER event interval matching; no network requests",
            "archive": {"path": str(args.archive), "sha256": sha256(args.archive), "json_records": total},
            "lockfiles": [{"path": str(path), "sha256": sha256(path)} for path in locks],
            "package_locations_checked": len(packages),
            "advisories_for_package_names": len(advisories),
            "counts": {
                "affected_locations": len({(f["lockfile"], f["path"]) for f in findings}),
                "unique_advisories": len({f["id"] for f in findings}),
                "runtime_advisory_package_versions": len({(f["id"], f["name"], f["version"]) for f in findings if not f["dev"]}),
                "development_advisory_package_versions": len({(f["id"], f["name"], f["version"]) for f in findings if f["dev"]}),
                "unassessed_entries": len(matched["unsupported"]),
            },
            "findings": findings, "unassessed": matched["unsupported"],
            "limitations": ["Package matching does not establish exploitability or application code reachability.",
                            "Optional/platform dependencies in the lockfile are checked even when not installed on this host.",
                            "The archive is a dated snapshot; this result is not a continuous vulnerability guarantee.",
                            "Fixed boundaries may belong to different release branches; they are not automatic upgrade recommendations."],
        }
        output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(output)
            print(json.dumps(report["counts"], ensure_ascii=False))
        else:
            print(output, end="")
        return 2 if matched["unsupported"] else 1 if findings else 0
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"Offline dependency audit incomplete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
