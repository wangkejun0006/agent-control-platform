"""Export only declared public source; never use a recursive project copy."""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def public_files(root=ROOT):
    config = json.loads((root / "release/manifest.json").read_text())
    paths = [root / name for name in config["files"]]
    for name in config["directories"]:
        paths.extend(p for p in (root / name).rglob("*") if p.is_file())
    selected = []
    for p in sorted(set(paths)):
        rel = p.relative_to(root)
        if any(
            part in config["excluded_parts"]
            or part.endswith((".egg-info", ".dist-info"))
            for part in rel.parts
        ):
            continue
        if (
            p.suffix in config["excluded_suffixes"]
            or p.name in config["excluded_names"]
            or p.name.startswith(".env.")
        ):
            continue
        if p.is_symlink() or not p.is_file():
            raise ValueError("public_file_missing_or_symlink:" + str(rel))
        selected.append(p)
    return selected


def audit(path):
    if path.suffix.lower() in {".png", ".zip"}:
        return
    raw = path.read_bytes()
    for pattern in (
        rb"\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]{24,}",
        rb"-----BEGIN [^\n]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{24,}",
    ):
        if re.search(pattern, raw):
            raise ValueError("credential_pattern_requires_review:" + path.name)


def export(destination, root=ROOT):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("fresh_export_directory_required")
    files = public_files(root)
    for p in files:
        audit(p)
    destination.mkdir(parents=True)
    manifest = []
    for p in files:
        rel = p.relative_to(root)
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
        manifest.append(
            {
                "path": rel.as_posix(),
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
    (destination / "release-export.json").write_text(
        json.dumps({"schema": "orbit.public-export/1", "files": manifest}, indent=2)
        + "\n"
    )
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = export(args.output)
    print(
        json.dumps({"files": len(manifest), "status": "exported_locally_not_published"})
    )


if __name__ == "__main__":
    main()
