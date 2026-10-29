"""Load a fixed profile and verify the recorded dependency trees."""
import hashlib
import json
import math
import os
from pathlib import Path
import stat


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root, prefixes=None, directories=True):
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"directory unavailable: {root}")
    entries = []
    starts = [(root, "")] if prefixes is None else [(root / x, x) for x in prefixes]
    for start, prefix in starts:
        if not start.is_dir():
            raise ValueError(f"missing directory: {start}")
        if not start.resolve().is_relative_to(root.resolve()):
            raise ValueError(f'external snapshot prefix: {start}')
        for parent, dirs, files in os.walk(start, followlinks=False, onerror=lambda e: (_ for _ in ()).throw(e)):
            dirs.sort(); files.sort()
            for name in list(dirs) + files:
                path = Path(parent) / name
                rel = path.relative_to(root).as_posix()
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    entries.append({"path": rel, "type": "symlink", "target": os.readlink(path)})
                    if name in dirs: dirs.remove(name)
                elif stat.S_ISDIR(info.st_mode):
                    if directories: entries.append({"path": rel, "type": "directory"})
                elif stat.S_ISREG(info.st_mode):
                    entries.append({"path": rel, "type": "file", "size": info.st_size, "sha256": sha(path)})
                else:
                    raise ValueError(f"unsupported entry: {rel}")
    entries.sort(key=lambda entry: entry["path"])
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return entries, hashlib.sha256(canonical).hexdigest()


def load(path):
    path = Path(path).expanduser().resolve()
    config = json.loads(path.read_text())
    if config.get("schema_version") != 1:
        raise ValueError("unsupported profile schema")
    for key in ("elfuse", "execution_sysroot", "bisheng_guest", "target_sysroot",
                "execution_manifest", "target_manifest", "elfuse_sha256", "bisheng_sha256",
                "execution_digest", "target_digest"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"missing profile field: {key}")
    for key in ("compile_flags", "link_flags", "environment", "required_target_files"):
        if not isinstance(config.get(key), list) or not all(isinstance(x, str) for x in config[key]):
            raise ValueError(f"invalid profile field: {key}")
    timeout = config.get('timeout_seconds', 180)
    try:
        valid_timeout = not isinstance(timeout, bool) and isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0
    except OverflowError:
        valid_timeout = False
    if not valid_timeout:
        raise ValueError('timeout_seconds must be a finite positive number')
    return config


def check(config):
    root = Path(config["execution_sysroot"])
    target = Path(config["target_sysroot"])
    elfuse = Path(config["elfuse"])
    guest = config["bisheng_guest"]
    if not guest.startswith("/") or ".." in Path(guest).parts:
        raise ValueError("bisheng_guest must be an absolute guest path")
    compiler = root / guest.lstrip("/")
    if not os.path.ismount(root):
        raise ValueError(f"execution sysroot is not mounted: {root}")
    for path in (elfuse, compiler):
        if not path.is_file(): raise ValueError(f"missing executable: {path}")
    if not os.access(elfuse, os.X_OK): raise ValueError(f'elfuse is not executable: {elfuse}')
    if sha(elfuse) != config["elfuse_sha256"]: raise ValueError("elfuse SHA-256 mismatch")
    if sha(compiler) != config["bisheng_sha256"]: raise ValueError("BiSheng SHA-256 mismatch")
    if not (root / "workspace").is_dir(): raise ValueError("execution sysroot lacks /workspace")
    for relative in config["required_target_files"]:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"invalid target dependency path: {relative}")
        if not (target / path).is_file(): raise ValueError(f"missing target dependency: {target / path}")
    for manifest_key, folder, prefixes, directories in (
        ("execution_manifest", root, ("bin", "lib", "usr", "opt"), False),
        ("target_manifest", target, None, True),
    ):
        manifest = json.loads(Path(config[manifest_key]).read_text())
        stored = manifest["entries"]
        stored_digest = hashlib.sha256(json.dumps(stored, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if stored_digest != manifest["digest"]: raise ValueError(f"invalid {manifest_key} digest")
        expected_digest = config["execution_digest" if manifest_key == "execution_manifest" else "target_digest"]
        if stored_digest != expected_digest: raise ValueError(f"{manifest_key} differs from pinned profile")
        entries, actual_digest = snapshot(folder, prefixes, directories)
        root = folder.resolve()
        for entry in entries:
            if entry['type'] == 'symlink':
                link = folder / entry['path']
                # Bootstrap rewrites guest-absolute package links to relative links.
                # Refuse host escapes instead of treating link text as content.
                if not link.resolve().is_relative_to(root):
                    raise ValueError(f'external symlink in pinned {manifest_key}: {link}')
                if prefixes and not any(link.resolve().is_relative_to((folder / prefix).resolve())
                                        for prefix in prefixes):
                    raise ValueError(f'symlink target outside snapshot in {manifest_key}: {link}')
        if actual_digest != stored_digest or entries != stored:
            wanted = {entry["path"]: entry for entry in stored}
            current = {entry["path"]: entry for entry in entries}
            missing = sorted(wanted.keys() - current.keys())
            extra = sorted(current.keys() - wanted.keys())
            changed = sorted(k for k in wanted.keys() & current.keys() if wanted[k] != current[k])
            first = (missing or extra or changed or ["unknown"])[0]
            category = "missing" if missing else "extra" if extra else "changed"
            raise ValueError(f"{manifest_key} mismatch ({category}): {folder / first}")
    return {"elfuse_sha256": config["elfuse_sha256"], "bisheng_sha256": config["bisheng_sha256"],
            "execution_digest": json.loads(Path(config["execution_manifest"]).read_text())["digest"],
            "target_digest": json.loads(Path(config["target_manifest"]).read_text())["digest"]}
