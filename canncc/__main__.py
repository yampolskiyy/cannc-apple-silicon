"""Experimental CLI for a pinned BiSheng + elfuse environment."""
import argparse
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tarfile
import uuid

from . import __version__
from . import authority, dependencies, profile, publication, runner
from .output import safe_print as print, silence as silence_broken_stream, write as write_stream, data_write

_operation_authority = ContextVar('cannc_operation_authority', default=None)


class ArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if message:
            write_stream(sys.stderr if file is None else file, message)


def parser():
    p = ArgumentParser(prog="cannc", description="Experimental Ascend C compiler runner")
    p.add_argument("--config", help="path to a fixed local profile JSON")
    sub = p.add_subparsers(dest="action", required=True)
    boot = sub.add_parser("bootstrap", help="install pinned inputs into new case-sensitive volumes")
    boot.add_argument("--recipe", required=True, type=Path)
    boot.add_argument("--destination", required=True, type=Path)
    boot.add_argument("--inputs-dir", type=Path, help="directory containing the locked input files")
    for name in ("mount", "unmount"):
        volume = sub.add_parser(name, help=f"{name} an existing installation")
        volume.add_argument("--destination", required=True, type=Path)
    sub.add_parser("doctor", help="verify the recorded environment without NPU access")
    sub.add_parser("version", help="run the pinned original BiSheng --version")
    key_cmd = sub.add_parser("recovery-key", help="manage the local recovery trust anchor")
    key_sub = key_cmd.add_subparsers(dest="key_action", required=True)
    key_sub.add_parser("init", help="initialize or register an existing recovery key")
    recover = sub.add_parser("recover", help="reconcile an interrupted output publication")
    recover.add_argument("manifest", type=Path, help="path to the affected build.json")
    recover.add_argument("--legacy-output", type=Path, help="explicitly trust an unsigned legacy journal for this exact output")
    for name in ("compile", "link", "build"):
        cmd = sub.add_parser(name)
        cmd.add_argument("inputs", nargs="+", type=Path)
        cmd.add_argument("-o", "--output", required=True, type=Path)
        if name in ("compile", "build"):
            cmd.add_argument("--mode", choices=("normal", "separate"), default="normal")
            cmd.add_argument("--flag", action="append", default=[], help="extra compiler option, e.g. --flag=-DVALUE=1")
        cmd.add_argument("--dry-run", action="store_true")
        cmd.add_argument("--log-root", type=Path, help="directory in which unique run logs are created")
    return p


def prefix(config):
    root = Path(config["execution_sysroot"])
    binary = root / config["bisheng_guest"].lstrip("/")
    cmd = [config["elfuse"], "--no-rosetta", "--sysroot", str(root), "--workdir", "/workspace", "--clear-env"]
    for env in config["environment"]:
        cmd += ["--env", env]
    return cmd + [str(binary)]


def expanded(config, name):
    return [x.replace("{target}", config["target_sysroot"]) for x in config[name]]


def inputs_for(args):
    paths = [p.expanduser().resolve() for p in args.inputs]
    if any(not p.is_file() for p in paths):
        raise ValueError("every input must be an existing regular file")
    output = args.output.expanduser().resolve()
    if output in paths:
        raise ValueError("output must not overwrite an input")
    if output.exists() and any(os.path.samefile(output, path) for path in paths):
        raise ValueError("output must not overwrite an input")
    if not output.parent.is_dir():
        raise ValueError(f"output directory does not exist: {output.parent}")
    if args.action == "compile" and len(paths) != 1:
        raise ValueError("compile accepts exactly one source")
    if args.action == "link" and any(p.suffix != ".o" for p in paths):
        raise ValueError("link accepts .o files")
    if args.action in ("compile", "build") and any(p.suffix not in (".asc", ".cpp") for p in paths):
        raise ValueError("compile/build accept .asc and .cpp sources")
    if args.action == "compile" and args.mode == "separate" and paths[0].suffix != ".asc":
        raise ValueError("separate mode requires an .asc source; compile host .cpp normally")
    for flag in getattr(args, "flag", []):
        if not re.fullmatch(r'-D[A-Za-z_][A-Za-z0-9_]*(?:=[^\x00\r\n]*)?|-U[A-Za-z_][A-Za-z0-9_]*', flag):
            raise ValueError(f"unsupported extra flag; only attached -D/-U macros are supported: {flag}")
    return paths, output


def plans(config, args, paths, output, run_dir):
    base = prefix(config)
    if args.action == "link":
        return [("link", base + expanded(config, "link_flags") + list(map(str, paths)) + ["-o", str(output)])]
    commands = []
    objects = []
    for index, source in enumerate(paths):
        obj = output if args.action == "compile" else run_dir / f"source-{index}.o"
        separate = args.mode == "separate" and source.suffix == ".asc"
        flags = expanded(config, "compile_flags") + list(args.flag) + (["-dc"] if separate else [])
        commands.append((f"compile-{index}", base + flags + ["-c", str(source), "-o", str(obj)]))
        objects.append(obj)
    if args.action == "build":
        commands.append(("link", base + expanded(config, "link_flags") + list(map(str, objects)) + ["-o", str(output)]))
    return commands


def write_json(path, data):
    if data.get('transaction') is not None:
        pinned = _operation_authority.get()
        if pinned is None:
            raise authority.JournalTrustError('operation has no pinned recovery key')
        pinned.sign(path, data)
    temp = path.with_name("." + path.name + ".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(temp, path)


def report_committed(output, manifest):
    """A closed output stream cannot undo an already recorded publication."""
    try:
        print(f"Created {output}\nManifest: {manifest}", flush=True)
    except (OSError, ValueError):
        silence_broken_stream(sys.stdout)


def report_committed_warning(message):
    try:
        print(message, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        silence_broken_stream(sys.stderr)


def check_elf(path, *, relocatable):
    """Check bounded ELF structures, not device code or full ABI semantics."""
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(64)
    if len(head) != 64 or head[:6] != b"\x7fELF\x02\x01" or head[6] != 1:
        raise ValueError(f"output is not ELF64 little-endian: {path}")
    kind, machine = struct.unpack_from("<HH", head, 16)
    if machine != 183 or kind not in ((1,) if relocatable else (2, 3)):
        raise ValueError(f"unexpected Linux AArch64 ELF type/machine: {path}")
    if struct.unpack_from("<I", head, 20)[0] != 1 or struct.unpack_from("<H", head, 52)[0] != 64:
        raise ValueError(f"invalid ELF header: {path}")
    if relocatable:
        shoff = struct.unpack_from("<Q", head, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", head, 58)
        if shoff < 64 or shentsize < 64 or shoff + shentsize > size:
            raise ValueError(f"invalid ELF section table: {path}")
        with path.open("rb") as stream:
            stream.seek(shoff)
            section0 = stream.read(64)
            if struct.unpack_from("<I", section0, 4)[0] != 0:
                raise ValueError(f"invalid ELF null section: {path}")
            if shnum == 0:  # ELF extended section count is stored in section zero.
                shnum = struct.unpack_from("<Q", section0, 32)[0]
            if shstrndx == 0xffff:
                shstrndx = struct.unpack_from("<I", section0, 40)[0]
            if shnum < 2 or shoff + shnum * shentsize > size or shstrndx >= shnum:
                raise ValueError(f"invalid ELF section table bounds: {path}")
            sections = []
            for index in range(shnum):
                stream.seek(shoff + index * shentsize)
                raw = stream.read(64)
                name, typ = struct.unpack_from("<II", raw, 0)
                offset, length = struct.unpack_from("<QQ", raw, 24)
                if typ not in (0, 8) and (offset > size or length > size - offset):
                    raise ValueError(f"ELF section outside file: {path}")
                sections.append((name, typ, offset, length))
            if not any(typ != 0 for _, typ, _, _ in sections[1:]):
                raise ValueError(f"ELF object lacks sections: {path}")
            # Section names are optional in ELF. If present, validate their table and offsets.
            if shstrndx:
                _, typ, offset, length = sections[shstrndx]
                if typ != 3 or length == 0:
                    raise ValueError(f"invalid ELF section-name table: {path}")
                stream.seek(offset)
                names = stream.read(length)
                if names[:1] != b"\0" or names[-1:] != b"\0":
                    raise ValueError(f"invalid ELF section names: {path}")
                if any(name >= length or names.find(b"\0", name) < 0 for name, _, _, _ in sections):
                    raise ValueError(f"invalid ELF section name offset: {path}")
        return
    phoff = struct.unpack_from("<Q", head, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", head, 54)
    if phoff < 64 or phentsize < 56 or not phnum or phoff + phnum * phentsize > size:
        raise ValueError(f"invalid ELF program headers: {path}")
    interpreter = None
    load_segments = 0
    with path.open("rb") as stream:
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            header = stream.read(56)
            typ = struct.unpack_from("<I", header)[0]
            offset = struct.unpack_from("<Q", header, 8)[0]
            length, memsize = struct.unpack_from("<QQ", header, 32)
            if typ and (offset > size or length > size - offset):
                raise ValueError(f"ELF segment outside file: {path}")
            if typ == 1:  # PT_LOAD
                if length > memsize:
                    raise ValueError(f"invalid ELF load segment: {path}")
                if length:
                    load_segments += 1
            if typ == 3:  # PT_INTERP
                if interpreter is not None:
                    raise ValueError(f"multiple ELF interpreters: {path}")
                if length == 0 or length > 4096 or offset + length > size:
                    raise ValueError(f"invalid ELF interpreter: {path}")
                stream.seek(offset)
                interpreter = stream.read(length)
    if not load_segments:
        raise ValueError(f"ELF executable lacks load segment: {path}")
    if interpreter != b"/lib/ld-linux-aarch64.so.1\0":
        raise ValueError(f"unexpected or missing target interpreter: {path}")


def _reject_protected_paths(config, output, log_root):
    execution = Path(config['execution_sysroot']).resolve()
    target = Path(config['target_sysroot']).resolve()
    protected = [execution / name for name in ('bin', 'lib', 'usr', 'opt')] + [target]
    for label, path in (('output', output), ('log root', log_root)):
        resolved = path.resolve()
        if any(resolved.is_relative_to(root.resolve()) for root in protected):
            raise ValueError(f'{label} must not be inside a pinned environment: {path}')


def _reject_dependency_output(output, dependencies):
    for name in dependencies:
        path = Path(name)
        if output.resolve() == path.resolve() or (output.exists() and path.exists() and os.path.samefile(output, path)):
            raise ValueError(f'output must not overwrite a dependency: {path}')


def build(config, args):
    paths, output = inputs_for(args)
    run_id = uuid.uuid4().hex
    root = args.log_root.expanduser().resolve() if args.log_root else output.parent / ".canncc" / "runs"
    _reject_protected_paths(config, output, root)
    run_dir = root / run_id
    # The staged output is on the same filesystem as the requested output.
    staged = output.parent / ("." + output.name + ".canncc-" + run_id + ".tmp")
    command_list = plans(config, args, paths, staged, run_dir)
    if args.dry_run:
        profile.check(config)
        data_write(sys.stdout, json.dumps({"mode": "dry-run", "commands": [c for _, c in command_list],
                          "dependency_commands": [dependencies.probe_command(c) for label, c in command_list if label.startswith('compile')],
                          "staged_output": str(staged), "final_output": str(output)}, indent=2) + '\n')
        return 0
    run_dir.mkdir(parents=True, exist_ok=False)
    input_hashes = {str(path): profile.sha(path) for path in paths}
    tool_sources = {str(path): profile.sha(path) for path in sorted(Path(__file__).resolve().parent.glob("*.py"))}
    record = {"schema_version": 1, "run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "running", "action": args.action, "mode": getattr(args, "mode", None),
              "profile_sha256": profile.sha(args.config), "profile_id": config.get("profile_id"),
              "environment_identity": None, "known_limitations": config.get("known_limitations", []),
              "toolchain": {"elfuse_commit": config.get("elfuse_commit"), "bisheng_version": config.get("bisheng_version")},
              "dependency_scope": "direct inputs, pinned snapshots and external headers emitted by BiSheng -M; not all file reads or absent include probes",
              "inputs": input_hashes, "tool_sources": tool_sources, "steps": [], "dependency_checks": [], "external_dependencies": {},
              "requested_output": str(output), "staged_output": str(staged), "output_sha256": None}
    manifest = run_dir / "build.json"
    write_json(manifest, record)
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    lock = None
    transaction = None
    replacement_attempted = False
    preserve_staged = False
    def on_term(_sig, _frame):
        raise InterruptedError("received SIGTERM")
    signal.signal(signal.SIGTERM, on_term)
    try:
        identity = profile.check(config)
        record["environment_identity"] = identity
        write_json(manifest, record)
        for label, command in command_list:
            if label.startswith('compile'):
                dependency_check, external = dependencies.scan(command, command[-3], run_dir, label, config)
                for path, digest in external.items():
                    if path in record['external_dependencies'] and record['external_dependencies'][path] != digest:
                        raise ValueError(f'external dependency changed between probes: {path}')
                    record['external_dependencies'][path] = digest
                record['dependency_checks'].append(dependency_check)
                _reject_dependency_output(output, record['external_dependencies'])
            stdout, stderr = run_dir / f"{label}.stdout", run_dir / f"{label}.stderr"
            outcome = runner.run(command, stdout, stderr, config.get("timeout_seconds", 180))
            outcome.update({"name": label, "command": command, "stdout": str(stdout), "stderr": str(stderr),
                            "stdout_sha256": profile.sha(stdout), "stderr_sha256": profile.sha(stderr)})
            record["steps"].append(outcome); write_json(manifest, record)
            if outcome["exit_code"] != 0:
                record.update(status="cancelled" if outcome.get("cancelled_by") else "failed", exit_code=outcome["exit_code"],
                              cancelled_by=outcome.get("cancelled_by"))
                write_json(manifest, record)
                print(f"{label} failed; logs: {run_dir}", file=sys.stderr)
                return outcome["exit_code"]
            stage_output = Path(command[-1])
            if not stage_output.is_file(): raise ValueError(f"{label} returned success without an output")
            check_elf(stage_output, relocatable=label.startswith("compile"))
            outcome.update(artifact_path=str(stage_output), artifact_sha256=profile.sha(stage_output))
            write_json(manifest, record)
        if not staged.is_file(): raise ValueError("compiler succeeded but output is missing")
        if any(profile.sha(path) != value for path, value in input_hashes.items()):
            raise ValueError("an input changed during the build")
        if any(not Path(path).is_file() or profile.sha(path) != value for path, value in record['external_dependencies'].items()):
            raise ValueError('an external dependency changed during the build')
        if any(profile.sha(path) != value for path, value in tool_sources.items()):
            raise ValueError("cannc source changed during the build")
        if profile.sha(args.config) != record["profile_sha256"]:
            raise ValueError("profile changed during the build")
        if profile.check(config) != identity:
            raise ValueError("environment changed during the build")
        lock = publication.acquire_lock(output)
        pinned = _operation_authority.get()
        pinned.check()
        # Recheck immediately before creating a backup and publishing.
        if output.exists() and any(os.path.samefile(output, path) for path in paths):
            raise ValueError("output must not overwrite an input")
        _reject_protected_paths(config, output, root)
        _reject_dependency_output(output, record['external_dependencies'])
        transaction = publication.prepare(output, staged, run_id)
        record.update(status="committing", output_sha256=transaction['new']['sha256'],
                      transaction=transaction)
        write_json(manifest, record)
        replacement_attempted = True
        if not publication.matches(output, transaction['previous']):
            raise publication.RecoveryRequired('output changed before publication')
        pinned.check()
        os.replace(staged, output)
        if not publication.matches(output, transaction['new']):
            raise publication.RecoveryRequired('published output differs from staged file')
        record.update(status="success", exit_code=0); write_json(manifest, record)
        try:
            pinned.check()
        except (OSError, authority.JournalTrustError) as exc:
            report_committed_warning(f"Build succeeded, but recovery key requires attention: {exc}; backup retained")
            report_committed(output, manifest)
            return 0
        try:
            publication.discard_backup(transaction)
        except (OSError, publication.RecoveryRequired) as exc:
            report_committed_warning(f"Build succeeded, but backup cleanup requires attention: {exc}")
        report_committed(output, manifest)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, KeyboardInterrupt, InterruptedError,
            publication.RecoveryRequired) as exc:
        code = (130 if isinstance(exc, KeyboardInterrupt) else 143 if isinstance(exc, InterruptedError)
                else exc.outcome['exit_code'] if isinstance(exc, dependencies.ProbeFailed) else 1)
        if isinstance(exc, authority.JournalTrustError) and transaction is not None:
            preserve_staged = True
            try:
                replaced = replacement_attempted and publication.matches(output, transaction['new'])
            except (OSError, ValueError, publication.RecoveryRequired):
                replaced = False
            state = ('output replaced; commit is unconfirmed' if replaced else 'output state requires inspection')
            print(f"Recovery key unavailable or changed; {state}. Retain output, backup and journal; "
                  f"restore the original key and run recover for {manifest}: {exc}", file=sys.stderr)
            return code
        if transaction is not None and replacement_attempted:
            # A second signal must not interrupt a rollback already in progress.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                result = publication.reconcile(manifest, record, write_json, error=exc, exit_code=code,
                                               authorize=_operation_authority.get().verify,
                                               recheck=_operation_authority.get().check)
                if result == 'committed':
                    try: publication.discard_backup(transaction)
                    except (OSError, publication.RecoveryRequired) as cleanup:
                        report_committed_warning(f"Build committed; backup cleanup requires attention: {cleanup}")
                    report_committed(output, manifest)
                    return 0
            except (OSError, ValueError, KeyError, publication.RecoveryRequired) as recovery:
                preserve_staged = True
                print(f"Publication state requires recovery: {recovery}; run cannc recover {manifest}", file=sys.stderr)
                return code
        else:
            if transaction is not None:
                try: publication.discard_backup(transaction)
                except (OSError, publication.RecoveryRequired) as cleanup:
                    print(f"Backup cleanup requires attention: {cleanup}", file=sys.stderr)
            cancelled = (bool(exc.outcome.get('cancelled_by')) if isinstance(exc, dependencies.ProbeFailed)
                         else code in (130, 143))
            if isinstance(exc, dependencies.ProbeFailed): record['dependency_failure'] = exc.outcome
            record.update(status="cancelled" if cancelled else "failed", exit_code=code,
                          error=str(exc), output_sha256=None)
            try: write_json(manifest, record)
            except OSError as journal_error:
                print(f"Cannot record failure: {journal_error}; inspect {manifest}", file=sys.stderr)
        print(f"Build failed: {exc}; logs: {run_dir}", file=sys.stderr)
        return code
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        if not preserve_staged and staged.exists():
            try: staged.unlink()
            except OSError as cleanup:
                print(f"Staged output cleanup requires attention: {cleanup}", file=sys.stderr)
        if lock is not None: lock.close()


def recover(manifest, legacy_output=None):
    manifest = Path(manifest).expanduser().resolve()
    saved = json.loads(manifest.read_text())
    pinned = _operation_authority.get()
    def authorize(path, record):
        pinned.check()
        if isinstance(record, dict) and 'journal_auth' not in record and legacy_output is not None:
            expected = Path(legacy_output).expanduser().resolve()
            if str(expected) != record.get('requested_output'):
                raise authority.JournalTrustError('legacy output does not match the journal')
            return
        pinned.verify(path, record)
    authorize(manifest, saved)
    tx = publication.validate(saved)
    lock = publication.acquire_lock(tx['output'])
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        result = publication.reconcile(manifest, saved, write_json,
                                       error=saved.get('error', 'interrupted during publication'),
                                       exit_code=saved.get('exit_code', 1), authorize=authorize,
                                       recheck=pinned.check)
        try:
            if result == 'committed': publication.discard_backup(tx)
            publication.discard_staged(tx)
        except (OSError, publication.RecoveryRequired) as cleanup:
            print(f"Recovery {result}; cleanup requires attention: {cleanup}", file=sys.stderr)
        print(f"Recovery {result}; manifest: {manifest}")
        return 0
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        lock.close()


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        if args.action == 'recovery-key':
            print(f'Recovery key initialized or registered: {authority.initialize()}')
            return 0
        if args.action == "bootstrap":
            from . import bootstrap
            return bootstrap.install(args.recipe, args.destination, args.inputs_dir)
        if args.action in ("mount", "unmount"):
            from . import bootstrap
            return bootstrap.volumes(args.destination, args.action)
        if args.action == "recover":
            token = _operation_authority.set(authority.Context.open())
            try: return recover(args.manifest, args.legacy_output)
            finally: _operation_authority.reset(token)
        if not args.config:
            raise ValueError("--config is required for this command")
        args.config = Path(args.config).expanduser().resolve()
        config = profile.load(args.config)
        if args.action in ("compile", "link", "build"):
            if args.dry_run: return build(config, args)
            token = _operation_authority.set(authority.Context.open())
            try: return build(config, args)
            finally: _operation_authority.reset(token)
        identity = profile.check(config)
        if args.action == "doctor":
            data_write(sys.stdout, json.dumps({"status": "static_checks_passed", "profile": config.get("profile_id"),
                              "identity": identity, "known_limitations": config.get("known_limitations", []),
                              "note": "compiler execution and NPU not tested by doctor"}, indent=2)+'\n')
            return 0
        if args.action == "version":
            import tempfile
            with tempfile.TemporaryDirectory(prefix="cannc-version-") as tmp:
                out, err = Path(tmp) / "stdout", Path(tmp) / "stderr"
                result = runner.run(prefix(config) + ["--version"], out, err, config.get("timeout_seconds", 180))
                data_write(sys.stdout, out.read_text(errors="replace")); write_stream(sys.stderr, err.read_text(errors="replace"))
                return result["exit_code"]
    except KeyboardInterrupt:
        print('cannc: interrupted', file=sys.stderr)
        return 130
    except InterruptedError as exc:
        print(f'cannc: {exc}', file=sys.stderr)
        return 143
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError,
            subprocess.SubprocessError, publication.RecoveryRequired) as exc:
        print(f"cannc: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
