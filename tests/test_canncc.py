import contextlib
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from canncc import authority, profile, publication, runner
from canncc import __main__ as cli
from canncc.__main__ import check_elf, main, plans


def fake_elf(kind):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[6] = 1
    struct.pack_into("<HHI", header, 16, kind, 183, 1)
    struct.pack_into("<H", header, 52, 64)
    if kind == 1:
        names = b"\0.text\0.shstrtab\0"
        data = b"\0\0\0\0" + names
        shoff = 64 + len(data)
        struct.pack_into("<Q", header, 40, shoff)
        struct.pack_into("<HHH", header, 58, 64, 3, 2)
        sections = bytearray(64 * 3)
        struct.pack_into("<II", sections, 64, 1, 1)
        struct.pack_into("<QQ", sections, 64 + 24, 64, 4)
        struct.pack_into("<II", sections, 128, 7, 3)
        struct.pack_into("<QQ", sections, 128 + 24, 68, len(names))
        return bytes(header + data + sections)
    return bytes(header)


class ProfileTests(unittest.TestCase):
    def test_snapshot_detects_content_and_symlink_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "lib").mkdir()
            (root / "lib/a").write_bytes(b"one")
            (root / "lib/link").symlink_to("a")
            before = profile.snapshot(root)
            self.assertEqual(before, profile.snapshot(root))
            (root / "lib/a").write_bytes(b"two")
            self.assertNotEqual(before[1], profile.snapshot(root)[1])
            (root / "lib/a").write_bytes(b"one")
            (root / "lib/link").unlink()
            (root / "lib/link").symlink_to("different")
            self.assertNotEqual(before[1], profile.snapshot(root)[1])

    def test_reports_missing_required_target_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); execution = root / "execution"; execution.mkdir()
            (execution / "workspace").mkdir(); (execution / "compiler").write_bytes(b"compiler")
            elfuse = root / "elfuse"; elfuse.write_bytes(b"elfuse")
            elfuse.chmod(0o755)
            target = root / "target"; target.mkdir()
            cfg = {"execution_sysroot": str(execution), "target_sysroot": str(target),
                   "elfuse": str(elfuse), "bisheng_guest": "/compiler",
                   "elfuse_sha256": profile.sha(elfuse), "bisheng_sha256": profile.sha(execution / "compiler"),
                   "required_target_files": ["lib64/libascendcl.so"]}
            with patch("canncc.profile.os.path.ismount", return_value=True):
                with self.assertRaisesRegex(ValueError, "missing target dependency.*libascendcl"):
                    profile.check(cfg)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key_env = patch.dict(os.environ, {'CANNC_RECOVERY_KEY_DIR': str(self.root / 'recovery-key')})
        self.key_env.start()
        authority.initialize()
        self.config = self.root / "profile.json"
        self.config.write_text("{}")
        self.source = self.root / "vector.asc"
        self.source.write_text("source")
        self.output = self.root / "result"
        self.fake_config = {"profile_id": "test", "elfuse": "/elfuse", "execution_sysroot": "/exec",
                            "bisheng_guest": "/compiler", "target_sysroot": "/target",
                            "compile_flags": ["-O2"], "link_flags": ["--sysroot={target}"],
                            "environment": [], "timeout_seconds": 5}
        self.load = patch("canncc.__main__.profile.load", return_value=self.fake_config)
        self.check = patch("canncc.__main__.profile.check", return_value={"target_digest": "test"})
        self.dep = patch("canncc.__main__.dependencies.scan", return_value=({'kind': 'fixture'}, {}))
        self.load.start(); self.check.start(); self.dep.start()

    def tearDown(self):
        self.load.stop(); self.check.stop(); self.dep.stop(); self.key_env.stop(); self.temp.cleanup()

    def argv(self, *extra):
        return ["--config", str(self.config), *extra]

    def test_dry_run_does_not_create_output_or_log_dir(self):
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = main(self.argv("build", str(self.source), "-o", str(self.output), "--dry-run"))
        self.assertEqual(code, 0)
        plan = json.loads(captured.getvalue()); commands = plan["commands"]
        self.assertEqual(len(commands), 2)
        self.assertIn('-M', plan['dependency_commands'][0])
        self.assertNotIn('-c', plan['dependency_commands'][0])
        self.assertIn("--sysroot=/target", commands[-1])
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / ".canncc").exists())

    def test_failure_never_replaces_existing_output(self):
        self.output.write_bytes(b"previous file")
        def fail(command, stdout, stderr, timeout):
            stdout.write_bytes(b""); stderr.write_bytes(b"failure")
            Path(command[-1]).write_bytes(b"partial")
            return {"exit_code": 42, "signal": None, "timed_out": False, "cleanup": None}
        with patch("canncc.__main__.runner.run", side_effect=fail), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        self.assertEqual(code, 42)
        self.assertEqual(self.output.read_bytes(), b"previous file")
        manifest = next(self.root.glob(".canncc/runs/*/build.json"))
        self.assertEqual(json.loads(manifest.read_text())["status"], "failed")
        self.assertFalse(list(self.root.glob(".result.canncc-*.tmp")))

    def test_external_dependency_change_prevents_publication(self):
        header = self.root / 'external.h'; header.write_text('before')
        digest = profile.sha(header)
        self.output.write_bytes(b'previous')
        def changed(command, stdout, stderr, timeout):
            header.write_text('after')
            return self.successful_compiler(command, stdout, stderr, timeout)
        with patch('canncc.__main__.dependencies.scan', return_value=({'kind':'fixture'}, {str(header):digest})), \
             patch('canncc.__main__.runner.run', side_effect=changed), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 1)
        self.assertEqual(self.output.read_bytes(), b'previous')
        self.assertEqual(json.loads(next(self.root.glob('.canncc/runs/*/build.json')).read_text())['status'], 'failed')

    def test_output_cannot_overwrite_scanned_header_or_hardlink(self):
        header = self.root / 'external.h'; header.write_text('keep me')
        alias = self.root / 'alias'; os.link(header, alias)
        for output in (header, alias):
            with self.subTest(output=output), \
                 patch('canncc.__main__.dependencies.scan', return_value=({'kind':'fixture'}, {str(header):profile.sha(header)})), \
                 patch('canncc.__main__.runner.run') as run, contextlib.redirect_stderr(io.StringIO()):
                code = main(self.argv('compile', str(self.source), '-o', str(output)))
                self.assertEqual(code, 1)
                run.assert_not_called()
                self.assertEqual(header.read_text(), 'keep me')

    def test_output_or_logs_inside_pinned_roots_rejected_before_writes(self):
        execution = self.root / 'execution'; target = self.root / 'target'
        (execution / 'opt').mkdir(parents=True); target.mkdir()
        self.fake_config.update(execution_sysroot=str(execution), target_sysroot=str(target))
        for extra in (['-o', str(execution / 'opt' / 'program')],
                      ['-o', str(self.output), '--log-root', str(target / 'logs')]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(self.argv('compile', str(self.source), *extra)), 1)
        self.assertFalse((execution / 'opt' / '.canncc').exists())
        self.assertFalse((target / 'logs').exists())

    def test_header_alias_created_during_compile_rejected_before_publication(self):
        header=self.root/'external.h';header.write_text('keep')
        def replace_alias(command, stdout, stderr, timeout):
            os.link(header,self.output)
            return self.successful_compiler(command,stdout,stderr,timeout)
        with patch('canncc.__main__.dependencies.scan',return_value=({'kind':'fixture'},{str(header):profile.sha(header)})), \
             patch('canncc.__main__.runner.run',side_effect=replace_alias),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(self.argv('compile',str(self.source),'-o',str(self.output))),1)
        self.assertEqual(header.read_text(),'keep')

    def test_non_elf_success_is_rejected(self):
        def bad(command, stdout, stderr, timeout):
            stdout.write_bytes(b""); stderr.write_bytes(b""); Path(command[-1]).write_bytes(b"not an ELF")
            return {"exit_code": 0, "signal": None, "timed_out": False, "cleanup": None}
        with patch("canncc.__main__.runner.run", side_effect=bad), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        self.assertEqual(code, 1)
        self.assertFalse(self.output.exists())

    def test_executable_requires_target_interpreter(self):
        header = bytearray(fake_elf(3))
        struct.pack_into("<Q", header, 32, 64)
        struct.pack_into("<HH", header, 54, 56, 2)
        program = bytearray(112)
        struct.pack_into("<I", program, 0, 1)
        struct.pack_into("<QQ", program, 32, 176, 176)
        struct.pack_into("<I", program, 56, 3)
        loader = b"/lib/ld-linux-aarch64.so.1\0"
        struct.pack_into("<Q", program, 56 + 8, 176)
        struct.pack_into("<Q", program, 56 + 32, len(loader))
        self.output.write_bytes(header + program + loader)
        check_elf(self.output, relocatable=False)
        self.output.write_bytes(header + program + b"/bad-loader\0")
        with self.assertRaises(ValueError):
            check_elf(self.output, relocatable=False)

    def test_object_rejects_header_only_and_out_of_bounds_section(self):
        self.output.write_bytes(fake_elf(1)[:64])
        with self.assertRaisesRegex(ValueError, 'section table'):
            check_elf(self.output, relocatable=True)
        data = bytearray(fake_elf(1))
        shoff = struct.unpack_from('<Q', data, 40)[0]
        struct.pack_into('<QQ', data, shoff + 64 + 24, len(data) - 1, 100)
        self.output.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'section outside file'):
            check_elf(self.output, relocatable=True)

    def test_elf_rejects_invalid_identification_version(self):
        data = bytearray(fake_elf(1)); data[6] = 0
        self.output.write_bytes(data)
        with self.assertRaises(ValueError):
            check_elf(self.output, relocatable=True)

    def test_object_accepts_extended_section_count_and_name_index(self):
        data = bytearray(fake_elf(1))
        shoff = struct.unpack_from('<Q', data, 40)[0]
        struct.pack_into('<HH', data, 60, 0, 0xffff)
        struct.pack_into('<Q', data, shoff + 32, 3)
        struct.pack_into('<I', data, shoff + 40, 2)
        self.output.write_bytes(data)
        check_elf(self.output, relocatable=True)

    def test_object_rejects_bad_section_name(self):
        data = bytearray(fake_elf(1))
        shoff = struct.unpack_from('<Q', data, 40)[0]
        struct.pack_into('<I', data, shoff + 64, 999)
        self.output.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'name offset'):
            check_elf(self.output, relocatable=True)

    def test_executable_rejects_missing_or_invalid_load_segment(self):
        data = bytearray(fake_elf(3))
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 2)
        ph = bytearray(112)
        struct.pack_into('<I', ph, 56, 3)
        loader = b'/lib/ld-linux-aarch64.so.1\0'
        struct.pack_into('<Q', ph, 56 + 8, 176)
        struct.pack_into('<Q', ph, 56 + 32, len(loader))
        self.output.write_bytes(data + ph + loader)
        with self.assertRaisesRegex(ValueError, 'lacks load'):
            check_elf(self.output, relocatable=False)
        struct.pack_into('<I', ph, 0, 1)
        struct.pack_into('<QQ', ph, 32, 100, 10)
        self.output.write_bytes(data + ph + loader)
        with self.assertRaisesRegex(ValueError, 'load segment'):
            check_elf(self.output, relocatable=False)

    def test_missing_dependency_saves_failed_manifest(self):
        self.check.stop()
        self.check = patch("canncc.__main__.profile.check", side_effect=ValueError("missing target dependency: libascendcl.so"))
        self.check.start()
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        self.assertEqual(code, 1)
        self.assertIn("libascendcl.so", captured.getvalue())
        record = json.loads(next(self.root.glob(".canncc/runs/*/build.json")).read_text())
        self.assertEqual(record["status"], "failed")
        self.assertIsNone(record["output_sha256"])
        self.assertFalse(self.output.exists())

    def test_cancelled_compiler_cannot_publish_or_claim_success(self):
        def cancel(command, stdout, stderr, timeout):
            stdout.write_bytes(b""); stderr.write_bytes(b"interrupted")
            Path(command[-1]).write_bytes(fake_elf(1))
            return {"exit_code": 130, "signal": None, "cancelled_by": signal.SIGINT, "timed_out": False, "cleanup": "term_sent"}
        with patch("canncc.__main__.runner.run", side_effect=cancel), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        record = json.loads(next(self.root.glob(".canncc/runs/*/build.json")).read_text())
        self.assertEqual(code, 130)
        self.assertEqual(record["status"], "cancelled")
        self.assertIsNone(record["output_sha256"])
        self.assertFalse(self.output.exists())

    def test_separate_mode_only_applies_dc_to_asc(self):
        host = self.root / "main.cpp"; host.write_text("host")
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = main(self.argv("build", "--mode", "separate", str(self.source), str(host), "-o", str(self.output), "--dry-run"))
        self.assertEqual(code, 0)
        commands = json.loads(captured.getvalue())["commands"]
        self.assertIn("-dc", commands[0])
        self.assertNotIn("-dc", commands[1])
        self.assertEqual(len(commands), 3)

    def test_success_publishes_and_records_hash(self):
        def success(command, stdout, stderr, timeout):
            stdout.write_bytes(b""); stderr.write_bytes(b"")
            Path(command[-1]).write_bytes(fake_elf(1))
            return {"exit_code": 0, "signal": None, "timed_out": False, "cleanup": None}
        with patch("canncc.__main__.runner.run", side_effect=success), contextlib.redirect_stdout(io.StringIO()):
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        self.assertEqual(code, 0)
        record = json.loads(next(self.root.glob(".canncc/runs/*/build.json")).read_text())
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["output_sha256"], profile.sha(self.output))

    @staticmethod
    def successful_compiler(command, stdout, stderr, timeout):
        stdout.write_bytes(b''); stderr.write_bytes(b'')
        Path(command[-1]).write_bytes(fake_elf(1))
        return {'exit_code': 0, 'signal': None, 'timed_out': False, 'cleanup': None}

    def build_manifest(self):
        return next(self.root.glob('.canncc/runs/*/build.json'))

    def test_final_manifest_failure_restores_existing_output(self):
        self.output.write_bytes(b'old output')
        original = cli.write_json
        def fail_success(path, record):
            if record.get('status') == 'success': raise OSError('simulated final write failure')
            return original(path, record)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=fail_success), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        record = json.loads(self.build_manifest().read_text())
        self.assertEqual(code, 1)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(record['status'], 'failed')
        self.assertIsNone(record['output_sha256'])
        self.assertEqual(record['recovery']['status'], 'previous_output_restored')
        self.assertFalse(list(self.root.glob('.result.canncc-*.backup')))

    def test_final_manifest_failure_restores_absence_of_output(self):
        original = cli.write_json
        def fail_success(path, record):
            if record.get('status') == 'success': raise OSError('simulated final write failure')
            return original(path, record)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=fail_success), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        record = json.loads(self.build_manifest().read_text())
        self.assertEqual(code, 1)
        self.assertFalse(self.output.exists())
        self.assertEqual(record['recovery']['status'], 'output_absent')

    def test_failure_before_output_rename_preserves_old_file(self):
        self.output.write_bytes(b'old output')
        original = os.replace
        def fail_output(src, dst):
            if Path(dst).resolve() == self.output.resolve(): raise OSError('rename failed')
            return original(src, dst)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.os.replace', side_effect=fail_output), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 1)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'failed')

    def test_failure_recording_commit_intent_does_not_change_output(self):
        self.output.write_bytes(b'old output')
        original = cli.write_json
        def fail_intent(path, record):
            if record.get('status') == 'committing': raise OSError('cannot record commit intent')
            return original(path, record)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=fail_intent), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 1)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'failed')
        self.assertFalse(list(self.root.glob('.result.canncc-*.backup')))

    def test_signal_after_rename_rolls_back(self):
        self.output.write_bytes(b'old output')
        original = os.replace
        signalled = [False]
        def signal_after(src, dst):
            result = original(src, dst)
            if Path(dst).resolve() == self.output.resolve() and not signalled[0]:
                signalled[0] = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.os.replace', side_effect=signal_after), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertTrue(signalled[0])
        self.assertEqual(code, 143)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'cancelled')

    def test_success_write_then_exception_is_recognized_as_committed(self):
        self.output.write_bytes(b'old output')
        original = cli.write_json
        def write_then_raise(path, record):
            original(path, record)
            if record.get('status') == 'success': raise OSError('interrupted after manifest replacement')
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=write_then_raise), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 0)
        self.assertEqual(self.output.read_bytes(), fake_elf(1))
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'success')
        self.assertFalse(list(self.root.glob('.result.canncc-*.backup')))

    def test_closed_stdout_after_commit_does_not_report_build_failure(self):
        self.output.write_bytes(b'old output')
        class BrokenOutput(io.StringIO):
            def write(self, _value): raise BrokenPipeError('consumer closed')
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             contextlib.redirect_stdout(BrokenOutput()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 0)
        self.assertEqual(self.output.read_bytes(), fake_elf(1))
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'success')

    def test_closed_pipe_after_commit_keeps_real_process_exit_successful(self):
        code = '''
import sys
from pathlib import Path
from unittest.mock import patch
from canncc import __main__ as cli
from test_canncc import fake_elf
root=Path(sys.argv[1]); source=root/'input.asc'; source.write_text('source')
config=root/'profile.json'; config.write_text('{}')
conf={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec',
      'bisheng_guest':'/compiler','target_sysroot':'/target','compile_flags':[],
      'link_flags':[],'environment':[],'timeout_seconds':5}
def runner(command, stdout, stderr, timeout):
    stdout.write_bytes(b''); stderr.write_bytes(b''); Path(command[-1]).write_bytes(fake_elf(1))
    return {'exit_code':0,'signal':None,'timed_out':False,'cleanup':None}
with patch.object(cli.profile,'load',return_value=conf), patch.object(cli.profile,'check',return_value={}), patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), patch.object(cli.runner,'run',side_effect=runner):
    sys.exit(cli.main(['--config',str(config),'compile',str(source),'-o',str(root/'output')]))
'''
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env['PYTHONPATH'] = os.pathsep.join((str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)))
            proc = subprocess.Popen([sys.executable, '-c', code, tmp], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env)
            proc.stdout.close()
            stderr = proc.stderr.read()
            proc.stderr.close()
            self.assertEqual(proc.wait(timeout=15), 0, stderr.decode(errors='replace'))
            record = json.loads(next(Path(tmp).glob('.canncc/runs/*/build.json')).read_text())
            self.assertEqual(record['status'], 'success')
            self.assertEqual((Path(tmp) / 'output').read_bytes(), fake_elf(1))

    def test_closed_stderr_during_post_commit_warning_keeps_success(self):
        code = '''
import sys
from pathlib import Path
from unittest.mock import patch
from canncc import __main__ as cli
from test_canncc import fake_elf
root=Path(sys.argv[1]); source=root/'input.asc'; source.write_text('source')
config=root/'profile.json'; config.write_text('{}')
conf={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec',
      'bisheng_guest':'/compiler','target_sysroot':'/target','compile_flags':[],
      'link_flags':[],'environment':[],'timeout_seconds':5}
def runner(command, stdout, stderr, timeout):
    stdout.write_bytes(b''); stderr.write_bytes(b''); Path(command[-1]).write_bytes(fake_elf(1))
    return {'exit_code':0,'signal':None,'timed_out':False,'cleanup':None}
with patch.object(cli.profile,'load',return_value=conf), patch.object(cli.profile,'check',return_value={}), patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), patch.object(cli.runner,'run',side_effect=runner), patch.object(cli.publication,'discard_backup',side_effect=OSError('cleanup failed')):
    sys.exit(cli.main(['--config',str(config),'compile',str(source),'-o',str(root/'output')]))
'''
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env['PYTHONPATH'] = os.pathsep.join((str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)))
            proc = subprocess.Popen([sys.executable, '-c', code, tmp], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env)
            proc.stderr.close()
            stdout = proc.stdout.read()
            proc.stdout.close()
            self.assertEqual(proc.wait(timeout=15), 0, stdout.decode(errors='replace'))
            record = json.loads(next(Path(tmp).glob('.canncc/runs/*/build.json')).read_text())
            self.assertEqual(record['status'], 'success')
            self.assertEqual((Path(tmp) / 'output').read_bytes(), fake_elf(1))

    def test_recovery_after_final_and_rollback_journal_failures(self):
        self.output.write_bytes(b'old output')
        original = cli.write_json
        def fail_transition(path, record):
            if record.get('status') in ('success', 'rolling_back'): raise OSError('journal unavailable')
            return original(path, record)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=fail_transition), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        manifest = self.build_manifest()
        self.assertEqual(code, 1)
        self.assertIn('requires recovery', err.getvalue())
        self.assertEqual(json.loads(manifest.read_text())['status'], 'committing')
        self.assertEqual(self.output.read_bytes(), fake_elf(1))
        self.assertTrue(list(self.root.glob('.result.canncc-*.backup')))
        with contextlib.redirect_stdout(io.StringIO()):
            recovered = main(['recover', str(manifest)])
        self.assertEqual(recovered, 0)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(json.loads(manifest.read_text())['status'], 'failed')
        self.assertFalse(list(self.root.glob('.result.canncc-*.backup')))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['recover', str(manifest)]), 0)
        self.assertEqual(self.output.read_bytes(), b'old output')

    def test_failed_rollback_rename_preserves_backup_for_recovery(self):
        self.output.write_bytes(b'old output')
        original_write = cli.write_json
        original_replace = os.replace
        def fail_success(path, record):
            if record.get('status') == 'success': raise OSError('manifest failure')
            return original_write(path, record)
        def fail_restore(src, dst):
            if str(src).endswith('.backup') and Path(dst).resolve() == self.output.resolve():
                raise OSError('restore failed')
            return original_replace(src, dst)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=fail_success), \
             patch('canncc.__main__.os.replace', side_effect=fail_restore), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        manifest = self.build_manifest()
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(manifest.read_text())['status'], 'rolling_back')
        self.assertEqual(self.output.read_bytes(), fake_elf(1))
        self.assertTrue(list(self.root.glob('.result.canncc-*.backup')))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['recover', str(manifest)]), 0)
        self.assertEqual(self.output.read_bytes(), b'old output')
        self.assertEqual(json.loads(manifest.read_text())['status'], 'failed')

    def test_changed_output_is_never_overwritten_during_recovery(self):
        self.output.write_bytes(b'old output')
        original = cli.write_json
        def change_after_publish(path, record):
            if record.get('status') == 'success':
                self.output.write_bytes(b'external change')
                raise OSError('write failed after external change')
            return original(path, record)
        with patch('canncc.__main__.runner.run', side_effect=self.successful_compiler), \
             patch('canncc.__main__.write_json', side_effect=change_after_publish), \
             contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv('compile', str(self.source), '-o', str(self.output)))
        self.assertEqual(code, 1)
        self.assertEqual(self.output.read_bytes(), b'external change')
        self.assertEqual(json.loads(self.build_manifest().read_text())['status'], 'committing')
        self.assertTrue(list(self.root.glob('.result.canncc-*.backup')))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['recover', str(self.build_manifest())]), 1)
        self.assertEqual(self.output.read_bytes(), b'external change')

    def test_recovery_refuses_while_output_locked(self):
        lock = publication.acquire_lock(self.output)
        try:
            with self.assertRaises(BlockingIOError):
                publication.acquire_lock(self.output)
        finally:
            lock.close()

    def test_sigkill_at_publication_boundaries_can_be_reconciled(self):
        # A separate process is killed at three distinct filesystem boundaries;
        # the recovery command then uses only the saved transaction and files.
        for scenario in ('before_intent_record', 'before_success_record', 'after_success_record', 'during_rollback', 'before_record_no_old'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); output = root / 'result'
                if scenario != 'before_record_no_old': output.write_bytes(b'old output')
                source = root / 'input.asc'; source.write_text('source')
                config = root / 'profile.json'; config.write_text('{}')
                code = '''
import os, signal, sys
from pathlib import Path
from unittest.mock import patch
from canncc import __main__ as cli
from test_canncc import fake_elf
scenario, config, source, output = sys.argv[1:]
conf = {'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec',
        'bisheng_guest':'/compiler','target_sysroot':'/target','compile_flags':['-O2'],
        'link_flags':[],'environment':[],'timeout_seconds':5}
def runner(command, stdout, stderr, timeout):
    stdout.write_bytes(b''); stderr.write_bytes(b''); Path(command[-1]).write_bytes(fake_elf(1))
    return {'exit_code':0,'signal':None,'timed_out':False,'cleanup':None}
original = cli.write_json
def interrupted(path, record):
    status = record.get('status')
    if status == 'committing' and scenario == 'before_intent_record': os.kill(os.getpid(), signal.SIGKILL)
    if status == 'success' and scenario in ('before_success_record', 'before_record_no_old'): os.kill(os.getpid(), signal.SIGKILL)
    if status == 'success' and scenario == 'during_rollback': raise OSError('force rollback')
    if status == 'failed' and scenario == 'during_rollback': os.kill(os.getpid(), signal.SIGKILL)
    original(path, record)
    if status == 'success' and scenario == 'after_success_record': os.kill(os.getpid(), signal.SIGKILL)
with patch.object(cli.profile, 'load', return_value=conf), patch.object(cli.profile, 'check', return_value={'identity':'fixture'}), patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), patch.object(cli.runner, 'run', side_effect=runner), patch.object(cli, 'write_json', side_effect=interrupted):
    cli.main(['--config',config,'compile',source,'-o',output])
'''
                env = dict(os.environ)
                env['PYTHONPATH'] = os.pathsep.join((str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)))
                proc = subprocess.run([sys.executable, '-c', code, scenario, str(config), str(source), str(output)],
                                      env=env, capture_output=True, timeout=15)
                self.assertEqual(proc.returncode, -signal.SIGKILL, proc.stderr.decode(errors='replace'))
                manifest = next(root.glob('.canncc/runs/*/build.json'))
                state = json.loads(manifest.read_text())['status']
                if scenario == 'before_intent_record':
                    self.assertEqual(state, 'running')
                    self.assertEqual(output.read_bytes(), b'old output')
                    self.assertTrue(list(root.glob('.result.canncc-*.backup')))
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(main(['recover', str(manifest)]), 1)
                    self.assertEqual(output.read_bytes(), b'old output')
                    continue  # No committed transaction record; inspect the orphan manually.
                self.assertEqual(state, 'success' if scenario == 'after_success_record' else
                                 'rolling_back' if scenario == 'during_rollback' else 'committing')
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(['recover', str(manifest)]), 0)
                if scenario == 'after_success_record':
                    self.assertEqual(output.read_bytes(), fake_elf(1))
                    self.assertEqual(json.loads(manifest.read_text())['status'], 'success')
                elif scenario == 'before_record_no_old':
                    self.assertFalse(output.exists())
                    self.assertEqual(json.loads(manifest.read_text())['status'], 'failed')
                else:
                    self.assertEqual(output.read_bytes(), b'old output')
                    self.assertEqual(json.loads(manifest.read_text())['status'], 'failed')
                self.assertFalse(list(root.glob('.result.canncc-*.backup')))

    def test_profile_change_during_compile_prevents_publication(self):
        def change_profile(command, stdout, stderr, timeout):
            stdout.write_bytes(b""); stderr.write_bytes(b"")
            Path(command[-1]).write_bytes(fake_elf(1))
            self.config.write_text('{"changed": true}')
            return {"exit_code": 0, "signal": None, "timed_out": False, "cleanup": None}
        with patch("canncc.__main__.runner.run", side_effect=change_profile), contextlib.redirect_stderr(io.StringIO()):
            code = main(self.argv("compile", str(self.source), "-o", str(self.output)))
        record = json.loads(next(self.root.glob(".canncc/runs/*/build.json")).read_text())
        self.assertEqual(code, 1)
        self.assertEqual(record["status"], "failed")
        self.assertIn("profile changed", record["error"])
        self.assertFalse(self.output.exists())


class RunnerTests(unittest.TestCase):
    def test_timeout_returns_nonzero_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            result = runner.run([sys.executable, "-c", "import time; time.sleep(20)"], folder / "out", folder / "err", 0.2)
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])

    def check_signal_cleans_child_ignoring_term(self, signum):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            child = folder / "child.py"
            child.write_text("import os,signal,time,sys\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nopen(sys.argv[1], 'w').write(str(os.getpid()))\ntime.sleep(30)\n")
            code = ("import sys; from pathlib import Path; from canncc.runner import run; "
                    "r=run([sys.executable,sys.argv[1],sys.argv[2]],Path(sys.argv[3]),Path(sys.argv[4]),30); "
                    "sys.exit(r['exit_code'])")
            proc = subprocess.Popen([sys.executable, "-c", code, str(child), str(folder / "pid"),
                                     str(folder / "out"), str(folder / "err")])
            try:
                deadline = time.monotonic() + 5
                while not (folder / "pid").exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue((folder / "pid").exists())
                pid = int((folder / "pid").read_text())
                proc.send_signal(signum)
                self.assertEqual(proc.wait(timeout=8), 128 + signum)
                with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
            finally:
                if proc.poll() is None:
                    proc.kill(); proc.wait()

    def test_sigterm_cleans_child_ignoring_term(self):
        self.check_signal_cleans_child_ignoring_term(signal.SIGTERM)

    def test_sigint_cleans_child_ignoring_term(self):
        self.check_signal_cleans_child_ignoring_term(signal.SIGINT)


if __name__ == "__main__":
    unittest.main()
