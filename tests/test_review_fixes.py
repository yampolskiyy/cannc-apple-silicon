import contextlib
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from canncc import authority, publication
from canncc.__main__ import main


class ReviewFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.env = patch.dict(os.environ, {'CANNC_RECOVERY_KEY_DIR': str(self.root / 'key')})
        self.env.start()
        authority.initialize()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def journal(self, status='committing', previous=None, signed=True):
        output = self.root / 'output'; output.write_bytes(b'new output')
        run = 'a'*32
        staged = self.root / ('.output.canncc-' + run + '.tmp')
        backup = self.root / ('.output.canncc-' + run + '.backup')
        new = publication.identity(output)
        tx = {'schema_version':1, 'run_id':run, 'output':str(output), 'staged':str(staged),
              'backup':str(backup), 'previous':previous, 'new':new}
        data = {'schema_version':1, 'run_id':run, 'status':status, 'requested_output':str(output),
                'staged_output':str(staged), 'output_sha256':new['sha256'], 'transaction':tx}
        journal = self.root / 'custom-log-root' / run / 'build.json'
        journal.parent.mkdir(parents=True)
        if signed: authority.sign(journal, data)
        journal.write_text(json.dumps(data))
        return journal, output, data

    def call(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(args)

    def test_unsigned_and_modified_manifest_cannot_remove_output(self):
        journal, output, data = self.journal(signed=False)
        self.assertEqual(self.call(['recover', str(journal)]), 1)
        self.assertEqual(output.read_bytes(), b'new output')
        authority.sign(journal, data)
        data['status'] = 'rolling_back'
        journal.write_text(json.dumps(data))
        self.assertEqual(self.call(['recover', str(journal)]), 1)
        self.assertEqual(output.read_bytes(), b'new output')
        self.assertEqual(self.call(['recover', '--legacy-output', str(output), str(journal)]), 1)

    def test_signed_journal_supports_custom_log_root(self):
        journal, output, _ = self.journal()
        self.assertEqual(self.call(['recover', str(journal)]), 0)
        self.assertFalse(output.exists())
        saved = json.loads(journal.read_text())
        self.assertEqual(saved['status'], 'failed')
        authority.verify(journal, saved)

    def test_legacy_requires_explicit_matching_output(self):
        journal, output, _ = self.journal(signed=False)
        self.assertEqual(self.call(['recover', '--legacy-output', str(self.root/'different'), str(journal)]), 1)
        self.assertTrue(output.exists())
        self.assertEqual(self.call(['recover', '--legacy-output', str(output), str(journal)]), 0)
        self.assertFalse(output.exists())
        authority.verify(journal, json.loads(journal.read_text()))

    def test_moved_signed_journal_is_rejected(self):
        journal, output, _ = self.journal()
        moved = self.root/'moved.json'; moved.write_bytes(journal.read_bytes())
        self.assertEqual(self.call(['recover', str(moved)]), 1)
        self.assertTrue(output.exists())

    def test_missing_key_refuses_without_changing_output(self):
        journal, output, _ = self.journal()
        shutil.rmtree(self.root/'key')
        self.assertEqual(self.call(['recover', str(journal)]), 1)
        self.assertEqual(output.read_bytes(), b'new output')

    def test_unsigned_journal_cannot_replace_output(self):
        journal, output, data = self.journal(signed=False)
        backup=Path(data['transaction']['backup']); backup.write_bytes(b'forged backup')
        data['transaction']['previous']=publication.identity(backup)
        journal.write_text(json.dumps(data))
        self.assertEqual(self.call(['recover', str(journal)]), 1)
        self.assertEqual(output.read_bytes(), b'new output')
        self.assertEqual(backup.read_bytes(), b'forged backup')

    def test_case_and_unicode_aliases_share_lock(self):
        first = publication.acquire_lock(self.root/'result')
        try:
            with self.assertRaises(BlockingIOError): publication.acquire_lock(self.root/'RESULT')
        finally: first.close()
        first = publication.acquire_lock(self.root/'résultat')
        try:
            with self.assertRaises(BlockingIOError): publication.acquire_lock(self.root/'re\u0301sultat')
        finally: first.close()

    def test_existing_hardlink_input_is_rejected(self):
        source=self.root/'input.asc'; source.write_text('source')
        output=self.root/'output.o'; os.link(source,output)
        config=self.root/'profile.json';config.write_text('{}')
        with patch('canncc.__main__.profile.load', return_value={}):
            self.assertEqual(self.call(['--config',str(config),'compile',str(source),'-o',str(output)]),1)
        self.assertEqual(source.read_text(),'source')

    def test_existing_case_alias_input_is_rejected(self):
        source=self.root/'input.asc';source.write_text('source')
        output=self.root/'INPUT.ASC'
        if not output.exists(): self.skipTest('filesystem is case-sensitive')
        config=self.root/'profile';config.write_text('{}')
        with patch('canncc.__main__.profile.load',return_value={}):
            self.assertEqual(self.call(['--config',str(config),'compile',str(source),'-o',str(output)]),1)
        self.assertEqual(source.read_text(),'source')

    def test_closed_stdout_after_recover_keeps_success(self):
        journal, output, _ = self.journal(status='success')
        cli=Path(__file__).resolve().parents[1]/'bin/cannc'
        read, write=os.pipe(); os.close(read)
        try: result=subprocess.run([str(cli),'recover',str(journal)], stdout=write, stderr=subprocess.PIPE, timeout=15)
        finally: os.close(write)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(journal.read_text())['status'],'success')
        self.assertEqual(output.read_bytes(),b'new output')

    def test_success_cleanup_warning_keeps_success(self):
        journal, output, data = self.journal(status='success')
        Path(data['transaction']['backup']).write_bytes(b'unexpected backup')
        self.assertEqual(self.call(['recover', str(journal)]), 0)
        self.assertEqual(json.loads(journal.read_text())['status'], 'success')
        self.assertEqual(output.read_bytes(), b'new output')

    def test_closed_stderr_preserves_compiler_failure(self):
        code = '''
import sys
from pathlib import Path
from unittest.mock import patch
from canncc import __main__ as cli
cfg={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec','bisheng_guest':'/compiler','target_sysroot':'/target','compile_flags':[],'link_flags':[],'environment':[],'timeout_seconds':5}
def fail(command,stdout,stderr,timeout):
 stdout.write_bytes(b'');stderr.write_bytes(b'failure');return {'exit_code':42,'signal':None,'timed_out':False,'cleanup':None}
with patch.object(cli.profile,'load',return_value=cfg),patch.object(cli.profile,'check',return_value={}),patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), patch.object(cli.runner,'run',side_effect=fail):
 sys.exit(cli.main(['--config',sys.argv[1],'compile',sys.argv[2],'-o',sys.argv[3]]))
'''
        config=self.root/'profile';config.write_text('{}')
        source=self.root/'input.asc';source.write_text('source')
        output=self.root/'output';output.write_bytes(b'old')
        read,write=os.pipe();os.close(read)
        env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        try: result=subprocess.run([sys.executable,'-c',code,str(config),str(source),str(output)],stdout=subprocess.PIPE,stderr=write,env=env,timeout=15)
        finally:os.close(write)
        self.assertEqual(result.returncode,42)
        record=json.loads(next((self.root/'.canncc/runs').glob('*/build.json')).read_text())
        self.assertEqual(record['exit_code'],42)
        self.assertEqual(output.read_bytes(),b'old')

    def test_closed_stderr_preserves_parser_error(self):
        cli=Path(__file__).resolve().parents[1]/'bin/cannc'
        read,write=os.pipe();os.close(read)
        try: result=subprocess.run([str(cli),'recover'],stdout=subprocess.PIPE,stderr=write,timeout=15)
        finally: os.close(write)
        self.assertEqual(result.returncode,2)

    def test_non_epipe_diagnostic_error_preserves_compiler_status(self):
        from canncc import __main__ as cli
        class Broken(io.StringIO):
            def write(self, _): raise OSError(28, 'no space for diagnostics')
        config=self.root/'profile';config.write_text('{}')
        source=self.root/'input.asc';source.write_text('source')
        output=self.root/'output';output.write_bytes(b'old')
        conf={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec','bisheng_guest':'/compiler',
              'target_sysroot':'/target','compile_flags':[],'link_flags':[],'environment':[],'timeout_seconds':5}
        def fail(command,stdout,stderr,timeout):
            stdout.write_bytes(b'');stderr.write_bytes(b'failure')
            return {'exit_code':42,'signal':None,'cancelled_by':None,'timed_out':False,'cleanup':None}
        with patch.object(cli.profile,'load',return_value=conf),patch.object(cli.profile,'check',return_value={}), \
             patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), \
             patch.object(cli.runner,'run',side_effect=fail),contextlib.redirect_stderr(Broken()):
            code=cli.main(['--config',str(config),'compile',str(source),'-o',str(output)])
        self.assertEqual(code,42);self.assertEqual(output.read_bytes(),b'old')
        record=json.loads(next((self.root/'.canncc/runs').glob('*/build.json')).read_text())
        self.assertEqual(record['exit_code'],42)

    def test_stderr_fd_closed_during_compile_preserves_status(self):
        code = '''
import os,sys
from unittest.mock import patch
from canncc import __main__ as cli
cfg={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec','bisheng_guest':'/compiler','target_sysroot':'/target','compile_flags':[],'link_flags':[],'environment':[],'timeout_seconds':5}
def fail(command,stdout,stderr,timeout):
 stdout.write_bytes(b'');stderr.write_bytes(b'failure');os.close(2)
 return {'exit_code':42,'signal':None,'cancelled_by':None,'timed_out':False,'cleanup':None}
with patch.object(cli.profile,'load',return_value=cfg),patch.object(cli.profile,'check',return_value={}),patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})),patch.object(cli.runner,'run',side_effect=fail):
 sys.exit(cli.main(['--config',sys.argv[1],'compile',sys.argv[2],'-o',sys.argv[3]]))
'''
        config=self.root/'profile';config.write_text('{}')
        source=self.root/'input.asc';source.write_text('source')
        output=self.root/'output';output.write_bytes(b'old')
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        proc=subprocess.run([sys.executable,'-c',code,str(config),str(source),str(output)],env=env,capture_output=True,timeout=15)
        self.assertEqual(proc.returncode,42)
        record=json.loads(next((self.root/'.canncc/runs').glob('*/build.json')).read_text())
        self.assertEqual(record['exit_code'],42);self.assertEqual(output.read_bytes(),b'old')

    def test_closed_stdout_preserves_help_success(self):
        cli=Path(__file__).resolve().parents[1]/'bin/cannc'
        read,write=os.pipe();os.close(read)
        try: result=subprocess.run([str(cli),'--help'],stdout=write,stderr=subprocess.PIPE,timeout=15)
        finally: os.close(write)
        self.assertEqual(result.returncode,0,result.stderr)
