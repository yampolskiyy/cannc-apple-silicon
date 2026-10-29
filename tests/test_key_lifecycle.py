import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from canncc import authority, publication
from canncc import __main__ as cli
from test_canncc import fake_elf


class KeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.env = patch.dict(os.environ, {'CANNC_RECOVERY_KEY_DIR': str(self.root / 'keys')})
        self.env.start()
        self.key = self.root/'keys/recovery-key-v1'

    def tearDown(self):
        self.env.stop(); self.tmp.cleanup()

    def init(self):
        authority.initialize(); self.key_bytes = self.key.read_bytes()

    def restore(self):
        self.key.write_bytes(self.key_bytes); self.key.chmod(0o600)

    def call(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            result=cli.main(args)
        return result,out.getvalue(),err.getvalue()

    def create_build(self, when):
        self.init()
        output=self.root/'output';output.write_bytes(b'old output')
        source=self.root/'input.asc';source.write_text('source')
        config=self.root/'profile.json';config.write_text('{}')
        conf={'profile_id':'test','elfuse':'/elfuse','execution_sysroot':'/exec','bisheng_guest':'/compiler',
              'target_sysroot':'/target','compile_flags':['-O2'],'link_flags':[], 'environment':[], 'timeout_seconds':5}
        def runner(command, stdout, stderr, timeout):
            stdout.write_bytes(b'');stderr.write_bytes(b'');Path(command[-1]).write_bytes(fake_elf(1))
            return {'exit_code':0,'signal':None,'cancelled_by':None,'timed_out':False,'cleanup':None}
        original_write=cli.write_json
        original_replace=os.replace
        def writer(path, record):
            original_write(path,record)
            if when=='before_replace' and record.get('status')=='committing': self.key.unlink()
            if when=='after_success' and record.get('status')=='success': self.key.unlink()
        def replace(src, dst):
            original_replace(src,dst)
            if when=='after_replace' and Path(dst)==output: self.key.unlink()
        with patch.object(cli.profile,'load',return_value=conf),patch.object(cli.profile,'check',return_value={}), \
             patch.object(cli.dependencies,'scan',return_value=({'kind':'fixture'},{})), \
             patch.object(cli.runner,'run',side_effect=runner),patch.object(cli,'write_json',side_effect=writer), \
             patch.object(cli.os,'replace',side_effect=replace):
            code,out,err=self.call(['--config',str(config),'compile',str(source),'-o',str(output)])
        journal=next((self.root/'.canncc/runs').glob('*/build.json'))
        return code,out,err,journal,output

    def test_no_implicit_init_or_verify_side_effect(self):
        with self.assertRaises(authority.JournalTrustError): authority.Context.open()
        self.assertFalse((self.root/'keys').exists())
        code,_,_=self.call(['recover',str(self.root/'missing.json')])
        self.assertEqual(code,1);self.assertFalse((self.root/'keys').exists())

    def test_w0_uninitialized_build_does_not_invoke_compiler(self):
        source=self.root/'input.asc';source.write_text('source')
        config=self.root/'profile';config.write_text('{}')
        output=self.root/'out';output.write_bytes(b'old')
        with patch.object(cli.profile,'load',return_value={}), patch.object(cli.runner,'run') as run:
            code,_,err=self.call(['--config',str(config),'compile',str(source),'-o',str(output)])
        self.assertEqual(code,1);self.assertIn('not initialized',err);run.assert_not_called()
        self.assertEqual(output.read_bytes(),b'old');self.assertFalse((self.root/'keys').exists())

    def test_explicit_init_and_v1_key_migration(self):
        root=self.root/'keys';root.mkdir(mode=0o700);self.key.write_bytes(b'x'*32);self.key.chmod(0o600)
        key_id=authority.initialize();self.assertEqual(self.key.read_bytes(),b'x'*32)
        self.assertEqual(key_id,hashlib.sha256(b'x'*32).hexdigest())
        self.assertEqual(authority.initialize(),key_id)
        self.key.unlink()
        with self.assertRaises(authority.JournalTrustError): authority.initialize()
        self.assertFalse(self.key.exists())

    def test_empty_relative_key_directory_rejected(self):
        for value in ('', 'relative/path'):
            with self.subTest(value=value),patch.dict(os.environ,{'CANNC_RECOVERY_KEY_DIR':value}):
                with self.assertRaises(authority.JournalTrustError):authority.initialize()

    def test_concurrent_initialization_uses_one_key(self):
        command=[sys.executable,'-c','from canncc.authority import initialize; print(initialize())']
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        procs=[subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(4)]
        results=[p.communicate(timeout=20) for p in procs]
        self.assertTrue(all(p.returncode==0 for p in procs),results)
        self.assertEqual(len({out.strip() for out,_ in results}),1)
        self.assertEqual(authority.Context.open().key_id,results[0][0].decode().strip())

    def test_w1_key_loss_retains_old_output_and_staged(self):
        code,_,err,journal,output=self.create_build('before_replace')
        data=json.loads(journal.read_text());self.assertEqual(code,1,err);self.assertEqual(data['status'],'committing')
        self.assertEqual(output.read_bytes(),b'old output');self.assertTrue(Path(data['staged_output']).exists())
        self.assertTrue(Path(data['transaction']['backup']).exists())
        self.restore();self.assertEqual(self.call(['recover',str(journal)])[0],0)
        self.assertEqual(output.read_bytes(),b'old output')

    def test_w3_key_loss_retains_new_unconfirmed_and_backup(self):
        code,_,err,journal,output=self.create_build('after_replace')
        data=json.loads(journal.read_text());self.assertEqual(code,1,err);self.assertEqual(data['status'],'committing')
        self.assertEqual(output.read_bytes(),fake_elf(1));self.assertTrue(Path(data['transaction']['backup']).exists())
        self.restore();self.assertEqual(self.call(['recover',str(journal)])[0],0)
        self.assertEqual(output.read_bytes(),b'old output')

    def test_w4_committed_success_with_key_warning_and_backup(self):
        code,_,err,journal,output=self.create_build('after_success')
        data=json.loads(journal.read_text());self.assertEqual(code,0,err);self.assertEqual(data['status'],'success')
        self.assertIn('recovery key',err);self.assertEqual(output.read_bytes(),fake_elf(1))
        self.assertTrue(Path(data['transaction']['backup']).exists())
        self.restore();self.assertEqual(self.call(['recover',str(journal)])[0],0)

    def test_recover_r3_restored_output_journal_not_finalized(self):
        _,_,_,journal,output=self.create_build('after_replace');self.restore()
        original=os.replace
        def replace(src,dst):
            original(src,dst)
            if Path(dst)==output and '.backup' in str(src):self.key.unlink()
        with patch.object(cli.os,'replace',side_effect=replace):
            code,_,err=self.call(['recover',str(journal)])
        self.assertEqual(code,1);self.assertIn('journal not finalized',err)
        self.assertEqual(output.read_bytes(),b'old output');self.assertEqual(json.loads(journal.read_text())['status'],'rolling_back')
        self.restore();self.assertEqual(self.call(['recover',str(journal)])[0],0)
        self.assertEqual(json.loads(journal.read_text())['status'],'failed')

    def test_recover_r2_key_loss_before_rollback_preserves_files(self):
        _,_,_,journal,output=self.create_build('after_replace');self.restore()
        original=publication.reconcile
        def wrapped(manifest,record,writer,**kwargs):
            authorize=kwargs['authorize']
            def lose_after_verify(path,saved):
                authorize(path,saved);self.key.unlink()
            kwargs['authorize']=lose_after_verify
            return original(manifest,record,writer,**kwargs)
        with patch.object(publication,'reconcile',side_effect=wrapped):
            code,_,_=self.call(['recover',str(journal)])
        record=json.loads(journal.read_text());self.assertEqual(code,1);self.assertEqual(record['status'],'committing')
        self.assertEqual(output.read_bytes(),fake_elf(1));self.assertTrue(Path(record['transaction']['backup']).exists())
        self.restore();self.assertEqual(self.call(['recover',str(journal)])[0],0)

    def test_recover_r4_terminal_written_before_key_loss(self):
        _,_,_,journal,output=self.create_build('after_replace');self.restore()
        original=cli.write_json
        def lose_after_terminal(path,record):
            original(path,record)
            if record.get('status')=='failed':self.key.unlink()
        with patch.object(cli,'write_json',side_effect=lose_after_terminal):
            code,_,_=self.call(['recover',str(journal)])
        self.assertEqual(code,0);self.assertEqual(output.read_bytes(),b'old output')
        self.assertEqual(json.loads(journal.read_text())['status'],'failed')
        self.restore();authority.verify(journal,json.loads(journal.read_text()))

    def test_v1_signed_recovery_upgrades_v2(self):
        code,_,_,journal,output=self.create_build('after_replace');self.assertEqual(code,1);self.restore()
        data=json.loads(journal.read_text());body={k:v for k,v in data.items() if k!='journal_auth'}
        envelope={'manifest':str(journal.resolve()),'record':body}
        payload=json.dumps(envelope,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
        data['journal_auth']={'version':1,'hmac_sha256':hmac.new(self.key_bytes,payload,hashlib.sha256).hexdigest()}
        journal.write_text(json.dumps(data));self.assertEqual(self.call(['recover',str(journal)])[0],0)
        updated=json.loads(journal.read_text());self.assertEqual(updated['journal_auth']['version'],2)
        self.assertEqual(output.read_bytes(),b'old output');authority.verify(journal,updated)

    def test_unknown_signed_version_never_falls_back_to_legacy(self):
        _,_,_,journal,output=self.create_build('after_replace');self.restore()
        data=json.loads(journal.read_text());data['journal_auth']['version']=99;journal.write_text(json.dumps(data))
        code,_,err=self.call(['recover','--legacy-output',str(output),str(journal)])
        self.assertEqual(code,1);self.assertIn('journal format v99',err);self.assertEqual(output.read_bytes(),fake_elf(1))
