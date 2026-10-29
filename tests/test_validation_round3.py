import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from canncc import dependencies, profile, runner
from canncc import __main__ as cli
from canncc.output import DataOutputError, data_write, safe_print


class ValidationTests(unittest.TestCase):
    def test_load_rejects_invalid_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'profile.json'
            cfg={'schema_version':1,'elfuse':'x','execution_sysroot':'x','bisheng_guest':'/x','target_sysroot':'x',
                 'execution_manifest':'x','target_manifest':'x','elfuse_sha256':'x','bisheng_sha256':'x',
                 'execution_digest':'x','target_digest':'x','compile_flags':[],'link_flags':[],'environment':[],'required_target_files':[]}
            for bad in (None,0,-1,'1',True,float('inf'),float('nan'),10**1000):
                with self.subTest(value=bad):
                    f.write_text(json.dumps({**cfg,'timeout_seconds':bad}))
                    with self.assertRaisesRegex(ValueError,'timeout_seconds'):profile.load(f)

    def test_runner_reports_child_signal_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            # A real SIGSEGV raises a macOS Crash Reporter dialog. Exercise a
            # real SIGKILL and inject the SIGSEGV child status separately.
            for sig in (signal.SIGKILL,):
                command=[sys.executable,'-c',f'import os,resource,signal;resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.kill(os.getpid(),{sig})']
                result=runner.run(command,p/f'out{sig}',p/f'err{sig}',3)
                self.assertEqual(result['exit_code'],128+sig);self.assertEqual(result['signal'],sig)
                self.assertIsNone(result['cancelled_by'])
            class SegvChild:
                pid = 1
                returncode = -signal.SIGSEGV
                def wait(self, timeout=None): return self.returncode
                def poll(self): return self.returncode
            with patch('canncc.runner.subprocess.Popen', return_value=SegvChild()):
                result=runner.run(['simulated-child'],p/'out-segv',p/'err-segv',3)
            self.assertEqual(result['exit_code'],139)
            self.assertEqual(result['signal'],signal.SIGSEGV)
            self.assertIsNone(result['cancelled_by'])

    def test_extra_flags_limited_to_macros(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source.asc';source.write_text('source')
            for flag in ('--target=x86_64-linux-gnu','-B/tmp/fake','-I/tmp/external','--sysroot=/tmp/fake'):
                args=cli.parser().parse_args(['compile',str(source),'-o',str(root/'out'),'--flag='+flag])
                with self.assertRaises(ValueError):cli.inputs_for(args)
            for flag in ('-DFOO=1','-UFOO','-DCASE_TILES=16'):
                args=cli.parser().parse_args(['compile',str(source),'-o',str(root/'out'),'--flag='+flag])
                cli.inputs_for(args)

    def test_internal_symlink_accepted_external_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);execution=base/'exec';target=base/'target';execution.mkdir();target.mkdir()
            for d in ('bin','lib','usr','opt','workspace'):(execution/d).mkdir()
            compiler=execution/'opt/bisheng';compiler.write_bytes(b'compiler')
            elfuse=base/'elfuse';elfuse.write_bytes(b'elfuse');elfuse.chmod(0o755)
            (target/'dep').write_bytes(b'inside');(target/'link').symlink_to('dep')
            external=base/'external';external.write_bytes(b'external')
            def cfg():
                result={'execution_sysroot':str(execution),'target_sysroot':str(target),'elfuse':str(elfuse),
                        'bisheng_guest':'/opt/bisheng','elfuse_sha256':profile.sha(elfuse),'bisheng_sha256':profile.sha(compiler),
                        'required_target_files':['link']}
                for name,folder,prefixes,dirs in [('execution',execution,('bin','lib','usr','opt'),False),('target',target,None,True)]:
                    entries,digest=profile.snapshot(folder,prefixes,dirs);m=base/(name+'.json');m.write_text(json.dumps({'entries':entries,'digest':digest}));result[name+'_manifest']=str(m);result[name+'_digest']=digest
                return result
            with patch('canncc.profile.os.path.ismount',return_value=True):
                profile.check(cfg())
                (target/'link').unlink();(target/'link').symlink_to(external)
                config=cfg()
                with self.assertRaisesRegex(ValueError,'external symlink'):profile.check(config)

    def test_diagnostic_and_data_output_errors_are_distinct(self):
        class Broken:
            closed=False
            def write(self, _):raise OSError(28,'disk full')
            def flush(self):pass
        broken=Broken()
        safe_print('warning',file=broken)
        with self.assertRaises(DataOutputError):data_write(broken,'data')

    def test_dependency_probe_records_external_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'root';target=base/'target';run=base/'run'
            for p in (root/'opt',target,run):p.mkdir(parents=True)
            source=base/'input.asc';source.write_text('source')
            internal=root/'opt/internal.h';internal.write_text('internal')
            external=base/'outside.h';external.write_text('external')
            command=['elfuse','-c',str(source),'-o',str(base/'out.o')]
            def fake(command,stdout,stderr,timeout):
                stdout.write_text(f'input.o: {source} /opt/internal.h {external}\n')
                stderr.write_text('')
                return {'exit_code':0,'signal':None,'cancelled_by':None,'timed_out':False,'cleanup':None}
            with patch('canncc.dependencies.runner.run',side_effect=fake):
                record,files=dependencies.scan(command,source,run,'compile-0',{'execution_sysroot':str(root),'target_sysroot':str(target)})
            self.assertEqual(files,{str(external.resolve()):profile.sha(external)})
            self.assertEqual(record['dependency_count'],3)

    def test_dependency_parser_rejects_unstructured_output(self):
        with self.assertRaises(ValueError):dependencies.parse_make('not a make rule')
        self.assertEqual(dependencies.parse_make('a.o: /tmp/a\\ b.h \\\n /tmp/c.h\n'),['/tmp/a b.h','/tmp/c.h'])

    def test_make_escaping_is_not_shell_quoting(self):
        self.assertEqual(dependencies.parse_make("o: input.asc\\\nheader.h a\\ b.h quote'file.h hash\\#file.h\n"),
                         ["a b.h", 'hash#file.h', 'header.h', 'input.asc', "quote'file.h"])

    def test_execution_symlink_into_untracked_workspace_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); execution=base/'exec'; target=base/'target'; target.mkdir()
            for d in ('bin','lib','usr','opt','workspace'): (execution/d).mkdir(parents=True)
            (execution/'opt/bisheng').write_bytes(b'compiler'); (execution/'workspace/lib.so').write_bytes(b'a')
            (execution/'lib/lib.so').symlink_to('../workspace/lib.so')
            elfuse=base/'elfuse'; elfuse.write_bytes(b'elfuse'); elfuse.chmod(0o755)
            config={'execution_sysroot':str(execution),'target_sysroot':str(target),'elfuse':str(elfuse),
                    'bisheng_guest':'/opt/bisheng','elfuse_sha256':profile.sha(elfuse),
                    'bisheng_sha256':profile.sha(execution/'opt/bisheng'),'required_target_files':[]}
            for name,folder,prefixes,dirs in [('execution',execution,('bin','lib','usr','opt'),False),('target',target,None,True)]:
                entries,digest=profile.snapshot(folder,prefixes,dirs); manifest=base/(name+'.json')
                manifest.write_text(json.dumps({'entries':entries,'digest':digest})); config[name+'_manifest']=str(manifest);config[name+'_digest']=digest
            with patch('canncc.profile.os.path.ismount',return_value=True):
                with self.assertRaisesRegex(ValueError,'outside snapshot'): profile.check(config)
