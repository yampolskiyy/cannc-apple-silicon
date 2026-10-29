import io
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from canncc import bootstrap, profile


class ExtractTests(unittest.TestCase):
    def test_debian_ar_reader_rejects_bad_and_duplicate_payloads(self):
        def member(name, data):
            header=(f'{name}/'.ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'100644'.ljust(8)+str(len(data)).ljust(10)+'`\n').encode()
            return header+data+(b'\n' if len(data)%2 else b'')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'x.deb';p.write_bytes(b'!<arch>\n'+member('data.tar.xz',b'hello'))
            self.assertEqual(bootstrap._debian_data(p),b'hello')
            p.write_bytes(p.read_bytes()+member('data.tar.gz',b'other'))
            with self.assertRaisesRegex(ValueError,'multiple Debian payloads'):bootstrap._debian_data(p)
            p.write_bytes(b'!<arch>\n'+member('data.tar.xz',b'hello')[:-2])
            with self.assertRaisesRegex(ValueError,'truncated|invalid Debian ar member size'):bootstrap._debian_data(p)
    def test_hardlink_to_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'hard.tar'; destination=root/'destination'; destination.mkdir()
            with tarfile.open(archive,'w') as out:
                link=tarfile.TarInfo('link');link.type=tarfile.SYMTYPE;link.linkname='elsewhere';out.addfile(link)
                hard=tarfile.TarInfo('hard');hard.type=tarfile.LNKTYPE;hard.linkname='link';out.addfile(hard)
            with self.assertRaisesRegex(ValueError,'hard links'):
                bootstrap._extract(archive,destination)
            self.assertFalse((destination/'hard').exists())

    def archive(self, root, name, entries):
        path = root / name
        with tarfile.open(path, 'w:gz') as archive:
            for filename, value, link in entries:
                info = tarfile.TarInfo(filename)
                if link:
                    info.type = tarfile.SYMTYPE
                    info.linkname = value
                    archive.addfile(info)
                else:
                    payload = value.encode()
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
        return path

    def test_absolute_linux_link_resolves_inside_new_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, 'a.tar.gz', [('lib/test', 'data', False), ('usr/lib/link', '/lib/test', True)])
            destination = root / 'root'; destination.mkdir()
            bootstrap._extract(archive, destination)
            self.assertEqual((destination / 'usr/lib/link').read_text(), 'data')
            self.assertFalse((destination / 'usr/lib/link').readlink().is_absolute())

    def test_parent_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, 'a.tar.gz', [('../outside', 'bad', False)])
            destination = root / 'root'; destination.mkdir()
            with self.assertRaises(ValueError): bootstrap._extract(archive, destination)
            self.assertFalse((root / 'outside').exists())

    def test_wrong_hash_never_creates_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'input'; source.write_text('wrong')
            names = ['bisheng', 'elfuse', 'target-collection', 'target-headers', 'asc-devkit', 'cann-runtime']
            recipe = root / 'recipe.json'
            recipe.write_text(json.dumps({'schema_version': 1, 'inputs': {k: {'path': str(source), 'sha256': '0'*64} for k in names}}))
            destination = root / 'new'
            with mock.patch.object(bootstrap.sys, 'platform', 'darwin'), mock.patch.object(bootstrap.os, 'uname') as uname:
                uname.return_value.machine = 'arm64'
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    bootstrap.install(recipe, destination)
            self.assertFalse(destination.exists())


class CleanupTests(unittest.TestCase):
    def test_owned_mounts_detached_in_reverse_order_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            execution = (root / 'execution.sparsebundle', root / 'execution-volume')
            target = (root / 'target.sparsebundle', root / 'target-volume')
            for image, mount in (execution, target): image.mkdir(); mount.mkdir()
            foreign = root / 'foreign.sparsebundle'; foreign.mkdir()
            images = {'images': [
                {'image-path': str(execution[0]), 'system-entities': [{'mount-point': str(execution[1])}]},
                {'image-path': str(foreign), 'system-entities': [{'mount-point': str(target[1])}]},
            ]}
            completed = subprocess.CompletedProcess(['hdiutil'], 0, stdout=plistlib.dumps(images), stderr=b'')
            with mock.patch('canncc.bootstrap.subprocess.run', return_value=completed), \
                 mock.patch('canncc.bootstrap._command') as command, \
                 mock.patch('canncc.bootstrap.os.path.ismount', return_value=False):
                result = bootstrap._cleanup_created_images([execution, target])
            self.assertEqual([x['status'] for x in result], ['unowned_mount', 'detached'])
            command.assert_called_once_with(['hdiutil', 'detach', execution[1]], timeout=20)

    def test_detach_failure_is_reported_and_other_mount_still_detached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = [(root / 'a', root / 'am'), (root / 'b', root / 'bm')]
            for image, mount in images: image.mkdir(); mount.mkdir()
            inventory = {'images': [{'image-path': str(i), 'system-entities': [{'mount-point': str(m)}]}
                                    for i, m in images]}
            completed = subprocess.CompletedProcess(['hdiutil'], 0, stdout=plistlib.dumps(inventory), stderr=b'')
            def detach(args, **_kwargs):
                if args[-1] == images[1][1]: raise ValueError('busy')
            with mock.patch('canncc.bootstrap.subprocess.run', return_value=completed), \
                 mock.patch('canncc.bootstrap._command', side_effect=detach), \
                 mock.patch('canncc.bootstrap.os.path.ismount', return_value=False):
                records = bootstrap._cleanup_created_images(images)
            self.assertEqual([x['status'] for x in records], ['detach_failed', 'detached'])
            self.assertIn('busy', records[0]['error'])

    def test_detach_timeout_is_reported_without_stopping_other_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); images = [(root / 'a', root / 'am'), (root / 'b', root / 'bm')]
            for image, mount in images: image.mkdir(); mount.mkdir()
            inventory = {'images': [{'image-path': str(i), 'system-entities': [{'mount-point': str(m)}]}
                                    for i, m in images]}
            completed = subprocess.CompletedProcess([], 0, stdout=plistlib.dumps(inventory), stderr=b'')
            def detach(args, **_kwargs):
                if args[-1] == images[1][1]: raise subprocess.TimeoutExpired('hdiutil', 20)
            with mock.patch('canncc.bootstrap.subprocess.run', return_value=completed), \
                 mock.patch('canncc.bootstrap._command', side_effect=detach), \
                 mock.patch('canncc.bootstrap.os.path.ismount', return_value=False):
                records = bootstrap._cleanup_created_images(images)
            self.assertEqual([x['status'] for x in records], ['detach_failed', 'detached'])

    def test_unknown_inventory_never_detaches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); image = root / 'image'; image.mkdir(); mount = root / 'mount'; mount.mkdir()
            with mock.patch('canncc.bootstrap.subprocess.run', side_effect=OSError('inventory unavailable')), \
                 mock.patch('canncc.bootstrap._command') as command:
                records = bootstrap._cleanup_created_images([(image, mount)])
            self.assertEqual(records[0]['status'], 'unverified')
            command.assert_not_called()

    def test_owned_image_at_unexpected_mountpoint_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); image = root / 'image'; image.mkdir()
            mount = root / 'expected'; mount.mkdir(); other = root / 'other'; other.mkdir()
            inventory = {'images': [{'image-path': str(image), 'system-entities': [{'mount-point': str(other)}]}]}
            completed = subprocess.CompletedProcess(['hdiutil'], 0, stdout=plistlib.dumps(inventory), stderr=b'')
            with mock.patch('canncc.bootstrap.subprocess.run', return_value=completed), \
                 mock.patch('canncc.bootstrap._command') as command:
                records = bootstrap._cleanup_created_images([(image, mount)])
            self.assertEqual(records[0]['status'], 'unverified')
            self.assertEqual(records[0]['observed_mountpoints'], [str(other.resolve())])
            command.assert_not_called()

    def test_attached_unmounted_image_is_detached_by_owned_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); image = root / 'image'; image.mkdir(); mount = root / 'expected'; mount.mkdir()
            before = {'images': [{'image-path': str(image), 'system-entities': [{'dev-entry': '/dev/disk42'}]}]}
            responses = [subprocess.CompletedProcess([], 0, stdout=plistlib.dumps(value), stderr=b'')
                         for value in (before, {'images': []})]
            with mock.patch('canncc.bootstrap.subprocess.run', side_effect=responses), \
                 mock.patch('canncc.bootstrap._command') as command, \
                 mock.patch('canncc.bootstrap.os.path.ismount', return_value=False):
                records = bootstrap._cleanup_created_images([(image, mount)])
            self.assertEqual(records[0]['status'], 'detached')
            command.assert_called_once_with(['hdiutil', 'detach', '/dev/disk42'], timeout=20)

    def test_attached_unmounted_image_with_unknown_device_is_not_claimed_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); image = root / 'image'; image.mkdir(); mount = root / 'expected'; mount.mkdir()
            inventory = {'images': [{'image-path': str(image), 'system-entities': []}]}
            completed = subprocess.CompletedProcess([], 0, stdout=plistlib.dumps(inventory), stderr=b'')
            with mock.patch('canncc.bootstrap.subprocess.run', return_value=completed), \
                 mock.patch('canncc.bootstrap._command') as command, \
                 mock.patch('canncc.bootstrap.os.path.ismount', return_value=False):
                records = bootstrap._cleanup_created_images([(image, mount)])
            self.assertEqual(records[0]['status'], 'unverified')
            command.assert_not_called()

    def test_attach_failure_tracks_created_image_for_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); created = []
            def command(args):
                if args[1] == 'create': Path(args[-1]).mkdir()
                if args[1] == 'attach': raise ValueError('attach interrupted')
            with mock.patch('canncc.bootstrap._command', side_effect=command):
                with self.assertRaisesRegex(ValueError, 'attach interrupted'):
                    bootstrap._disk(root, 'execution', 'name', '1g', created)
            self.assertEqual(created, [(root / 'execution.sparsebundle', root / 'execution-volume')])

    def test_failed_second_disk_and_signal_are_journaled_and_cleaned(self):
        for failure in ('second-disk', 'sigterm', 'sigint'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); source = root / 'input'; source.write_bytes(b'input')
                names = ['bisheng', 'elfuse', 'target-collection', 'target-headers', 'asc-devkit', 'cann-runtime']
                item = {'path': str(source), 'sha256': profile.sha(source), 'size': source.stat().st_size}
                recipe = root / 'recipe.json'
                recipe.write_text(json.dumps({'schema_version': 1, 'inputs': {k: item for k in names},
                                              'sources': {}, 'provenance': 'fixture'}))
                destination = root / 'new'
                def disk(dest, name, _volume, _size, created):
                    image = dest / (name + '.sparsebundle'); image.mkdir()
                    mount = dest / (name + '-volume'); mount.mkdir()
                    created.append((image, mount))
                    if failure == 'second-disk' and name == 'target': raise ValueError('second disk failed')
                    if failure in ('sigterm', 'sigint') and name == 'execution':
                        os.kill(os.getpid(), signal.SIGTERM if failure == 'sigterm' else signal.SIGINT)
                    return mount
                def cleanup(created):
                    return [{'image': str(i), 'mountpoint': str(m), 'status': 'detached'} for i, m in reversed(created)]
                error = ValueError if failure == 'second-disk' else bootstrap.BootstrapTerminated if failure == 'sigterm' else KeyboardInterrupt
                with mock.patch.object(bootstrap.sys, 'platform', 'darwin'), \
                     mock.patch.object(bootstrap.os, 'uname') as uname, \
                     mock.patch('canncc.bootstrap._disk', side_effect=disk), \
                     mock.patch('canncc.bootstrap._cleanup_created_images', side_effect=cleanup) as cleaned:
                    uname.return_value.machine = 'arm64'
                    with self.assertRaises(error): bootstrap.install(recipe, destination)
                journal = json.loads((destination / 'bootstrap.json').read_text())
                self.assertEqual(journal['status'], 'failed' if failure == 'second-disk' else 'cancelled')
                self.assertEqual(len(journal['cleanup']), 2 if failure == 'second-disk' else 1)
                self.assertTrue(cleaned.called)


if __name__ == '__main__':
    unittest.main()
