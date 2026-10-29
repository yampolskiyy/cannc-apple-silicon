"""Create a pinned local environment from independently provided archives."""
import io
import json
import os
import plistlib
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile

from . import profile
from .output import safe_print as print


def _command(args, *, timeout=None):
    result = subprocess.run(list(map(str, args)), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    if result.returncode:
        raise ValueError(f"command failed ({result.returncode}): {args[0]}: {result.stderr.strip()}")
    return result.stdout


def _members(archive, destination, prefix='', output_prefix=''):
    """Map known archive trees and keep links inside the reconstructed root."""
    prefix = prefix.strip('/')
    dest = str(destination)
    for original in archive:
        name = original.name
        while name.startswith('./'):
            name = name[2:]
        if name in ('', '.'):
            continue
        if prefix:
            if name == prefix:
                continue
            if not name.startswith(prefix + '/'):
                continue
            name = name[len(prefix) + 1:]
        name = '/'.join(part for part in (output_prefix.strip('/'), name) if part)
        parts = PurePosixPath(name).parts
        if not name or name.startswith('/') or '..' in parts:
            raise ValueError(f'invalid archive path: {original.name}')
        member = original.replace(name=name, deep=False)
        if member.issym() and member.linkname.startswith('/'):
            # Linux packages sometimes use absolute links inside the guest root.
            guest_target = PurePosixPath(member.linkname.lstrip('/'))
            link_parent = PurePosixPath(name).parent
            member = member.replace(linkname=os.path.relpath(str(guest_target), str(link_parent)), deep=False)
        # The fixed, audited input archives contain no hard links. Refuse them
        # rather than follow a hard-link-to-symlink chain during extraction.
        if member.islnk():
            raise ValueError(f'hard links are not supported in locked inputs: {original.name}')
        member = tarfile.data_filter(member, dest)
        if member is not None:
            archive.extract(member, path=dest, filter='data')


def _extract(path, destination, prefix='', output_prefix=''):
    with tarfile.open(path, 'r:*') as archive:
        _members(archive, destination, prefix, output_prefix)


def _debian_data(path):
    """Read the single data.tar member from the fixed Debian ar archives."""
    result = None
    with Path(path).open('rb') as stream:
        if stream.read(8) != b'!<arch>\n':
            raise ValueError(f'invalid Debian ar archive: {path}')
        while True:
            header = stream.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b'`\n':
                raise ValueError(f'invalid Debian ar member: {path}')
            try:
                name = header[:16].decode('ascii').strip().rstrip('/')
                size = int(header[48:58].decode('ascii').strip())
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError(f'invalid Debian ar header: {path}') from exc
            if size < 0 or size > os.fstat(stream.fileno()).st_size - stream.tell():
                raise ValueError(f'invalid Debian ar member size: {path}')
            data = stream.read(size)
            if len(data) != size or (size % 2 and len(stream.read(1)) != 1):
                raise ValueError(f'truncated Debian ar member: {path}')
            if name.startswith('data.tar.'):
                if result is not None: raise ValueError(f'multiple Debian payloads: {path}')
                result = data
    if result is None: raise ValueError(f'missing Debian payload: {path}')
    return result


def _disk(destination, name, volume_name, size, created):
    image = destination / (name + '.sparsebundle')
    mount = destination / (name + '-volume')
    mount.mkdir()
    _command(['hdiutil', 'create', '-size', size, '-type', 'SPARSEBUNDLE', '-fs', 'Case-sensitive APFS', '-volname', volume_name, image])
    # Register before attaching: an interrupted or failed attach may still have mounted it.
    created.append((image, mount))
    _command(['hdiutil', 'attach', '-nobrowse', '-mountpoint', mount, image])
    return mount


def _cleanup_created_images(created):
    """Detach only mounts whose image and mountpoint match this installation."""
    candidates = list(reversed(created))
    try:
        result = subprocess.run(['hdiutil', 'info', '-plist'], check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15)
        info = plistlib.loads(result.stdout)
        if not isinstance(info, dict) or not isinstance(info.get('images'), list):
            raise ValueError('invalid hdiutil image inventory')
    except (OSError, subprocess.SubprocessError, ValueError, plistlib.InvalidFileException) as exc:
        return [{'image': str(image), 'mountpoint': str(mount), 'status': 'unverified',
                 'error': str(exc)} for image, mount in candidates if image.exists()]
    mounted = {}
    by_image = {}
    devices_by_image = {}
    for item in info['images']:
        image_path = item.get('image-path')
        if not image_path:
            continue
        resolved_image = str(Path(image_path).resolve())
        devices_by_image.setdefault(resolved_image, [])
        for entity in item.get('system-entities', []):
            device = entity.get('dev-entry', '')
            if re.fullmatch(r'/dev/disk[0-9]+', device):
                devices_by_image[resolved_image].append(device)
            if entity.get('mount-point'):
                mounted_at = str(Path(entity['mount-point']).resolve())
                mounted[mounted_at] = resolved_image
                by_image.setdefault(resolved_image, []).append(mounted_at)
    records = []
    for image, mount in candidates:
        if not image.exists():
            continue
        record = {'image': str(image), 'mountpoint': str(mount)}
        actual = mounted.get(str(mount.resolve()))
        detach_target = None
        if actual is None:
            other_mounts = by_image.get(str(image.resolve()), [])
            if other_mounts:
                record.update(status='unverified', error='image mounted at an unexpected mountpoint',
                              observed_mountpoints=other_mounts)
            elif os.path.ismount(mount):
                record.update(status='unverified', error='mountpoint missing from image inventory')
            elif str(image.resolve()) in devices_by_image:
                devices = devices_by_image[str(image.resolve())]
                if devices:
                    # The image is attached, but no volume is mounted. Detach the
                    # owning whole-disk device from this image's inventory entry.
                    detach_target = devices[0]
                    record['detach_target'] = detach_target
                else:
                    record.update(status='unverified', error='attached image has no identifiable whole-disk device')
            else:
                record['status'] = 'not_mounted'
        elif actual != str(image.resolve()):
            record.update(status='unowned_mount', error='mountpoint belongs to a different image')
        else:
            detach_target = mount
        if detach_target is not None:
            try:
                _command(['hdiutil', 'detach', detach_target], timeout=20)
                if os.path.ismount(mount):
                    record.update(status='detach_failed', error='mountpoint remains mounted')
                elif isinstance(detach_target, str) and detach_target.startswith('/dev/disk'):
                    after = subprocess.run(['hdiutil', 'info', '-plist'], check=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                    remaining = plistlib.loads(after.stdout)
                    if any(str(Path(item['image-path']).resolve()) == str(image.resolve())
                           for item in remaining['images'] if item.get('image-path')):
                        record.update(status='detach_failed', error='image remains attached')
                    else:
                        record['status'] = 'detached'
                else:
                    record['status'] = 'detached'
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, plistlib.InvalidFileException) as exc:
                record.update(status='detach_failed', error=str(exc))
        records.append(record)
    return records


class BootstrapTerminated(InterruptedError):
    """A handled SIGTERM during installation."""


def install(recipe_path, destination, inputs_dir=None):
    if sys.platform != 'darwin': raise ValueError('bootstrap requires macOS on Apple Silicon')
    if sys.version_info < (3, 12): raise ValueError('bootstrap requires Python 3.12 or newer')
    if os.uname().machine != 'arm64': raise ValueError('bootstrap requires Apple Silicon')
    recipe_path = Path(recipe_path).expanduser().resolve()
    data = json.loads(recipe_path.read_text())
    if data.get('schema_version') != 1: raise ValueError('unsupported recipe schema')
    inputs = data['inputs']
    required = {'bisheng', 'elfuse', 'target-collection', 'target-headers', 'asc-devkit', 'cann-runtime'}
    if not required <= set(inputs): raise ValueError('recipe is missing required inputs')
    base = Path(inputs_dir).expanduser().resolve() if inputs_dir else recipe_path.parent
    def path(name):
        source = Path(inputs[name]['path']).expanduser()
        if inputs_dir:
            source = base / source.name
        elif not source.is_absolute():
            source = base / source
        return source.resolve()
    for name, item in inputs.items():
        source_path = path(name)
        if not source_path.is_file() or profile.sha(source_path) != item['sha256']:
            raise ValueError(f'input unavailable or SHA-256 mismatch: {name}: {source_path}')
    destination = Path(destination).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=False)
    journal = destination / 'bootstrap.json'
    state = {'schema_version': 1, 'status': 'running', 'recipe_sha256': profile.sha(recipe_path),
             'inputs': {name: {'sha256': item['sha256'], 'size': item['size']} for name, item in inputs.items()},
             'sources': data['sources'], 'provenance': data['provenance'], 'steps': []}
    def step(name):
        state['steps'].append(name)
        journal.write_text(json.dumps(state, indent=2) + '\n')
    created = []
    old_term = signal.getsignal(signal.SIGTERM)
    old_int = signal.getsignal(signal.SIGINT)
    def on_term(_signum, _frame):
        raise BootstrapTerminated('received SIGTERM')
    signal.signal(signal.SIGTERM, on_term)
    try:
        step('inputs verified')
        root = _disk(destination, 'execution', 'cannc-execution', '3g', created)
        target_volume = _disk(destination, 'target', 'cannc-target', '3g', created)
        target = target_volume / 'root'
        target.mkdir()
        step('case-sensitive volumes mounted')
        for name in sorted(x for x in inputs if x.startswith('deb:')):
            package = path(name)
            content = _debian_data(package)
            with tarfile.open(fileobj=io.BytesIO(content), mode='r:*') as archive:
                _members(archive, root)
        step('Debian packages extracted')
        _extract(path('bisheng'), root, output_prefix='opt/cann')
        _extract(path('asc-devkit'), root, prefix='include', output_prefix='opt/cann/asc-devkit/include')
        _extract(path('asc-devkit'), root, prefix='impl', output_prefix='opt/cann/asc-devkit/impl')
        _extract(path('cann-runtime'), root, prefix='include/external', output_prefix='opt/cann/runtime/include')
        for directory in ('workspace', 'tmp'):
            (root / directory).mkdir(exist_ok=True)
        generator = root / 'opt/cann/asc-devkit/impl/adv_api/cmake/scripts/gen_kernel_tiling_data_def.py'
        output = root / 'opt/cann/generated/kernel_tiling/kernel_tiling.h'
        _command([sys.executable, generator, root / 'opt/cann/asc-devkit/include/adv_api', output])
        step('compiler and SDK headers installed')
        _extract(path('target-collection'), target, prefix='collection-v3/target-root')
        _extract(path('target-headers'), target)
        step('target snapshot reconstructed')
        elfuse = destination / 'elfuse'
        shutil.copy2(path('elfuse'), elfuse)
        if profile.sha(elfuse) != inputs['elfuse']['sha256']: raise ValueError('elfuse copy mismatch')
        config = dict(data['profile'])
        config.update(profile_id='bisheng-9.2.0-dav-2201-phase2', elfuse=str(elfuse),
                      execution_sysroot=str(root), target_sysroot=str(target),
                      execution_manifest=str(destination / 'execution-manifest.json'),
                      target_manifest=str(destination / 'target-manifest.json'))
        for key, folder, prefixes, dirs in (('execution', root, ('bin', 'lib', 'usr', 'opt'), False), ('target', target, None, True)):
            entries, digest = profile.snapshot(folder, prefixes, dirs)
            expected = data.get('expected_digests', {}).get(key)
            if expected is not None and digest != expected:
                raise ValueError(f'{key} snapshot differs from the locked expected digest')
            manifest = {'schema_version': 1, 'digest': digest, 'entries': entries}
            Path(config[key + '_manifest']).write_text(json.dumps(manifest, indent=2) + '\n')
            config[key + '_digest'] = digest
        config_path = destination / 'profile.json'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        identity = profile.check(config)
        state.update(status='success', profile=str(config_path), identity=identity)
        step('profile verified')
        print(f'Installed local environment. Profile: {config_path}')
        return 0
    except BaseException as exc:
        # Protect cleanup from a second interrupt while retaining the original error.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        state.update(status='cancelled' if isinstance(exc, (KeyboardInterrupt, BootstrapTerminated)) else 'failed',
                     error=str(exc) or type(exc).__name__)
        try:
            state['cleanup'] = _cleanup_created_images(created) if created else []
        except Exception as cleanup_error:
            state['cleanup'] = [{'image': str(image), 'mountpoint': str(mount), 'status': 'unverified',
                                 'error': str(cleanup_error)} for image, mount in reversed(created)]
        unresolved = [x for x in state['cleanup'] if x['status'] not in ('detached', 'not_mounted')]
        try:
            journal.write_text(json.dumps(state, indent=2) + '\n')
        except OSError as journal_error:
            print(f'Could not write bootstrap journal: {journal_error}', file=sys.stderr)
        if unresolved:
            print(f'Bootstrap cleanup incomplete; inspect {journal} and verify the reported images before detaching.',
                  file=sys.stderr)
        raise
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def volumes(destination, action):
    destination = Path(destination).expanduser().resolve()
    config = profile.load(destination / 'profile.json')
    execution = Path(config['execution_sysroot'])
    target = Path(config['target_sysroot']).parent
    for name, mount in (("execution", execution), ("target", target)):
        expected = destination / (name + '-volume')
        if mount != expected:
            raise ValueError(f'unexpected {name} mountpoint in profile')
        if action == 'mount' and not os.path.ismount(mount):
            _command(['hdiutil', 'attach', '-nobrowse', '-mountpoint', mount, destination / (name + '.sparsebundle')])
        if action == 'unmount' and os.path.ismount(mount):
            _command(['hdiutil', 'detach', mount])
    print(f'{action} complete: {destination}')
    return 0
