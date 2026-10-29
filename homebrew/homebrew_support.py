"""Homebrew entry point for the pinned, self-contained cannc environment."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'app'))
from canncc import authority, bootstrap, profile
from canncc.__main__ import main


def state_root(base):
    path = Path(base)
    if not path.is_absolute():
        raise ValueError('Homebrew state root must be absolute')
    root = path/str(os.getuid())
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise ValueError('Homebrew state directory must belong to the current user')
    return root


@contextlib.contextmanager
def locked(root):
    fd = os.open(root/'.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != os.getuid():
            raise ValueError('invalid Homebrew environment lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def prepare(root):
    recipe = HERE/'app/config/input-lock.json'
    environment = root/'environment-v1'
    receipt = root/'ready.json'
    expected = {'schema': 1, 'recipe_sha256': profile.sha(recipe), 'environment': str(environment)}
    os.environ.setdefault('CANNC_RECOVERY_KEY_DIR', str(root/'recovery-key'))
    with locked(root):
        if environment.exists() or environment.is_symlink() or receipt.exists() or receipt.is_symlink():
            if environment.is_symlink() or receipt.is_symlink() or not receipt.is_file():
                raise ValueError(f'partial environment at {environment}; inspect it before retrying')
            if json.loads(receipt.read_text()) != expected:
                raise ValueError('existing Homebrew environment does not match this recipe')
            bootstrap.volumes(environment, 'mount')
            profile.check(profile.load(environment/'profile.json'))
            return environment
        authority.initialize()
        bootstrap.install(recipe, environment, HERE/'inputs')
        code = main(['--config', str(environment/'profile.json'), 'version'])
        if code:
            raise ValueError(f'compiler version check failed with exit {code}')
        fd, name = tempfile.mkstemp(prefix='.ready-', dir=root)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(expected, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, receipt)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return environment


def cli(argv):
    if len(argv) < 2 or argv[0] not in ('setup', 'run'):
        raise ValueError('expected setup|run and the Homebrew state root')
    action, root = argv[0], state_root(argv[1])
    args = argv[2:]
    if action == 'run' and (not args or args[0] in ('-h', '--help')):
        return main(args)
    if action == 'run' and any(x == '--config' or x.startswith('--config=') for x in args):
        return main(args)
    environment = prepare(root)
    if action == 'setup':
        return 0
    return main(['--config', str(environment/'profile.json')] + args)


if __name__ == '__main__':
    try:
        raise SystemExit(cli(sys.argv[1:]))
    except (ValueError, OSError) as exc:
        print(f'cannc Homebrew: {exc}', file=sys.stderr)
        raise SystemExit(1)
