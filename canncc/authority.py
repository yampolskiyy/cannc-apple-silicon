"""Local recovery trust anchor and versioned journal authentication.

This protects journals only while the current user's private key is protected.
It cannot prevent another process with the same account from reading the key.
"""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile


class JournalTrustError(ValueError):
    """The recovery authority cannot be established safely."""


def _directory(*, create=False):
    configured = os.environ.get('CANNC_RECOVERY_KEY_DIR')
    if configured is not None:
        if not configured or not Path(configured).is_absolute():
            raise JournalTrustError('CANNC_RECOVERY_KEY_DIR must be a nonempty absolute path')
        root = Path(configured)
    else:
        root = Path.home() / '.cannc'
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = root.lstat()
    except FileNotFoundError as exc:
        raise JournalTrustError('recovery key is not initialized; run cannc recovery-key init') from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise JournalTrustError('recovery key directory must be private and owned by this user')
    return root


def _read_private(path, *, limit):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise JournalTrustError(f'recovery trust file missing: {path}; restore the original key') from exc
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise JournalTrustError('recovery trust files must be private and owned by this user')
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise JournalTrustError('invalid recovery trust file')
    return value


def _key(root):
    data = _read_private(root / 'recovery-key-v1', limit=32)
    if len(data) != 32:
        raise JournalTrustError('invalid recovery key')
    return data


def _marker(root):
    try:
        data = json.loads(_read_private(root / 'trust-anchor-v1', limit=1024))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise JournalTrustError('invalid recovery trust anchor') from exc
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('key_id'), str) or not re.fullmatch('[0-9a-f]{64}', data['key_id']):
        raise JournalTrustError('invalid recovery trust anchor')
    return data['key_id']


def _exclusive_write(root, path, data):
    fd, name = tempfile.mkstemp(prefix='.trust-', dir=root)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        try:
            os.link(name, path)
        except FileExistsError:
            return False
        # Persist the directory entry where the filesystem supports it.
        directory = os.open(root, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return True
    finally:
        os.unlink(name)


def initialize():
    """Explicitly initialize or register an existing v1 key; never rotate it."""
    root = _directory(create=True)
    lock_fd = os.open(root / 'init.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(lock_fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise JournalTrustError('invalid recovery initialization lock')
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        marker_path = root / 'trust-anchor-v1'
        key_path = root / 'recovery-key-v1'
        if marker_path.exists():
            pinned = Context.open()
            return pinned.key_id
        if not key_path.exists():
            _exclusive_write(root, key_path, secrets.token_bytes(32))
        value = _key(root)
        key_id = hashlib.sha256(value).hexdigest()
        marker = json.dumps({'schema': 1, 'key_id': key_id}, sort_keys=True).encode() + b'\n'
        if not _exclusive_write(root, marker_path, marker):
            if _marker(root) != key_id:
                raise JournalTrustError('recovery trust anchor changed during initialization')
        return Context.open().key_id


def _payload(manifest, record, version, key_id=None):
    body = {name: value for name, value in record.items() if name != 'journal_auth'}
    envelope = {'manifest': str(Path(manifest).resolve()), 'record': body}
    if version == 2:
        envelope.update(version=2, key_id=key_id)
    return json.dumps(envelope, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class Context:
    def __init__(self, root, value, key_id):
        self.root, self.value, self.key_id = root, value, key_id

    @classmethod
    def open(cls):
        root = _directory()
        value = _key(root)
        key_id = hashlib.sha256(value).hexdigest()
        if not hmac.compare_digest(key_id, _marker(root)):
            raise JournalTrustError('recovery key does not match the trust anchor')
        return cls(root, value, key_id)

    def check(self):
        try:
            root = _directory()
            if root != self.root:
                raise JournalTrustError('recovery key directory changed during operation')
            current = _key(root)
            if not hmac.compare_digest(hashlib.sha256(current).hexdigest(), self.key_id) or not hmac.compare_digest(_marker(root), self.key_id):
                raise JournalTrustError('recovery key changed during operation; restore the original key')
        except OSError as exc:
            raise JournalTrustError(f'cannot access pinned recovery key: {exc}') from exc

    def sign(self, manifest, record):
        self.check()
        mac = hmac.new(self.value, _payload(manifest, record, 2, self.key_id), hashlib.sha256).hexdigest()
        record['journal_auth'] = {'version': 2, 'key_id': self.key_id, 'hmac_sha256': mac}

    def verify(self, manifest, record):
        self.check()
        if not isinstance(record, dict): raise JournalTrustError('journal must be a JSON object')
        auth = record.get('journal_auth')
        if not isinstance(auth, dict): raise JournalTrustError('journal is not authenticated; legacy recovery requires --legacy-output')
        version = auth.get('version')
        if version not in (1, 2): raise JournalTrustError(f'journal format v{version} requires a compatible cannc')
        if version == 2 and auth.get('key_id') != self.key_id: raise JournalTrustError('journal key_id does not match current key')
        digest = auth.get('hmac_sha256')
        if not isinstance(digest, str): raise JournalTrustError('invalid journal authentication')
        expected = hmac.new(self.value, _payload(manifest, record, version, self.key_id), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, digest): raise JournalTrustError('journal authentication failed; no recovery performed')


def sign(manifest, record):
    Context.open().sign(manifest, record)


def verify(manifest, record):
    Context.open().verify(manifest, record)
