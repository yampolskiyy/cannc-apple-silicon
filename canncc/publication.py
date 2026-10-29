"""Recoverable publication of one output and its separately stored build record.

This is a process-failure protocol, not a two-file atomic transaction or a
power-loss durability guarantee. Concurrent writers outside canncc must not
modify the same output; mismatches are left for manual recovery.
"""
import json
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import unicodedata

from . import authority, profile


class RecoveryRequired(Exception):
    """The output cannot be reconciled without risking another writer's data."""


class LockSet:
    def __init__(self, handles):
        self.handles = handles

    def close(self):
        for handle in reversed(self.handles):
            handle.close()


def acquire_lock(output):
    """Reject concurrent publications using equivalent path spellings."""
    output = Path(output)
    folder = output.parent / '.canncc' / 'locks'
    folder.mkdir(parents=True, exist_ok=True)
    # Conservative across filesystems: collisions on a case-sensitive volume
    # only reject a concurrent operation, while aliases share a lock.
    normalized = unicodedata.normalize('NFC', str(output)).casefold()
    keys = sorted({hashlib.sha256(x.encode()).hexdigest() for x in (normalized, str(output))})
    handles = []
    try:
        for key in keys:
            handle = (folder / (key + '.lock')).open('a+b')
            handles.append(handle)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        for handle in reversed(handles): handle.close()
        raise
    return LockSet(handles)


def identity(path):
    path = Path(path)
    try:
        first = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(first.st_mode):
        raise RecoveryRequired(f'not a regular file: {path}')
    digest = profile.sha(path)
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode')
    if any(getattr(first, k) != getattr(after, k) for k in fields):
        raise RecoveryRequired(f'file changed while hashing: {path}')
    return {'device': after.st_dev, 'inode': after.st_ino, 'size': after.st_size,
            'mtime_ns': after.st_mtime_ns, 'mode': stat.S_IMODE(after.st_mode), 'sha256': digest}


def matches(path, expected):
    return identity(path) == expected


def prepare(output, staged, run_id):
    output, staged = Path(output), Path(staged)
    backup = output.parent / ('.' + output.name + '.canncc-' + run_id + '.backup')
    new = identity(staged)
    if new is None:
        raise RecoveryRequired('staged output is missing')
    previous = identity(output)
    created = False
    try:
        if previous is not None:
            os.link(output, backup, follow_symlinks=False)
            created = True
            if not matches(backup, previous) or not matches(output, previous):
                raise RecoveryRequired('previous output changed during backup')
        return {'schema_version': 1, 'run_id': run_id, 'output': str(output), 'staged': str(staged),
                'backup': str(backup), 'previous': previous, 'new': new}
    except BaseException:
        if created:
            try: backup.unlink()
            except OSError: pass
        raise


def validate(record):
    tx = record.get('transaction')
    run_id = record.get('run_id')
    if not isinstance(tx, dict) or tx.get('schema_version') != 1 or not isinstance(run_id, str) or not re.fullmatch('[0-9a-f]{32}', run_id):
        raise RecoveryRequired('manifest has no supported publication transaction')
    if tx.get('run_id') != run_id:
        raise RecoveryRequired('transaction run identity mismatch')
    output = Path(record['requested_output'])
    staged = output.parent / ('.' + output.name + '.canncc-' + run_id + '.tmp')
    backup = output.parent / ('.' + output.name + '.canncc-' + run_id + '.backup')
    if not output.is_absolute() or tx.get('output') != str(output) or tx.get('staged') != str(staged) or tx.get('backup') != str(backup) or record.get('staged_output') != str(staged):
        raise RecoveryRequired('transaction paths do not match the recorded output')
    for info in (tx.get('new'), tx.get('previous')):
        if info is None:
            continue
        if not isinstance(info, dict) or not all(k in info for k in ('device','inode','size','mtime_ns','mode','sha256')) or not re.fullmatch('[0-9a-f]{64}', str(info['sha256'])):
            raise RecoveryRequired('invalid recorded file identity')
    terminal_rollback = record.get('status') in ('failed', 'cancelled')
    expected_hash = None if terminal_rollback else tx['new']['sha256'] if tx.get('new') else None
    if tx.get('new') is None or record.get('output_sha256') != expected_hash:
        raise RecoveryRequired('candidate output identity mismatch')
    return tx


def discard_backup(tx):
    backup = Path(tx['backup'])
    if identity(backup) is None:
        return
    if tx['previous'] is None or not matches(backup, tx['previous']):
        raise RecoveryRequired('backup changed; not removing it')
    backup.unlink()


def discard_staged(tx):
    staged = Path(tx['staged'])
    if identity(staged) is None:
        return
    if not matches(staged, tx['new']):
        raise RecoveryRequired('staged file changed; not removing it')
    staged.unlink()


def reconcile(manifest, record, write_json, *, error, exit_code, authorize=None, recheck=None):
    """Confirm commit or restore prior output; retain evidence on uncertainty.

    Returns ``committed`` or ``rolled_back``. An unrecoverable mismatch raises
    RecoveryRequired without overwriting the output. The caller must not erase
    staged or backup files when this function raises.
    """
    manifest = Path(manifest)
    try:
        saved = json.loads(manifest.read_text())
    except (OSError, ValueError) as exc:
        raise RecoveryRequired(f'cannot read publication manifest: {exc}') from exc
    if authorize is not None:
        authorize(manifest, saved)
    tx = validate(saved)
    if record.get('run_id') != saved.get('run_id'):
        raise RecoveryRequired('manifest run identity changed')
    output, backup = Path(tx['output']), Path(tx['backup'])
    if saved.get('status') == 'success':
        if not matches(output, tx['new']):
            raise RecoveryRequired('manifest says success but output identity differs')
        return 'committed'
    if saved.get('status') in ('failed', 'cancelled'):
        if not matches(output, tx['previous']):
            raise RecoveryRequired('terminal failure does not match previous output')
        record.clear(); record.update(saved)
        try: discard_backup(tx)
        except (OSError, RecoveryRequired): pass
        return 'rolled_back'
    if saved.get('status') not in ('committing', 'rolling_back', 'recovery_required'):
        raise RecoveryRequired(f"cannot reconcile manifest state: {saved.get('status')}")
    previous = tx['previous']
    if matches(output, previous):
        # Either replacement never happened or an earlier rollback completed.
        pass
    elif matches(output, tx['new']):
        if previous is not None and not matches(backup, previous):
            raise RecoveryRequired('previous-output backup missing or changed')
        saved.update(status='rolling_back', error=str(error), exit_code=exit_code)
        write_json(manifest, saved)
        # Recheck immediately before modifying the destination; external writers
        # remain out of scope because POSIX has no compare-and-swap rename.
        if not matches(output, tx['new']):
            raise RecoveryRequired('output changed before rollback')
        if recheck is not None:
            recheck()
        try:
            if previous is None:
                output.unlink()
            else:
                os.replace(backup, output)
        except OSError:
            # A syscall can have completed even if its outcome was interrupted.
            if not matches(output, previous):
                raise
        if not matches(output, previous):
            raise RecoveryRequired('rollback result differs from previous output')
    else:
        raise RecoveryRequired('output differs from both recorded versions; no changes made')
    saved.update(status='failed' if exit_code not in (130,143) else 'cancelled',
                 exit_code=exit_code, error=str(error), output_sha256=None,
                 recovery={'status': 'previous_output_restored' if previous is not None else 'output_absent'})
    try:
        write_json(manifest, saved)
    except authority.JournalTrustError as exc:
        raise RecoveryRequired('previous output restored, but journal not finalized; restore the original key and retry') from exc
    record.clear(); record.update(saved)
    # Cleanup occurs only after a successfully written terminal record. If cleanup fails, the
    # record still correctly describes the output and the backup remains visible.
    try: discard_backup(tx)
    except (OSError, RecoveryRequired): pass
    return 'rolled_back'
