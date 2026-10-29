"""Preserve command status when output pipes close early."""
import builtins
import os
import sys


def silence(stream):
    try:
        descriptor = stream.fileno()
        null = os.open(os.devnull, os.O_WRONLY)
        if null != descriptor:
            try: os.dup2(null, descriptor)
            finally: os.close(null)
    except (OSError, ValueError, AttributeError):
        pass


def write(stream, data):
    if stream is None: return
    try:
        stream.write(data); stream.flush()
    except (OSError, ValueError) as exc:
        if isinstance(exc, ValueError) and not getattr(stream, 'closed', False): raise
        silence(stream)


class DataOutputError(OSError):
    """A command could not deliver its requested output."""


def data_write(stream, data):
    if stream is None:
        raise DataOutputError('output stream is unavailable')
    try:
        stream.write(data); stream.flush()
    except (OSError, ValueError) as exc:
        silence(stream)
        raise DataOutputError(f'could not deliver command output: {exc}') from exc


def safe_print(*args, **kwargs):
    stream = kwargs.get('file', sys.stdout)
    if stream is None: return
    kwargs['flush'] = True
    try:
        builtins.print(*args, **kwargs)
    except (OSError, ValueError) as exc:
        if isinstance(exc, ValueError) and not getattr(stream, 'closed', False): raise
        silence(stream)
