"""Preprocessor dependency capture for the pinned BiSheng driver.

The -M probe covers emitted header dependencies, not every possible file read
or negative __has_include query. That boundary must remain visible to users.
"""
import os
from pathlib import Path
import re

from . import profile, runner


class ProbeFailed(ValueError):
    def __init__(self, result, stderr):
        self.outcome = result
        super().__init__(f'dependency probe failed: exit {result["exit_code"]}; see {stderr}')


def parse_make(text):
    # Clang emits one make rule per host/device preprocessing job.
    text = re.sub(r'\\\r?\n[ \t]*', ' ', text)
    found = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        escaped = False
        colon = None
        for index, char in enumerate(line):
            if char == ':' and not escaped:
                colon = index; break
            if char == '\\' and not escaped: escaped = True
            else: escaped = False
        if colon is None:
            raise ValueError('invalid compiler dependency rule')
        # Make escaping is not shell quoting: quote characters are literal.
        words, word = [], []
        text_part = line[colon + 1:]
        index = 0
        while index < len(text_part):
            char = text_part[index]
            if char == '#':
                break
            if char == '\\':
                index += 1
                if index == len(text_part):
                    raise ValueError('invalid compiler dependency escaping')
                word.append(text_part[index])
            elif char.isspace():
                if word:
                    words.append(''.join(word)); word = []
            else:
                word.append(char)
            index += 1
        if word:
            words.append(''.join(word))
        found.update(word.replace('$$', '$') for word in words)
    if not found:
        raise ValueError('compiler dependency output is empty')
    return sorted(found)


def probe_command(command):
    if '-c' not in command or command[-2] != '-o':
        raise ValueError('unsupported dependency-probe command')
    probe = list(command[:-2])
    probe[probe.index('-c')] = '-M'
    return probe


def scan(command, source, run_dir, label, config):
    probe = probe_command(command)
    stdout, stderr = run_dir / (label + '.dependencies.stdout'), run_dir / (label + '.dependencies.stderr')
    result = runner.run(probe, stdout, stderr, config.get('timeout_seconds', 180))
    if result['exit_code']:
        raise ProbeFailed(result, stderr)
    names = parse_make(stdout.read_text(errors='strict'))
    execution = Path(config['execution_sysroot']).resolve()
    target = Path(config['target_sysroot']).resolve()
    pinned = tuple(execution / x for x in ('bin', 'lib', 'usr', 'opt')) + (target,)
    direct = Path(source).resolve()
    external = {}
    found_source = False
    for name in names:
        guest = Path(name)
        if guest.is_absolute():
            mapped = execution / name.lstrip('/')
            host = mapped if mapped.is_file() else guest
        else:
            host = execution / 'workspace' / guest
        host = host.resolve()
        if not host.is_file():
            raise ValueError(f'compiler dependency cannot be resolved: {name}')
        if host == direct:
            found_source = True
        if host != direct and not any(host.is_relative_to(root) for root in pinned):
            external[str(host)] = profile.sha(host)
    if not found_source:
        raise ValueError(f'compiler dependency output omitted source: {source}')
    return {'command': probe, 'exit_code': result['exit_code'], 'stdout': str(stdout), 'stderr': str(stderr),
            'stdout_sha256': profile.sha(stdout), 'stderr_sha256': profile.sha(stderr),
            'dependency_count': len(names)}, external
