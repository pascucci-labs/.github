#!/usr/bin/env python3
"""Install Linux amd64 release binaries after checking committed SHA-256 hashes."""
import argparse
import hashlib
import io
import json
import platform
import tarfile
import urllib.request
from pathlib import Path


def install(name, destination):
    if platform.system() != 'Linux' or platform.machine() not in {'x86_64', 'AMD64'}:
        raise RuntimeError('Release lock is for Linux amd64; use an ephemeral Linux runner')
    lock = json.loads((Path(__file__).resolve().parents[1] / 'config/tools.json').read_text())[name]
    request = urllib.request.Request(lock['url'], headers={'User-Agent': 'pascucci-labs-quality'})
    with urllib.request.urlopen(request, timeout=120) as response:
        content = response.read()
    if hashlib.sha256(content).hexdigest() != lock['sha256']:
        raise ValueError('Tool archive checksum mismatch: ' + name)
    if 'member' in lock:
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
            member = archive.getmember(lock['member'])
            if not member.isfile():
                raise ValueError('Expected regular binary')
            content = archive.extractfile(member).read()
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / name
    path.write_bytes(content)
    path.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('names', nargs='+')
    parser.add_argument('--destination', type=Path, default=Path.home() / '.local/bin')
    args = parser.parse_args()
    for name in args.names:
        install(name, args.destination)
