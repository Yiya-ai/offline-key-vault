"""Fetch and verify the two public source archives in the isolated builder."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

for name, source in json.loads(Path('sources.json').read_text()).items():
    with urllib.request.urlopen(source['url'], timeout=120) as response:
        data = response.read(80 * 1024 * 1024 + 1)
    if len(data) > 80 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != source['sha256']:
        raise ValueError('Public source digest mismatch')
    path = Path(name + '.tar.gz')
    path.write_bytes(data)
    with tarfile.open(path) as archive:
        archive.extractall(path='.', filter='data')
