"""Build the patched public WASM dependency in Docker; never mount user data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

WEB = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rebuild', action='store_true', help='Rebuild and verify even if a matching wheel is cached')
    args = parser.parse_args()
    lock = json.loads((WEB / 'dependencies.lock.json').read_text(encoding='utf-8'))
    item = next(p for p in lock['files'] if p['name'] == 'cryptography')
    if item.get('build') != 'wasm-build/Dockerfile' or Path(item['file']).name != item['file']:
        raise ValueError('Expected a reviewed local WASM recipe')
    cache = WEB / '.vendor'
    cache.mkdir(exist_ok=True)
    if cache.is_symlink() or cache.is_junction():
        raise ValueError('Linked dependency cache')
    target = cache / item['file']
    if target.is_symlink() or (target.exists() and target.stat().st_nlink != 1):
        raise ValueError('Linked WASM cache file')
    if not args.rebuild and target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == item['sha256']:
        print('Verified patched WASM wheel is already cached')
        return
    tag = 'offline-key-vault-wasm:crypto-' + item['version']
    subprocess.run(['docker', 'build', '--platform', 'linux/amd64', '--progress=plain', '--tag', tag,
                    str(WEB / 'wasm-build')], check=True)
    container = subprocess.check_output(['docker', 'create', '--network', 'none', tag], text=True).strip()
    try:
        with tempfile.TemporaryDirectory(prefix='wasm-wheel-', dir=cache) as temporary:
            folder = Path(temporary)
            subprocess.run(['docker', 'cp', container + ':/output/.', str(folder)], check=True)
            wheel = folder / item['file']
            if hashlib.sha256(wheel.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('WASM build differs from the reviewed binary; do not deploy')
            os.replace(wheel, target)
    finally:
        subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
    print('Patched WASM wheel built and SHA-256 verified')


if __name__ == '__main__':
    main()
