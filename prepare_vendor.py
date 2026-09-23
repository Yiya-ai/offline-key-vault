"""DEVELOPMENT ONLY: install explicitly supplied local wheels. Never downloads."""
from pathlib import Path
import subprocess
import sys
from build_portable import PACKAGES


def main():
    if len(sys.argv) != 2: raise SystemExit('Usage: python prepare_vendor.py LOCAL_WHEEL_DIRECTORY')
    wheelhouse = Path(sys.argv[1]).resolve(strict=True)
    if not wheelhouse.is_dir(): raise SystemExit('A local wheel directory is required')
    root = Path(__file__).resolve().parent
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--target', str(root / 'vendor'), '--upgrade', '--no-deps', '--no-index', '--only-binary=:all:', '--find-links', str(wheelhouse), *[name + '==' + version for name, version in PACKAGES.items()]], check=True)
    init = root / 'vendor/jks/__init__.py'
    init.write_text(init.read_text(encoding='utf-8').replace('from .bks import *', '# BKS is intentionally not loaded'), encoding='utf-8')
    print('Local vendor dependencies ready. No network used.')


if __name__ == '__main__': main()
