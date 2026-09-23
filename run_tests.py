"""Offline test runner with third-party pytest autoload disabled."""
import os
import sys
import sysconfig
from pathlib import Path
from datetime import datetime
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
sys.path.insert(1, str(Path(__file__).resolve().parent / 'vendor'))
os.chdir(root)
for path in {sysconfig.get_path('purelib'), sysconfig.get_path('platlib')}:
    if path not in sys.path:
        sys.path.append(path)
os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
(root / 'test-results').mkdir(exist_ok=True)
import pytest
raise SystemExit(pytest.main([str(root / 'tests'), '-q', '--basetemp=' + str(root / 'test-results' / ('run-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f')))]))
