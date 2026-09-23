"""Runs before PyInstaller's Tk hook; do not override its bundled Tcl paths later."""
import os
for name in ('PYTHONHOME', 'PYTHONPATH', 'PYTHONSTARTUP', 'TCL_LIBRARY', 'TK_LIBRARY',
             'TCLLIBPATH', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES'):
    os.environ.pop(name, None)
from keyvault.offline import install
install()
