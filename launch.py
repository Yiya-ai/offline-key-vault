"""Isolated source and portable entry point. No online installation."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(Path(__file__).resolve().parent / 'vendor'))
from keyvault.offline import install
install()
import os
# Python -I ignores Python settings, but not Tcl/OpenSSL settings.
# Frozen apps use the bundled Tcl paths installed by their runtime hooks.
for name in ('OPENSSL_CONF', 'OPENSSL_MODULES', 'OPENSSL_ENGINES'):
    os.environ.pop(name, None)
if not getattr(sys, 'frozen', False):
    for name in ('TCL_LIBRARY', 'TK_LIBRARY', 'TCLLIBPATH'):
        os.environ.pop(name, None)
    if sys.platform == 'win32':
        tcl = Path(sys.base_prefix) / 'tcl'
        os.environ['TCL_LIBRARY'] = str(tcl / 'tcl8.6')
        os.environ['TK_LIBRARY'] = str(tcl / 'tk8.6')
    # macOS Python/Tk distributions locate their own framework resources.
    import sysconfig
    for path in {sysconfig.get_path('purelib'), sysconfig.get_path('platlib')}:
        if path not in sys.path:
            sys.path.append(path)
if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        from keyvault.diagnostics import run
        run()
    elif sys.argv[1:]:
        raise SystemExit('Unsupported arguments')
    else:
        from keyvault.app import main
        main()
