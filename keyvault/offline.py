"""Defence in depth: install before loading any application modules."""
import sys

_installed = False


def install():
    global _installed
    if _installed:
        return

    def deny_network(event, args):
        if event.startswith(('socket.', 'subprocess.')) or event in {
            'os.system', 'os.startfile', 'os.startfile/2', 'os.posix_spawn',
            'os.posix_spawnp', 'os.fork', 'os.forkpty', 'os.exec', 'os.spawn',
        }:
            raise PermissionError('离线策略阻止网络或外部进程访问')

    sys.addaudithook(deny_network)
    _installed = True
