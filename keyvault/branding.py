"""Reproducible local application artwork; no external assets or dependencies."""
import math
import struct
import sys
import zlib
from functools import lru_cache


@lru_cache(maxsize=12)
def pixels(size):
    """Return antialiased RGBA: a white key on the application's red tile."""
    if size not in (16, 24, 32, 48, 64, 128, 256, 512, 1024):
        raise ValueError('Unsupported icon size')
    output = bytearray()
    edge = 1.0 / size
    for row in range(size):
        y = (row + 0.5) / size
        for column in range(size):
            x = (column + 0.5) / size
            qx, qy = abs(x - .5) - .28, abs(y - .5) - .28
            tile = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - .16
            alpha = max(0, min(1, .5 - tile / edge))
            # Rotate the shaft coordinates 45 degrees around the ring center.
            u, v = (x + y - .76) / math.sqrt(2), (y - x) / math.sqrt(2)
            ring = abs(math.hypot(x - .38, y - .38) - .114) - .032
            shaft = max(.09 - u, u - .43, abs(v) - .034)
            tooth = max(.295 - u, u - .35, -.11 - v, v + .01)
            tip = max(.375 - u, u - .43, -.09 - v, v + .01)
            white = max(0, min(1, .5 - min(ring, shaft, tooth, tip) / edge))
            output.extend((round(220 + 35 * white), round(53 + 202 * white),
                           round(69 + 186 * white), round(255 * alpha)))
    return bytes(output)


@lru_cache(maxsize=12)
def png(size):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rgba = pixels(size)
    rows = b''.join(b'\0' + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b''))


def write_ico(path):
    """Classic 32-bit DIB frames support Windows Explorer and the C# compiler."""
    sizes = (16, 24, 32, 48, 64, 128, 256)
    directory, frames = bytearray(), bytearray()
    offset = 6 + 16 * len(sizes)
    for size in sizes:
        rgba = pixels(size)
        bitmap = bytearray()
        mask = bytearray()
        stride = ((size + 31) // 32) * 4
        for y in range(size - 1, -1, -1):
            mask_row = bytearray(stride)
            for x in range(size):
                r, g, b, a = rgba[(y * size + x) * 4:(y * size + x + 1) * 4]
                bitmap.extend((b, g, r, a))
                if a == 0:
                    mask_row[x // 8] |= 128 >> (x % 8)
            mask.extend(mask_row)
        frame = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32, 0, len(bitmap), 0, 0, 0, 0) + bitmap + mask
        directory.extend(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(frame), offset))
        frames.extend(frame)
        offset += len(frame)
    path.write_bytes(struct.pack('<HHH', 0, 1, len(sizes)) + directory + frames)


def install_window_icon(root):
    import tkinter as tk
    # Packaged macOS uses its high-resolution .icns for Finder and the Dock.
    if sys.platform == 'darwin' and getattr(sys, 'frozen', False):
        return
    images = [tk.PhotoImage(master=root, data=png(size)) for size in (16, 32, 48, 128)]
    root.iconphoto(True, *images)
    root._application_icons = images
