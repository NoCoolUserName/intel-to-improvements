#!/usr/bin/env python3
"""Rebuild code-drawn macOS ICNS and touch PNG (requires macOS Swift + sips)."""
from pathlib import Path
import struct
import subprocess

root = Path(__file__).resolve().parent.parent
work = root / 'runtime/icon-build'
work.mkdir(parents=True, exist_ok=True)
subprocess.run(['swift', '-module-cache-path', str(root / 'runtime/swift-module-cache'),
                str(root / 'desktop/render-icon.swift'), str(work / 'icon.png')], check=True)
chunks = []
# Modern ICNS entries embed PNG representations, including Retina variants.
for kind, size in [('icp4', 16), ('icp5', 32), ('icp6', 64), ('ic07', 128),
                   ('ic08', 256), ('ic09', 512), ('ic10', 1024),
                   ('ic11', 32), ('ic12', 64), ('ic13', 256), ('ic14', 512)]:
    output = work / f'{kind}.png'
    subprocess.run(['sips', '-z', str(size), str(size), str(work / 'icon.png'),
                    '--out', str(output)], check=True, stdout=subprocess.DEVNULL)
    png = output.read_bytes()
    chunks.append(kind.encode('ascii') + struct.pack('>I', len(png) + 8) + png)
payload = b''.join(chunks)
(root / 'desktop/AppIcon.icns').write_bytes(b'icns' + struct.pack('>I', len(payload) + 8) + payload)
subprocess.run(['sips', '-z', '180', '180', str(work / 'icon.png'), '--out',
                str(root / 'web/public/apple-touch-icon.png')], check=True, stdout=subprocess.DEVNULL)
print('Built desktop/AppIcon.icns and web/public/apple-touch-icon.png')
