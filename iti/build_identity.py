"""Frozen identity for the code and frontend served by one app process."""
import hashlib
from pathlib import Path

from .store import ROOT

LAUNCHER_PROTOCOL = 1


def checkout_id(root: Path = ROOT) -> str:
    """Identify a checkout without exposing its local filesystem path."""
    return hashlib.sha256(str(root.resolve()).encode()).hexdigest()


def build_id(root: Path = ROOT) -> str:
    """Hash files that require a server restart or frontend rebuild."""
    paths = [
        *sorted((root / 'iti').glob('*.py')),
        *sorted((root / 'web/dist').glob('**/*')),
        root / 'uv.lock',
        root / 'web/package-lock.json',
        root / 'scripts/run',
        root / 'scripts/iti',
    ]
    value = hashlib.sha256()
    for path in paths:
        if not path.is_file():
            continue
        value.update(path.relative_to(root).as_posix().encode())
        value.update(b'\0')
        value.update(path.read_bytes())
        value.update(b'\0')
    return value.hexdigest()


# These values are deliberately frozen when the server process imports code.
CHECKOUT_ID = checkout_id()
BUILD_ID = build_id()
