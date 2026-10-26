#!/usr/bin/env python3
"""Start the loopback workbench if needed, then open it in the default browser."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent.parent
URL = 'http://127.0.0.1:8000'
sys.path.insert(0, str(ROOT))
from iti.build_identity import BUILD_ID, CHECKOUT_ID, LAUNCHER_PROTOCOL

def health():
    try:
        with urllib.request.urlopen(URL + '/health', timeout=2) as response:
            data = json.load(response)
        return data if data.get('status') == 'ok' and data.get('mode') == 'local single operator' else None
    except (OSError, ValueError):
        return None


def current(data):
    return bool(data and data.get('launcher_protocol') == LAUNCHER_PROTOCOL
                and data.get('checkout_id') == CHECKOUT_ID and data.get('build_id') == BUILD_ID)


def same_checkout_listener():
    """Return a listener only when lsof proves it is this checkout's server."""
    try:
        result = subprocess.run(['/usr/sbin/lsof', '-nP', '-t', '-iTCP:8000', '-sTCP:LISTEN'],
                                capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    for value in result.stdout.splitlines():
        if not value.isdigit():
            continue
        pid = int(value)
        try:
            command = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'command='],
                                     capture_output=True, text=True, check=True).stdout
            cwd = subprocess.run(['/usr/sbin/lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'],
                                 capture_output=True, text=True, check=True).stdout
            directories = [line[1:] for line in cwd.splitlines() if line.startswith('n')]
            if 'iti.cli run' in command and len(directories) == 1 and Path(directories[0]).resolve() == ROOT.resolve():
                return pid
        except (OSError, subprocess.CalledProcessError):
            continue
    return None


def stop_stale_server():
    pid = same_checkout_listener()
    if pid is None:
        raise SystemExit('Port 8000 is serving an older or different workbench that this launcher cannot safely stop. '
                         'Quit that server, then reopen Intel to Improvements. No process was changed.')
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while health() is not None:
        if time.monotonic() > deadline:
            raise SystemExit('The stale workbench did not stop. Quit it manually, then reopen the app.')
        time.sleep(.25)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-browser', action='store_true', help='Check/start the server without opening a browser')
    args = parser.parse_args()
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    # Finder supplies a minimal PATH. Include common macOS package-manager paths.
    env = dict(os.environ)
    env['PATH'] = '/opt/homebrew/bin:/usr/local/bin:' + env.get('PATH', '/usr/bin:/bin')
    observed = health()
    if observed and not current(observed):
        stop_stale_server()
        observed = None
    if not observed:
        with (runtime / 'launcher.log').open('ab') as log:
            process = subprocess.Popen([str(ROOT / 'scripts/run')], cwd=ROOT, env=env,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 180
        while not current(health()):
            if process.poll() is not None or time.monotonic() > deadline:
                raise SystemExit('Workbench did not start. See ' + str(runtime / 'launcher.log'))
            time.sleep(.5)
    if not args.no_browser:
        webbrowser.open(URL)
    print(URL)

if __name__ == '__main__':
    main()
