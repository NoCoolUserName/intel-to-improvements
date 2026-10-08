#!/usr/bin/env python3
"""Start the loopback workbench if needed, then open it in the default browser."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent.parent
URL = 'http://127.0.0.1:8000'

def healthy():
    try:
        with urllib.request.urlopen(URL + '/health', timeout=2) as response:
            data = json.load(response)
        return data.get('status') == 'ok' and data.get('mode') == 'local single operator'
    except (OSError, ValueError):
        return False

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-browser', action='store_true', help='Check/start the server without opening a browser')
    args = parser.parse_args()
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    # Finder supplies a minimal PATH. Include common macOS package-manager paths.
    env = dict(os.environ)
    env['PATH'] = '/opt/homebrew/bin:/usr/local/bin:' + env.get('PATH', '/usr/bin:/bin')
    if not healthy():
        with (runtime / 'launcher.log').open('ab') as log:
            process = subprocess.Popen([str(ROOT / 'scripts/run')], cwd=ROOT, env=env,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 180
        while not healthy():
            if process.poll() is not None or time.monotonic() > deadline:
                raise SystemExit('Workbench did not start. See ' + str(runtime / 'launcher.log'))
            time.sleep(.5)
    if not args.no_browser:
        webbrowser.open(URL)
    print(URL)

if __name__ == '__main__':
    main()
