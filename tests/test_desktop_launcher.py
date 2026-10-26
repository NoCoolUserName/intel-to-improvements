import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from iti.api import create_app
from iti.build_identity import BUILD_ID, CHECKOUT_ID, LAUNCHER_PROTOCOL, build_id, checkout_id


def launcher():
    path = Path(__file__).parents[1] / 'scripts/desktop-launcher.py'
    spec = importlib.util.spec_from_file_location('desktop_launcher', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_health_exposes_frozen_non_path_identity(service):
    with TestClient(create_app(service), base_url='http://localhost') as client:
        value = client.get('/health').json()
    assert value['launcher_protocol'] == LAUNCHER_PROTOCOL
    assert value['checkout_id'] == CHECKOUT_ID == checkout_id()
    assert value['build_id'] == BUILD_ID == build_id()
    assert str(Path.cwd()) not in json.dumps(value)


def test_launcher_accepts_only_exact_current_build():
    module = launcher()
    value = {'status':'ok','mode':'local single operator','launcher_protocol':module.LAUNCHER_PROTOCOL,
             'checkout_id':module.CHECKOUT_ID,'build_id':module.BUILD_ID}
    assert module.current(value)
    for field in ('launcher_protocol','checkout_id','build_id'):
        changed = value | {field:'different'}
        assert not module.current(changed)
    assert not module.current({'status':'ok','mode':'local single operator'})


def test_same_checkout_listener_requires_command_and_cwd(monkeypatch):
    module = launcher()
    responses = iter([
        SimpleNamespace(stdout='42\n'),
        SimpleNamespace(stdout='python -m iti.cli run\n'),
        SimpleNamespace(stdout='p42\nn'+str(module.ROOT)+'\n'),
    ])
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: next(responses))
    assert module.same_checkout_listener() == 42

    responses = iter([
        SimpleNamespace(stdout='42\n'),
        SimpleNamespace(stdout='python -m iti.cli run\n'),
        SimpleNamespace(stdout='p42\nn/tmp/other-checkout\n'),
    ])
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: next(responses))
    assert module.same_checkout_listener() is None


def test_stale_unknown_listener_is_never_stopped(monkeypatch):
    module = launcher()
    monkeypatch.setattr(module, 'same_checkout_listener', lambda: None)
    called = []
    monkeypatch.setattr(module.os, 'kill', lambda *args: called.append(args))
    try:
        module.stop_stale_server()
    except SystemExit as error:
        assert 'cannot safely stop' in str(error)
    else:
        raise AssertionError('Unknown listener should stop launcher with guidance')
    assert not called


def test_stale_same_checkout_listener_gets_graceful_stop(monkeypatch):
    module = launcher()
    monkeypatch.setattr(module, 'same_checkout_listener', lambda: 42)
    monkeypatch.setattr(module, 'health', lambda: None)
    called = []
    monkeypatch.setattr(module.os, 'kill', lambda *args: called.append(args))
    module.stop_stale_server()
    assert called == [(42, module.signal.SIGTERM)]


def test_current_server_is_reused_without_starting_process(monkeypatch, capsys):
    module = launcher()
    value = {'launcher_protocol':module.LAUNCHER_PROTOCOL,
             'checkout_id':module.CHECKOUT_ID,'build_id':module.BUILD_ID}
    monkeypatch.setattr(module, 'health', lambda: value)
    monkeypatch.setattr(module.sys, 'argv', ['desktop-launcher.py', '--no-browser'])
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('server restarted')))
    module.main()
    assert capsys.readouterr().out.strip() == module.URL
