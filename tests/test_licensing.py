import json
import zipfile

from iti import detection
from iti.store import ROOT, digest


def test_new_export_revision_preserves_legacy_packages(service, assessed):
    from iti.store import uid
    legacy_id = uid('package', assessed['id'], 'packages-6-attack-flow-2')
    legacy = {'id': legacy_id, 'marker': 'preserve historical package'}
    service.store.put('package', legacy_id, legacy, immutable=True)
    package = service.generate(assessed['id'], 'fictional-bank')
    assert package['id'] != legacy_id
    assert service.store.get('package', legacy_id) == legacy
    assert 'THIRD_PARTY_LICENSES.txt' in package['artifacts']['names']


def test_match_messages_preserve_supplied_author():
    rule, _, _ = detection.catalog()[0]
    result = detection.fixture_test(rule['id'])
    for case in result['cases'].values():
        assert case['rule_author'] == rule['author']
        assert case['rule_id'] == str(rule['id'])
        assert case['rule_license'] == rule.get('license', 'Detection Rule License 1.1 (repository license)')


def test_export_carries_attribution_and_exact_license_texts(service, assessed):
    package = service.generate(assessed['id'], 'fictional-bank')
    root = service.store.root / 'artifacts' / package['id']
    assert package['candidates']
    with zipfile.ZipFile(root / 'package.zip') as archive:
        attribution = json.loads(archive.read('RULE_ATTRIBUTIONS.json'))
        for candidate in package['candidates']:
            retained = next(r for r in attribution['rules'] if r['id'] == candidate['id'] and r['behavior_id'] == candidate['behavior_id'])
            assert retained['author'] == candidate['author']
            assert retained['license'] == candidate['license']
            assert retained['source']['url'] == candidate['source']['url']
        for filename in ('hunt.json', 'purple-team.json'):
            assert json.loads(archive.read(filename))['rule_attributions'] == attribution['rules']
        hunt = archive.read('hunt.md').decode()
        for candidate in package['candidates']:
            if any(h['behavior_id'] == candidate['behavior_id'] for h in package['hunts']):
                assert candidate['author'] in hunt
                assert candidate['source']['url'] in hunt
        for filename in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
            assert archive.read(filename).decode() == (ROOT / filename).read_text()
        licenses = archive.read('THIRD_PARTY_LICENSES.txt').decode()
        for filename in ('catalogs/SIGMA_DRL_LICENSE', 'catalogs/ATTACK_LICENSE', 'catalogs/d3fend/D3FEND-LICENSE', 'integrations/attack-flow/LICENSE'):
            assert (ROOT / filename).read_text() in licenses
        assert package['artifacts']['manifest']['artifacts']['THIRD_PARTY_LICENSES.txt'] == digest(licenses)
    from fastapi.testclient import TestClient
    from iti.api import create_app
    with TestClient(create_app(service), base_url='http://127.0.0.1') as client:
        response = client.get(f'/api/artifacts/{package["id"]}/THIRD_PARTY_LICENSES.txt', params={'customer_id': 'fictional-bank', 'environment_id': 'windows-ad'})
        assert response.status_code == 200
        assert response.text == licenses
