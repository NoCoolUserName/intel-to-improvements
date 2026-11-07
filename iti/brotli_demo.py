"""Explicit, atomic, offline Brotli exposure governance teaching case."""
import json
import shutil
import tempfile
from datetime import timedelta

from . import analysis, appsec, application_findings as findings, defenses, ingestion, ledger, pipeline, profiles
from . import vulnerabilities as vi
from .models import (CustomerProfile, EnvironmentProfile, Extraction, ReportedBehavior,
                     EntityRelationship, ImprovementAction, TestRun, EvidenceAttachment)
from .services import Service
from .store import ROOT, Store, digest, now, uid

VERSION = 'brotli-cve-2026-111497-v1'
CUSTOMER = 'fictional-harborlight-brotli'
ENVIRONMENT = 'brotli-estate'
CVE = 'CVE-2026-111497'
FIXTURES = ROOT / 'fixtures/brotli'
DOSSIER_SHA256 = '45b98ae6a0e2a8b92074f6dd39f1cb6cf59a823c182cb5df048f36a2c1af4157'
SOURCES_SHA256 = '66771c568f5e353d00cdc4f7cf7040353b051506bd7ba1519465cc4b269655df'
FILES = {'dossier.md', 'sources.json', 'inventory.json', 'artifact-evidence.json', 'events.json', 'findings.sarif.json',
         'initial-pipeline.yml', 'initial-run.json', 'revised-pipeline.yml', 'revised-run.json'}
STOPS = [
    ('Add Intelligence', 'What do we know? Inspect dated source facts, analyst hypotheses and fictional observations.'),
    ('Case overview', 'Which conditional attack paths have cited spans? Review the two-branch hypothetical flow.'),
    ('Vulnerability Intelligence', 'Where does the decoder matter? Compare six distinct asset decisions and reasons.'),
    ('Application Findings', 'Who owns the package and evidence gates? Review authored SARIF, triage and retests.'),
    ('Hunts', 'Could prior activity be investigated? Check inbound, outbound and process telemetry separately.'),
    ('Purple team', 'What benign validation is approved? Inspect scoped plans, Attack Flow and D3FEND suggestions.'),
    ('Improvement Actions', 'What blocks the fix? Follow the advisor package rebuild and evidence commitments.'),
    ('Pipeline Assurance', 'Why is green insufficient? Compare skipped and reported successful runtime checks.'),
    ('Exposure Overview', 'What can leadership report? Inspect contributing records and qualified outcomes.'),
    ('Coverage', 'Which telemetry and test gaps remain? Keep candidate rules distinct from deployed detection.'),
    ('Evaluation', 'Which bounded integrity checks ran? Distinguish workflow quality from estate security.'),
    ('Intelligence exports', 'Which source and synthetic labels survive export? Download the package and scenario manifest.'),
    ('Customer profiles', 'Which fictional services, consequences, owners and controls define the scope.'),
]


def load(service):
    """Stage via existing services, then publish records in one transaction."""
    store = service.store
    with store.lock(VERSION):
        prior = store.maybe('working_case_demo', VERSION)
        if prior:
            return prior
        if store.maybe('customer', CUSTOMER):
            raise ValueError('Reserved Brotli demo customer already exists without a completed marker; refusing collision')
        with tempfile.TemporaryDirectory(prefix='brotli-demo-') as directory:
            staged = Store(directory)
            with store.connect() as source, staged.connect() as target:
                target.executemany('INSERT INTO identities VALUES(?,?)', source.execute('SELECT * FROM identities').fetchall())
            builder = Service.__new__(Service)
            builder.store = staged
            result = build(builder)
            for blob in (staged.root / 'blobs').iterdir():
                if store.blob(blob.read_bytes()) != blob.name:
                    raise ValueError('Demo blob integrity mismatch')
            for artifact in (staged.root / 'artifacts').iterdir():
                destination = store.root / 'artifacts' / artifact.name
                if destination.exists():
                    if {p.name: digest(p.read_bytes()) for p in destination.iterdir()} != {p.name: digest(p.read_bytes()) for p in artifact.iterdir()}:
                        raise ValueError('Existing demo artifact collision')
                else:
                    shutil.copytree(artifact, destination)
            with staged.connect() as source, store.connect() as target:
                target.execute('BEGIN IMMEDIATE')
                if target.execute("SELECT 1 FROM records WHERE kind='customer' AND id=?", (CUSTOMER,)).fetchone():
                    raise ValueError('Demo customer created concurrently; no records replaced')
                target.executemany('INSERT INTO records VALUES(?,?,?,?)', source.execute('SELECT * FROM records').fetchall())
                target.executemany('INSERT OR IGNORE INTO identities VALUES(?,?)', source.execute('SELECT * FROM identities').fetchall())
                target.executemany('INSERT INTO activity(at,kind,scope,data) VALUES(?,?,?,?)', source.execute('SELECT at,kind,scope,data FROM activity ORDER BY seq').fetchall())
            return result


def build(service):
    store = service.store
    if digest((FIXTURES / 'dossier.md').read_bytes()) != DOSSIER_SHA256 or digest((FIXTURES / 'sources.json').read_bytes()) != SOURCES_SHA256:
        raise ValueError('Brotli curated replay requires exact versioned dossier and source manifest bytes')
    profiles.save(store, CustomerProfile(id=CUSTOMER, name='Harborlight Capital — fictional Brotli demo',
        sector='financial-services', subsector='Synthetic financial-services application estate', allow_live_processing=False,
        priorities=['Client document confidentiality', 'Advisor package availability', 'Evidence-led remediation'],
        intelligence_requirements=['Brotli decoder applicability', 'Inbound and outbound decoding paths', 'Prior-compromise investigation'],
        environments=[EnvironmentProfile(id=ENVIRONMENT, name='Financial-services application estate — synthetic',
            platforms=['linux'], technologies=['Node.js', '.NET', 'Brotli', 'GitHub Actions'],
            exposed_services=['client-api.example.invalid'],
            important_assets=['client-api', 'research-fetcher', 'advisor-package', 'reporting-service', 'vendor-analytics-agent', 'patched-reference'],
            telemetry={'proxy': ['request_id', 'host', 'route', 'content_encoding', 'status'],
                       'application': ['request_id', 'decoder_error', 'runtime_version'],
                       'response': ['destination', 'content_encoding', 'status'],
                       'process_creation': ['host', 'pid', 'process_start', 'boot_id', 'image'],
                       'network': ['host', 'destination', 'bytes']},
            retention_days=14,
            controls=[{'name': 'Inbound Brotli request filter', 'status': 'Synthetic route-limited claim; outbound path uncovered', 'version': 'demo-policy-1'},
                      {'name': 'Runtime/package upgrade', 'status': 'Engineering-owned; advisor bundle rebuild blocked', 'version': 'demo-release-1'},
                      {'name': 'Response and process telemetry', 'status': 'Declared fields; retention and collection unverified', 'version': 'demo-telemetry-1'}],
            notes='All organization records and outcomes are synthetic; no real financial institution is represented.')]))
    ctx = profiles.context(store, CUSTOMER, ENVIRONMENT)
    evidence_manifest = json.loads((FIXTURES / 'sources.json').read_text())
    sources = []
    for item in evidence_manifest['sources']:
        sources.append(item | ({'excerpt_sha256': digest(item['excerpt'].encode('utf-8'))} if 'excerpt' in item else {}))
    source = ingestion.ingest(store, (FIXTURES / 'dossier.md').read_bytes(), 'brotli-dossier.md',
        'authored-demo:brotli', CUSTOMER,
        extra_gaps=['Attributed derivative, not original publisher bytes; individual excerpt hashes cover stored excerpts or paraphrases only.',
                    'Direct CISA feed returned 403 and NVD page text was unavailable; no direct KEV, EPSS or NVD score snapshot.',
                    'All organization observations, investigation signals, pipeline results and retests are authored synthetic replay.'],
        metadata={'title': 'Brotli exposure response — from intelligence to verified outcomes · synthetic',
                  'publisher': 'Developer-curated teaching dossier with dated publisher references',
                  'fixture': True, 'synthetic': True, 'synthetic_scenario': True,
                  'references': sources, 'retrieval': {k:evidence_manifest[k] for k in ('retrieved_at', 'representation')}})
    def refs(anchor):
        matches = [span.id for span in source.spans if anchor in span.text]
        if len(matches) != 1:
            raise ValueError('Brotli dossier anchor must identify one span: ' + anchor)
        return matches
    specs = [
        ('inbound', 'Synthetic inbound hypothesis:', 'T1190', ['proxy', 'application']),
        ('outbound', 'Synthetic outbound hypothesis:', None, ['response', 'application']),
        ('decoder', 'Synthetic decoder hypothesis:', None, ['application']),
        ('process', 'Synthetic process hypothesis:', 'T1059.004', ['process_creation']),
    ]
    behaviors = [ReportedBehavior(id=uid('behavior', source.revision_id, key), key='brotli_' + key,
        text=next(s.text for s in source.spans if anchor in s.text), evidence=refs(anchor), kind='analyst_inference',
        qualifier='Hypothetical authored path; no customer compromise, exploitation or operational test observed',
        confidence_rationale='Bound to an exact dossier span; application-path assumption needs engineering validation',
        platform='linux', technique_id=technique,
        technique_name=analysis.resolve_attack(technique)['name'] if technique else None,
        mapping_basis='analyst_proposed' if technique else 'none', technology=['Brotli'], telemetry=telemetry,
        sequence=i + 1, review_required=True)
        for i, (key, anchor, technique, telemetry) in enumerate(specs)]
    relations = [EntityRelationship(id=uid('relationship', source.revision_id, left.id, right.id),
        text='Authored path ordering only; no observed intrusion or causation', evidence=refs('Synthetic ordering:'),
        kind='proposed', qualifier='Hypothetical branch', confidence_rationale='Explicit authored scenario ordering',
        source_ref=left.id, target_ref=right.id, relationship='precedes')
        for left, right in [(behaviors[0], behaviors[2]), (behaviors[1], behaviors[2]), (behaviors[2], behaviors[3])]]
    extraction = Extraction(id=uid('extraction', VERSION, source.content_hash), source_revision=source.revision_id,
        mode='analyst-curated', provider='Versioned exact-content Brotli demo analysis',
        behaviors=behaviors, relationships=relations,
        review_status='Developer-curated synthetic exercise; operator review required', warnings=source.gaps)
    store.put('customer_receipt', uid('receipt', CUSTOMER, source.id), {'at': source.retrieved_at}, immutable=True)
    analysis.validate_evidence(extraction, source)
    store.put('extraction', extraction.id, extraction.model_dump(), immutable=True)
    assessment = service.assess(source, extraction, ctx)
    package = service.generate(assessment['id'], CUSTOMER)
    suggestions = defenses.suggestions(store, assessment)
    candidate = suggestions['behaviors'][behaviors[0].id]['candidates']
    defense_action = None
    if candidate:
        choice = candidate[0]
        defense_action = ledger.improve(store, assessment, ImprovementAction(behavior_id=behaviors[0].id,
            owner='Fictional detection engineering', priority='high',
            rationale='Review a catalog-derived defense for the inbound path; patching remains separate',
            proposed_change=choice['prefill']['proposed_change'], retest=choice['prefill']['retest']),
            {'snapshot_id': suggestions['snapshot_id'], 'candidate_id': choice['id']})['id']
    vuln = seed_vulnerabilities(service, ctx.model_dump(), source, refs)
    app = seed_appsec(store)
    pipe = seed_pipeline(store)
    relations_manifest = {
        'source_revision': source.revision_id, 'extraction_id': extraction.id, 'assessment_id': assessment['id'],
        'package_id': package['id'], 'asset_to_exposure': vuln['exposures'],
        'asset_to_decision': vuln['decisions'], 'asset_to_vulnerability_action': vuln['actions'],
        'asset_to_vulnerability_tests': vuln['tests'], 'rule_to_finding': app['findings'],
        'rule_to_appsec_action': app['actions'], 'rule_to_appsec_tests': app['tests'],
        'pipeline_snapshot_ids': pipe, 'defense_action_id': defense_action,
        'relationship_limits': [
            'SARIF findings and CVE exposures share authored asset labels; no native cross-domain foreign key or automatic deduplication exists.',
            'Pipeline snapshots are explicitly listed here as supporting context; they never become exposure findings or close actions.',
            'The CVE advisor action verifies deployed identity; the AppSec advisor action owns rebuild/redeploy. Evidence overlaps but commitments differ.']}
    result = {'id': VERSION, 'customer_id': CUSTOMER, 'environment_id': ENVIRONMENT,
              'assessment_id': assessment['id'], 'package_id': package['id'], 'cve': CVE,
              'sources': sources, 'source_retrieval': evidence_manifest['retrieved_at'],
              'relations': relations_manifest, 'stops': [{'workspace': w, 'task': task} for w, task in STOPS],
              'checks': {'attack_flow': package['artifacts']['validation']['attack_flow'],
                         'hypothetical_actions': len(behaviors), 'hypothetical_edges': len(relations),
                         'six_assets': len(vuln['exposures']) == 6, 'appsec_findings': len(app['findings']),
                         'pipeline_snapshots': len(pipe), 'operational_tests_executed': False},
              'label': 'Fictional organization and synthetic replay; source facts and reported exploitation are attributed and dated.'}
    store.put('working_case_demo', VERSION, result, immutable=True)
    return result


def seed_vulnerabilities(service, ctx, source, refs):
    store = service.store
    vi.sync_sources(service, ctx)
    vi.assert_source(store, ctx, {'cve': CVE, 'source_revision': source.revision_id,
        'evidence': refs('Datadog Security Labs reported'), 'classification': 'observed exploitation',
        'explanation': 'Datadog reported confirmed in-the-wild exploitation as of 29 October 2026; underlying cases were not independently retrieved.',
        'confidence_qualifier': 'First-party technical research statement; no Harborlight compromise, count or actor inferred. Direct CISA feed unavailable.',
        'review_status': 'reviewed', 'reviewer': 'Fictional source-evidence reviewer',
        'relevance_assessment': 'Asset-specific decoder use and business consequence drive fictional customer priority.'})
    inventory_raw = (FIXTURES / 'inventory.json').read_bytes()
    inventory_sha = store.blob(inventory_raw)
    assets = json.loads(inventory_raw)['assets']
    exposures = {}
    for asset in assets:
        row = vi.observe(store, ctx, {'asset_id': asset['asset_id'], 'cve': CVE, 'product': asset['product'],
            'observed_version': asset['observed_version'], 'finding_id': 'SYNTHETIC-' + asset['asset_id'],
            'owner': asset['owner'], 'observed_at': now(), 'evidence_reference': 'blob:' + inventory_sha + '#' + asset['asset_id'],
            'evidence_kind': 'synthetic fixture', 'exposure': asset['exposure'], 'reachability': asset['reachability'],
            'reachability_evidence': asset['reachability_evidence'], 'criticality': asset['criticality'],
            'consequence': asset['consequence'], 'applicability': asset['applicability'],
            'applicability_reason': asset['package_provenance'] + '; ' + asset['confidence'] + '; missing: ' + asset['missing'],
            'assessment_basis': 'version evidence' if asset['asset_id'] not in ('vendor-analytics-agent', 'reporting-service') else 'analyst judgment',
            'control_claim': 'Synthetic inbound filter covers a named route only; outbound and embedded runtime require separate checks'})
        exposures[asset['asset_id']] = row['id']
    workspace = vi.workspace(service, CUSTOMER, ENVIRONMENT)
    decisions, actions, tests = {}, {}, {}
    plans = {
        'client-api': ('Replace affected Node.js runtime, rebuild the client API image, test compatibility and deploy/restart through engineering change control.', 'Fictional client API engineering'),
        'research-fetcher': ('Patch the bundled Node.js decoder and rebuild/deploy the fetcher; separately validate outbound response handling and any scoped egress mitigation.', 'Fictional research platform engineering'),
        'advisor-package': ('Establish running self-contained bundle identity, reject host-only patch claim and require the separately owned AppSec rebuild/redeploy action.', 'Fictional advisor application engineering'),
        'reporting-service': ('Plan vendor-fixed runtime upgrade; recheck the bounded no-untrusted-input judgment when routes or dependencies change.', 'Fictional reporting engineering'),
        'vendor-analytics-agent': ('Obtain vendor advisory/SBOM, package build and decoder path; determine applicability urgently before selecting a fix.', 'Fictional vendor-management engineering'),
    }
    for item in workspace['items']:
        if item['cve'] != CVE:
            continue
        for decision in item['decisions']:
            asset = decision.get('asset')
            if not asset:
                continue
            name = asset['asset_id']
            decisions[name] = decision['id']
            vi.review(store, decision['id'], CUSTOMER, ENVIRONMENT, {'disposition': 'accept',
                'reviewer': 'Fictional exposure-management reviewer',
                'reason': 'Review the source-qualified policy result against synthetic asset applicability and consequence; no operational finding asserted.'})
            if name not in plans:
                continue
            change, owner = plans[name]
            subject = vi.subject(store, decision['id'], CUSTOMER, ENVIRONMENT)
            action = ledger.improve(store, subject, ImprovementAction(vulnerability_assessment_id=decision['id'],
                owner=owner, priority='critical' if name == 'client-api' else 'high',
                rationale='Accountable local commitment for ' + name + '; permanent patch and investigation remain separate',
                proposed_change=change, retest='Preserve exact installed/running artifact and decoder configuration; compare source-supported branch fix, benign path and retained history.',
                remediation={'review_date': (appsec.dt(now()) + timedelta(days=2)).date().isoformat(),
                    'residual_uncertainty': 'Synthetic inventory and route review only; owner evidence, compatibility, deployment and historical telemetry remain required',
                    'permanent_fix': 'Supported vendor-fixed runtime/package in the running engineering-owned artifact',
                    'source_references': [source.origin, 'https://nodejs.org/en/blog/vulnerability/october-2026-security-releases',
                                          'https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9'],
                    'blocker_owner': owner, 'blocker_required_evidence': asset['applicability_reason'],
                    'next_action': change, 'dependency_note': 'Inventory → patch build → compatibility → deploy/restart → running artifact → scoped retest; historical investigation separate'}))
            actions[name] = action['id']
            tests[name] = []
            if name == 'advisor-package':
                tests[name].append(ledger.record_test(store, subject, TestRun(vulnerability_assessment_id=decision['id'],
                    improvement_id=action['id'], environment_version=ctx['environment_version'], control_id='host-runtime-claim',
                    control_version='demo-host-8.0.33', procedure='Read owner statement that host/shared runtime was updated',
                    expected='Self-contained application bundle must be rebuilt and deployed', actual='Owner attested host update only',
                    executed_at=now(), method='analyst attestation', result='inconclusive', dimension='remediation',
                    scope='Synthetic advisor-package host only', variant='Host claim', evidence=[EvidenceAttachment(
                        id='host-attestation', reference='synthetic:host-attestation', description='Authored owner statement', kind='analyst attestation')]))['id'])
            if name in ('advisor-package', 'client-api'):
                raw = (FIXTURES / 'artifact-evidence.json').read_bytes()
                evidence = vi.capture_evidence(store, ctx, name + '-artifact.json', raw, 'synthetic fixture replay')
                passed = name == 'client-api'
                tests[name].append(ledger.record_test(store, subject, TestRun(vulnerability_assessment_id=decision['id'],
                    improvement_id=action['id'], environment_version=ctx['environment_version'],
                    control_id='synthetic-artifact-review', control_version=VERSION,
                    procedure='Review authored version and deployment sample; no system was patched or scanned',
                    expected='Runtime and deployed package must both match supported fix for this branch',
                    actual='Authored comparison illustrates a fixed candidate build only' if passed else 'Host 8.0.33, deployed self-contained bundle 8.0.32',
                    executed_at=now(), method='version/configuration evidence', result='passed' if passed else 'failed',
                    dimension='remediation', scope='Synthetic fixture review only', variant='Artifact identity',
                    measurement={'asset_id': name, 'observed_value': '24.22.1 synthetic candidate; baseline still 24.22.0' if passed else 'bundle 8.0.32',
                                 'acceptance_basis': 'Authored synthetic comparison; never operational verification'},
                    evidence=[EvidenceAttachment(id=evidence['id'], reference=evidence['reference'], sha256=evidence['sha256'],
                        description='Authored inventory comparison', kind='synthetic fixture replay')]))['id'])
    return {'exposures': exposures, 'decisions': decisions, 'actions': actions, 'tests': tests}


def seed_appsec(store):
    raw = (FIXTURES / 'findings.sarif.json').read_bytes()
    preview = findings.preview(store, CUSTOMER, ENVIRONMENT, raw, {'application': 'Harborlight Brotli application estate · synthetic',
        'repository': 'synthetic/harborlight-brotli', 'branch': 'main', 'commit': 'a' * 40, 'synthetic': True})
    findings.confirm(store, preview['id'], CUSTOMER, ENVIRONMENT)
    ids, actions, tests = {}, {}, {}
    for f in preview['findings']:
        rule = f['rule_id']
        ids[rule] = f['id']
        with appsec.transaction(store) as tx:
            ctx = profiles.context(tx, CUSTOMER, ENVIRONMENT).model_dump()
            review = appsec.review(tx, f, ctx, {'reviewer': 'Fictional AppSec reviewer', 'disposition': appsec.APPLICABLE,
                'reason': 'Authored repository/packaging observation; no scanner execution or memory-safety detection claimed',
                'evidence_ids': [f['source_id']]})
            if rule == 'demo/outbound-control-scope':
                request = appsec.request_exception(tx, f, ctx, {'requester': 'Fictional research engineering',
                    'justification': 'Two-day compatibility window while the outbound decoder path and supported runtime update are reviewed',
                    'residual_risk': 'Externally supplied compressed response can still reach affected decoder',
                    'compensating_controls': 'Restrict approved feed destinations and monitor decoder/resource anomalies; effectiveness unverified',
                    'review_by': (appsec.dt(now()) + timedelta(days=2)).isoformat(), 'evidence_ids': [f['source_id']]})
                appsec.decide_exception(tx, f, ctx, request['id'], {'authority': 'Fictional risk-acceptance officer',
                    'decision': 'approved', 'reason': 'Bounded synthetic acceptance with permanent runtime fix and telemetry review; not remediation'})
                continue
            subject = appsec.subject(tx, f, appsec.versions(ctx))
            subject['appsec_command'] = {'review_id': review['id'], 'actor': 'Fictional engineering owner',
                'reason': 'Authored evidence-gate or package-change commitment', 'expected_updated_at': None}
            change = ('Require exact running Node.js/image version evidence before client API release' if rule == 'demo/brotli-runtime-evidence'
                      else 'Rebuild the self-contained .NET application with supported patched runtime; test, deploy and verify bundle identity')
            action = ledger.improve(tx, subject, ImprovementAction(owner='Fictional release engineering' if 'runtime-evidence' in rule else 'Fictional advisor application engineering',
                priority='high', rationale='Complementary AppSec commitment; CVE action retains asset-level decision and verification',
                proposed_change=change, retest='Review authored artifact manifest and benign compatibility result against exact commit and implementation reference',
                remediation={'security_reviewer': 'Fictional AppSec reviewer', 'expected_result': 'Current artifact/version evidence'}))
            plan = action['remediation'] | {'implementation_ref': 'synthetic-change-' + rule.rsplit('/', 1)[-1],
                'implementation_claim': 'Owner reports change ready for evidence review; not independently verified',
                'target_date': (appsec.dt(now()) + timedelta(days=3)).date().isoformat()}
            subject['appsec_command']['expected_updated_at'] = action['updated_at']
            action = ledger.improve(tx, subject, ImprovementAction(**{k: action[k] for k in ImprovementAction.model_fields if k in action and k != 'origin'}
                | {'status': 'retest requested', 'remediation': plan}))
            actions[rule] = action['id']
            tests[rule] = []
            if rule == 'demo/self-contained-package':
                att = appsec.capture_evidence(tx, f, ctx, 'advisor-owner-claim.txt', b'SYNTHETIC: host runtime updated; bundle rebuild pending',
                    'analyst attestation', 'Fictional owner statement; cannot verify bundle')
                tests[rule].append(appsec.retest(tx, subject, {'action_id': action['id'], 'review_id': review['id'],
                    'implementation_ref': plan['implementation_ref'], 'finding_context_hash': appsec.context_hash(f),
                    'reviewer': 'Fictional evidence reviewer', 'judgment': 'Host update is insufficient for self-contained deployment',
                    'procedure': 'Read owner claim', 'expected': 'Rebuilt and deployed bundle', 'actual': 'Host updated only',
                    'executed_at': now(), 'result': 'inconclusive', 'method': 'analyst attestation',
                    'evidence_ids': [att['id']]} )['id'])
            evidence = appsec.capture_evidence(tx, f, ctx, rule.rsplit('/', 1)[-1] + '-review.json',
                (FIXTURES / 'artifact-evidence.json').read_bytes(), 'synthetic/lab evidence',
                'Authored artifact/configuration review; no live scanner or deployment')
            success = rule == 'demo/brotli-runtime-evidence'
            tests[rule].append(appsec.retest(tx, subject, {'action_id': action['id'], 'review_id': review['id'],
                'implementation_ref': plan['implementation_ref'], 'finding_context_hash': appsec.context_hash(f),
                'reviewer': 'Fictional evidence reviewer', 'judgment': 'Synthetic evidence only; operational verification unavailable',
                'procedure': 'Compare authored package manifest and exact release context',
                'expected': 'Running artifact matches supported branch fix',
                'actual': 'Authored candidate manifest passes local check only' if success else 'Deployed self-contained bundle remains 8.0.32',
                'executed_at': now(), 'result': 'passed' if success else 'failed',
                'method': 'version/configuration evidence', 'evidence_ids': [evidence['id']]} )['id'])
    return {'findings': ids, 'actions': actions, 'tests': tests}


def seed_pipeline(store):
    snapshots = []
    for prefix, commit in [('initial', 'a'), ('revised', 'b')]:
        preview = pipeline.preview(store, CUSTOMER, ENVIRONMENT,
            [('brotli.yml', (FIXTURES / (prefix + '-pipeline.yml')).read_bytes())],
            {'repository': 'synthetic/harborlight-brotli', 'ref': 'main', 'commit': commit * 40,
             'application': 'Harborlight Brotli application estate · synthetic', 'synthetic': True})
        snapshot = pipeline.confirm(store, preview['id'], CUSTOMER, ENVIRONMENT)
        execution = pipeline.preview_execution(store, CUSTOMER, ENVIRONMENT, snapshot['id'],
            (FIXTURES / (prefix + '-run.json')).read_bytes())
        pipeline.confirm(store, execution['id'], CUSTOMER, ENVIRONMENT)
        snapshots.append(snapshot['id'])
    return snapshots
