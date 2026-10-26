"""One explicit, atomic, offline investment-firm teaching case across workspaces."""
import shutil
import tempfile
from datetime import timedelta

from . import analysis, appsec, application_findings as af, defenses, ingestion, ledger, pipeline, profiles
from . import vulnerabilities as vi
from .models import (CustomerProfile, EnvironmentProfile, Extraction, ReportedBehavior,
                     EntityRelationship, ImprovementAction, TestRun, EvidenceAttachment)
from .services import Service
from .store import ROOT, Store, digest, now, uid

CUSTOMER = 'fictional-harborlight'
ENVIRONMENT = 'php-estate'
VERSION = 'php2shell-1'
FIXTURES = ROOT / 'fixtures/php2shell'
CVES = ['CVE-2026-109618', 'CVE-2026-109619']
SOURCES = [
    {'title': 'PHP security advisory · 21 October 2026', 'url': 'https://www.php.net/archive/2026.php#2026-10-21-5'},
    {'title': 'AttackIQ assessment scope · 22 October 2026', 'url': 'https://www.attackiq.com/2026/10/22/php2shell/'},
    {'title': 'Unit 42 correction · 25 October 2026', 'url': 'https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/'},
]
STOPS = [
    ('Add Intelligence', 'Read the attributed dossier, dates and the retracted-report warning.'),
    ('Case overview', 'Inspect proposed behavior mappings and the explicitly synthetic ordering.'),
    ('Coverage', 'Compare declared telemetry, D3FEND suggestions and open control improvements.'),
    ('Hunts', 'Investigate request → worker → process → file → egress with bounded conclusions.'),
    ('Purple team', 'Review the AttackIQ probe plan and blocked / signature / no-signature interpretation exercise.'),
    ('Vulnerability Intelligence', 'Compare affected portal, uncertain research service and patched reporting host; inspect owners and mitigation evidence.'),
    ('Application Findings', 'Review synthetic runtime, origin-bypass and release-check findings, commitments and a bounded exception.'),
    ('Improvement Actions', 'Follow existing scoped commitments back to their case, finding or vulnerability evidence.'),
    ('Exposure Overview', 'Drill into open work and qualified synthetic results for this investment firm.'),
    ('Pipeline Assurance', 'Compare original and revised configuration, failed regression and skipped control reports.'),
    ('Intelligence exports', 'Download the case package, STIX/MISP and validated ATT&CK Flow with provenance.'),
    ('Evaluation', 'Inspect the demo checks below; global capability evaluation remains separately identified.'),
    ('Customer profiles', 'Inspect Harborlight’s synthetic business priorities, services, telemetry and control claims.'),
]


def load(service):
    """Stage first; publish records together. Reopening never resets operator edits."""
    store = service.store
    with store.lock(VERSION):
        previous = store.maybe('working_case_demo', VERSION)
        if previous:
            return previous
        if store.maybe('customer', CUSTOMER):
            raise ValueError('Harborlight demo scope already exists without a completed marker; refusing to overwrite it')
        with tempfile.TemporaryDirectory(prefix='php2shell-') as directory:
            staged = Store(directory)
            # Reuse existing export identities; do not change identities of other cases.
            with store.connect() as source, staged.connect() as target:
                target.executemany('INSERT INTO identities VALUES(?,?)', source.execute('SELECT * FROM identities').fetchall())
            # Avoid default-customer seeding inside this isolated publication set.
            builder = Service.__new__(Service)
            builder.store = staged
            result = build(builder)
            for blob in (staged.root / 'blobs').iterdir():
                if store.blob(blob.read_bytes()) != blob.name:
                    raise ValueError('Demo blob integrity check failed')
            for artifact in (staged.root / 'artifacts').iterdir():
                destination = store.root / 'artifacts' / artifact.name
                if destination.exists():
                    if {p.name: digest(p.read_bytes()) for p in destination.iterdir()} != {p.name: digest(p.read_bytes()) for p in artifact.iterdir()}:
                        raise ValueError('Existing demo artifacts differ; refusing to overwrite them')
                else:
                    shutil.copytree(artifact, destination)
            with staged.connect() as source, store.connect() as target:
                target.execute('BEGIN IMMEDIATE')
                if target.execute("SELECT 1 FROM records WHERE kind='customer' AND id=?", (CUSTOMER,)).fetchone():
                    raise ValueError('Demo customer was created concurrently; no records replaced')
                target.executemany('INSERT INTO records VALUES(?,?,?,?)', source.execute('SELECT * FROM records').fetchall())
                target.executemany('INSERT OR IGNORE INTO identities VALUES(?,?)', source.execute('SELECT * FROM identities').fetchall())
                target.executemany('INSERT INTO activity(at,kind,scope,data) VALUES(?,?,?,?)', source.execute('SELECT at,kind,scope,data FROM activity ORDER BY seq').fetchall())
            return result


def build(service):
    store = service.store
    profiles.save(store, CustomerProfile(id=CUSTOMER, name='Harborlight Capital · PHP2Shell fictional demo', sector='financial-services',
        subsector='Investment management · fictional', allow_live_processing=False,
        priorities=['Investor document confidentiality', 'Client portal availability', 'Investment reporting integrity'],
        intelligence_requirements=['PHP runtime exposure', 'WAF bypass and origin coverage', 'Evidence of prior compromise'],
        environments=[EnvironmentProfile(id=ENVIRONMENT, name='Client portal and research lab · synthetic', platforms=['linux'],
            technologies=['PHP', 'Apache', 'PHP-FPM', 'GitHub Actions'], exposed_services=['Client portal', 'Research uploads'],
            important_assets=['Investor documents · fictional', 'Investment statements · fictional'],
            telemetry={'proxy': ['request_id', 'host', 'route', 'action', 'status'], 'application': ['request_id', 'worker', 'error'],
                       'process_creation': ['host', 'pid', 'ppid', 'image', 'command_line'], 'file': ['host', 'path', 'sha256'],
                       'network': ['host', 'destination', 'bytes']},
            controls=[{'name': 'WAF', 'status': 'Synthetic public-route block; direct origin remains open', 'version': 'demo-policy-1'},
                      {'name': 'PHP runtime upgrade', 'status': 'Synthetic rollout pending; verify serving workers', 'version': 'demo-image-1'},
                      {'name': 'Egress restriction', 'status': 'Declared; effectiveness unknown', 'version': 'demo-egress-1'}],
            notes='All company assets and outcomes are synthetic. No real customer or operational evidence.')]))
    ctx = profiles.context(store, CUSTOMER, ENVIRONMENT)
    source = ingestion.ingest(store, (FIXTURES / 'dossier.md').read_bytes(), 'php2shell-dossier.md', 'authored-demo:php2shell', CUSTOMER,
        extra_gaps=['Limited source paraphrases, not original publisher bytes. Hypothetical stages are not a reported intrusion.',
                    'No live AttackIQ, scanner, SIEM, WAF, pipeline or model execution. KEV/EPSS require explicit fresh enrichment.'],
        metadata={'title': 'PHP2Shell → Harborlight Capital · synthetic working case', 'fixture': True, 'synthetic': True, 'synthetic_scenario': True,
                  'publisher': 'Developer-curated teaching dossier with linked primary sources', 'references': SOURCES,
                  'gaps': ['Limited source paraphrases, not original publisher bytes. Hypothetical stages are not a reported intrusion.',
                           'No live AttackIQ, scanner, SIEM, WAF, pipeline or model execution. KEV/EPSS require explicit fresh enrichment.']})
    def refs(anchor):
        matches = [s.id for s in source.spans if anchor in s.text]
        if len(matches) != 1:
            raise ValueError('Dossier anchor must identify one span: ' + anchor)
        return matches
    specs = [('request', 'Synthetic initial-access hypothesis:', 'T1190', ['proxy', 'application']),
             ('shell', 'Synthetic execution hypothesis:', 'T1059.004', ['process_creation']),
             ('script', 'Synthetic persistence hypothesis:', 'T1505.003', ['file', 'process_creation']),
             ('egress', 'Synthetic collection hypothesis:', 'T1041', ['network'])]
    behaviors = [ReportedBehavior(id=uid('behavior', source.revision_id, key), key='php2shell_' + key,
        text=next(s.text for s in source.spans if anchor in s.text), evidence=refs(anchor), kind='analyst_inference',
        qualifier='Authored hypothetical exercise; not observed exploitation or customer compromise',
        confidence_rationale='Mapping to an explicitly authored scenario, not an inferred real incident', platform='linux',
        technique_id=tid, technique_name=analysis.resolve_attack(tid)['name'], mapping_basis='analyst_proposed',
        technology=['PHP'], telemetry=telemetry, sequence=i + 1, review_required=True)
        for i, (key, anchor, tid, telemetry) in enumerate(specs)]
    relationships = [EntityRelationship(id=uid('relationship', source.revision_id, i), text='Authored scenario ordering only; no real intrusion asserted',
        evidence=refs('Synthetic ordering:'), kind='proposed', qualifier='Hypothetical ordering', confidence_rationale='Explicit dossier ordering',
        source_ref=left.id, target_ref=right.id, relationship='precedes') for i, (left, right) in enumerate(zip(behaviors, behaviors[1:]))]
    extraction = Extraction(id=uid('extraction', VERSION, source.content_hash), source_revision=source.revision_id,
        mode='analyst-curated', provider='Versioned PHP2Shell teaching fixture', behaviors=behaviors, relationships=relationships,
        review_status='Developer-curated synthetic exercise; not operator-approved', warnings=source.gaps)
    store.put('customer_receipt', uid('receipt', CUSTOMER, source.id), {'at': source.retrieved_at}, immutable=True)
    analysis.validate_evidence(extraction, source)
    store.put('extraction', extraction.id, extraction.model_dump(), immutable=True)
    assessment = service.assess(source, extraction, ctx)
    package = service.generate(assessment['id'], CUSTOMER)
    suggestions = defenses.suggestions(store, assessment)
    for b in behaviors:
        candidates = suggestions['behaviors'][b.id]['candidates']
        if candidates:
            candidate = candidates[0]
            ledger.improve(store, assessment, ImprovementAction(behavior_id=b.id, owner='Synthetic SOC / platform control owner', priority='high',
                rationale='Assess a catalog-derived countermeasure against the authored investment-portal scenario',
                proposed_change=candidate['prefill']['proposed_change'], retest=candidate['prefill']['retest']),
                {'snapshot_id': suggestions['snapshot_id'], 'candidate_id': candidate['id']})
    raw = (FIXTURES / 'waf-results.json').read_bytes()
    store.blob(raw)
    ledger.record_test(store, assessment, TestRun(behavior_id=behaviors[0].id, environment_version=1,
        control_id='synthetic-request-correlation', control_version=VERSION, procedure='Read authored request interpretation samples; no traffic generated',
        expected='Blocked, signature and absent-signature branches remain distinct', actual='Authored samples illustrate all three branches',
        executed_at=now(), method='analyst attestation', result='inconclusive', dimension='detection', scope='Authored fixtures only',
        evidence=[EvidenceAttachment(id='php2shell-authored-samples', reference='blob:' + digest(raw), sha256=digest(raw),
            description='Authored results, not an executed probe or actual matcher', kind='synthetic fixture replay')], variant='PHP2Shell result interpretation'))
    vulnerability_ids = seed_vulnerabilities(service, ctx.model_dump(), source, refs)
    findings = seed_appsec(store)
    snapshots = seed_pipeline(store)
    checks = {'attack_flow': package['artifacts']['validation']['attack_flow'], 'hypothetical_behaviors': len(behaviors),
              'explicit_scenario_edges': len(relationships), 'd3fend_candidates': sum(len(r['candidates']) for r in suggestions['behaviors'].values()),
              'synthetic_appsec_findings': len(findings), 'pipeline_snapshots': len(snapshots), 'operational_tests_executed': False}
    result = {'id': VERSION, 'customer_id': CUSTOMER, 'environment_id': ENVIRONMENT, 'assessment_id': assessment['id'],
              'package_id': package['id'], 'vulnerability_decisions': vulnerability_ids, 'finding_ids': findings,
              'pipeline_snapshot_ids': snapshots, 'sources': SOURCES, 'stops': [{'workspace': w, 'task': t} for w, t in STOPS],
              'checks': checks, 'label': 'All firm data and results are synthetic; source reporting is dated and attributed.'}
    store.put('working_case_demo', VERSION, result, immutable=True)
    return result


def seed_vulnerabilities(service, ctx, source, refs):
    store = service.store
    vi.sync_sources(service, ctx)
    for cve in CVES:
        vi.assert_source(store, ctx, {'cve': cve, 'source_revision': source.revision_id, 'evidence': refs('The PHP project identifies'),
            'classification': 'public exploit availability only', 'explanation': 'The linked PHP advisory documents demonstrated exploitability; no real Harborlight intrusion is asserted.',
            'confidence_qualifier': 'Dated vendor advisory; demonstration and source correction are not evidence of customer compromise',
            'review_status': 'reviewed', 'reviewer': 'Synthetic teaching-case source reviewer', 'relevance_assessment': 'Fictional firm declares PHP web services'})
        for asset, version, applicability, reachability, reason in [
            ('client-portal-01', '8.4.26 · authored inventory', 'confirmed affected', 'confirmed', 'Authored affected upstream runtime, no backport assumed'),
            ('research-upload-01', 'vendor-backport status unknown', 'needs verification', 'unknown', 'Package version and direct-origin route need owner evidence'),
            ('reporting-01', '8.4.27 · authored serving-worker evidence', 'assessed not affected', 'not reachable', 'Authored patched worker plus restricted route; no live verification')]:
            vi.observe(store, ctx, {'asset_id': asset, 'cve': cve, 'product': 'PHP web runtime', 'observed_version': version,
                'finding_id': 'SYNTHETIC-' + asset + '-' + cve, 'owner': 'Synthetic investment platform engineering',
                'observed_at': now(), 'evidence_reference': 'synthetic:php2shell-inventory', 'evidence_kind': 'synthetic fixture',
                'exposure': 'external' if asset != 'reporting-01' else 'internal', 'reachability': reachability,
                'reachability_evidence': 'Authored route map; direct origin must be checked independently', 'criticality': 'critical',
                'consequence': 'Investor document confidentiality and client reporting availability', 'applicability': applicability,
                'applicability_reason': reason, 'assessment_basis': 'analyst judgment',
                'control_claim': 'Synthetic WAF sample blocked; patch and alternate-path coverage remain separately assessed'})
    decisions = []
    for item in vi.workspace(service, CUSTOMER, ENVIRONMENT)['items']:
        for decision in item['decisions']:
            if decision['asset']['asset_id'] != 'client-portal-01':
                continue
            vi.review(store, decision['id'], CUSTOMER, ENVIRONMENT, {'disposition': 'accept', 'reviewer': 'Synthetic vulnerability lead',
                'reason': 'Authored exposed portal has sensitive documents; prioritize permanent patch and bounded temporary controls'})
            subject = vi.subject(store, decision['id'], CUSTOMER, ENVIRONMENT)
            action = ledger.improve(store, subject, ImprovementAction(vulnerability_assessment_id=decision['id'], owner='Synthetic platform engineering', priority='critical',
                rationale='Patch affected PHP workers; contain exposure during a compatibility-tested rollout',
                proposed_change='Upgrade serving PHP to vendor-fixed build; restart all workers. Restrict origin to WAF, validate route coverage and request limits.',
                retest='Inspect immutable package/worker version evidence and authorized exact-route control tests; include benign uploads and alternate route checks.',
                remediation={'review_date': (appsec.dt(now()) + timedelta(days=2)).date().isoformat(),
                    'residual_uncertainty': 'A blocked probe covers one route and variant only; PHP configuration mitigations are incomplete',
                    'permanent_fix': 'Vendor-fixed PHP runtime and restarted serving workers', 'source_references': [SOURCES[0]['url'], SOURCES[1]['url']]}))
            raw = (FIXTURES / 'waf-results.json').read_bytes()
            evidence = vi.capture_evidence(store, ctx, 'php2shell-authored-waf-results.json', raw, 'synthetic fixture replay')
            ledger.record_test(store, subject, TestRun(vulnerability_assessment_id=decision['id'], improvement_id=action['id'], environment_version=1,
                control_id='synthetic-waf-route-policy', control_version='demo-policy-1', procedure='Review authored exact-route block sample and bypass limitation',
                expected='One blocked route sample; residual origin risk remains', actual='Authored sample blocked, alternate origin route unresolved',
                executed_at=now(), method='version/configuration evidence', result='passed', dimension='mitigation', scope='Synthetic public-WAF route only',
                residual_risk='Direct-origin bypass and untested variants remain; no complete protection established', permanent_fix='Patch and restart PHP workers',
                evidence=[EvidenceAttachment(id=evidence['id'], reference=evidence['reference'], sha256=evidence['sha256'],
                    description='Authored control-result fixture', kind='synthetic fixture replay')], variant='Specific request pattern only',
                measurement={'asset_id': 'client-portal-01', 'observed_value': 'Synthetic WAF block sample', 'acceptance_basis': 'Authored sample only, no operational verification'}))
            decisions.append(decision['id'])
    return decisions


def seed_appsec(store):
    raw = (FIXTURES / 'findings.sarif.json').read_bytes()
    preview = af.preview(store, CUSTOMER, ENVIRONMENT, raw, {'application': 'Harborlight client portal · synthetic',
        'repository': 'synthetic/harborlight-portal', 'commit': 'a' * 40, 'synthetic': True})
    af.confirm(store, preview['id'], CUSTOMER, ENVIRONMENT)
    for f in preview['findings']:
        with appsec.transaction(store) as tx:
            ctx = profiles.context(tx, CUSTOMER, ENVIRONMENT).model_dump()
            review = appsec.review(tx, f, ctx, {'reviewer': 'Synthetic AppSec reviewer', 'disposition': appsec.APPLICABLE,
                'reason': 'Authored deployment/configuration review; no actual scanner or engine-bug detection', 'evidence_ids': [f['source_id']]})
            if f['rule_id'] == 'demo/research-compatibility':
                request = appsec.request_exception(tx, f, ctx, {'requester': 'Synthetic research engineering',
                    'justification': 'Authored two-day compatibility window for the research upload service',
                    'residual_risk': 'Vulnerable runtime may remain; WAF path coverage is incomplete',
                    'compensating_controls': 'Restrict research uploads to approved network, enforce origin allowlist and review WAF logs; effectiveness unverified',
                    'review_by': (appsec.dt(now()) + timedelta(days=2)).isoformat(), 'evidence_ids': [f['source_id']]})
                appsec.decide_exception(tx, f, ctx, request['id'], {'authority': 'Synthetic investment risk officer', 'decision': 'approved',
                    'reason': 'Authored bounded exception; does not verify remediation'})
                continue
            subject = appsec.subject(tx, f, appsec.versions(ctx))
            subject['appsec_command'] = {'review_id': review['id'], 'actor': 'Synthetic engineering owner',
                'reason': 'Authored PHP2Shell release commitment', 'expected_updated_at': None}
            ledger.improve(tx, subject, ImprovementAction(owner='Synthetic platform / release engineering', priority='high',
                rationale='Remove the reviewed configuration gap from the investment portal release',
                proposed_change='Patch the serving image, restrict origin access and require a runtime evidence check before release',
                retest='Preserve package and worker versions, route checks, authorized probe results and benign upload regression evidence',
                remediation={'security_reviewer': 'Synthetic AppSec reviewer', 'expected_result': 'Patched serving runtime and bounded route coverage evidence'}))
    return [f['id'] for f in preview['findings']]


def seed_pipeline(store):
    snapshots = []
    for prefix in ('initial', 'revised'):
        preview = pipeline.preview(store, CUSTOMER, ENVIRONMENT, [('portal.yml', (FIXTURES / (prefix + '-pipeline.yml')).read_bytes())],
            {'repository': 'synthetic/harborlight-portal', 'ref': 'main', 'commit': ('a' if prefix == 'initial' else 'b') * 40,
             'application': 'Harborlight client portal · synthetic', 'synthetic': True})
        snapshot = pipeline.confirm(store, preview['id'], CUSTOMER, ENVIRONMENT)
        execution = pipeline.preview_execution(store, CUSTOMER, ENVIRONMENT, snapshot['id'], (FIXTURES / (prefix + '-run.json')).read_bytes())
        pipeline.confirm(store, execution['id'], CUSTOMER, ENVIRONMENT)
        snapshots.append(snapshot['id'])
    return snapshots
