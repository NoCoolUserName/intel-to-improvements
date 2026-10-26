"""Immutable, scoped SARIF batches using the existing SQLite records and blob store."""
import json
import secrets
from datetime import datetime, timezone, timedelta
from . import profiles
from .application_models import ApplicationContext, ApplicationFinding
from .application_sarif import parse, normalize
from .store import uid, digest, canonical, now


def in_scope(row, customer, environment):
    return row['context']['customer_id'] == customer and row['context']['environment_id'] == environment


def scoped(store, kind, id, customer, environment):
    profiles.context(store, customer, environment)
    row = store.get(kind, id)
    if not in_scope(row, customer, environment):
        raise KeyError('Not found in selected customer/environment')
    return row


def preview(store, customer, environment, raw, operator):
    context = profiles.context(store, customer, environment).model_dump()
    operator = ApplicationContext.model_validate(operator).model_dump()
    document = parse(raw)
    sha = digest(raw)
    rows, warnings = normalize(document, context, operator, sha)
    if len(canonical(context).encode()) * max(1, len(rows)) + len(canonical(rows).encode()) > 32 * 1024 * 1024:
        raise ValueError('Findings with frozen profile context exceed 32 MiB; split the report')
    batch_id = uid('app_batch', context, sha, operator, 'sarif-normalizer-1')
    source_id = uid('app_source', customer, environment, sha)
    timestamp = now()
    findings = [ApplicationFinding(**r, id=uid('app_finding', batch_id, r['run_index'], r['result_index']),
        batch_id=batch_id, source_id=source_id, source_sha256=sha, context=context,
        operator_context=operator, imported_at=timestamp).model_dump() for r in rows]
    # Validation is complete before any evidence/preview is persisted.
    store.blob(raw)
    row = {'id': 'app_preview_' + secrets.token_hex(24), 'batch_id': batch_id, 'source_id': source_id,
        'source_sha256': sha, 'context': context, 'operator_context': operator, 'findings': findings,
        'warnings': warnings, 'recorded_at': timestamp,
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        'runs': [{k: r[k] for k in ('automationDetails','invocations','versionControlProvenance','properties') if k in r} | {'index': i, 'scanner': {k: r['tool']['driver'][k] for k in ('name','version') if k in r['tool']['driver']}, 'results_present': 'results' in r} for i, r in enumerate(document['runs'])]}
    store.put('application_preview', row['id'], row, immutable=True)
    return row | {'already_imported': store.maybe('application_batch', batch_id) is not None}


def confirm(store, preview_id, customer, environment):
    preview_row = scoped(store, 'application_preview', preview_id, customer, environment)
    # BEGIN IMMEDIATE makes profile version comparison and all batch writes atomic.
    with store.connect() as connection:
        connection.execute('BEGIN IMMEDIATE')
        current = json.loads(connection.execute("SELECT data FROM records WHERE kind='customer' AND id=?", (customer,)).fetchone()[0])
        env = next((e for e in current['environments'] if e['id'] == environment), None)
        frozen = preview_row['context']
        if not env or current['version'] != frozen['customer_version'] or env['version'] != frozen['environment_version']:
            raise ValueError('Profile changed; preview SARIF again')
        if datetime.now(timezone.utc) > datetime.fromisoformat(preview_row['expires_at']):
            raise ValueError('Preview expired; preview SARIF again')
        prior = connection.execute("SELECT data FROM records WHERE kind='application_batch' AND id=?", (preview_row['batch_id'],)).fetchone()
        if prior:
            return json.loads(prior[0]) | {'duplicate': True}
        raw = (store.root / 'blobs' / preview_row['source_sha256']).read_bytes()
        if digest(raw) != preview_row['source_sha256']:
            raise ValueError('Stored SARIF evidence integrity check failed')
        timestamp = now()
        batch = {k: preview_row[k] for k in ('context','operator_context','source_id','source_sha256','warnings','runs')}
        batch.update(id=preview_row['batch_id'], imported_at=timestamp, normalizer='sarif-normalizer-1',
            finding_ids=[r['id'] for r in preview_row['findings']], scan_completeness='unknown')
        source = {'id': batch['source_id'], 'context': frozen, 'sha256': batch['source_sha256'],
            'reference': 'blob:' + batch['source_sha256'], 'byte_length': len(raw), 'recorded_at': timestamp}
        records = [('application_source', source), ('application_batch', batch)]
        records += [('application_finding', r | {'imported_at': timestamp}) for r in preview_row['findings']]
        for kind, row in records:
            connection.execute('INSERT OR IGNORE INTO records VALUES(?,?,?,?)', (kind, row['id'], canonical(row), timestamp))
        connection.execute('INSERT INTO activity(at,kind,scope,data) VALUES(?,?,?,?)',
            (timestamp, 'application_sarif_imported', customer + ':' + environment, canonical({'batch_id': batch['id'], 'count': len(batch['finding_ids'])})))
    return batch | {'duplicate': False}


def workspace(store, customer, environment):
    context = profiles.context(store, customer, environment).model_dump()
    return {'context': context,
        'findings': [r for r in store.all('application_finding') if in_scope(r, customer, environment)],
        'imports': [r for r in store.all('application_batch') if in_scope(r, customer, environment)]}
