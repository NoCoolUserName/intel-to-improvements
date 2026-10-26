"""Bounded, read-only leadership projection over authoritative local records."""
import json
from collections import defaultdict
from datetime import datetime, timezone
from statistics import median
from . import profiles, appsec, vulnerabilities as vi
from .store import now, digest

KINDS = ('application_finding', 'application_batch', 'application_source', 'appsec_review',
         'appsec_evidence', 'appsec_exception_request', 'appsec_exception_decision',
         'vulnerability_exposure', 'vulnerability_mention', 'vulnerability_evidence', 'improvement', 'test')
LIMIT = 5000
EVIDENCE_LIMIT = 64*1024*1024
CAVEAT = ('Selected local records only; inventory completeness is unknown. Synthetic results are not operational outcomes. '
          'Counts are distinct identities within this environment; categories can overlap. No risk score or SLA is inferred.')


def timestamp(value):
    try:
        d = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return d.astimezone(timezone.utc) if d.tzinfo else None
    except (ValueError, TypeError, AttributeError):
        return None


def days(start, end):
    a, b = timestamp(start), timestamp(end)
    return (b-a).days if a and b and b >= a else None


def band(value):
    return 'Unknown' if value is None else next((label for bound, label in [(7,'0–7 days'),(30,'8–30 days'),(60,'31–60 days'),(90,'61–90 days')] if value <= bound), 'Over 90 days')


class Snapshot:
    """One bounded SQLite read transaction; scoped data indexed once in memory."""
    def __init__(self, store, customer, environment):
        self.root = store.root
        self.rows = defaultdict(list)
        self.by_id = {}
        with store.connect() as c:
            c.execute('BEGIN')
            record = c.execute("SELECT data FROM records WHERE kind='customer' AND id=?", (customer,)).fetchone()
            self.customer = json.loads(record[0]) if record else None
            if self.customer is None:
                raise KeyError('Unknown customer')
            self.by_id['customer', customer] = self.customer
            self.context = profiles.context(self, customer, environment).model_dump()
            args = (*KINDS, customer, environment)
            where = 'kind IN (' + ','.join('?' for _ in KINDS) + ") AND json_extract(data,'$.context.customer_id')=? AND json_extract(data,'$.context.environment_id')=?"
            count, size = c.execute('SELECT count(*),coalesce(sum(length(CAST(data AS BLOB))),0) FROM records WHERE ' + where, args).fetchone()
            if count > LIMIT or size > 64*1024*1024:
                raise ValueError('Overview limit: 5000 scoped records / 64 MiB; totals unavailable, not truncated')
            for r in c.execute("SELECT kind,id,CASE WHEN kind='vulnerability_mention' THEN json_set(json_remove(data,'$.source'),'$.synthetic',coalesce(json_extract(data,'$.source.metadata.fixture'),0)) ELSE data END AS data FROM records WHERE " + where + ' ORDER BY created_at,id', args):
                row = json.loads(r['data']); self.rows[r['kind']].append(row); self.by_id[r['kind'],r['id']] = row
            keys = {r['logical_id']+':operational' for r in self.rows['vulnerability_exposure']}
            if keys:
                for clock in c.execute("SELECT id,data FROM records WHERE kind='confirmed_exposure' AND id IN (" + ','.join('?' for _ in keys) + ')', tuple(keys)):
                    self.by_id['confirmed_exposure',clock['id']] = json.loads(clock['data'])
        self.groups = defaultdict(lambda: defaultdict(list))
        for kind, rows in self.rows.items():
            for row in rows:
                logical = row.get('logical_id') or row.get('appsec_logical_id') or row.get('vulnerability_asset_id')
                if logical: self.groups[kind][logical].append(row)

        # Only latest exposure retests need attachment integrity checks. Bound the I/O
        # before existing governance verification opens any supporting bytes.
        evidence_bytes = 0
        for tests in self.groups['test'].values():
            test = tests[-1]
            if not (test.get('appsec_logical_id') or test.get('vulnerability_asset_id')): continue
            ids = (test.get('measurement') or {}).get('evidence_ids', []) if test.get('appsec_logical_id') else [e['reference'].split(':',1)[1] for e in test['evidence'] if e['reference'].startswith('vulnerability-evidence:')]
            for id in ids:
                evidence = self.maybe('appsec_evidence', id) or self.maybe('application_source', id) or self.maybe('vulnerability_evidence', id)
                if not evidence: continue
                path = self.root / 'blobs' / evidence['sha256']
                try: evidence_bytes += path.stat().st_size
                except OSError: pass  # Existing verification marks missing evidence stale.
        if evidence_bytes > EVIDENCE_LIMIT:
            raise ValueError('Overview evidence limit: 64 MiB of current retest attachments; totals unavailable, not truncated')

    def get(self, kind, id):
        return self.by_id[kind,id]

    def maybe(self, kind, id):
        return self.by_id.get((kind,id))

    def all(self, kind):
        return self.rows[kind]


class Subject:
    def __init__(self, snapshot, logical):
        self.snapshot, self.logical, self.root = snapshot, logical, snapshot.root

    def get(self, kind, id): return self.snapshot.get(kind,id)
    def maybe(self, kind, id): return self.snapshot.maybe(kind,id)
    def all(self, kind):
        if kind in ('application_batch', 'improvement'): return self.snapshot.all(kind)
        rows = self.snapshot.groups[kind][self.logical]
        # Current outcome is the latest recorded test; old tests cannot restore success.
        return rows[-1:] if kind == 'test' else rows


def overview(store, customer, environment):
    snapshot = Snapshot(store, customer, environment)
    ctx, at = snapshot.context, now()
    today = timestamp(at).date()
    rows = []
    actions_by_asset = defaultdict(list)
    for action in snapshot.all('improvement'):
        actions_by_asset[(action.get('origin') or {}).get('asset_logical_id')].append(action)
    def base(id, origin, entity, label, synthetic, reference, sources):
        return dict(id=id, origin=origin, entity=entity, label=label, synthetic=synthetic,
            reference=reference, source_ids=sources, environment_id=environment, customer_id=customer,
            owner='Unassigned', status='Unknown', verification='Pending / no qualifying evidence',
            priority=None, scanner_level=None, opened_at=None, target_date=None, overdue_days=None,
            outstanding=True, exception_status=None, age_days=None, age_band='Unknown', last_retest_at=None,
            retest_age_days=None, timing_seconds=None, timing_cohort=None)
    def work(row, action, resolved):
        row.update(action_id=action['id'], owner=action.get('owner') or 'Unassigned', priority=action.get('priority'),
                   status=action['status'], opened_at=action.get('opened_at'), outstanding=not resolved)
        row['age_days'] = days(row['opened_at'], at) if row['outstanding'] else None
        row['age_band'] = band(row['age_days'])
        date = row['target_date']
        if date and row['outstanding'] and row.get('applicability') not in ('Not applicable','False positive (reviewed determination)',appsec.DUPLICATE,'assessed not affected'):
            try:
                delta = (today-datetime.strptime(date, '%Y-%m-%d').date()).days
                row['overdue_days'] = delta if delta > 0 else 0
            except ValueError: pass
        rows.append(row)
    for logical, occurrences in snapshot.groups['application_finding'].items():
        f = max(occurrences, key=lambda r:(r['imported_at'],r['id']))
        subject = Subject(snapshot, logical)
        deps = appsec.dependencies(subject, f)
        reviews = subject.all('appsec_review'); review = reviews[-1] if reviews else None
        disposition = review['disposition'] if review and review['dependencies']==deps else 'Needs review'
        action = appsec.action_for(subject, f)
        outcome = appsec.verification(subject, f, action, as_of=at)
        test = outcome['history'][-1] if outcome['history'] else None
        synthetic = f['synthetic'] or bool(test and 'synthetic' in test['assurance'])
        verification = ('Stale evidence' if test and test['stale'] else
            'Retest '+test['result'] if test and test['result']!='passed' else
            'Attestation only' if test and test['method']=='analyst attestation' else
            ('Synthetic AppSec evidence reviewed' if synthetic else 'Supplied AppSec evidence reviewed') if outcome['can_close'] else
            'Fix reported / verification pending' if action and action['status']=='retest requested' else 'Pending / no qualifying evidence')
        resolved = bool(action and action['status']=='closed' and outcome['can_close'])
        row = base('app:'+logical, 'AppSec', 'exposure', f['rule_id'] or 'Unknown rule', synthetic,
                   {'finding_id':f['id']}, [f['id'],f['source_id'],f['batch_id']])
        row.update(status=disposition, applicability=disposition, verification=verification, scanner_level=f['scanner_level'],
                   owner=action.get('owner') or 'Unassigned' if action else 'Unassigned',
                   application=f['operator_context'].get('application'), repository=f['operator_context'].get('repository'),
                   occurrence_count=len(occurrences), outstanding=not resolved and disposition not in ('Not applicable','False positive (reviewed determination)',appsec.DUPLICATE),
                   last_retest_at=test['executed_at'] if test else None, review_id=review['id'] if review else None,
                   test_id=test['id'] if test else None, stale_reasons=test['stale_reasons'] if test else [])
        if test: row['retest_age_days'] = days(test['executed_at'],at)
        if resolved:
            start = min((r['imported_at'] for r in occurrences), key=lambda s:timestamp(s) or datetime.max.replace(tzinfo=timezone.utc))
            end = test['recorded_at']
            if timestamp(start) and timestamp(end) and timestamp(end)>=timestamp(start):
                row.update(timing_seconds=(timestamp(end)-timestamp(start)).total_seconds(), timing_cohort='Synthetic AppSec' if synthetic else 'Supplied AppSec')
        rows.append(row)
        requests = subject.all('appsec_exception_request'); decisions = subject.all('appsec_exception_decision')
        statuses = []
        for request in requests:
            history = [r for r in decisions if r['request_id']==request['id']]
            decision = history[-1] if history else None
            status = decision['decision'] if decision else 'unapproved request'
            expires = timestamp(request['review_by'])
            if expires and expires<=timestamp(at): status='expired'
            elif request['dependencies']!=deps or (decision and decision['dependencies']!=deps): status='stale; renewed decision required'
            elif status=='approved': status='active operator-recorded acceptance; finding remains'
            statuses.append(status)
            ex = base('exception:'+request['id'], 'AppSec', 'exception', f['rule_id'] or 'Unknown rule', f['synthetic'], row['reference'], [request['id']] + [d['id'] for d in history])
            ex.update(status=status, exception_status=status, review_by=request['review_by'],
                      approaching_review=bool(expires and timestamp(at)<expires and (expires-timestamp(at)).total_seconds()<=7*86400))
            rows.append(ex)
        row['exception_status'] = '; '.join(statuses) or None
        if action:
            a = row | {'id':'action:'+action['id'], 'entity':'action', 'target_date':action.get('remediation',{}).get('target_date'), 'exposure_id':row['id'], 'source_ids':row['source_ids']+[action['id']]}
            work(a, action, resolved)
            if action['status']=='closed' and not resolved: a['status']='Reopen/review required; prior closure is historical'
    current_assets = {}
    for asset in snapshot.all('vulnerability_exposure'): current_assets[asset['logical_id']] = asset
    for logical, asset in current_assets.items():
        subject = Subject(snapshot, logical)
        stale = not vi.same_version(asset['context'],ctx) or days(asset['observed_at'],at) is None or (timestamp(at)-timestamp(asset['observed_at'])).total_seconds()>30*86400
        outcome = vi.verification(subject,ctx,asset,as_of=at)
        test = outcome['tests'][-1] if outcome['tests'] else None
        evidence_ok = True
        if test and test['method']!='analyst attestation':
            for evidence in test['evidence']:
                ref = evidence['reference'].split(':',1)
                saved = snapshot.maybe('vulnerability_evidence',ref[1]) if len(ref)==2 and ref[0]=='vulnerability-evidence' else None
                try:
                    evidence_ok = evidence_ok and bool(saved and saved['kind']==evidence['kind'] and saved['sha256']==evidence['sha256'] and digest((snapshot.root/'blobs'/saved['sha256']).read_bytes())==saved['sha256'])
                except OSError: evidence_ok = False
        synthetic = asset['evidence_kind']=='synthetic fixture' or bool(test and any(e['kind']=='synthetic fixture replay' for e in test['evidence']))
        verified = outcome['status']=='verified remediation' and not stale and not synthetic and asset['applicability']=='confirmed affected' and evidence_ok
        verification = ('Stale evidence' if test and (not test['fresh'] or stale or not evidence_ok) else
            'Retest '+test['result'] if test and test['result']!='passed' else
            'Operational infrastructure remediation' if verified else
            'Operational mitigation only' if outcome['status']=='verified mitigation' and not synthetic else
            'Attestation only' if test and test['method']=='analyst attestation' else
            'Synthetic / lab evidence only' if test else 'Pending / no qualifying evidence')
        row = base('infra:'+logical,'Infrastructure','exposure',asset['cve']+' · '+asset['asset_id'],synthetic,{'cve':asset['cve']},[asset['id']])
        row.update(status='needs verification' if stale else asset['applicability'], applicability='needs verification' if stale else asset['applicability'], verification=verification,
                   owner=asset.get('owner') or 'Unassigned', application=asset['asset_id'], repository=None,
                   outstanding=not verified and (stale or asset['applicability']!='assessed not affected'),
                   last_retest_at=test['executed_at'] if test else None, test_id=test['id'] if test else None,
                   retest_age_days=days(test['executed_at'],at) if test else None, observation_stale=stale)
        clock = snapshot.maybe('confirmed_exposure',logical+':operational')
        if verified and clock and timestamp(clock['at']) and timestamp(test['executed_at'])>=timestamp(clock['at']):
            row.update(timing_seconds=(timestamp(test['executed_at'])-timestamp(clock['at'])).total_seconds(),timing_cohort='Operational infrastructure')
        rows.append(row)
        for action in actions_by_asset[logical]:
            a = row | {'id':'action:'+action['id'], 'entity':'action', 'target_date':asset.get('commitment_deadline'), 'exposure_id':row['id'], 'source_ids':[asset['id'],action['id']]}
            work(a,action,verified and test['improvement_id']==action['id'])
            if test and test['improvement_id']!=action['id']:
                a.update(verification='Pending / evidence belongs to another action',test_id=None,last_retest_at=None,retest_age_days=None)
    mentions = defaultdict(list)
    for m in snapshot.all('vulnerability_mention'): mentions[m['cve']].append(m)
    for cve, records in mentions.items():
        row = base('mention:'+cve,'Infrastructure','mention',cve,all(m.get('synthetic') for m in records),{'cve':cve},[m['id'] for m in records])
        row.update(status='CVE source mention; applicability not established',outstanding=False)
        rows.append(row)
    linked = {r.get('action_id') for r in rows}
    for action in snapshot.all('improvement'):
        origin=action.get('origin') or {}
        if action['id'] in linked or origin.get('kind') not in ('application_finding','vulnerability_decision'): continue
        row=base('action:'+action['id'],'AppSec' if origin['kind']=='application_finding' else 'Infrastructure','action','Origin unavailable',False,{},[action['id']])
        row['verification']='Unknown; origin unavailable'
        work(row,action,False)
    metrics=[]
    def metric(id,label,entity,predicate,definition):
        population=[r for r in rows if r['entity']==entity]
        ids=[r['id'] for r in population if predicate(r)]
        metrics.append(dict(id=id,label=label,value=len(ids),record_ids=ids,population_count=len(population),
            population=entity,definition=definition,exclusions='Other populations and historical revisions excluded.',caveat=CAVEAT))
    metric('appsec','Current logical AppSec findings','exposure',lambda r:r['origin']=='AppSec','Latest occurrence per logical AppSec identity, including reviewed exclusions; imports are not exposures.')
    metric('affected','Confirmed affected infrastructure','exposure',lambda r:r['origin']=='Infrastructure' and r['status']=='confirmed affected','Latest asset/CVE observation with current profile and observation age at most 30 days. Includes synthetic observations with labels.')
    metric('potential','Potential / unassessed infrastructure','exposure',lambda r:r['origin']=='Infrastructure' and r['status']=='needs verification','Unknown applicability or stale observation; never confirmed by a CVE mention.')
    metric('mentions','Distinct CVEs mentioned in sources','mention',lambda r:True,'Distinct CVE identifiers in already persisted scoped source mentions. No asset exposure inferred; may overlap registered asset CVEs.')
    for id,label,status in [('unreviewed','AppSec needs review','Needs review'),('applicable','Reviewed applicable AppSec',appsec.APPLICABLE),('duplicates','Reviewed duplicate AppSec',appsec.DUPLICATE)]:
        metric(id,label,'exposure',lambda r,s=status:r['origin']=='AppSec' and r['status']==s,'Current review dependency must match. Duplicate dispositions remain distinct auditable records, excluded from outstanding exposure.')
    metric('outstanding','Outstanding exposure records','exposure',lambda r:r['outstanding'],'Unresolved current logical records, excluding current not-applicable/false-positive/duplicate determinations. Acceptance does not resolve exposure.')
    metric('work','Outstanding remediation actions','action',lambda r:r['outstanding'],'Unique current ledger actions without a corresponding current qualifying resolution. Closed status alone is insufficient.')
    metric('implementation','Awaiting implementation','action',lambda r:r['outstanding'] and r['status'] in ('open','in progress'),'Outstanding actions with existing open or in-progress status.')
    metric('fix','Fix reported / retest requested','action',lambda r:r['outstanding'] and r['status'] in ('deployed','retest requested'),'Existing deployment or retest-request status with no qualifying resolution.')
    metric('unassigned','Unassigned outstanding records','exposure',lambda r:r['outstanding'] and not any(a.get('owner')!='Unassigned' for a in rows if a['entity']=='action' and a.get('exposure_id')==r['id']) and r['owner']=='Unassigned','Outstanding exposures without recorded asset/action owner; records without actions stay visible.')
    metric('overdue','Actions past recorded target','action',lambda r:r['outstanding'] and bool(r['overdue_days']),'Actual AppSec target date or infrastructure asset commitment deadline before today UTC; review dates are not completion targets. Reviewed exclusions are not overdue remediation. No SLA inferred.')
    metric('unassigned_actions','Unassigned outstanding actions','action',lambda r:r['outstanding'] and r['owner']=='Unassigned','Outstanding ledger actions without a recorded owner. Missing commitments remain visible separately as unassigned exposure records.')
    for label in ['Synthetic AppSec evidence reviewed','Supplied AppSec evidence reviewed','Operational infrastructure remediation','Operational mitigation only','Attestation only','Synthetic / lab evidence only','Retest failed','Retest inconclusive','Stale evidence','Pending / no qualifying evidence','Fix reported / verification pending']:
        metric('verification:'+label,label,'exposure',lambda r,s=label:r['verification']==s,'Latest recorded outcome only, qualified by original method, provenance, current dependencies and 30-day freshness. Separate from action status.')
    for status in ['active operator-recorded acceptance; finding remains','unapproved request','expired','rejected','revoked','stale; renewed decision required']:
        metric('exception:'+status,'Exceptions: '+status,'exception',lambda r,s=status:r['status']==s,'One request with latest decision; expiration evaluated from review_by, then dependency freshness. Operator-declared approval, never a fix.')
    metric('expiring','Exceptions due for review within 7 days','exception',lambda r:r['approaching_review'] and r['status'].startswith('active'),'Active acceptance with recorded review/expiry instant within the next seven days.')
    for label in ['0–7 days','8–30 days','31–60 days','61–90 days','Over 90 days','Unknown']:
        metric('age:'+label,'Outstanding action age: '+label,'action',lambda r,s=label:r['outstanding'] and r['age_band']==s,'Completed elapsed UTC days since recorded action opened_at; missing, invalid or future start is Unknown. Descriptive bands, not SLA thresholds.')
    timing=[]
    for cohort in ['Synthetic AppSec','Supplied AppSec','Operational infrastructure']:
        eligible=[r for r in rows if r['entity']=='exposure' and r['timing_cohort']==cohort and r['timing_seconds'] is not None]
        timing.append(dict(cohort=cohort,sample_count=len(eligible),median_seconds=median([r['timing_seconds'] for r in eligible]) if eligible else None,
            record_ids=[r['id'] for r in eligible],definition='AppSec: first persisted occurrence to current successful review recording, with qualified closure. Infrastructure: confirmed-exposure clock to current qualifying remediation execution. Unresolved, stale, invalid clocks and other cohorts excluded.', unavailable_reason=None if eligible else 'No eligible current resolved records with both milestones.'))
    return dict(context=appsec.versions(ctx),as_of=at,rows=rows,metrics=metrics,timing=timing,caveat=CAVEAT,
                raw_appsec_occurrences=len(snapshot.all('application_finding')),synthetic_present=any(r['synthetic'] for r in rows),
                evidence_policy='Current retest attachments are integrity checked; AppSec uses existing governance rules; raw SARIF is never reparsed. CVE verification uses existing method/dependency rules. This workbench does not authenticate uploaded evidence.')


def register(app, service):
    @app.get('/api/exposure-overview')
    def read(customer_id: str, environment_id: str):
        return overview(service.store,customer_id,environment_id)
    @app.post('/api/exposure-overview/demo')
    def demo():
        from .exposure_demo import load
        return load(service)
