from .models import CoverageAssessment
from .store import uid
POLICY_VERSION='relevance-1'
def relevance(extraction,source,context):
    env=context.environment_snapshot; customer=context.customer_snapshot
    tech=sorted({t for b in extraction.behaviors for t in b.technology if t.lower() in [x.lower() for x in env.technologies+env.platforms]})
    platform_match=any(b.platform in env.platforms for b in extraction.behaviors)
    targets=[f for f in extraction.sector_factors if f['kind']=='explicit targeting']
    sector='match' if any(f['sector'] in [customer.sector]+customer.additional_sectors for f in targets) else ('mismatch' if targets else 'unknown')
    ir=[x for x in customer.intelligence_requirements if x.lower() in source.normalized.lower()]
    if tech: rank='High'; reason='Supported shared technology matches: '+', '.join(tech)+'. Sector mismatch does not veto technical relevance.'
    elif platform_match: rank='Medium'; reason='Reported behavior applies to a declared platform; exact technology/service exposure needs confirmation.'
    elif not extraction.behaviors: rank='Unknown'; reason='Insufficient technical evidence to determine operational relevance.'
    elif ir: rank='Medium'; reason='Intelligence requirement matches; reported platform is absent, so only explicitly proposed follow-up is justified.'
    else: rank='Low'; reason='Known reported platforms are outside this selected environment; retain source and inspect cross-platform lessons.'
    return {'policy_version':POLICY_VERSION,'rank':rank,'explanation':reason,'sector':{'status':sector,'factors':targets,'explanation':'Only explicit targeting counts; publisher identity and passing mentions do not.'},'technology_matches':tech,'platform_match':platform_match,'intelligence_requirement_matches':ir,'source_confidence':'Source reliability not independently established','recency':{'publication':source.published_at,'incident':source.incident_time,'explanation':'Publication/message time does not establish recent threat activity; historical IOCs need current context.'},'evidence':sorted({e for b in extraction.behaviors for e in b.evidence}),'uncertainty':source.gaps+extraction.warnings,'manual_override':None}

def applicability(extraction,context):
    rows=[]; env=context.environment_snapshot
    for b in extraction.behaviors:
        if b.kind in ('unsupported','conflicting'): app='unknown';reason='Unsupported/conflicting assertion requires review'
        elif b.platform=='unknown': app='unknown';reason='Platform or prerequisites unresolved'
        elif b.platform not in env.platforms: app='not applicable';reason=f'Reported {b.platform} behavior; selected environment declares {env.platforms}. No invented equivalent.'
        else: app='applicable';reason=f'{b.platform} platform declared. Technology exposure and control behavior still require tests.'
        missing=[t for t in b.telemetry if t not in env.telemetry]
        rows.append(CoverageAssessment(behavior_id=b.id,applicability=app,reason=reason,missing_prerequisites=missing,telemetry_readiness='missing declared sources: '+', '.join(missing) if missing else 'declared; not checked',detection_readiness='not assessed'))
    return rows

def visible(rank,view='Recommended',include_unknown=True,levels=None):
    if view=='All': return True
    allowed=set(levels if view=='Custom' else ['High','Medium'])
    if include_unknown: allowed.add('Unknown')
    return rank in allowed
