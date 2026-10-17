import {useEffect, useRef, useState} from 'react';
import {Download, ExternalLink, Maximize2, Minimize2, RotateCcw, Scan} from 'lucide-react';
import './attack-flow.css';
type Package = Record<string, any>;
type Props = {pack: Package; customer: string; environment: string; regenerate: () => void; busy: boolean};

export function attackFlowUrls(origin: string, packageId: string, customer: string, environment: string, frame: string) {
  const artifact = new URL(`/api/artifacts/${encodeURIComponent(packageId)}/attack-flow.json`, origin);
  artifact.search = new URLSearchParams({customer_id: customer, environment_id: environment}).toString();
  const builder = new URL('/attack-flow-builder/', origin);
  builder.search = new URLSearchParams({src: artifact.href, iti_package: packageId, iti_frame: frame, theme: 'light_theme'}).toString();
  const editor = builder.href;
  builder.searchParams.set('readonly', '1');
  return {artifact: artifact.href, viewer: builder.href, editor};
}

/** The render-time scope gate removes a previous customer's iframe immediately. */
export default function AttackFlowPanel(props: Props) {
  const {pack, customer, environment} = props;
  if (pack.context.customer_id !== customer || pack.context.environment_id !== environment) return null;
  return <ScopedFlow key={`${customer}:${environment}:${pack.id}`} {...props}/>;
}
function ScopedFlow({pack, customer, environment, regenerate, busy}: Props) {
  const info = pack.artifacts.validation.attack_flow;
  const available = pack.artifacts.names.includes('attack-flow.json');
  const [frame, setFrame] = useState(() => crypto.randomUUID());
  const [state, setState] = useState<'loading'|'ready'|'error'>('loading');
  const [message, setMessage] = useState('');
  const [expanded, setExpanded] = useState(false);
  const iframe = useRef<HTMLIFrameElement>(null), panel = useRef<HTMLElement>(null);
  const urls = attackFlowUrls(location.origin, pack.id, customer, environment, frame);
  const fit = () => iframe.current?.contentWindow?.postMessage({type: 'iti-attack-flow-fit', frame, packageId: pack.id}, location.origin);
  useEffect(() => {
    if (!available) return;
    const controller = new AbortController(); let live = true;
    const timer = setTimeout(() => {if(live) {setState('error');setMessage('The viewer did not confirm a rendered graph. Retry, or download the JSON.');}}, 20000);
    const receive = (event: MessageEvent) => {
      if (!live || event.origin !== location.origin || event.source !== iframe.current?.contentWindow) return;
      const data = event.data;
      if (data?.type !== 'iti-attack-flow' || data.frame !== frame || data.packageId !== pack.id) return;
      if (data.status === 'ready' && data.nodes === info.actions) {clearTimeout(timer);setState('ready');setMessage('');}
      else if (data.status === 'error') {clearTimeout(timer);setState('error');setMessage(String(data.message || 'The viewer could not render this flow.'));}
    };
    window.addEventListener('message', receive);
    fetch('/api/attack-flow/viewer', {signal: controller.signal}).then(r => r.json()).then(result => {
      if (live && !result.available) {clearTimeout(timer);setState('error');setMessage(result.reason || 'Build the local viewer with ./scripts/build-attack-flow, then retry.');}
    }).catch(error => {if(live && error.name !== 'AbortError') {clearTimeout(timer);setState('error');setMessage('Cannot check the local viewer. Confirm the application is running.');}});
    return () => {live=false;clearTimeout(timer);controller.abort();window.removeEventListener('message', receive);};
  }, [frame, pack.id, available]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {if(event.key === 'Escape') setExpanded(false);};
    const onFull = () => {setExpanded(document.fullscreenElement === panel.current);};
    window.addEventListener('keydown', onKey); document.addEventListener('fullscreenchange', onFull);
    const observer = new ResizeObserver(() => fit()); if(panel.current) observer.observe(panel.current);
    return () => {window.removeEventListener('keydown', onKey);document.removeEventListener('fullscreenchange', onFull);observer.disconnect();};
  }, [frame]);
  async function expand() {
    if(expanded) {if(document.fullscreenElement) await document.exitFullscreen();setExpanded(false);return;}
    try {await panel.current?.requestFullscreen();setExpanded(true);} catch {setExpanded(true);}
  }
  return <section ref={panel} className={`panel padded attack-flow-panel ${expanded?'flow-expanded':''}`} aria-label="Reported attack flow">
    <div className="panel-header"><div><h2>Reported attack flow</h2><p>{pack.source.title}</p></div><span className="badge amber">{available?'Generated — review required':info?.status==='empty'?'No supported actions':'Not generated'}</span></div>
    <p className="fine">Reported attacker actions, including those outside this environment. The human-led scenarios below are scoped separately.</p>
    {!info ? <div className="flow-empty"><p>This historical package predates Attack Flow. Its existing artifacts remain unchanged.</p><button disabled={busy} onClick={regenerate}>Generate updated package</button></div>
      : info.status === 'empty' ? <div className="flow-empty"><strong>No supported reported actions</strong><p>{info.reason}</p></div>
      : !available ? <div className="banner error">Attack Flow is missing from this package. Other artifacts remain available.</div>
      : <>
        <div className="flow-controls"><button onClick={expand}>{expanded?<Minimize2 size={16}/>:<Maximize2 size={16}/>} {expanded?'Collapse':'Expand / fullscreen'}</button><button disabled={state!=='ready'} onClick={fit}><Scan size={16}/> Fit view</button><a className="button" href={urls.artifact} download="attack-flow.json"><Download size={16}/> Download Attack Flow JSON</a><a className="button" href={urls.editor} target="_blank" rel="noopener noreferrer"><ExternalLink size={16}/> Open in Builder</a></div>
        <div className="flow-notes"><strong>{info.actions} reported actions · {info.edges} supported links · {info.ordering}</strong><p>{info.explanation}</p>{info.source_gaps?.length>0&&<p>Source gaps: {info.source_gaps.join('; ')}</p>}</div>
        <div className="flow-viewport" aria-busy={state==='loading'}>
          {state!=='error'&&<iframe key={frame} ref={iframe} src={urls.viewer} title={`Reported attack flow: ${pack.source.title}`} sandbox="allow-scripts allow-same-origin allow-downloads" allow="fullscreen" onError={()=>{setState('error');setMessage('The local viewer failed to load.');}}/>}
          {state==='loading'&&<div className="flow-status" role="status">Loading and rendering reported actions…</div>}
          {state==='error'&&<div className="flow-status" role="alert"><strong>Flow viewer unavailable</strong><p>{message}</p><button onClick={()=>{setState('loading');setMessage('');setFrame(crypto.randomUUID());}}><RotateCcw size={16}/> Retry viewer</button><p className="fine">The validation scenarios and artifact downloads remain available.</p></div>}
        </div>
        <p className="fine">Drag the canvas to pan; scroll to zoom. Builder edits are a separate local draft: use its save/export controls. They do not save into or approve this immutable package.</p>
      </>}
  </section>;
}
