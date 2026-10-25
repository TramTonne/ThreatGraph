import { useEffect, useRef, useState } from 'react';
import { Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, useNodesState, type Node, type NodeProps } from '@xyflow/react';
import { Activity, ArrowRight, Check, ChevronRight, CircleDot, Database, Fingerprint, GitBranch, LoaderCircle, LockKeyhole, Monitor, Play, RotateCcw, Server, Shield, ShieldAlert, ShieldCheck, Unplug, UserRound } from 'lucide-react';
import { analyze, buildRequest } from './api';
import { isSensitive, label, networks, typeNames } from './networks';
import type { AnalyzeResponse, Network, NetworkNode } from './types';

const icons = { user: UserRound, device: Monitor, server: Server, asset: Database };
type SecurityNode = Node<{ item: NetworkNode; source: boolean; exposed: boolean; protected: boolean; onPath: boolean }, 'security'>;
function GraphNode({ data, selected }: NodeProps<SecurityNode>) {
  const Icon = icons[data.item.type];
  return <div className={`security-node ${data.item.type} ${selected ? 'is-selected' : ''} ${data.onPath ? 'on-path' : ''} ${data.source ? 'is-source' : ''} ${data.protected ? 'is-protected' : ''}`}>
    <Handle type="target" position={Position.Left} />
    <Handle id="return-target" type="target" position={Position.Top} />
    <div className="node-top"><span className="node-icon"><Icon size={19} /></span><span className="node-kind">{typeNames[data.item.type]}</span>{isSensitive(data.item) && <LockKeyhole size={12} />}</div>
    <strong>{label(data.item.id)}</strong><code>{data.item.id}</code>
    <div className="node-status">{data.source ? <><CircleDot size={10} /> Compromised source</> : data.protected ? <><ShieldCheck size={10} /> Protected in simulation</> : data.exposed ? <><ShieldAlert size={10} /> Sensitive · exposed</> : isSensitive(data.item) ? 'Sensitive asset' : 'Network entity'}</div>
    <Handle type="source" position={Position.Right} />
    <Handle id="return-source" type="source" position={Position.Top} />
  </div>;
}
const nodeTypes = { security: GraphNode };
function positionNodes(network: Network): SecurityNode[] {
  const rows: Record<string, number> = {};
  return network.nodes.map(item => {
    const column = { user: 0, device: 1, server: 2, asset: 3 }[item.type];
    const row = rows[item.type] ?? 0; rows[item.type] = row + 1;
    return { id: item.id, type: 'security', position: { x: column * 265, y: row * 200 + (column % 2 ? 60 : 0) }, data: { item, source: false, exposed: false, protected: false, onPath: false } };
  });
}

export default function App() {
  const [networkId, setNetworkId] = useState(networks[0].id);
  const network = networks.find(n => n.id === networkId)!;
  const [source, setSource] = useState(network.source);
  const [selectedNode, setSelectedNode] = useState(network.source);
  const [selectedEdge, setSelectedEdge] = useState('');
  const [removedEdge, setRemovedEdge] = useState<string>();
  const [view, setView] = useState<'baseline' | 'simulation'>('baseline');
  const [target, setTarget] = useState('');
  const [result, setResult] = useState<AnalyzeResponse>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [search, setSearch] = useState('');
  const [nodes, setNodes, onNodesChange] = useNodesState<SecurityNode>(positionNodes(network));
  const requestId = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    const id = ++requestId.current;
    setLoading(true); setError(''); setResult(undefined);
    const timer = window.setTimeout(() => controller.abort('timeout'), 12000);
    analyze(buildRequest(network, source, removedEdge), controller.signal).then(data => {
      if (id !== requestId.current) return;
      setResult(data);
      setTarget(data.baseline.sources.find(s => s.source === source)?.shortest_paths[0]?.target ?? '');
    }).catch(reason => {
      if (id !== requestId.current) return;
      setError(controller.signal.aborted ? 'The request timed out. Check the backend and retry.' : reason instanceof TypeError ? 'Cannot reach the analysis API. Start FastAPI at 127.0.0.1:8000, then retry.' : reason.message);
    }).finally(() => { if (id === requestId.current) setLoading(false); window.clearTimeout(timer); });
    return () => { ++requestId.current; controller.abort(); window.clearTimeout(timer); };
  }, [network, source, removedEdge, revision]);

  function changeNetwork(id: string) {
    const next = networks.find(n => n.id === id)!;
    setNetworkId(id); setSource(next.source); setSelectedNode(next.source); setSelectedEdge(''); setRemovedEdge(undefined); setResult(undefined); setView('baseline'); setSearch(''); setNodes(positionNodes(next));
  }
  function changeSource(id: string) { setSource(id); setRemovedEdge(undefined); setView('baseline'); setResult(undefined); }
  const simulation = result?.simulations.find(s => s.id === 'revoke-selected');
  const current = view === 'simulation' && simulation ? simulation.analysis : result?.baseline;
  const paths = current?.sources.find(s => s.source === source)?.shortest_paths ?? [];
  const activePath = paths.find(p => p.target === target);
  const detail = network.nodes.find(n => n.id === selectedNode);
  const highlightedNodes = new Set(activePath?.nodes ?? []);
  const highlightedEdges = new Set(activePath?.edges ?? []);
  const protectedAssets = simulation?.protected_assets ?? [];
  const visibleNodes = network.nodes.filter(n => `${label(n.id)} ${n.id}`.toLowerCase().includes(search.toLowerCase()));
  const displayNodes = nodes.map(node => ({ ...node, selected: node.id === selectedNode, data: { item: node.data.item, source: node.id === source, exposed: current?.exposed_assets.includes(node.id) ?? false, protected: view === 'simulation' && protectedAssets.includes(node.id), onPath: highlightedNodes.has(node.id) } }));
  const displayEdges = network.edges.map(edge => {
    const removed = view === 'simulation' && simulation?.removed_edges.includes(edge.id);
    const onPath = highlightedEdges.has(edge.id) && !removed;
    const color = removed ? '#f18d75' : onPath ? '#a796ff' : edge.id === selectedEdge ? '#e0e7f3' : '#435470';
    // Route visual return edges above the nodes so opposite permissions stay distinct.
    const returnsLeft = (nodes.find(n => n.id === edge.source)?.position.x ?? 0) > (nodes.find(n => n.id === edge.target)?.position.x ?? 0);
    return { ...edge, label: edge.id, type: returnsLeft ? 'smoothstep' : 'default', sourceHandle: returnsLeft ? 'return-source' : undefined, targetHandle: returnsLeft ? 'return-target' : undefined, selected: edge.id === selectedEdge, animated: onPath, markerEnd: { type: MarkerType.ArrowClosed, color }, style: { stroke: color, strokeWidth: onPath ? 2.5 : 1.5, strokeDasharray: removed ? '6 6' : undefined, opacity: removed ? 0.5 : 1 }, labelStyle: { fill: removed ? '#f18d75' : '#b9c7dd', fontSize: 11, fontFamily: 'monospace' }, labelBgStyle: { fill: '#111b2a' }, labelBgPadding: [6, 4] as [number, number], labelBgBorderRadius: 4 };
  });

  return <div className="app-shell">
    <aside className="left-sidebar">
      <a className="brand" href="/" aria-label="ThreatGraph home"><span className="brand-mark"><Shield size={24} /></span><span>ThreatGraph<small>ATTACK PATH EXPLORER</small></span></a>
      <div className="workspace-label">WORKSPACE <span>LOCAL</span></div>
      <div className="nav-active"><GitBranch size={17} /> Attack surface <ChevronRight size={15} /></div>
      <section className="network-section"><label className="eyebrow" htmlFor="network">SYNTHETIC ENVIRONMENT</label><select id="network" value={networkId} onChange={e => changeNetwork(e.target.value)}>{networks.map(n => <option key={n.id} value={n.id}>{n.title}</option>)}</select><p>{network.description}</p></section>
      <div className="node-list-heading"><span className="eyebrow">NETWORK ENTITIES</span><span className="count">{network.nodes.length}</span></div>
      <input className="search" aria-label="Search nodes" placeholder="Search name or ID…" value={search} onChange={e => setSearch(e.target.value)} />
      <div className="node-list">{visibleNodes.map(n => { const Icon = icons[n.type]; return <button key={n.id} className={`entity ${selectedNode === n.id ? 'active' : ''}`} onClick={() => setSelectedNode(n.id)}><span className={`entity-icon ${n.type}`}><Icon size={17} /></span><span><strong>{label(n.id)}</strong><small>{n.id}</small></span>{source === n.id ? <span className="source-dot" title="Compromised source" /> : isSensitive(n) && <LockKeyhole size={12} />}</button>; })}{!visibleNodes.length && <div className="empty-state">No matching entities.</div>}</div>
      <div className="sidebar-footer"><ShieldCheck size={17} /><span>Safe to explore<small>All network data is synthetic.</small></span></div>
    </aside>

    <main className="main-content">
      <header className="page-header"><div><div className="breadcrumb">Workspace <ChevronRight size={12} /> Attack surface</div><h1>Follow the attack. <span>Find the fix.</span></h1><p>Trace access to sensitive assets and test permission changes.</p></div><span className="environment-tag"><span /> SYNTHETIC LAB</span></header>
      <div className="summary-grid">
        {[{ name: 'Network entities', value: network.nodes.length, Icon: Fingerprint, sub: 'Identities & infrastructure', tone: 'blue' }, { name: 'Permissions', value: network.edges.length, Icon: GitBranch, sub: 'Directed access relationships', tone: 'purple' }, { name: 'Exposed assets', value: result?.baseline.exposed_assets.length ?? '—', Icon: ShieldAlert, sub: 'Baseline · sensitive & reachable', tone: 'orange' }, { name: 'Protected assets', value: simulation ? protectedAssets.length : '—', Icon: ShieldCheck, sub: simulation ? 'After permission simulation' : 'Run a removal simulation', tone: 'green' }].map(stat => <div className={`stat ${stat.tone}`} key={stat.name}><div><span>{stat.name}</span><stat.Icon size={17} /></div><strong>{stat.value}</strong><small>{stat.sub}</small></div>)}
      </div>
      {error && <div className="error-banner" role="alert"><ShieldAlert size={19} /><span>{error}</span><button onClick={() => setRevision(r => r + 1)}>Retry</button></div>}
      <div className="analysis-layout">
        <section className="graph-panel">
          <div className="panel-heading"><div><span className="live-dot" /><strong>Network topology</strong><span className="muted">/ {network.title}</span></div><span className="graph-count">{network.nodes.length} NODES · {network.edges.length} EDGES</span></div>
          <div className="graph-toolbar"><div className="segmented"><button aria-pressed={view === 'baseline'} className={view === 'baseline' ? 'active' : ''} onClick={() => setView('baseline')}>Baseline</button><button aria-pressed={view === 'simulation'} disabled={!simulation} className={view === 'simulation' ? 'active' : ''} onClick={() => setView('simulation')}>Simulation {simulation && <span className="tiny-dot" />}</button></div><span className="toolbar-hint">{loading ? <><LoaderCircle size={13} className="spin" /> Analyzing via C++</> : result ? <><Check size={13} /> Engine analysis ready</> : 'Awaiting analysis'}</span></div>
          <div className="graph-canvas" aria-label="Interactive attack graph">
            <ReactFlow key={networkId} colorMode="dark" style={{ background: 'transparent' }} nodes={displayNodes} edges={displayEdges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} onNodeClick={(_, node) => setSelectedNode(node.id)} onEdgeClick={(_, edge) => setSelectedEdge(edge.id)} nodesConnectable={false} edgesReconnectable={false} fitView fitViewOptions={{ padding: 0.16 }} minZoom={0.25} maxZoom={1.8} proOptions={{ hideAttribution: false }}>
              <Background color="#273245" gap={24} size={1} /><Controls showInteractive={false} /><MiniMap pannable zoomable nodeColor={n => n.id === source ? '#f18d75' : '#8995b0'} maskColor="#080d16bb" />
            </ReactFlow>
            {loading && <div className="canvas-status" role="status"><LoaderCircle size={15} className="spin" /> Computing attack paths…</div>}
          </div>
          <div className="graph-legend"><span><i className="legend-line" /> Permission</span><span><i className="legend-line path" /> Selected path</span><span><i className="legend-dot" /> Compromised</span>{simulation && <span><i className="legend-line removed" /> Removal preview</span>}<span className="legend-tip">Drag to arrange · Scroll to zoom</span></div>
          <div className="path-inspector"><div className="eyebrow"><Activity size={13} /> {view === 'simulation' ? 'SIMULATED' : 'BASELINE'} ATTACK PATH</div>{activePath ? <><div className="path-chain">{activePath.nodes.map((id, index) => <span key={`${id}-${index}`}>{index > 0 && <ArrowRight size={14} />}<button onClick={() => setSelectedNode(id)}>{label(id)}</button></span>)}</div><small>{activePath.distance} {activePath.distance === 1 ? 'hop' : 'hops'} · Edge IDs: {activePath.edges.join(' → ') || 'none (source is sensitive)'}</small></> : <p>{loading ? 'Waiting for the engine…' : !result ? 'Connect to the API to explore attack paths.' : view === 'simulation' && target ? 'No attack path to this asset remains in this simulation.' : 'No sensitive assets are reachable from this source.'}</p>}</div>
        </section>

        <aside className="right-sidebar">
          <section className="inspector-section"><div className="section-title"><span className="eyebrow">ENTITY INSPECTOR</span><CircleDot size={14} /></div>{detail && <><div className="detail-name"><span className={`entity-icon ${detail.type}`}>{(() => { const Icon = icons[detail.type]; return <Icon size={21} />; })()}</span><div><h2>{label(detail.id)}</h2><code>{detail.id}</code></div></div><dl><div><dt>Entity type</dt><dd>{typeNames[detail.type]}</dd></div><div><dt>Classification</dt><dd>{isSensitive(detail) ? 'Sensitive' : 'Standard'}</dd></div><div><dt>Reachability</dt><dd>{!current ? 'Not analyzed' : current.sources.find(s => s.source === source)?.reachable_nodes.includes(detail.id) ? 'Reachable' : 'Unreachable'}</dd></div></dl>{source !== detail.id && <button className="secondary full" onClick={() => changeSource(detail.id)}><CircleDot size={14} /> Use as compromised source</button>}</>}</section>
          <section className="inspector-section"><div className="section-title"><span className="eyebrow">ENTRY POINT</span><span className="badge orange">COMPROMISED</span></div><label className="field-label" htmlFor="source">Compromised source</label><select id="source" value={source} onChange={e => changeSource(e.target.value)}>{network.nodes.map(n => <option key={n.id} value={n.id}>{label(n.id)} ({n.id})</option>)}</select><button className="primary full" disabled={loading} onClick={() => { setRemovedEdge(undefined); setView('baseline'); setRevision(r => r + 1); }}>{loading ? <LoaderCircle size={15} className="spin" /> : <Play size={14} />} {loading ? 'Analyzing…' : 'Run baseline analysis'}</button></section>
          <section className="inspector-section"><div className="section-title"><span className="eyebrow">SENSITIVE ASSET EXPOSURE</span><span className="count">{current?.exposed_assets.length ?? '—'}</span></div><p className="section-note">{view === 'baseline' ? 'Reachable assets in the baseline network.' : 'Assets still reachable after removal.'}</p>{!result ? <div className="empty-state">{loading ? 'Analyzing the network…' : 'Run analysis to see exposure.'}</div> : <>{current?.exposed_assets.map(id => <button key={id} className={`asset-row ${target === id ? 'active' : ''}`} onClick={() => setTarget(id)}><Database size={16} /><span>{label(id)}<small>{view === 'simulation' ? 'Remains exposed' : 'Exposed'} · {paths.find(p => p.target === id)?.distance ?? 0} hops</small></span><ChevronRight size={14} /></button>)}{!current?.exposed_assets.length && <div className="success-note"><ShieldCheck size={17} /> No sensitive assets reachable.</div>}</>}</section>
          <section className="inspector-section simulation-section"><div className="section-title"><span className="eyebrow">PERMISSION WHAT-IF</span><Unplug size={15} /></div><p className="section-note">Preview one revoked permission. The original network stays intact.</p><label className="field-label" htmlFor="permission">Permission to remove</label><select id="permission" value={selectedEdge} onChange={e => setSelectedEdge(e.target.value)}><option value="">Select a permission…</option>{network.edges.map(e => <option key={e.id} value={e.id}>{e.id} · {e.source} → {e.target}</option>)}</select><button className="secondary full" disabled={loading || !selectedEdge} onClick={() => { setRemovedEdge(selectedEdge); setView('simulation'); setRevision(r => r + 1); }}><Unplug size={14} /> Simulate removal</button>{simulation && <div className="simulation-result" data-testid="simulation-result"><div className="simulation-caption">PREVIEW · {simulation.removed_edges.join(', ')}</div><div className="comparison"><span>Exposed assets</span><strong>{result?.baseline.exposed_assets.length} <ArrowRight size={12} /> {simulation.analysis.exposed_assets.length}</strong></div>{protectedAssets.length > 0 ? <div className="success-note"><ShieldCheck size={16} /><span>{protectedAssets.length} asset protected: {protectedAssets.map(label).join(', ')}</span></div> : <div className="warning-note"><ShieldAlert size={16} /><span>No assets protected. {simulation.analysis.exposed_assets.length ? 'An attack path still exists; listed assets remain exposed.' : 'No baseline assets were exposed.'}</span></div>}<button className="text-button" onClick={() => { setRemovedEdge(undefined); setView('baseline'); setRevision(r => r + 1); }}><RotateCcw size={12} /> Clear simulation</button></div>}</section>
        </aside>
      </div>
      <footer className="page-footer"><span><Shield size={12} /> C++ graph engine <span className="footer-divider">/</span> FastAPI adapter</span><span>Local exploration · No live infrastructure</span></footer>
    </main>
  </div>;
}
