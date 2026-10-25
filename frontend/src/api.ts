import type { AnalyzeRequest, AnalyzeResponse, Network } from './types';

export function buildRequest(network: Network, source: string, removedEdge?: string): AnalyzeRequest {
  return {
    nodes: network.nodes.map(({ id, type, sensitive }) => ({ id, type, ...(sensitive == null ? {} : { sensitive }) })),
    edges: network.edges.map(({ id, source, target }) => ({ id, source, target })),
    compromised_node: source,
    simulations: removedEdge ? [{ id: 'revoke-selected', remove_edges: [removedEdge] }] : [],
  };
}

export async function analyze(request: AnalyzeRequest, signal?: AbortSignal): Promise<AnalyzeResponse> {
  const response = await fetch('http://127.0.0.1:8000/api/analyze', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request), signal,
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = body?.detail;
    const message = typeof detail?.message === 'string' ? detail.message : Array.isArray(detail) ? detail.map((item: { msg: string }) => item.msg).join('; ') : `Analysis failed (HTTP ${response.status}).`;
    throw new Error(message);
  }
  if (body?.schema_version !== 1 || !body?.baseline || !Array.isArray(body?.simulations)) throw new Error('Unsupported analysis response. Expected engine schema version 1.');
  return body as AnalyzeResponse;
}
