import { afterEach, describe, expect, it, vi } from 'vitest';
import { analyze, buildRequest } from './api';
import { networks } from './networks';

afterEach(() => vi.unstubAllGlobals());
describe('API adapter', () => {
  it('preserves IDs and sends the singular source and exact removed edge', () => {
    const request = buildRequest(networks[0], 'alice', 'ssh');
    expect(request.compromised_node).toBe('alice');
    expect(request).not.toHaveProperty('compromised_nodes');
    expect(request.nodes.map(n => n.id)).toEqual(networks[0].nodes.map(n => n.id));
    expect(request.edges).toEqual(networks[0].edges);
    expect(request.simulations).toEqual([{ id: 'revoke-selected', remove_edges: ['ssh'] }]);
    expect(request.nodes[0]).toEqual({ id: 'alice', type: 'user' });
    expect(buildRequest(networks[0], 'alice').simulations).toEqual([]);
  });
  it('uses fetch and leaves engine output untouched', async () => {
    const result = { schema_version: 1, baseline: { sources: [], exposed_assets: [] }, simulations: [] };
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(result)));
    vi.stubGlobal('fetch', fetch);
    const request = buildRequest(networks[0], 'alice');
    expect(await analyze(request)).toEqual(result);
    expect(fetch).toHaveBeenCalledWith('http://127.0.0.1:8000/api/analyze', expect.objectContaining({ method: 'POST', body: JSON.stringify(request) }));
  });
  it('surfaces backend errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: { code: 'engine_timeout', message: 'Graph analysis exceeded its time limit' } }), { status: 504 })));
    await expect(analyze(buildRequest(networks[0], 'alice'))).rejects.toThrow('exceeded its time limit');
  });
  it('handles validation details and non-JSON failures', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ detail: [{ msg: 'Unknown node' }] }), { status: 422 })).mockResolvedValueOnce(new Response('unavailable', { status: 503 })));
    await expect(analyze(buildRequest(networks[0], 'alice'))).rejects.toThrow('Unknown node');
    await expect(analyze(buildRequest(networks[0], 'alice'))).rejects.toThrow('HTTP 503');
  });
  it('rejects unsupported schema versions', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"schema_version":2}')));
    await expect(analyze(buildRequest(networks[0], 'alice'))).rejects.toThrow('schema version 1');
  });
});
