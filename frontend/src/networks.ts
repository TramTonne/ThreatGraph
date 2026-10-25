import office from '../../examples/office.json';
import redundant from '../../examples/redundant-access.json';
import apiExample from '../../examples/api-analyze.json';
import type { Network, NetworkNode } from './types';

// Positions and friendly names are display-only. Original IDs remain intact.
export const networks: Network[] = [
  { id: 'office', title: 'Office network', description: 'A compromised workstation, an application server, and an isolated backup.', nodes: office.nodes as NetworkNode[], edges: office.edges, source: office.compromised_nodes[0] },
  { id: 'redundant', title: 'Redundant access', description: 'Two independent routes to a vault. Revoking one may leave another open.', nodes: redundant.nodes as NetworkNode[], edges: redundant.edges, source: redundant.compromised_nodes[0] },
  { id: 'api-example', title: 'API quickstart', description: 'The repository’s minimal API example: one source, three permissions.', nodes: apiExample.nodes as NetworkNode[], edges: apiExample.edges, source: apiExample.compromised_node },
];
export const typeNames = { user: 'Identity', device: 'Device', server: 'Server', asset: 'Asset' };
export const isSensitive = (node: NetworkNode) => node.sensitive ?? node.type === 'asset';
export const label = (id: string) => ({ alice: 'Alice Morgan', laptop: 'Workstation', app: 'Application server', 'customer-db': 'Customer database', backup: 'Backup archive', user: 'Standard user', 'server-a': 'Server A', 'server-b': 'Server B', vault: 'Data vault' }[id] ?? id);
