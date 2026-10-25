export type NodeType = 'user' | 'device' | 'server' | 'asset';
export interface NetworkNode { id: string; type: NodeType; sensitive?: boolean | null }
export interface Permission { id: string; source: string; target: string }
export interface Network { id: string; title: string; description: string; nodes: NetworkNode[]; edges: Permission[]; source: string }
export interface AnalyzeRequest { nodes: NetworkNode[]; edges: Permission[]; compromised_node: string; simulations: { id: string; remove_edges: string[] }[] }
export interface AttackPath { target: string; distance: number; nodes: string[]; edges: string[] }
export interface Analysis { sources: { source: string; reachable_nodes: string[]; shortest_paths: AttackPath[] }[]; exposed_assets: string[] }
export interface AnalyzeResponse { schema_version: 1; baseline: Analysis; simulations: { id: string; removed_edges: string[]; analysis: Analysis; protected_assets: string[] }[] }
