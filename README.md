# ThreatGraph

A cybersecurity attack-path explorer. This first milestone implements the C++20
analysis engine, JSON CLI, synthetic networks, and automated tests. FastAPI and
React/TypeScript/Vite/React Flow integration remain future work.

## Build and test

Requires a C++20 compiler and CMake 3.20+. CMake uses an installed nlohmann/json
3.11+ package when available; otherwise it downloads the pinned 3.11.3 release
with SHA-256 verification (network access required on the first configure).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/threatgraph_engine examples/office.json
./build/threatgraph_engine - < examples/redundant-access.json
```

No argument also reads stdin. Success writes one JSON document to stdout and exits
0. Invalid JSON, validation failures, and unreadable files write
`{"error":{"code":"invalid_input","message":"..."}}` to stdout and exit 1.
The CLI never emits partial analysis on invalid requests.

## Layout

- `engine/include/threatgraph/graph.hpp`: graph model and public analysis API
- `engine/src/graph.cpp`: validation, directed BFS, reachability, simulations
- `engine/src/main.cpp`: JSON process boundary
- `engine/tests/`: C++ checks and CLI integration checks, registered with CTest
- `examples/`: fictional office and redundant-access networks

## Input contract

```json
{
  "nodes": [
    {"id": "alice", "type": "user"},
    {"id": "vault", "type": "asset", "sensitive": true}
  ],
  "edges": [{"id": "read", "source": "alice", "target": "vault"}],
  "compromised_nodes": ["alice"],
  "simulations": [{"id": "revoke-read", "remove_edges": ["read"]}]
}
```

Nodes support `user`, `device`, `server`, and `asset`. Assets default to sensitive;
other types default to nonsensitive. An explicit boolean `sensitive` overrides
either default. All node, edge, and simulation IDs must be nonempty strings and
unique within their respective collections. Edge endpoints, compromised nodes,
and removed edge IDs must exist. Duplicate IDs in request lists are rejected.
Unknown fields are ignored, allowing labels and display metadata to be added.
`nodes`, `edges`, and `compromised_nodes` are required arrays; `simulations` is
optional. Empty graphs and empty compromised-node lists are valid.

Edges represent directed, unweighted permissions. Parallel edges with distinct
IDs and self-loops are supported. A simulation removes exact edge IDs, so revoking
one of two parallel permissions leaves the other active. Every simulation starts
from the original graph; removals do not accumulate.

## Output contract (schema version 1)

```json
{
  "schema_version": 1,
  "baseline": {
    "sources": [{
      "source": "alice",
      "reachable_nodes": ["alice", "vault"],
      "shortest_paths": [{
        "target": "vault", "distance": 1,
        "nodes": ["alice", "vault"], "edges": ["read"]
      }]
    }],
    "exposed_assets": ["vault"]
  },
  "simulations": [{
    "id": "revoke-read", "removed_edges": ["read"],
    "analysis": {
      "sources": [{"source": "alice", "reachable_nodes": ["alice"], "shortest_paths": []}],
      "exposed_assets": []
    },
    "protected_assets": ["vault"]
  }]
}
```

Reachability includes the source itself. A sensitive compromised source has a
zero-hop path. Only reachable sensitive nodes appear in `shortest_paths`;
unreachable nodes are omitted. `exposed_assets` is the union of sensitive nodes
reachable from any source, including sensitive servers or devices.
`protected_assets` lists baseline-exposed assets unreachable from **all** sources
after the simulation; a longer alternate path does not count as protection.

BFS returns one minimum-hop path per source/target, breaking ties by ascending
edge ID. Node and target lists are lexicographically sorted; source and simulation
order follows the request. BFS traversal takes O(V + E) per source. Reconstructing
and serializing paths additionally costs the total number of emitted path steps;
path output can be quadratic on long chains with many sensitive nodes. Each
simulation repeats analysis with its own filtered adjacency lists. The engine
does not enumerate all attack paths, compute weighted risk, or infer permissions.

## Remaining MVP work

Add a thin FastAPI adapter that invokes the engine with process timeouts and
request-size limits, then a React Flow UI for graph display, source selection,
shortest-path highlighting, and permission-revocation comparisons. Add adapter/UI
tests and deployment instructions. These layers should reuse this JSON contract
and keep graph analysis in C++.
