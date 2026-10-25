# ThreatGraph

A cybersecurity attack-path explorer. This first milestone implements the C++20
analysis engine, JSON CLI, synthetic networks, and automated tests. A thin FastAPI
backend and React/TypeScript/React Flow dashboard complete the local MVP.

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
- `backend/`: Pydantic models, FastAPI subprocess adapter, and API tests
- `frontend/`: Vite, React, Tailwind CSS, React Flow dashboard, and frontend tests

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

Public deployment, authentication, raw request/output byte limits, and concurrency
controls remain outside this local MVP. See the backend limitations below.

## FastAPI backend (Phase 2)

Run these commands from the repository root after building the engine:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-dev.txt
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python -m uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
curl --fail-with-body http://127.0.0.1:8000/api/analyze \
  -H 'Content-Type: application/json' \
  --data-binary @examples/api-analyze.json
```

Interactive OpenAPI documentation is at `http://127.0.0.1:8000/docs`.
For runtime-only installation, use `backend/requirements.txt`.

`POST /api/analyze` accepts `nodes`, `edges`, a single `compromised_node`, and
optional `simulations` with `id` and `remove_edges`. See
`examples/api-analyze.json` for a complete request. Each simulation independently
removes its listed permission edges; submit one edge ID to revoke one permission.
The API returns the engine's versioned output unchanged in shape:
`baseline.exposed_assets`, `baseline.sources[].shortest_paths`, reachability, and
each simulation's `analysis` and `protected_assets`. The example exposes
`customer-db` along `alice → laptop → app → customer-db`; removing `db-read`
protects that asset.

Pydantic validates node types, unique IDs, references, strict ID/boolean types,
and list limits (500 nodes, 5,000 edges, 20 simulations). Extra fields are rejected
by the API. Omitting `sensitive` uses the C++ defaults; `null` is treated as omitted.
Python performs no BFS, reachability, or path comparison: it translates the source
field, launches the executable without a shell, and validates its output schema.
The synchronous route runs in FastAPI's thread pool. A subprocess timeout kills
and reaps the engine process.

Configuration, read when the app starts:

- `THREATGRAPH_ENGINE`: executable path; defaults to this repository's
  `build/threatgraph_engine`, independent of the server's working directory.
- `THREATGRAPH_TIMEOUT_SECONDS`: positive finite timeout, default `5` seconds.

CORS permits POST requests with Content-Type from `http://localhost:5173` and
`http://127.0.0.1:5173` (the Vite development server). Other origins are not allowed.

Error responses use FastAPI's `detail` envelope:

| Status | Meaning |
| --- | --- |
| 422 | Malformed JSON or request validation failure, with field details |
| 503 | Engine cannot be launched (`engine_unavailable`) |
| 504 | Engine exceeded its timeout (`engine_timeout`) |
| 502 | Nonzero engine exit (`engine_failed`) or invalid output (`invalid_engine_output`) |

Engine failures return generic messages without exposing stderr or filesystem
paths. Tests exercise the real C++ binary, request validation, subprocess failures,
stdin translation, and CORS. Build the C++ engine before running them; the integration
test fails rather than skips if the executable is missing.

This is a local MVP without authentication. Model list limits bound graph size,
but do not impose a byte limit on the raw HTTP body or subprocess output. Add
transport byte limits, concurrency controls, and authentication before public deployment.

## React dashboard (Phase 3)

Requires Node.js 22.12+ (tested with Node.js 24.10) and npm. Start the complete stack
from the repository root:

```sh
# Build the C++ executable once. It is launched per request by FastAPI;
# there is no separate C++ server to start.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel

python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements-dev.txt
.venv/bin/python -m uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. Vite uses strict port 5173 to match the backend's
development CORS configuration. The browser calls `http://127.0.0.1:8000/api/analyze`
directly; both servers must run on the same machine as the browser.

The dashboard imports the existing JSON examples from `examples/`, including
`api-analyze.json`. No copies of example networks are maintained in the frontend.
For CLI examples with multiple compromised nodes, the first node becomes the
initial selection; the UI always submits a single `compromised_node`.

Try these workflows:

1. Open **Office network**. Analysis runs automatically. Select the exposed
   customer database to highlight the engine's shortest path and exact edge IDs.
2. Select `db-read` in **Permission what-if** (or click its graph edge), then
   **Simulate removal**. The database becomes protected. The dashed permission
   remains a temporary preview; the local graph is never mutated.
3. Switch between **Baseline** and **Simulation** to compare paths and exposure.
   **Clear simulation** restores baseline analysis.
4. Choose **Redundant access**, revoke `c`, and select **Data vault**. The vault
   remains exposed through `b → d`, as returned by C++.
5. Choose a different compromised source, inspect nodes, drag nodes, zoom/pan,
   use the minimap, or filter the entity list. Changing source/network cancels
   pending requests and clears old results before rerunning analysis.

The top cards show total entities/permissions, **baseline** exposed assets, and
assets protected by the current simulation. The exposure panel and path inspector
follow the Baseline/Simulation view. A compromised sensitive source can have a
zero-hop path. Pending/error states show dashes rather than fabricated counts;
connection errors include a retry action. No paths or reachability are computed
in TypeScript. Positions, labels, and node styling are display-only; requests
preserve original IDs and include only Pydantic-approved fields.

### Frontend verification

```sh
cd frontend
npm test                     # API serialization and error handling unit tests
npm run build               # TypeScript check + production bundle in dist/
npm run test:e2e            # Browser → FastAPI → C++ integration tests
```

The browser tests require the built C++ engine and FastAPI running at port 8000.
They automatically start Vite at port 5173, or reuse an existing server. They use
Google Chrome (`channel: 'chrome'`); if Chrome is absent, install it or run
`npx playwright install chrome`. Tests verify actual returned paths, temporary
edge removal, alternate-route exposure, source changes, errors/retry, and mobile
viewport width. No backend mock is used for successful analysis tests.

To preview the production build locally, stop the Vite dev server and run
`npm run preview` from `frontend/`. It uses port 5173 for CORS compatibility;
keep FastAPI running. The UI is responsive and supports keyboard controls,
visible focus indicators, and reduced-motion preferences.
