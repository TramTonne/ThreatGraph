import json
from pathlib import Path
import subprocess
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from backend.app import ROOT, create_app


@pytest.fixture
def request_body():
    payload = json.loads((ROOT / "examples/office.json").read_text())
    payload["compromised_node"] = payload.pop("compromised_nodes")[0]
    return payload


def test_real_engine_matches_cpp(request_body):
    engine = ROOT / "build/threatgraph_engine"
    assert engine.is_file(), "Build the C++ engine before running API tests"
    response = TestClient(create_app(engine_path=engine)).post("/api/analyze", json=request_body)
    assert response.status_code == 200, response.text
    direct = subprocess.run([str(engine)], input=(ROOT / "examples/office.json").read_text(), text=True, capture_output=True, check=True)
    assert response.json() == json.loads(direct.stdout)
    baseline = response.json()["baseline"]
    assert baseline["exposed_assets"] == ["customer-db"]
    assert baseline["sources"][0]["shortest_paths"][0]["nodes"] == ["alice", "laptop", "app", "customer-db"]
    assert response.json()["simulations"][0]["protected_assets"] == ["customer-db"]


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(compromised_node="missing"),
    lambda p: p["nodes"].append(p["nodes"][0]),
    lambda p: p["edges"].append(p["edges"][0]),
    lambda p: p["edges"][0].update(target="missing"),
    lambda p: p["nodes"][0].update(type="invalid"),
    lambda p: p["nodes"][0].update(sensitive="yes"),
    lambda p: p["simulations"][0].update(remove_edges=["missing"]),
    lambda p: p["simulations"][0].update(remove_edges=["ssh", "ssh"]),
    lambda p: p.update(compromised_node=123),
    lambda p: p.update(unknown=True),
    lambda p: p.pop("compromised_node"),
])
def test_invalid_requests_never_launch_engine(request_body, mutation):
    mutation(request_body)
    with patch("backend.app.subprocess.run") as run:
        response = TestClient(create_app()).post("/api/analyze", json=request_body)
    assert response.status_code == 422
    run.assert_not_called()


@pytest.mark.parametrize(("outcome", "status", "code"), [
    (subprocess.TimeoutExpired("engine", 1), 504, "engine_timeout"),
    (FileNotFoundError(), 503, "engine_unavailable"),
    (PermissionError(), 503, "engine_unavailable"),
    (subprocess.CompletedProcess([], 1, '{"error":{}}', "private detail"), 502, "engine_failed"),
    (subprocess.CompletedProcess([], 0, "not json", ""), 502, "invalid_engine_output"),
    (subprocess.CompletedProcess([], 0, '{"schema_version":1}', ""), 502, "invalid_engine_output"),
])
def test_engine_failures(request_body, outcome, status, code):
    kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
    with patch("backend.app.subprocess.run", **kwargs) as run:
        response = TestClient(create_app(timeout=0.5)).post("/api/analyze", json=request_body)
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code
    assert "private detail" not in response.text
    assert run.call_args.kwargs["timeout"] == 0.5
    assert run.call_args.args[0] == [str(ROOT / "build/threatgraph_engine")]
    sent = json.loads(run.call_args.kwargs["input"])
    assert sent["compromised_nodes"] == ["alice"]
    assert "sensitive" not in sent["nodes"][0]


def test_cors_and_malformed_json():
    client = TestClient(create_app())
    allowed = client.options("/api/analyze", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    denied = client.options("/api/analyze", headers={"Origin": "https://example.com", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in denied.headers
    assert client.post("/api/analyze", content="{broken", headers={"Content-Type": "application/json"}).status_code == 422


def test_missing_binary_real(request_body):
    response = TestClient(create_app(engine_path=Path("/nonexistent/threatgraph"))).post("/api/analyze", json=request_body)
    assert response.status_code == 503
