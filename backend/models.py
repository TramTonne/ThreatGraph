"""Transport validation only. All graph analysis belongs to the C++ engine."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Identifier = Annotated[str, Field(strict=True, min_length=1, max_length=256)]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Node(Model):
    id: Identifier
    type: Literal["user", "device", "server", "asset"]
    sensitive: bool | None = Field(default=None, strict=True)


class Edge(Model):
    id: Identifier
    source: Identifier
    target: Identifier


class Simulation(Model):
    id: Identifier
    remove_edges: list[Identifier] = Field(max_length=5000)


class AnalyzeRequest(Model):
    nodes: list[Node] = Field(max_length=500)
    edges: list[Edge] = Field(max_length=5000)
    compromised_node: Identifier
    simulations: list[Simulation] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def validate_references(self) -> "AnalyzeRequest":
        def unique(values: list[str], label: str) -> set[str]:
            if len(set(values)) != len(values):
                raise ValueError(f"Duplicate {label} IDs")
            return set(values)

        nodes = unique([node.id for node in self.nodes], "node")
        edges = unique([edge.id for edge in self.edges], "edge")
        unique([sim.id for sim in self.simulations], "simulation")
        if self.compromised_node not in nodes:
            raise ValueError("compromised_node must reference an existing node")
        if any(edge.source not in nodes or edge.target not in nodes for edge in self.edges):
            raise ValueError("Edge endpoints must reference existing nodes")
        for sim in self.simulations:
            removed = unique(sim.remove_edges, "removed edge")
            if not removed <= edges:
                raise ValueError("remove_edges must reference existing edges")
        return self

    def engine_payload(self) -> dict:
        payload = self.model_dump(exclude_none=True, exclude={"compromised_node"})
        payload["compromised_nodes"] = [self.compromised_node]
        return payload


class AttackPath(Model):
    target: str
    distance: int = Field(ge=0, strict=True)
    nodes: list[str]
    edges: list[str]


class SourceAnalysis(Model):
    source: str
    reachable_nodes: list[str]
    shortest_paths: list[AttackPath]


class Analysis(Model):
    sources: list[SourceAnalysis]
    exposed_assets: list[str]


class SimulationResult(Model):
    id: str
    removed_edges: list[str]
    analysis: Analysis
    protected_assets: list[str]


class AnalyzeResponse(Model):
    schema_version: Literal[1]
    baseline: Analysis
    simulations: list[SimulationResult]
