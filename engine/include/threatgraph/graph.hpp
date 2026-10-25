#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace threatgraph {
using Json = nlohmann::json;
struct Node { std::string id; std::string type; bool sensitive; };
struct Edge { std::string id; std::string source; std::string target; };
// Immutable graph; BFS is O(V + E) per source, including path discovery.
class Graph {
public:
    static Graph from_json(const Json& input);
    Json analyze(const std::vector<std::string>& sources,
                 const std::vector<std::string>& removed_edges = {}) const;
private:
    std::vector<Node> nodes_;
    std::vector<Edge> edges_;
};
// Validates the request and runs baseline plus optional independent simulations.
Json evaluate(const Json& request);
}
