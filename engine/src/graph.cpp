#include "threatgraph/graph.hpp"
#include <algorithm>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace threatgraph {
namespace {
void require(bool ok, const std::string& message) {
    if (!ok) throw std::invalid_argument(message);
}
std::string name(const Json& object, const char* key) {
    require(object.is_object() && object.contains(key) && object.at(key).is_string(),
            std::string("Expected string field: ") + key);
    auto value = object.at(key).get<std::string>();
    require(!value.empty(), std::string("Empty field: ") + key);
    return value;
}
std::vector<std::string> strings(const Json& value) {
    require(value.is_array(), "Expected an array of IDs");
    std::vector<std::string> result;
    std::unordered_set<std::string> seen;
    for (const auto& item : value) {
        require(item.is_string() && !item.get<std::string>().empty(), "IDs must be nonempty strings");
        auto id = item.get<std::string>();
        require(seen.insert(id).second, "Duplicate ID: " + id);
        result.push_back(id);
    }
    return result;
}
}
Graph Graph::from_json(const Json& input) {
    require(input.is_object() && input.contains("nodes") && input.at("nodes").is_array()
            && input.contains("edges") && input.at("edges").is_array(), "Expected nodes and edges arrays");
    Graph graph;
    std::unordered_set<std::string> ids, edge_ids;
    for (const auto& item : input.at("nodes")) {
        auto id = name(item, "id"), type = name(item, "type");
        require(ids.insert(id).second, "Duplicate node ID: " + id);
        require(type == "user" || type == "device" || type == "server" || type == "asset", "Invalid node type: " + type);
        require(!item.contains("sensitive") || item.at("sensitive").is_boolean(), "sensitive must be boolean");
        graph.nodes_.push_back({id, type, item.value("sensitive", type == "asset")});
    }
    for (const auto& item : input.at("edges")) {
        auto id = name(item, "id"), source = name(item, "source"), target = name(item, "target");
        require(edge_ids.insert(id).second, "Duplicate edge ID: " + id);
        require(ids.contains(source) && ids.contains(target), "Unknown edge endpoint: " + id);
        graph.edges_.push_back({id, source, target});
    }
    std::sort(graph.nodes_.begin(), graph.nodes_.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    std::sort(graph.edges_.begin(), graph.edges_.end(), [](const auto& a, const auto& b) { return a.id < b.id; });
    return graph;
}
Json Graph::analyze(const std::vector<std::string>& sources, const std::vector<std::string>& removed_edges) const {
    std::unordered_map<std::string, std::size_t> index;
    for (std::size_t i = 0; i < nodes_.size(); ++i) index.emplace(nodes_[i].id, i);
    std::unordered_set<std::string> removed, available, unique_sources;
    for (const auto& e : edges_) available.insert(e.id);
    for (const auto& id : removed_edges) {
        require(available.contains(id), "Unknown edge ID: " + id);
        require(removed.insert(id).second, "Duplicate removed edge ID: " + id);
    }
    std::vector<std::vector<const Edge*>> adjacency(nodes_.size());
    for (const auto& e : edges_) if (!removed.contains(e.id)) adjacency[index.at(e.source)].push_back(&e);
    Json analyses = Json::array();
    std::unordered_set<std::string> exposed;
    for (const auto& source : sources) {
        require(index.contains(source), "Unknown compromised node: " + source);
        require(unique_sources.insert(source).second, "Duplicate compromised node: " + source);
        std::vector<bool> visited(nodes_.size(), false);
        std::vector<const Edge*> parent(nodes_.size(), nullptr);
        std::queue<std::size_t> queue;
        auto start = index.at(source);
        visited[start] = true;
        queue.push(start);
        while (!queue.empty()) {
            auto current = queue.front(); queue.pop();
            for (const auto* edge : adjacency[current]) {
                auto next = index.at(edge->target);
                if (visited[next]) continue;
                visited[next] = true; parent[next] = edge; queue.push(next);
            }
        }
        Json reachable = Json::array(), paths = Json::array();
        for (std::size_t i = 0; i < nodes_.size(); ++i) {
            if (!visited[i]) continue;
            reachable.push_back(nodes_[i].id);
            if (!nodes_[i].sensitive) continue;
            exposed.insert(nodes_[i].id);
            std::vector<std::string> path_nodes{nodes_[i].id}, path_edges;
            auto cursor = i;
            while (cursor != start) {
                const auto* edge = parent[cursor];
                path_edges.push_back(edge->id); path_nodes.push_back(edge->source);
                cursor = index.at(edge->source);
            }
            std::reverse(path_nodes.begin(), path_nodes.end());
            std::reverse(path_edges.begin(), path_edges.end());
            paths.push_back({{"target", nodes_[i].id}, {"distance", path_edges.size()}, {"nodes", path_nodes}, {"edges", path_edges}});
        }
        analyses.push_back({{"source", source}, {"reachable_nodes", reachable}, {"shortest_paths", paths}});
    }
    std::vector<std::string> exposed_ids(exposed.begin(), exposed.end());
    std::sort(exposed_ids.begin(), exposed_ids.end());
    return {{"sources", analyses}, {"exposed_assets", exposed_ids}};
}
Json evaluate(const Json& request) {
    auto graph = Graph::from_json(request);
    require(request.contains("compromised_nodes"), "Missing compromised_nodes");
    auto sources = strings(request.at("compromised_nodes"));
    auto baseline = graph.analyze(sources);
    Json simulations = Json::array();
    std::unordered_set<std::string> simulation_ids;
    if (request.contains("simulations")) {
        require(request.at("simulations").is_array(), "simulations must be an array");
        for (const auto& simulation : request.at("simulations")) {
            auto id = name(simulation, "id");
            require(simulation_ids.insert(id).second, "Duplicate simulation ID: " + id);
            require(simulation.contains("remove_edges"), "Missing remove_edges");
            auto removed = strings(simulation.at("remove_edges"));
            auto result = graph.analyze(sources, removed);
            Json protected_assets = Json::array();
            for (const auto& asset : baseline.at("exposed_assets")) {
                const auto& remaining = result.at("exposed_assets");
                if (std::find(remaining.begin(), remaining.end(), asset) == remaining.end()) protected_assets.push_back(asset);
            }
            simulations.push_back({{"id", id}, {"removed_edges", removed}, {"analysis", result}, {"protected_assets", protected_assets}});
        }
    }
    return {{"schema_version", 1}, {"baseline", baseline}, {"simulations", simulations}};
}
}
