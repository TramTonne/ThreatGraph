#include "threatgraph/graph.hpp"
#include <iostream>
#include <stdexcept>
#include <functional>
using threatgraph::Json;
void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void rejects(const std::function<void()>& action) {
    try { action(); } catch (const std::exception&) { return; }
    throw std::runtime_error("Expected rejection");
}
Json fixture() {
    return Json::parse(R"({
      "nodes":[{"id":"u","type":"user"},{"id":"d","type":"device"},
               {"id":"s","type":"server"},{"id":"a","type":"asset"},
               {"id":"isolated","type":"asset"}],
      "edges":[{"id":"1","source":"u","target":"d"},
               {"id":"2","source":"d","target":"a"},
               {"id":"3","source":"u","target":"s"},
               {"id":"4","source":"s","target":"a"},
               {"id":"5","source":"a","target":"u"},
               {"id":"6","source":"u","target":"u"}],
      "compromised_nodes":["u"]})");
}
int main() {
    try {
        auto input = fixture();
        auto graph = threatgraph::Graph::from_json(input);
        auto baseline = graph.analyze({"u"});
        auto path = baseline["sources"][0]["shortest_paths"][0];
        check(path["nodes"] == Json({"u", "d", "a"}), "Deterministic BFS path");
        check(path["edges"] == Json({"1", "2"}) && path["distance"] == 2, "Path edges and distance");
        check(baseline["sources"][0]["reachable_nodes"] == Json({"a", "d", "s", "u"}), "Cycles and disconnected nodes");
        check(graph.analyze({"u"}, {"2"})["sources"][0]["shortest_paths"][0]["edges"] == Json({"3", "4"}), "Alternate route");
        check(graph.analyze({"u"}, {"2", "4"})["exposed_assets"].empty(), "Cut all routes");
        check(graph.analyze({"u"}) == baseline, "Simulation preserves graph");
        auto self = graph.analyze({"isolated"})["sources"][0];
        check(self["reachable_nodes"] == Json({"isolated"}) && self["shortest_paths"][0]["distance"] == 0, "Zero-hop sensitive source");
        check(graph.analyze({"d", "isolated"})["exposed_assets"] == Json({"a", "isolated"}), "Multiple sources union");
        check(graph.analyze({})["sources"].empty(), "Empty sources");
        auto directed = fixture(); directed["edges"].erase(4);
        check(threatgraph::Graph::from_json(directed).analyze({"a"})["sources"][0]["reachable_nodes"] == Json({"a"}), "Directed edges");
        auto parallel = fixture(); parallel["edges"].push_back({{"id", "7"}, {"source", "u"}, {"target", "d"}});
        check(!threatgraph::Graph::from_json(parallel).analyze({"u"}, {"1", "4"})["exposed_assets"].empty(), "Parallel permissions");
        input["simulations"] = Json::array({{{"id", "cut"}, {"remove_edges", {"2", "4"}}}, {{"id", "noop"}, {"remove_edges", Json::array()}}});
        auto output = threatgraph::evaluate(input);
        check(output["simulations"][0]["protected_assets"] == Json({"a"}), "Protected asset delta");
        check(output["simulations"][1]["analysis"] == output["baseline"], "Independent scenarios");
        rejects([&] { graph.analyze({"unknown"}); });
        rejects([&] { graph.analyze({"u"}, {"missing"}); });
        rejects([&] { graph.analyze({"u", "u"}); });
        rejects([&] { graph.analyze({"u"}, {"1", "1"}); });
        for (int kind = 0; kind < 9; ++kind) {
            auto bad = fixture();
            switch (kind) {
            case 0: bad["nodes"].push_back(bad["nodes"][0]); break;
            case 1: bad["edges"].push_back(bad["edges"][0]); break;
            case 2: bad["edges"][0]["target"] = "missing"; break;
            case 3: bad["nodes"][0]["type"] = "invalid"; break;
            case 4: bad["nodes"][0]["sensitive"] = "yes"; break;
            case 5: bad["compromised_nodes"] = {"u", "u"}; break;
            case 6: bad["edges"][0]["id"] = ""; break;
            case 7: bad.erase("compromised_nodes"); break;
            case 8: bad["simulations"] = Json::object(); break;
            }
            rejects([&] { threatgraph::evaluate(bad); });
        }
        auto empty = threatgraph::evaluate(Json::parse(R"({"nodes":[],"edges":[],"compromised_nodes":[]})"));
        check(empty["baseline"]["exposed_assets"].empty(), "Empty graph");
        std::cout << "All engine checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
