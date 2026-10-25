#include "threatgraph/graph.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        if (argc > 2) throw std::invalid_argument("Usage: threatgraph_engine [input.json|-]");
        std::ifstream file;
        std::istream* input = &std::cin;
        if (argc == 2 && std::string(argv[1]) != "-") {
            file.open(argv[1]);
            if (!file) throw std::invalid_argument("Cannot open input file");
            input = &file;
        }
        // Parse the whole stream so trailing garbage or multiple documents fail.
        std::string document((std::istreambuf_iterator<char>(*input)), {});
        auto request = threatgraph::Json::parse(document);
        auto result = threatgraph::evaluate(request);
        std::cout << result.dump(2) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cout << threatgraph::Json({{"error", {{"code", "invalid_input"}, {"message", error.what()}}}}).dump() << '\n';
        return 1;
    }
}
