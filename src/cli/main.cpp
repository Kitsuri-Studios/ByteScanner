#include "bytescanner/cli.hpp"

#include <iostream>

int main(int argc, char** argv) {
	try {
		std::vector<std::string> args;
		args.reserve(static_cast<size_t>(argc));
		for (int i = 0; i < argc; i++)
			args.emplace_back(argv[i]);
		bscan::Options opt = bscan::parseArgs(args);
		return bscan::run(opt);
	} catch (const std::exception& ex) {
		std::cerr << "error: " << ex.what() << "\n" << bscan::usage();
		return 2;
	}
}
