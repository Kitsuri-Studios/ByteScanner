#pragma once

#include "siggen.hpp"

#include <string>
#include <vector>

namespace bscan {

enum class Command {
	None,
	Gen,
	Find,
	Help,
};

enum class ColorMode {
	Auto,
	Always,
	Never,
};

struct Options {
	Command command = Command::None;
	std::string binPath;
	std::string newPath;
	std::string oldPath;
	std::string csvPath;
	std::string outPath;
	std::string jsonPath;
	std::string offsets;
	std::string arch;
	std::string memSpec;
	GenOptions gen;
	bool findAll = false;
	bool resolveConflicts = false;
	bool fuzz = false;
	bool withStatus = true;
	bool logProgress = true;
	ColorMode color = ColorMode::Auto;
};

Options parseArgs(const std::vector<std::string>& args);
int run(const Options& opt);
std::string usage();

}
