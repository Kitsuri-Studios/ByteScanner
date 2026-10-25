#pragma once

#include "func.hpp"
#include "siggen.hpp"

namespace bscan {

struct FindOptions {
	bool scopeAll = false;
	bool findAll = false;
	bool resolveConflicts = false;
	bool fuzz = false;
	size_t resolveInsns = 24;
	size_t hitCap = 32;
	const Binary* origin = nullptr;
	MemBudget* mem = nullptr;
	const Logger* log = nullptr;
};

std::vector<WorkResult> relocateSigs(const Binary& bin, const std::vector<SymbolRow>& rows,
	const FindOptions& opt);

}
