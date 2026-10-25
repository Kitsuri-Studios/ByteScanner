#pragma once

#include "csv.hpp"
#include "pattern.hpp"
#include "scan.hpp"

namespace bscan {

struct GenOptions {
	size_t minLen = 0;
	size_t maxLen = 64;
	bool scopeAll = false;
	SigFormat format = SigFormat::Ida;
	MemBudget* mem = nullptr;
	const Logger* log = nullptr;
};

std::vector<WorkResult> generateSigs(const Binary& bin, const std::vector<SymbolRow>& rows,
	const GenOptions& opt);
Pattern generateAt(const Binary& bin, const Scanner& scanner, uint64_t fileOff, bool isData,
	const GenOptions& opt, size_t& hitsOut);

}
