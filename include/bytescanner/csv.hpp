#pragma once

#include "func.hpp"
#include "image.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace bscan {

struct SymbolRow {
	std::string name;
	std::string group;
	std::string signature;
	std::string siteKind;
	std::string section;
	std::string parent;
	std::string note;
	std::string typeInfo;
	std::string strings;
	std::string callees;
	uint64_t address = 0;
	uint64_t oldAddress = 0;
	AddressKind kind = AddressKind::Rva;
	uint32_t callCount = 0;
	int vtableSlot = -1;
	bool hasAddress = false;
	bool hasOldAddress = false;
};

struct WorkResult {
	SymbolRow row;
	std::string status;
	std::string error;
	size_t hits = 0;
};

struct CsvFile {
	std::vector<SymbolRow> rows;
	bool hasSignatureColumn = false;
};

CsvFile parseCsv(std::string_view text);
CsvFile loadCsv(const std::string& path);
std::vector<SymbolRow> parseOffsetList(std::string_view text, std::string_view group = "Functions");
struct ResultSummary {
	size_t work = 0;
	size_t exact = 0;
	size_t resolved = 0;
	size_t ambiguous = 0;
	size_t missing = 0;
	size_t error = 0;
	double confidence = 0;
};

std::string formatCsv(const std::vector<SymbolRow>& rows, bool withSig, bool withStatus,
	const std::vector<std::string>& status = {}, const std::vector<size_t>& hits = {});
std::string formatResults(const std::vector<WorkResult>& results);
ResultSummary summarize(const std::vector<WorkResult>& results);
std::string formatSummary(const ResultSummary& s);
std::string formatJson(const std::vector<WorkResult>& results, const ResultSummary& sum, bool withNew);
std::string jsonPathFromOut(const std::string& outPath);
void fillRowSite(SymbolRow& row, const Binary& bin, const SiteInfo& info, AddressKind emitKind);
void applyFingerprint(SymbolRow& row, const Fingerprint& fp);
Fingerprint hintsFromRow(const SymbolRow& row);
bool rowHasHints(const SymbolRow& row);

}
