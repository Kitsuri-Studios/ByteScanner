#include "bytescanner/csv.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace bscan {

namespace {

std::string trim(std::string_view s) {
	while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
		s.remove_prefix(1);
	while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
		s.remove_suffix(1);
	return std::string(s);
}

std::string unquote(std::string s) {
	if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
		s = s.substr(1, s.size() - 2);
		std::string out;
		for (size_t i = 0; i < s.size(); i++) {
			if (s[i] == '"' && i + 1 < s.size() && s[i + 1] == '"') {
				out.push_back('"');
				i++;
			} else {
				out.push_back(s[i]);
			}
		}
		return out;
	}
	return s;
}

std::string quote(const std::string& s) {
	bool need = s.find_first_of(",\"\n") != std::string::npos;
	if (!need)
		return s;
	std::string out = "\"";
	for (char c : s) {
		if (c == '"')
			out += "\"\"";
		else
			out.push_back(c);
	}
	out += "\"";
	return out;
}

std::vector<std::string> splitCsvLine(std::string_view line) {
	std::vector<std::string> cells;
	std::string cur;
	bool inQ = false;
	for (size_t i = 0; i < line.size(); i++) {
		const char c = line[i];
		if (inQ) {
			if (c == '"') {
				if (i + 1 < line.size() && line[i + 1] == '"') {
					cur.push_back('"');
					i++;
				} else {
					inQ = false;
				}
			} else {
				cur.push_back(c);
			}
		} else if (c == '"') {
			inQ = true;
		} else if (c == ',') {
			cells.push_back(trim(cur));
			cur.clear();
		} else {
			cur.push_back(c);
		}
	}
	cells.push_back(trim(cur));
	return cells;
}

std::string lower(std::string s) {
	return asciiLowerCopy(std::move(s));
}

bool isHeader(const std::vector<std::string>& cells) {
	if (cells.empty())
		return false;
	return lower(cells[0]) == "name";
}

int colIndex(const std::vector<std::string>& header, const char* want) {
	for (int i = 0; i < static_cast<int>(header.size()); i++) {
		if (lower(header[i]) == want)
			return i;
	}
	return -1;
}

std::string cellAt(const std::vector<std::string>& cells, int idx) {
	if (idx < 0 || idx >= static_cast<int>(cells.size()))
		return {};
	return cells[static_cast<size_t>(idx)];
}

bool looksGroup(const std::vector<std::string>& cells) {
	if (cells.empty() || cells[0].empty())
		return false;
	if (cells.size() == 1)
		return true;
	for (size_t i = 1; i < cells.size(); i++) {
		if (!cells[i].empty())
			return false;
	}
	return true;
}

} // namespace

CsvFile parseCsv(std::string_view text) {
	CsvFile file;
	std::string group;
	std::string line;
	std::istringstream in{std::string(text)};
	bool first = true;
	std::vector<std::string> header;
	int iName = 0, iAddr = 1, iOld = -1, iNew = -1, iSig = 2, iKind = -1, iSec = -1, iPar = -1, iNote = -1;
	int iCalls = -1, iTi = -1, iStr = -1, iSlot = -1, iCal = -1;
	while (std::getline(in, line)) {
		if (!line.empty() && line.back() == '\r')
			line.pop_back();
		if (trim(line).empty())
			continue;
		auto cells = splitCsvLine(line);
		if (cells.empty() || (cells.size() == 1 && cells[0].empty()))
			continue;
		if (first && isHeader(cells)) {
			first = false;
			header = cells;
			iName = colIndex(header, "name");
			iAddr = colIndex(header, "address");
			iOld = colIndex(header, "oldaddress");
			iNew = colIndex(header, "newaddress");
			iSig = colIndex(header, "signature");
			iKind = colIndex(header, "kind");
			iSec = colIndex(header, "section");
			iPar = colIndex(header, "parent");
			iNote = colIndex(header, "note");
			iCalls = colIndex(header, "calls");
			iTi = colIndex(header, "typeinfo");
			iStr = colIndex(header, "strings");
			iSlot = colIndex(header, "vslot");
			iCal = colIndex(header, "callees");
			if (iName < 0)
				iName = 0;
			if (iAddr < 0 && iOld >= 0)
				iAddr = iOld;
			if (iSig >= 0)
				file.hasSignatureColumn = true;
			continue;
		}
		first = false;
		if (looksGroup(cells)) {
			group = unquote(cells[0]);
			SymbolRow row;
			row.name = group;
			row.group = group;
			file.rows.push_back(std::move(row));
			continue;
		}
		SymbolRow row;
		row.group = group;
		row.name = unquote(cellAt(cells, iName));
		const std::string addr = cellAt(cells, iAddr);
		if (!addr.empty()) {
			row.address = parseHexU64(addr);
			row.hasAddress = true;
		}
		const std::string oldA = cellAt(cells, iOld);
		if (!oldA.empty()) {
			row.oldAddress = parseHexU64(oldA);
			row.hasOldAddress = true;
			if (!row.hasAddress) {
				row.address = row.oldAddress;
				row.hasAddress = true;
			}
		}
		const std::string sig = iSig >= 0 ? cellAt(cells, iSig) : (cells.size() > 2 ? cells[2] : "");
		if (!sig.empty() && lower(sig) != "status") {
			row.signature = unquote(sig);
			file.hasSignatureColumn = true;
		}
		row.siteKind = unquote(cellAt(cells, iKind));
		row.section = unquote(cellAt(cells, iSec));
		row.parent = unquote(cellAt(cells, iPar));
		row.note = unquote(cellAt(cells, iNote));
		const std::string newA = cellAt(cells, iNew);
		if (!newA.empty() && !row.hasAddress) {
			row.address = parseHexU64(newA);
			row.hasAddress = true;
		}
		const std::string calls = cellAt(cells, iCalls);
		if (!calls.empty())
			row.callCount = static_cast<uint32_t>(parseHexU64(calls));
		row.typeInfo = unquote(cellAt(cells, iTi));
		row.strings = unquote(cellAt(cells, iStr));
		row.callees = unquote(cellAt(cells, iCal));
		const std::string slot = cellAt(cells, iSlot);
		if (!slot.empty())
			row.vtableSlot = static_cast<int>(parseHexU64(slot));
		file.rows.push_back(std::move(row));
	}
	return file;
}

CsvFile loadCsv(const std::string& path) {
	auto bytes = readFileBytes(path);
	std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
	return parseCsv(text);
}

std::vector<SymbolRow> parseOffsetList(std::string_view text, std::string_view group) {
	std::vector<SymbolRow> rows;
	std::string cur;
	auto flush = [&]() {
		std::string t = trim(cur);
		cur.clear();
		if (t.empty())
			return;
		SymbolRow row;
		row.group = std::string(group);
		row.address = parseHexU64(t);
		row.hasAddress = true;
		row.name = "off_" + formatHex(row.address, false);
		rows.push_back(std::move(row));
	};
	for (char c : text) {
		if (c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n')
			flush();
		else
			cur.push_back(c);
	}
	flush();
	return rows;
}

std::string formatCsv(const std::vector<SymbolRow>& rows, bool withSig, bool withStatus,
	const std::vector<std::string>& status, const std::vector<size_t>& hits) {
	std::ostringstream os;
	os << "Name,Address";
	if (withSig)
		os << ",Signature";
	if (withStatus)
		os << ",Status,Hits";
	os << "\n";
	for (size_t i = 0; i < rows.size(); i++) {
		const SymbolRow& r = rows[i];
		if (!r.hasAddress && r.signature.empty()) {
			os << quote(r.name) << ",\n";
			continue;
		}
		os << quote(r.name) << ",";
		if (r.hasAddress)
			os << formatHex(r.address);
		if (withSig) {
			os << "," << quote(r.signature);
		}
		if (withStatus) {
			os << ",";
			if (i < status.size())
				os << quote(status[i]);
			os << ",";
			if (i < hits.size())
				os << hits[i];
			else
				os << 0;
		}
		os << "\n";
	}
	return os.str();
}

std::string formatResults(const std::vector<WorkResult>& results) {
	const bool hasSignature = std::any_of(results.begin(), results.end(),
		[](const WorkResult& r) { return !r.row.signature.empty(); });
	std::ostringstream os;
	os << "Name,Address";
	if (hasSignature)
		os << ",Signature";
	os << "\n";
	for (const WorkResult& r : results) {
		const SymbolRow& row = r.row;
		if (r.status == "group" || (!row.hasAddress && row.signature.empty() && row.name == row.group)) {
			os << quote(row.name) << ",\n";
			continue;
		}
		os << quote(row.name) << ",";
		if (row.hasAddress)
			os << formatHex(row.address);
		if (hasSignature)
			os << "," << quote(row.signature);
		os << "\n";
	}
	return os.str();
}

ResultSummary summarize(const std::vector<WorkResult>& results) {
	ResultSummary s;
	for (const WorkResult& r : results) {
		if (r.status == "group")
			continue;
		s.work++;
		if (r.status == "unique" || r.status == "matched")
			s.exact++;
		else if (r.status == "resolved")
			s.resolved++;
		else if (r.status == "ambiguous")
			s.ambiguous++;
		else if (r.status == "error" || r.status == "out_of_range" || r.status == "missing")
			s.error++;
		else
			s.missing++;
	}
	if (s.work)
		s.confidence = 100.0 * static_cast<double>(s.exact + s.resolved) / static_cast<double>(s.work);
	return s;
}

std::string formatSummary(const ResultSummary& s) {
	char buf[192];
	std::snprintf(buf, sizeof(buf),
		"done exact=%zu resolved=%zu ambiguous=%zu missing=%zu error=%zu confidence=%.1f%%",
		s.exact, s.resolved, s.ambiguous, s.missing, s.error, s.confidence);
	return buf;
}

std::string jsonPathFromOut(const std::string& outPath) {
	if (outPath.empty() || outPath == "-")
		return {};
	const size_t slash = outPath.find_last_of("/\\");
	const size_t dot = outPath.find_last_of('.');
	if (dot != std::string::npos && (slash == std::string::npos || dot > slash))
		return outPath.substr(0, dot) + ".json";
	return outPath + ".json";
}

} // namespace

namespace {

std::string jsonStr(std::string_view s) {
	std::string o = "\"";
	for (unsigned char c : s) {
		if (c == '"')
			o += "\\\"";
		else if (c == '\\')
			o += "\\\\";
		else if (c == '\n')
			o += "\\n";
		else if (c == '\r')
			o += "\\r";
		else if (c == '\t')
			o += "\\t";
		else if (c < 0x20) {
			char buf[8];
			std::snprintf(buf, sizeof(buf), "\\u%04x", c);
			o += buf;
		} else
			o.push_back(static_cast<char>(c));
	}
	o += '"';
	return o;
}

std::string jsonHex(uint64_t v, bool ok) {
	if (!ok)
		return "null";
	return jsonStr(bscan::formatHex(v));
}

void jsonList(std::ostringstream& os, std::string_view joined) {
	os << "[";
	bool first = true;
	std::string cur;
	auto flush = [&]() {
		if (cur.empty())
			return;
		if (!first)
			os << ",";
		first = false;
		os << jsonStr(cur);
		cur.clear();
	};
	for (char c : joined) {
		if (c == ';' || c == '|')
			flush();
		else
			cur.push_back(c);
	}
	flush();
	os << "]";
}

} // namespace

namespace bscan {

std::string formatJson(const std::vector<WorkResult>& results, const ResultSummary& sum, bool withNew) {
	std::ostringstream os;
	os << "{\n  \"summary\": {\n";
	os << "    \"work\": " << sum.work << ",\n";
	os << "    \"exact\": " << sum.exact << ",\n";
	os << "    \"resolved\": " << sum.resolved << ",\n";
	os << "    \"ambiguous\": " << sum.ambiguous << ",\n";
	os << "    \"missing\": " << sum.missing << ",\n";
	os << "    \"error\": " << sum.error << ",\n";
	os << "    \"relocated\": " << (withNew ? "true" : "false") << ",\n";
	char pct[32];
	std::snprintf(pct, sizeof(pct), "%.1f", sum.confidence);
	os << "    \"confidence\": " << pct << "\n";
	os << "  },\n  \"rows\": [\n";
	bool first = true;
	for (const WorkResult& r : results) {
		if (!first)
			os << ",\n";
		first = false;
		const SymbolRow& row = r.row;
		os << "    {\n";
		os << "      \"name\": " << jsonStr(row.name) << ",\n";
		os << "      \"group\": " << jsonStr(row.group) << ",\n";
		os << "      \"status\": " << jsonStr(r.status) << ",\n";
		os << "      \"hits\": " << r.hits << ",\n";
		os << "      \"address\": " << jsonHex(row.address, row.hasAddress) << ",\n";
		os << "      \"oldAddress\": " << jsonHex(row.oldAddress, row.hasOldAddress) << ",\n";
		os << "      \"signature\": " << jsonStr(row.signature) << ",\n";
		os << "      \"kind\": " << jsonStr(row.siteKind) << ",\n";
		os << "      \"section\": " << jsonStr(row.section) << ",\n";
		os << "      \"parent\": " << jsonStr(row.parent) << ",\n";
		os << "      \"calls\": " << row.callCount << ",\n";
		os << "      \"typeInfo\": " << jsonStr(row.typeInfo) << ",\n";
		os << "      \"strings\": ";
		jsonList(os, row.strings);
		os << ",\n";
		if (row.vtableSlot >= 0)
			os << "      \"vslot\": " << row.vtableSlot << ",\n";
		else
			os << "      \"vslot\": null,\n";
		os << "      \"callees\": ";
		jsonList(os, row.callees);
		os << ",\n";
		os << "      \"note\": " << jsonStr(row.note) << ",\n";
		os << "      \"error\": " << jsonStr(r.error) << "\n";
		os << "    }";
	}
	os << "\n  ]\n}\n";
	return os.str();
}

}
