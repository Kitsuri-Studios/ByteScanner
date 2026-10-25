#include "bytescanner/pattern.hpp"

namespace bscan {

std::string formatPattern(const Pattern& p, SigFormat fmt) {
	std::string out;
	for (size_t i = 0; i < p.size(); i++) {
		if (i)
			out.push_back(' ');
		const uint8_t m = p.mask[i];
		const uint8_t b = p.bytes[i];
		if (m == 0)
			out += (fmt == SigFormat::Ida) ? "?" : "??";
		else if (m == 0xF0) {
			out.push_back(kHexDigits[b >> 4]);
			out.push_back('?');
		} else if (m == 0x0F) {
			out.push_back('?');
			out.push_back(kHexDigits[b & 0xF]);
		} else {
			out.push_back(kHexDigits[b >> 4]);
			out.push_back(kHexDigits[b & 0xF]);
		}
	}
	return out;
}

SigFormat parseSigFormat(std::string_view s) {
	if (s == "ida")
		return SigFormat::Ida;
	if (s == "x64dbg" || s == "x64" || s == "dbg")
		return SigFormat::X64dbg;
	throw ScanError("unknown format " + std::string(s));
}

std::string_view sigFormatName(SigFormat f) {
	return f == SigFormat::X64dbg ? "x64dbg" : "ida";
}

}
