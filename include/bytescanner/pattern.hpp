#pragma once

#include "bytes.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace bscan {

enum class SigFormat {
	Ida,
	X64dbg,
};

struct Pattern {
	std::vector<uint8_t> bytes;
	std::vector<uint8_t> mask;

	constexpr size_t size() const { return bytes.size(); }
	constexpr bool empty() const { return bytes.empty(); }

	constexpr bool hasExact() const {
		for (uint8_t m : mask) {
			if (m != 0)
				return true;
		}
		return false;
	}

	constexpr bool hasPartialMask() const {
		for (uint8_t m : mask) {
			if (m != 0 && m != 0xFF)
				return true;
		}
		return false;
	}

	constexpr bool matches(std::span<const uint8_t> data) const {
		if (data.size() < bytes.size())
			return false;
		for (size_t i = 0; i < bytes.size(); i++) {
			if ((data[i] & mask[i]) != (bytes[i] & mask[i]))
				return false;
		}
		return true;
	}

	constexpr void append(uint8_t byte, uint8_t byteMask) {
		bytes.push_back(static_cast<uint8_t>(byte & byteMask));
		mask.push_back(byteMask);
	}

	constexpr void clear() {
		bytes.clear();
		mask.clear();
	}
};

namespace detail {

constexpr void skipSpace(std::string_view& s) {
	while (!s.empty() && isAsciiSpace(static_cast<unsigned char>(s.front())))
		s.remove_prefix(1);
}

constexpr bool allCompact(std::string_view s) {
	if (s.size() < 2 || (s.size() % 2) != 0)
		return false;
	for (size_t i = 0; i < s.size(); i += 2) {
		const char a = s[i];
		const char b = s[i + 1];
		const bool pairWild = (a == '?' && b == '?');
		const bool hex = hexNibble(a) >= 0 && hexNibble(b) >= 0;
		const bool nibble = (hexNibble(a) >= 0 && b == '?') || (a == '?' && hexNibble(b) >= 0);
		if (!pairWild && !hex && !nibble)
			return false;
	}
	return true;
}

constexpr void appendCell(Pattern& p, std::string_view cell) {
	if (cell.empty())
		return;
	if (cell == "?" || cell == "??") {
		p.append(0, 0);
		return;
	}
	if (cell.size() == 2 && cell[0] == '?' && hexNibble(cell[1]) >= 0) {
		p.append(static_cast<uint8_t>(hexNibble(cell[1])), 0x0F);
		return;
	}
	if (cell.size() == 2 && cell[1] == '?' && hexNibble(cell[0]) >= 0) {
		p.append(static_cast<uint8_t>(hexNibble(cell[0]) << 4), 0xF0);
		return;
	}
	if (cell.size() == 2 && hexNibble(cell[0]) >= 0 && hexNibble(cell[1]) >= 0) {
		p.append(static_cast<uint8_t>((hexNibble(cell[0]) << 4) | hexNibble(cell[1])), 0xFF);
		return;
	}
	throw ScanError("bad pattern cell " + std::string(cell));
}

inline std::string stripCBytes(std::string_view s) {
	std::string out;
	out.reserve(s.size());
	for (size_t i = 0; i < s.size();) {
		if (s[i] == '\\' && i + 3 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
			out.push_back(s[i + 2]);
			out.push_back(s[i + 3]);
			out.push_back(' ');
			i += 4;
			continue;
		}
		if (s[i] == '0' && i + 3 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
			out.push_back(s[i + 2]);
			out.push_back(s[i + 3]);
			out.push_back(' ');
			i += 4;
			continue;
		}
		if (s[i] == ',' || s[i] == ';' || s[i] == '|') {
			out.push_back(' ');
			i++;
			continue;
		}
		out.push_back(s[i]);
		i++;
	}
	return out;
}

} // namespace detail

inline Pattern parsePattern(std::string_view text) {
	std::string cleaned = detail::stripCBytes(text);
	std::string_view s = cleaned;
	detail::skipSpace(s);
	if (s.empty())
		throw ScanError("empty pattern");
	Pattern p;
	if (s.find(' ') == std::string_view::npos && detail::allCompact(s)) {
		while (!s.empty()) {
			detail::appendCell(p, s.substr(0, 2));
			s.remove_prefix(2);
		}
	} else {
		while (!s.empty()) {
			detail::skipSpace(s);
			if (s.empty())
				break;
			size_t n = 0;
			while (n < s.size() && !isAsciiSpace(static_cast<unsigned char>(s[n])))
				n++;
			detail::appendCell(p, s.substr(0, n));
			s.remove_prefix(n);
		}
	}
	if (p.empty())
		throw ScanError("empty pattern");
	if (!p.hasExact())
		throw ScanError("pattern needs an exact byte");
	return p;
}

template<size_t N>
struct PatternLit {
	char v[N]{};
	constexpr PatternLit(const char (&s)[N]) {
		for (size_t i = 0; i < N; i++)
			v[i] = s[i];
	}
};

template<PatternLit S>
Pattern compilePattern() {
	return parsePattern(std::string_view(S.v, sizeof(S.v) - 1));
}

std::string formatPattern(const Pattern& p, SigFormat fmt = SigFormat::Ida);
SigFormat parseSigFormat(std::string_view s);
std::string_view sigFormatName(SigFormat f);

}
