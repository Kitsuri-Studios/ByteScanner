#include "bytescanner/bytes.hpp"

#include <fstream>
#include <sstream>

namespace bscan {

std::vector<uint8_t> readFileBytes(const std::string& path) {
	if (path.empty())
		throw ScanError("empty path");
	std::ifstream in(path, std::ios::binary);
	if (!in)
		throw ScanError("cannot open " + path);
	in.seekg(0, std::ios::end);
	const std::streamoff sz = in.tellg();
	if (sz < 0)
		throw ScanError("cannot size " + path);
	if (sz == 0)
		throw ScanError("empty file " + path);
	if (static_cast<uint64_t>(sz) > 0xC0000000ull)
		throw ScanError("file too big " + path);
	in.seekg(0, std::ios::beg);
	std::vector<uint8_t> out(static_cast<size_t>(sz));
	in.read(reinterpret_cast<char*>(out.data()), sz);
	if (!in)
		throw ScanError("read fail " + path);
	return out;
}

void writeTextFile(const std::string& path, const std::string& text) {
	std::ofstream out(path, std::ios::binary);
	if (!out)
		throw ScanError("cannot write " + path);
	out.write(text.data(), static_cast<std::streamsize>(text.size()));
	if (!out)
		throw ScanError("write fail " + path);
}

uint64_t parseHexU64(std::string_view s) {
	while (!s.empty() && isAsciiSpace(static_cast<unsigned char>(s.front())))
		s.remove_prefix(1);
	while (!s.empty() && isAsciiSpace(static_cast<unsigned char>(s.back())))
		s.remove_suffix(1);
	if (s.empty())
		throw ScanError("empty number");
	int base = 10;
	if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		base = 16;
		s.remove_prefix(2);
	} else if (!s.empty() && (s.find_first_of("abcdefABCDEF") != std::string_view::npos)) {
		base = 16;
	}
	if (s.empty())
		throw ScanError("bad number");
	uint64_t v = 0;
	for (char c : s) {
		int d;
		if (base == 16) {
			d = hexNibble(c);
			if (d < 0)
				throw ScanError("bad hex");
		} else {
			if (c < '0' || c > '9')
				throw ScanError("bad dec");
			d = c - '0';
		}
		if (v > (UINT64_MAX - static_cast<uint64_t>(d)) / static_cast<uint64_t>(base))
			throw ScanError("number overflow");
		v = v * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
	}
	return v;
}

std::string formatHex(uint64_t v, bool prefix) {
	std::ostringstream os;
	if (prefix)
		os << "0x";
	os << std::hex << std::uppercase << v;
	return os.str();
}

}
