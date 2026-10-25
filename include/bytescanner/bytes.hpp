#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <climits>

namespace bscan {

constexpr char kHexDigits[] = "0123456789ABCDEF";

constexpr bool isAsciiSpace(unsigned char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

constexpr char asciiLower(char c) {
	return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

inline std::string asciiLowerCopy(std::string s) {
	for (char& c : s)
		c = asciiLower(c);
	return s;
}

constexpr int hexNibble(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

template<class T>
constexpr T loadLe(const uint8_t* p) {
	T v = 0;
	for (size_t i = 0; i < sizeof(T); i++)
		v |= static_cast<T>(static_cast<T>(p[i]) << (8 * i));
	return v;
}

template<class T>
constexpr T loadBe(const uint8_t* p) {
	T v = 0;
	for (size_t i = 0; i < sizeof(T); i++)
		v = static_cast<T>((v << 8) | p[i]);
	return v;
}

template<class T>
constexpr void storeLe(uint8_t* p, T v) {
	for (size_t i = 0; i < sizeof(T); i++)
		p[i] = static_cast<uint8_t>(v >> (8 * i));
}

template<class T>
constexpr void storeBe(uint8_t* p, T v) {
	for (size_t i = 0; i < sizeof(T); i++)
		p[i] = static_cast<uint8_t>(v >> (8 * (sizeof(T) - 1 - i)));
}

constexpr uint16_t loadU16le(const uint8_t* p) {
	return loadLe<uint16_t>(p);
}

constexpr uint32_t loadU32le(const uint8_t* p) {
	return loadLe<uint32_t>(p);
}

constexpr uint64_t loadU64le(const uint8_t* p) {
	return loadLe<uint64_t>(p);
}

constexpr uint16_t loadU16be(const uint8_t* p) {
	return loadBe<uint16_t>(p);
}

constexpr uint32_t loadU32be(const uint8_t* p) {
	return loadBe<uint32_t>(p);
}

constexpr uint64_t loadU64be(const uint8_t* p) {
	return loadBe<uint64_t>(p);
}

constexpr uint16_t loadU16(const uint8_t* p, bool be) {
	return be ? loadU16be(p) : loadU16le(p);
}

constexpr uint32_t loadU32(const uint8_t* p, bool be) {
	return be ? loadU32be(p) : loadU32le(p);
}

constexpr uint64_t loadU64(const uint8_t* p, bool be) {
	return be ? loadU64be(p) : loadU64le(p);
}

constexpr bool inRange(size_t off, size_t n, size_t cap) {
	return n <= cap && off <= cap - n;
}

inline std::span<const uint8_t> subspan(std::span<const uint8_t> s, size_t off, size_t n) {
	if (!inRange(off, n, s.size()))
		return {};
	return s.subspan(off, n);
}

template<class C, class T>
constexpr bool contains(const C& c, const T& v) {
	for (const auto& x : c) {
		if (x == v)
			return true;
	}
	return false;
}

template<class C, class T>
void pushUnique(C& c, T v) {
	if (!contains(c, v))
		c.push_back(std::move(v));
}

inline std::string join(const std::vector<std::string>& v, char sep) {
	std::string out;
	for (size_t i = 0; i < v.size(); i++) {
		if (i)
			out.push_back(sep);
		out += v[i];
	}
	return out;
}

inline std::vector<std::string> splitAny(std::string_view s, std::string_view seps) {
	std::vector<std::string> out;
	std::string cur;
	for (char c : s) {
		if (seps.find(c) != std::string_view::npos) {
			if (!cur.empty())
				out.push_back(std::move(cur));
			cur.clear();
		} else
			cur.push_back(c);
	}
	if (!cur.empty())
		out.push_back(std::move(cur));
	return out;
}

inline std::vector<uint64_t> findBytes(std::span<const uint8_t> hay, std::span<const uint8_t> needle, size_t cap,
	size_t step = 1) {
	std::vector<uint64_t> hits;
	if (needle.empty() || hay.size() < needle.size() || step == 0)
		return hits;
	if (step == 1) {
		const uint8_t* p0 = hay.data();
		const uint8_t* end = p0 + hay.size();
		const uint8_t* cur = p0;
		while (hits.size() < cap) {
			const size_t left = static_cast<size_t>(end - cur);
			if (left < needle.size())
				break;
			const uint8_t* hit = static_cast<const uint8_t*>(
				std::memchr(cur, needle[0], left - needle.size() + 1));
			if (!hit)
				break;
			if (std::memcmp(hit, needle.data(), needle.size()) == 0)
				hits.push_back(static_cast<uint64_t>(hit - p0));
			cur = hit + 1;
		}
		return hits;
	}
	for (size_t i = 0; i + needle.size() <= hay.size(); i += step) {
		if (hay[i] != needle[0])
			continue;
		if (std::memcmp(hay.data() + i, needle.data(), needle.size()) != 0)
			continue;
		hits.push_back(i);
		if (hits.size() >= cap)
			break;
	}
	return hits;
}

class ScanError : public std::runtime_error {
public:
	explicit ScanError(const std::string& msg) : std::runtime_error(msg) {}
};

std::vector<uint8_t> readFileBytes(const std::string& path);
void writeTextFile(const std::string& path, const std::string& text);

uint64_t parseHexU64(std::string_view s);
std::string formatHex(uint64_t v, bool prefix = true);

}
