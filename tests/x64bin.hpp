#pragma once

#include "bytescanner/relocate.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace tfix {

inline void putProlog(std::vector<uint8_t>& img, size_t at) {
	img[at] = 0x55;
	img[at + 1] = 0x48;
	img[at + 2] = 0x89;
	img[at + 3] = 0xE5;
}

inline void putCall(std::vector<uint8_t>& img, size_t at, size_t target) {
	img[at] = 0xE8;
	const int32_t rel = static_cast<int32_t>(target - (at + 5));
	std::memcpy(img.data() + at + 1, &rel, 4);
}

inline void putLea(std::vector<uint8_t>& img, size_t at, size_t target) {
	img[at] = 0x48;
	img[at + 1] = 0x8D;
	img[at + 2] = 0x05;
	const int32_t rel = static_cast<int32_t>(target - (at + 7));
	std::memcpy(img.data() + at + 3, &rel, 4);
}

inline void putCalls(std::vector<uint8_t>& img, size_t at, int n, size_t target0) {
	putProlog(img, at);
	for (int i = 0; i < n; i++)
		putCall(img, at + 4 + static_cast<size_t>(i) * 5, target0 + static_cast<size_t>(i) * 8);
	img[at + 4 + static_cast<size_t>(n) * 5] = 0xC3;
}

inline void putTagged(std::vector<uint8_t>& img, size_t at, uint8_t tag) {
	putProlog(img, at);
	img[at + 4] = 0xB8;
	img[at + 5] = tag;
	img[at + 6] = 0;
	img[at + 7] = 0;
	img[at + 8] = 0;
	img[at + 9] = 0xC3;
}

inline void put64(std::vector<uint8_t>& img, size_t at, uint64_t v) {
	std::memcpy(img.data() + at, &v, 8);
}

inline void putU32(std::vector<uint8_t>& img, size_t at, uint32_t w) {
	img[at] = static_cast<uint8_t>(w);
	img[at + 1] = static_cast<uint8_t>(w >> 8);
	img[at + 2] = static_cast<uint8_t>(w >> 16);
	img[at + 3] = static_cast<uint8_t>(w >> 24);
}

inline void putCstr(std::vector<uint8_t>& img, size_t at, const char* s) {
	std::memcpy(img.data() + at, s, std::strlen(s) + 1);
}

inline bscan::Binary loadX64(std::vector<uint8_t> img) {
	return bscan::Binary::loadBytes(std::move(img), bscan::Arch::X64);
}

inline bscan::Binary loadArm64(std::vector<uint8_t> img) {
	return bscan::Binary::loadBytes(std::move(img), bscan::Arch::Arm64);
}

inline void splitExecData(bscan::Binary& b, uint64_t split) {
	b.clearSections();
	bscan::Section ex;
	ex.name = ".text";
	ex.fileSize = split;
	ex.virtSize = split;
	ex.isExec = true;
	bscan::Section dt;
	dt.name = ".rdata";
	dt.va = split;
	dt.fileOffset = split;
	dt.fileSize = b.bytes().size() - split;
	dt.virtSize = dt.fileSize;
	dt.isExec = false;
	b.addSection(ex);
	b.addSection(dt);
}

inline bscan::SymbolRow fileRow(std::string name, uint64_t addr, std::string sig = {}) {
	bscan::SymbolRow r;
	r.name = std::move(name);
	r.address = addr;
	r.hasAddress = true;
	r.kind = bscan::AddressKind::File;
	r.group = "Functions";
	r.signature = std::move(sig);
	return r;
}

inline bscan::FindOptions hunt(const bscan::Binary* origin, bool fuzz = false) {
	bscan::FindOptions fo;
	fo.scopeAll = true;
	fo.origin = origin;
	fo.fuzz = fuzz;
	return fo;
}

inline bscan::GenOptions genAll(size_t minLen = 5, size_t maxLen = 32) {
	bscan::GenOptions g;
	g.minLen = minLen;
	g.maxLen = maxLen;
	g.scopeAll = true;
	return g;
}

inline std::vector<uint8_t> cc(size_t n) {
	return std::vector<uint8_t>(n, 0xCC);
}

inline std::vector<uint8_t> zeros(size_t n) {
	return std::vector<uint8_t>(n, 0);
}

}
