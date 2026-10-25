#pragma once

#include "bytescanner/func.hpp"

namespace bscan::fp {

inline bool isPrintable(uint8_t c) {
	return c >= 0x20 && c < 0x7F;
}

inline bool looksTypeInfo(std::string_view s) {
	if (s.size() < 4)
		return false;
	if (s.starts_with(".?A") || s.starts_with("_ZTS") || s.starts_with("_ZTI") || s.starts_with("_ZTV"))
		return true;
	if (s.starts_with("typeinfo for ") || s.starts_with("vtable for "))
		return true;
	return s.size() > 4 && s[0] == '.' && s.find("@@") != std::string_view::npos;
}

inline bool isCStringAt(const Binary& bin, uint64_t fileOff, size_t len) {
	if (fileOff > 0) {
		auto prev = bin.sliceFile(fileOff - 1, 1);
		if (!prev.empty() && isPrintable(prev[0]))
			return false;
	}
	auto z = bin.sliceFile(fileOff + len, 1);
	return !z.empty() && z[0] == 0;
}

inline bool isExecPtr(const Binary& bin, uint64_t fileOff) {
	auto p = bin.readPtr(fileOff);
	return p && bin.isExecVa(*p);
}

inline void packPtr(const Binary& bin, uint64_t va, uint8_t* raw, size_t n) {
	if (n == 8) {
		if (bin.isLittleEndian())
			storeLe<uint64_t>(raw, va);
		else
			storeBe<uint64_t>(raw, va);
		return;
	}
	const uint32_t w = static_cast<uint32_t>(va);
	if (bin.isLittleEndian())
		storeLe<uint32_t>(raw, w);
	else
		storeBe<uint32_t>(raw, w);
}

inline std::vector<uint64_t> findNeedle(const Binary& bin, std::string_view s) {
	if (s.empty())
		return {};
	const auto hay = bin.bytes();
	return findBytes(hay, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()), 8);
}

inline std::vector<uint64_t> findPtrHitsCap(const Binary& bin, uint64_t va, size_t cap, size_t step) {
	const size_t n = bin.ptrWidth();
	uint8_t raw[8]{};
	packPtr(bin, va, raw, n);
	auto hits = findBytes(bin.bytes(), std::span<const uint8_t>(raw, n), cap, step);
	if (hits.size() >= cap)
		return hits;
	for (const auto& kv : bin.relocValues()) {
		if (kv.second != va)
			continue;
		if (contains(hits, kv.first))
			continue;
		hits.push_back(kv.first);
		if (hits.size() >= cap)
			break;
	}
	return hits;
}

inline std::vector<uint64_t> findPtrHits(const Binary& bin, uint64_t va) {
	return findPtrHitsCap(bin, va, 16, 1);
}

inline std::optional<uint64_t> pickLiteralSite(const Binary& bin, const FuncMap& map,
	const std::vector<uint64_t>& ptrs, bool wantData) {
	std::vector<uint64_t> pick;
	for (uint64_t off : ptrs) {
		auto at = bin.resolve(off, AddressKind::File);
		if (!at)
			continue;
		const bool exec = bin.isExecVa(at->va);
		if (wantData && !exec)
			pick.push_back(off);
		else if (!wantData && exec)
			pick.push_back(off);
	}
	if (pick.size() != 1)
		return std::nullopt;
	if (wantData)
		return pick[0];
	auto site = map.classifyFile(bin, pick[0]);
	if (site.hasParent)
		return site.parentFile;
	return pick[0];
}

inline std::optional<uint64_t> locateByLiteral(const Binary& bin, const FuncMap& map, std::string_view s,
	bool wantData, bool needCString, size_t minLen) {
	if (s.size() < minLen)
		return std::nullopt;
	auto strHits = findNeedle(bin, s);
	std::vector<uint64_t> bounded;
	if (needCString) {
		for (uint64_t off : strHits) {
			if (isCStringAt(bin, off, s.size()))
				bounded.push_back(off);
		}
	} else
		bounded = std::move(strHits);
	if (bounded.size() != 1)
		return std::nullopt;
	auto r = bin.resolve(bounded[0], AddressKind::File);
	if (!r)
		return std::nullopt;
	return pickLiteralSite(bin, map, findPtrHits(bin, r->va), wantData);
}

} // namespace bscan::fp
