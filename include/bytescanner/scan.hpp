#pragma once

#include "image.hpp"
#include "mem.hpp"
#include "pattern.hpp"

namespace bscan {

struct Match {
	uint64_t fileOffset = 0;
	uint64_t va = 0;
	uint64_t rva = 0;
};

struct PackedRange {
	uint32_t packedOff = 0;
	uint32_t length = 0;
	uint64_t va = 0;
	uint64_t fileOffset = 0;
};

class Scanner {
public:
	Scanner(const Binary& bin, bool scopeAll);
	Scanner(const Binary& bin, bool scopeAll, MemBudget* mem, const Logger* log);
	Scanner(const Scanner&) = delete;
	Scanner& operator=(const Scanner&) = delete;
	Scanner(Scanner&& o) noexcept;
	Scanner& operator=(Scanner&& o) noexcept;
	~Scanner();

	size_t count(const Pattern& p, size_t limit) const;
	std::vector<Match> find(const Pattern& p, size_t limit) const;
	Match toMatch(uint32_t packedOff) const;
	bool containsFileOffset(uint64_t fileOffset) const;
	bool hasIndex() const { return !positions_.empty(); }
	const std::vector<PackedRange>& ranges() const { return ranges_; }

private:
	const uint8_t* data_ = nullptr;
	size_t dataSize_ = 0;
	std::vector<PackedRange> ranges_;
	std::vector<uint32_t> positions_;
	std::vector<uint32_t> heads_;
	MemBudget* mem_ = nullptr;
	uint64_t reserved_ = 0;
	uint64_t imageBase_ = 0;
	uint32_t packedLen_ = 0;

	void buildRanges(const Binary& bin, bool scopeAll);
	void buildIndex(const Logger* log);
	void releaseIndex();
	uint8_t byteAt(uint32_t packedOff) const;
	std::span<const uint8_t> spanAt(uint32_t packedOff, size_t n) const;
	const PackedRange* rangeAt(uint32_t packedOff) const;
	bool seed(const Pattern& p, std::vector<uint32_t>& out) const;
	void refine(const Pattern& p, std::vector<uint32_t>& cand, size_t limit) const;
	void scanHybrid(const Pattern& p, size_t limit, std::vector<Match>* hits, size_t& count) const;
};

size_t searchHybrid(std::span<const uint8_t> data, const Pattern& p);
void searchHybridN(std::span<const uint8_t> data, const Pattern& p, size_t limit, std::vector<size_t>& out);
bool patternMatches(std::span<const uint8_t> data, const Pattern& p);

}
