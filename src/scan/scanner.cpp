#include "bytescanner/scan.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <string>

namespace bscan {

namespace {

constexpr uint32_t kHeads = 65537;

} // namespace

Scanner::Scanner(const Binary& bin, bool scopeAll) : Scanner(bin, scopeAll, nullptr, nullptr) {}

Scanner::Scanner(const Binary& bin, bool scopeAll, MemBudget* mem, const Logger* log)
	: mem_(mem), imageBase_(bin.imageBase()) {
	data_ = bin.bytes().data();
	dataSize_ = bin.bytes().size();
	buildRanges(bin, scopeAll);
	buildIndex(log);
}

Scanner::Scanner(Scanner&& o) noexcept
	: data_(o.data_), dataSize_(o.dataSize_), ranges_(std::move(o.ranges_)),
	  positions_(std::move(o.positions_)), heads_(std::move(o.heads_)), mem_(o.mem_),
	  reserved_(o.reserved_), imageBase_(o.imageBase_), packedLen_(o.packedLen_) {
	o.mem_ = nullptr;
	o.reserved_ = 0;
	o.data_ = nullptr;
	o.packedLen_ = 0;
}

Scanner& Scanner::operator=(Scanner&& o) noexcept {
	if (this == &o)
		return *this;
	releaseIndex();
	data_ = o.data_;
	dataSize_ = o.dataSize_;
	ranges_ = std::move(o.ranges_);
	positions_ = std::move(o.positions_);
	heads_ = std::move(o.heads_);
	mem_ = o.mem_;
	reserved_ = o.reserved_;
	imageBase_ = o.imageBase_;
	packedLen_ = o.packedLen_;
	o.mem_ = nullptr;
	o.reserved_ = 0;
	o.data_ = nullptr;
	o.packedLen_ = 0;
	return *this;
}

Scanner::~Scanner() {
	releaseIndex();
}

void Scanner::releaseIndex() {
	positions_.clear();
	heads_.clear();
	if (mem_ && reserved_) {
		mem_->release(reserved_);
		reserved_ = 0;
	}
}

void Scanner::buildRanges(const Binary& bin, bool scopeAll) {
	uint32_t packed = 0;
	for (const Section& s : bin.sections()) {
		if (!scopeAll && !s.isExec)
			continue;
		if (s.fileSize == 0)
			continue;
		if (s.fileOffset >= bin.bytes().size())
			continue;
		const uint32_t n = static_cast<uint32_t>(
			std::min<uint64_t>(s.fileSize, bin.bytes().size() - s.fileOffset));
		if (n == 0)
			continue;
		PackedRange r;
		r.packedOff = packed;
		r.length = n;
		r.va = s.va;
		r.fileOffset = s.fileOffset;
		ranges_.push_back(r);
		packed += n;
	}
	packedLen_ = packed;
}

uint8_t Scanner::byteAt(uint32_t packedOff) const {
	const PackedRange* r = rangeAt(packedOff);
	if (!r)
		return 0;
	const uint64_t fo = r->fileOffset + (packedOff - r->packedOff);
	if (fo >= dataSize_)
		return 0;
	return data_[static_cast<size_t>(fo)];
}

std::span<const uint8_t> Scanner::spanAt(uint32_t packedOff, size_t n) const {
	const PackedRange* r = rangeAt(packedOff);
	if (!r)
		return {};
	const uint32_t delta = packedOff - r->packedOff;
	if (delta + n > r->length)
		return {};
	const uint64_t fo = r->fileOffset + delta;
	if (fo + n > dataSize_)
		return {};
	return std::span<const uint8_t>(data_ + static_cast<size_t>(fo), n);
}

void Scanner::buildIndex(const Logger* log) {
	if (packedLen_ < 2)
		return;
	const uint64_t need = static_cast<uint64_t>(packedLen_ - 1) * sizeof(uint32_t);
	if (mem_ && !mem_->tryReserve(need)) {
		if (log)
			log->info(std::string("scan index skip need=") + formatMem(need) + " left="
				+ formatMem(mem_->left()));
		return;
	}
	if (mem_)
		reserved_ = need;
	try {
		heads_.assign(kHeads, 0);
		const uint32_t n = packedLen_ - 1;
		auto eachPair = [&](auto&& fn) {
			for (const PackedRange& r : ranges_) {
				if (r.length < 2 || r.fileOffset >= dataSize_)
					continue;
				const uint32_t len = static_cast<uint32_t>(
					std::min<uint64_t>(r.length, dataSize_ - r.fileOffset));
				if (len < 2)
					continue;
				const uint8_t* p = data_ + static_cast<size_t>(r.fileOffset);
				for (uint32_t i = 0; i + 1 < len; i++)
					fn(r.packedOff + i, p[i], p[i + 1]);
			}
		};
		eachPair([&](uint32_t, uint8_t a, uint8_t b) {
			const uint16_t key = static_cast<uint16_t>((a << 8) | b);
			heads_[key + 1]++;
		});
		for (uint32_t i = 1; i < kHeads; i++)
			heads_[i] += heads_[i - 1];
		positions_.assign(n, 0);
		std::vector<uint32_t> cur = heads_;
		eachPair([&](uint32_t packed, uint8_t a, uint8_t b) {
			const uint16_t key = static_cast<uint16_t>((a << 8) | b);
			positions_[cur[key]++] = packed;
		});
	} catch (const std::bad_alloc&) {
		releaseIndex();
		if (log)
			log->info("scan index oom, hybrid scan");
		return;
	}
	if (log)
		log->info(std::string("scan index ") + formatMem(need));
}

const PackedRange* Scanner::rangeAt(uint32_t packedOff) const {
	if (ranges_.empty())
		return nullptr;
	size_t lo = 0;
	size_t hi = ranges_.size();
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		const PackedRange& r = ranges_[mid];
		if (packedOff < r.packedOff)
			hi = mid;
		else if (packedOff >= r.packedOff + r.length)
			lo = mid + 1;
		else
			return &r;
	}
	return nullptr;
}

bool Scanner::containsFileOffset(uint64_t fileOffset) const {
	for (const PackedRange& r : ranges_) {
		if (fileOffset >= r.fileOffset && fileOffset < r.fileOffset + r.length)
			return true;
	}
	return false;
}

Match Scanner::toMatch(uint32_t packedOff) const {
	Match m;
	const PackedRange* r = rangeAt(packedOff);
	if (!r)
		return m;
	const uint64_t delta = packedOff - r->packedOff;
	m.fileOffset = r->fileOffset + delta;
	m.va = r->va + delta;
	m.rva = m.va - imageBase_;
	return m;
}

bool Scanner::seed(const Pattern& p, std::vector<uint32_t>& out) const {
	out.clear();
	if (!hasIndex() || p.empty() || packedLen_ < p.size())
		return false;
	size_t bestI = 0;
	uint32_t bestCost = std::numeric_limits<uint32_t>::max();
	int bestKind = 0;
	uint16_t bestKey = 0;
	uint8_t bestByte = 0;
	for (size_t i = 0; i + 1 < p.size(); i++) {
		if (p.mask[i] != 0xFF || p.mask[i + 1] != 0xFF)
			continue;
		const uint16_t key = static_cast<uint16_t>((p.bytes[i] << 8) | p.bytes[i + 1]);
		const uint32_t cost = heads_[key + 1] - heads_[key];
		if (cost < bestCost) {
			bestCost = cost;
			bestKind = 2;
			bestI = i;
			bestKey = key;
		}
	}
	for (size_t i = 0; i < p.size(); i++) {
		if (p.mask[i] != 0xFF)
			continue;
		const uint8_t b = p.bytes[i];
		const uint32_t lo = static_cast<uint32_t>(b) << 8;
		uint32_t cost = heads_[lo + 256] - heads_[lo];
		if (packedLen_ && byteAt(packedLen_ - 1) == b)
			cost++;
		if (cost < bestCost) {
			bestCost = cost;
			bestKind = 1;
			bestI = i;
			bestByte = b;
		}
	}
	if (bestKind == 0)
		return false;
	auto push = [&](uint32_t pos) {
		if (pos < bestI)
			return;
		const uint32_t off = pos - static_cast<uint32_t>(bestI);
		if (off + p.size() > packedLen_)
			return;
		const PackedRange* a = rangeAt(off);
		const PackedRange* b = rangeAt(off + static_cast<uint32_t>(p.size() - 1));
		if (!a || a != b)
			return;
		out.push_back(off);
	};
	if (bestKind == 2) {
		for (uint32_t k = heads_[bestKey]; k < heads_[bestKey + 1]; k++)
			push(positions_[k]);
	} else {
		const uint32_t lo = static_cast<uint32_t>(bestByte) << 8;
		for (uint32_t k = heads_[lo]; k < heads_[lo + 256]; k++)
			push(positions_[k]);
		if (packedLen_ && byteAt(packedLen_ - 1) == bestByte)
			push(packedLen_ - 1);
	}
	return true;
}

void Scanner::refine(const Pattern& p, std::vector<uint32_t>& cand, size_t limit) const {
	size_t w = 0;
	for (uint32_t off : cand) {
		auto sl = spanAt(off, p.size());
		if (sl.size() == p.size() && patternMatches(sl, p)) {
			cand[w++] = off;
			if (w >= limit)
				break;
		}
	}
	cand.resize(w);
}

void Scanner::scanHybrid(const Pattern& p, size_t limit, std::vector<Match>* hits, size_t& count) const {
	count = 0;
	std::vector<size_t> rel;
	for (const PackedRange& r : ranges_) {
		if (count >= limit)
			return;
		if (r.length < p.size() || r.fileOffset >= dataSize_)
			continue;
		const size_t n = std::min<size_t>(r.length, dataSize_ - static_cast<size_t>(r.fileOffset));
		std::span<const uint8_t> slice(data_ + static_cast<size_t>(r.fileOffset), n);
		rel.clear();
		searchHybridN(slice, p, limit - count, rel);
		for (size_t hit : rel) {
			count++;
			if (hits) {
				hits->push_back(toMatch(r.packedOff + static_cast<uint32_t>(hit)));
				if (hits->size() >= limit)
					return;
			} else if (count >= limit)
				return;
		}
	}
}

size_t Scanner::count(const Pattern& p, size_t limit) const {
	if (p.empty() || packedLen_ < p.size() || limit == 0)
		return 0;
	std::vector<uint32_t> cand;
	if (!seed(p, cand)) {
		size_t hits = 0;
		scanHybrid(p, limit, nullptr, hits);
		return hits;
	}
	refine(p, cand, limit);
	return cand.size();
}

std::vector<Match> Scanner::find(const Pattern& p, size_t limit) const {
	std::vector<Match> out;
	if (p.empty() || packedLen_ < p.size() || limit == 0)
		return out;
	std::vector<uint32_t> cand;
	if (seed(p, cand)) {
		std::sort(cand.begin(), cand.end());
		cand.erase(std::unique(cand.begin(), cand.end()), cand.end());
		refine(p, cand, limit);
		for (uint32_t off : cand)
			out.push_back(toMatch(off));
		return out;
	}
	size_t ignored = 0;
	scanHybrid(p, limit, &out, ignored);
	return out;
}

}
