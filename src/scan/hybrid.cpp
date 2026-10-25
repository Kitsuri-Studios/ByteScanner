#include "bytescanner/scan.hpp"

#include <cstring>

#if defined(__AVX2__)
#include <immintrin.h>
#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#define BSCAN_NEON 1
#endif

namespace bscan {

namespace {

#if defined(__AVX2__)
bool cmp32(const uint8_t* data, const uint8_t* sig, const uint8_t* mask) {
	const __m256i d = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data));
	const __m256i m = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(mask));
	const __m256i s = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(sig));
	const __m256i diff = _mm256_xor_si256(_mm256_and_si256(d, m), s);
	return _mm256_testz_si256(diff, diff) != 0;
}

bool cmp16(const uint8_t* data, const uint8_t* sig, const uint8_t* mask) {
	const __m128i d = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data));
	const __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(mask));
	const __m128i s = _mm_loadu_si128(reinterpret_cast<const __m128i*>(sig));
	const __m128i diff = _mm_xor_si128(_mm_and_si128(d, m), s);
	return _mm_testz_si128(diff, diff) != 0;
}
#elif defined(BSCAN_NEON)
bool cmp16(const uint8_t* data, const uint8_t* sig, const uint8_t* mask) {
	const uint64x2_t d = vandq_u64(vld1q_u64(reinterpret_cast<const uint64_t*>(data)),
		vld1q_u64(reinterpret_cast<const uint64_t*>(mask)));
	const uint64x2_t s = vld1q_u64(reinterpret_cast<const uint64_t*>(sig));
	const uint64x2_t diff = veorq_u64(d, s);
	return (vgetq_lane_u64(diff, 0) | vgetq_lane_u64(diff, 1)) == 0;
}
#endif

uint8_t anchorScore(uint8_t b) {
	if (b == 0x00 || b == 0xFF)
		return 0;
	if (b == 0x90 || b == 0xCC)
		return 1;
	return 8;
}

size_t pickAnchor(const Pattern& p) {
	size_t best = 0;
	int bestS = -1;
	for (size_t i = 0; i < p.size(); i++) {
		if (p.mask[i] != 0xFF)
			continue;
		const int s = anchorScore(p.bytes[i]);
		if (s > bestS) {
			bestS = s;
			best = i;
		}
	}
	if (bestS < 0) {
		for (size_t i = 0; i < p.size(); i++) {
			if (p.mask[i] != 0)
				return i;
		}
	}
	return best;
}

} // namespace

bool patternMatches(std::span<const uint8_t> data, const Pattern& p) {
	if (data.size() < p.size())
		return false;
	size_t j = 0;
#if defined(__AVX2__)
	for (; j + 32 <= p.size(); j += 32) {
		if (!cmp32(data.data() + j, p.bytes.data() + j, p.mask.data() + j))
			return false;
	}
	for (; j + 16 <= p.size(); j += 16) {
		if (!cmp16(data.data() + j, p.bytes.data() + j, p.mask.data() + j))
			return false;
	}
#elif defined(BSCAN_NEON)
	for (; j + 16 <= p.size(); j += 16) {
		if (!cmp16(data.data() + j, p.bytes.data() + j, p.mask.data() + j))
			return false;
	}
#endif
	for (; j + 8 <= p.size(); j += 8) {
		uint64_t dv, sv, mv;
		std::memcpy(&dv, data.data() + j, 8);
		std::memcpy(&sv, p.bytes.data() + j, 8);
		std::memcpy(&mv, p.mask.data() + j, 8);
		if ((dv & mv) != (sv & mv))
			return false;
	}
	for (; j < p.size(); j++) {
		if ((data[j] & p.mask[j]) != (p.bytes[j] & p.mask[j]))
			return false;
	}
	return true;
}

namespace {

template<class Fn>
void forEachHybrid(std::span<const uint8_t> data, const Pattern& p, Fn&& fn) {
	if (p.empty() || data.size() < p.size())
		return;
	bool hasFull = false;
	for (uint8_t m : p.mask) {
		if (m == 0xFF) {
			hasFull = true;
			break;
		}
	}
	if (!hasFull) {
		for (size_t i = 0; i + p.size() <= data.size(); i++) {
			if (patternMatches(data.subspan(i, p.size()), p) && !fn(i))
				return;
		}
		return;
	}
	const size_t anc = pickAnchor(p);
	const uint8_t needle = p.bytes[anc];
	const uint8_t* p0 = data.data();
	const uint8_t* end = p0 + data.size() - p.size() + anc + 1;
	const uint8_t* cur = p0;
	uint8_t skip[256];
	const bool useBmh = !p.hasPartialMask() && p.size() >= 4;
	size_t right = 0;
	if (useBmh) {
		for (size_t i = 0; i < p.size(); i++) {
			if (p.mask[i] == 0xFF)
				right = i;
		}
		const uint8_t def = static_cast<uint8_t>(right >= 255 ? 255 : right + 1);
		std::memset(skip, def, 256);
		for (size_t i = 0; i < right; i++) {
			if (p.mask[i] != 0xFF)
				continue;
			uint8_t sh = static_cast<uint8_t>(right - i);
			if (sh < 1)
				sh = 1;
			skip[p.bytes[i]] = sh;
		}
	}
	while (cur < end) {
		const uint8_t* hit = static_cast<const uint8_t*>(std::memchr(cur, needle, static_cast<size_t>(end - cur)));
		if (!hit)
			break;
		const size_t pos = static_cast<size_t>(hit - p0);
		if (pos < anc) {
			cur = hit + 1;
			continue;
		}
		const size_t off = pos - anc;
		if (off + p.size() > data.size())
			break;
		if (patternMatches(data.subspan(off, p.size()), p)) {
			if (!fn(off))
				return;
			cur = p0 + off + 1;
			continue;
		}
		if (useBmh) {
			uint8_t sh = skip[data[off + right]];
			if (sh == 0)
				sh = 1;
			const uint8_t* np = p0 + off + sh + anc;
			cur = np > hit + 1 ? np : hit + 1;
		} else
			cur = hit + 1;
	}
}

} // namespace

size_t searchHybrid(std::span<const uint8_t> data, const Pattern& p) {
	size_t hit = static_cast<size_t>(-1);
	forEachHybrid(data, p, [&](size_t off) {
		hit = off;
		return false;
	});
	return hit;
}

void searchHybridN(std::span<const uint8_t> data, const Pattern& p, size_t limit, std::vector<size_t>& out) {
	if (limit == 0)
		return;
	forEachHybrid(data, p, [&](size_t off) {
		out.push_back(off);
		return out.size() < limit;
	});
}

}
