#include "bytescanner/func.hpp"
#include "bytescanner/csv.hpp"
#include "bytescanner/mem.hpp"
#include "internal.hpp"

#include <algorithm>
#include <unordered_set>

namespace bscan {

namespace {

constexpr size_t kMaxStrings = 6;
constexpr size_t kMaxStringLen = 48;
constexpr size_t kMaxCallees = 32;
constexpr size_t kWalkInsns = 4096;

int64_t sx(uint64_t v, int bits) {
	const uint64_t m = 1ull << (bits - 1);
	return static_cast<int64_t>((v ^ m) - m);
}

bool readCString(const Binary& bin, uint64_t va, std::string& out, size_t maxLen) {
	auto r = bin.resolve(va);
	if (!r)
		return false;
	out.clear();
	for (size_t i = 0; i < maxLen + 1; i++) {
		auto sl = bin.sliceFile(r->fileOffset + i, 1);
		if (sl.empty())
			return false;
		if (sl[0] == 0)
			return out.size() >= 4 || fp::looksTypeInfo(out);
		if (!fp::isPrintable(sl[0]))
			return false;
		if (out.size() < maxLen)
			out.push_back(static_cast<char>(sl[0]));
	}
	return false;
}

void pushString(Fingerprint& fp, std::string s) {
	if (s.size() < 4 && !fp::looksTypeInfo(s))
		return;
	if (s.size() > kMaxStringLen)
		s.resize(kMaxStringLen);
	if (contains(fp.strings, s))
		return;
	if (fp::looksTypeInfo(s) && fp.typeInfo.empty())
		fp.typeInfo = s;
	if (fp.strings.size() < kMaxStrings)
		fp.strings.push_back(std::move(s));
}

void addDataTarget(const Binary& bin, Fingerprint& fp, uint64_t va) {
	fp.xrefCount++;
	std::string s;
	if (readCString(bin, va, s, kMaxStringLen)) {
		pushString(fp, std::move(s));
		return;
	}
	auto r = bin.resolve(va);
	if (!r)
		return;
	const size_t n = bin.ptrWidth();
	auto namePtr = bin.readPtr(r->fileOffset + n);
	if (namePtr && readCString(bin, *namePtr, s, kMaxStringLen))
		pushString(fp, std::move(s));
	for (size_t off : {size_t{0}, n, n * 2, size_t{12}, size_t{16}}) {
		if (readCString(bin, va + off, s, kMaxStringLen) && fp::looksTypeInfo(s)) {
			pushString(fp, std::move(s));
			return;
		}
	}
}

void refsX86(const Binary& bin, Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn,
	bool is64) {
	if (insn.length == 0 || bytes.size() < insn.length)
		return;
	const size_t i = skipX86Prefix(bytes, is64);
	if (i >= bytes.size())
		return;
	if (bytes[i] == 0xE8 && insn.length >= i + 5) {
		const int32_t rel = static_cast<int32_t>(loadU32le(bytes.data() + i + 1));
		pushUnique(fp.callees, va + insn.length + static_cast<int64_t>(rel));
		return;
	}
	size_t op = i;
	if (bytes[i] == 0x0F && i + 1 < bytes.size())
		op = i + 1;
	if (op + 1 >= insn.length)
		return;
	const uint8_t modrm = bytes[op + 1];
	if ((modrm & 0xC7) != 0x05)
		return;
	const size_t dispAt = op + 2;
	if (dispAt + 4 > insn.length || dispAt + 4 > bytes.size())
		return;
	const int32_t disp = static_cast<int32_t>(loadU32le(bytes.data() + dispAt));
	addDataTarget(bin, fp, va + insn.length + static_cast<int64_t>(disp));
}

void refsArm64(const Binary& bin, Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4)
		return;
	const uint32_t w = loadU32le(bytes.data());
	const uint32_t op26 = w >> 26;
	if (op26 == 0x25 || op26 == 0x05) {
		const int64_t imm = sx(w & 0x03FFFFFF, 26) << 2;
		if (op26 == 0x25)
			pushUnique(fp.callees, va + static_cast<uint64_t>(imm));
		return;
	}
	if ((w & 0x1F000000u) == 0x10000000u) {
		const uint32_t immlo = (w >> 29) & 3;
		const uint32_t immhi = (w >> 5) & 0x7FFFF;
		const int64_t imm = sx((static_cast<uint64_t>(immhi) << 2) | immlo, 21);
		if (w & 0x80000000u)
			addDataTarget(bin, fp, (va & ~0xFFFull) + static_cast<uint64_t>(imm << 12));
		else
			addDataTarget(bin, fp, va + static_cast<uint64_t>(imm));
	}
}

void refsArm32(Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4)
		return;
	const uint32_t w = loadU32le(bytes.data());
	if (((w >> 24) & 0x0F) != 0xB)
		return;
	const int64_t imm = sx(w & 0x00FFFFFF, 24) << 2;
	pushUnique(fp.callees, va + 8 + static_cast<uint64_t>(imm));
}

void refsThumb(Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4)
		return;
	const uint16_t h1 = loadU16le(bytes.data());
	const uint16_t h2 = loadU16le(bytes.data() + 2);
	if ((h1 & 0xF800) != 0xF000 || (h2 & 0xD000) != 0xD000)
		return;
	const int64_t s = (h1 >> 10) & 1;
	const int64_t j1 = (h2 >> 13) & 1;
	const int64_t j2 = (h2 >> 11) & 1;
	const int64_t i1 = ~(j1 ^ s) & 1;
	const int64_t i2 = ~(j2 ^ s) & 1;
	const int64_t imm = sx(
		(static_cast<uint64_t>(s) << 24) | (static_cast<uint64_t>(i1) << 23) | (static_cast<uint64_t>(i2) << 22)
			| (static_cast<uint64_t>(h1 & 0x3FF) << 12) | (static_cast<uint64_t>(h2 & 0x7FF) << 1),
		25);
	pushUnique(fp.callees, va + 4 + static_cast<uint64_t>(imm));
}

void refsMips(Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4)
		return;
	const uint32_t w = loadU32le(bytes.data());
	if ((w >> 26) != 3)
		return;
	pushUnique(fp.callees, (va & 0xF0000000ull) | (static_cast<uint64_t>(w & 0x03FFFFFF) << 2));
}

void refsRiscv(Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	if (insn.length < 4 || bytes.size() < 4)
		return;
	const uint32_t w = loadU32le(bytes.data());
	if ((w & 0x7F) != 0x6F)
		return;
	const uint32_t rd = (w >> 7) & 0x1F;
	if (rd != 1)
		return;
	const int64_t imm = sx(((w >> 31) & 1) << 20 | ((w >> 21) & 0x3FF) << 1 | ((w >> 20) & 1) << 11
			| ((w >> 12) & 0xFF) << 12,
		21);
	pushUnique(fp.callees, va + static_cast<uint64_t>(imm));
}

struct Arm64Xref {
	uint64_t page[32]{};
	uint8_t has[32]{};
};

void followArm64(const Binary& bin, Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, Arm64Xref& st) {
	if (bytes.size() < 4)
		return;
	const uint32_t w = loadU32le(bytes.data());
	if ((w & 0x1F000000u) == 0x10000000u && (w & 0x80000000u)) {
		const uint32_t rd = w & 31;
		const uint32_t immlo = (w >> 29) & 3;
		const uint32_t immhi = (w >> 5) & 0x7FFFF;
		const int64_t imm = sx((static_cast<uint64_t>(immhi) << 2) | immlo, 21);
		st.page[rd] = (va & ~0xFFFull) + static_cast<uint64_t>(imm << 12);
		st.has[rd] = 1;
		return;
	}
	if ((w & 0x7F800000u) == 0x11000000u) {
		const uint32_t rd = w & 31;
		const uint32_t rn = (w >> 5) & 31;
		const uint32_t imm12 = (w >> 10) & 0xFFF;
		const uint32_t sh = (w >> 22) & 1;
		const uint64_t add = sh ? static_cast<uint64_t>(imm12) << 12 : imm12;
		if (st.has[rn])
			addDataTarget(bin, fp, st.page[rn] + add);
		st.has[rd] = 0;
	}
}

void collectRefs(const Binary& bin, Fingerprint& fp, std::span<const uint8_t> bytes, uint64_t va, const Insn& insn) {
	switch (bin.arch()) {
	case Arch::X86:
		refsX86(bin, fp, bytes, va, insn, false);
		break;
	case Arch::X64:
		refsX86(bin, fp, bytes, va, insn, true);
		break;
	case Arch::Arm64:
		refsArm64(bin, fp, bytes, va, insn);
		break;
	case Arch::Arm32:
		refsArm32(fp, bytes, va, insn);
		break;
	case Arch::Thumb:
		refsThumb(fp, bytes, va, insn);
		break;
	case Arch::Mips32:
	case Arch::Mips64:
		refsMips(fp, bytes, va, insn);
		break;
	case Arch::Riscv32:
	case Arch::Riscv64:
		refsRiscv(fp, bytes, va, insn);
		break;
	default:
		break;
	}
}

void collectRelocPtrs(const Binary& bin, Fingerprint& fp, uint64_t from, uint64_t to) {
	const size_t n = bin.ptrWidth();
	for (uint64_t off = from; off + n <= to; off++) {
		if (!bin.isRelocByte(off))
			continue;
		if (off > from && bin.isRelocByte(off - 1))
			continue;
		auto p = bin.readPtr(off);
		if (p)
			addDataTarget(bin, fp, *p);
	}
}

void fillVtableHint(Fingerprint& fp, const Binary& bin, uint64_t fileOff) {
	auto p = bin.readPtr(fileOff);
	if (!p || !bin.isExecVa(*p))
		return;
	const size_t n = bin.ptrWidth();
	uint64_t slotOff = fileOff;
	int slot = 0;
	while (slot < 256 && slotOff >= n) {
		auto prev = bin.readPtr(slotOff - n);
		if (!prev || !bin.isExecVa(*prev))
			break;
		slotOff -= n;
		slot++;
	}
	fp.vtableSlot = slot;
	if (slotOff < n)
		return;
	auto ti = bin.readPtr(slotOff - n);
	if (!ti)
		return;
	addDataTarget(bin, fp, *ti);
}

void walkBody(const Binary& bin, Fingerprint& fp, uint64_t fileOff, uint64_t fileEnd, size_t nInsns) {
	const Arch arch = bin.arch();
	auto start = bin.resolve(fileOff, AddressKind::File);
	uint64_t va = start ? start->va : fileOff;
	size_t steps = 0;
	uint64_t off = fileOff;
	Arm64Xref a64{};
	bool pastRet = false;
	while (off < fileEnd) {
		if (pastRet && steps >= nInsns)
			break;
		if (!pastRet && steps >= kWalkInsns)
			break;
		auto sl = bin.sliceFile(off, 16);
		if (sl.empty())
			break;
		Insn insn = decodeInsn(arch, sl);
		if (insn.length == 0)
			break;
		const bool prefix = steps < nInsns;
		const bool body = !pastRet;
		if (prefix) {
			fp.keys.push_back(insn.key);
			fp.classes.push_back(static_cast<uint8_t>(insn.cls));
		}
		if (body && insn.cls == InsnClass::Call)
			fp.callCount++;
		if (body || prefix) {
			const size_t nCallee = fp.callees.size();
			collectRefs(bin, fp, sl, va, insn);
			if (!body)
				fp.callees.resize(nCallee);
			if (arch == Arch::Arm64)
				followArm64(bin, fp, sl, va, a64);
		}
		off += insn.length;
		va += insn.length;
		steps++;
		if (body && insn.cls == InsnClass::Ret)
			pastRet = true;
	}
	if (fp.callees.size() > kMaxCallees)
		fp.callees.resize(kMaxCallees);
	fp.callUnique = static_cast<uint32_t>(fp.callees.size());
}

void walkRange(const Binary& bin, const FuncMap&, Fingerprint& fp, uint64_t fileOff, size_t nInsns) {
	uint64_t bodyTo = fileOff + 0x8000;
	auto sec = bin.sectionAtFile(fileOff);
	if (sec) {
		const uint64_t secEnd = bin.sections()[*sec].fileOffset + bin.sections()[*sec].fileSize;
		if (bodyTo > secEnd)
			bodyTo = secEnd;
	} else if (bodyTo > bin.bytes().size())
		bodyTo = bin.bytes().size();
	walkBody(bin, fp, fileOff, bodyTo, nInsns);
	collectRelocPtrs(bin, fp, fileOff, bodyTo);
}

int scoreCalls(uint32_t oldC, uint32_t newC) {
	if (oldC == 0 && newC == 0)
		return 0;
	if (oldC == 0)
		return newC <= 3 ? 0 : -6;
	if ((oldC >= 4 && newC * 2 < oldC) || (oldC >= 6 && newC <= 1))
		return -40;
	if (newC > oldC * 2u + 3u)
		return -12;
	const int d = newC > oldC ? static_cast<int>(newC - oldC) : static_cast<int>(oldC - newC);
	if (d == 0)
		return 20;
	if (d <= 2)
		return 12;
	const int slack = static_cast<int>(std::max<uint32_t>(3, oldC / 4));
	if (d <= slack)
		return 6;
	return 0;
}

int scoreStrings(const Fingerprint& origin, const Fingerprint& cand) {
	int s = 0;
	if (!origin.typeInfo.empty()) {
		if (origin.typeInfo == cand.typeInfo)
			s += 40;
		else if (contains(cand.strings, origin.typeInfo))
			s += 32;
	}
	int hit = 0;
	for (const auto& a : origin.strings) {
		if (contains(cand.strings, a))
			hit++;
	}
	s += std::min(hit, 3) * 8;
	return s;
}

int scoreSlot(int a, int b) {
	if (a < 0 || b < 0)
		return 0;
	if (a == b)
		return 32;
	const int d = a > b ? a - b : b - a;
	if (d == 1)
		return 8;
	if (d <= 3)
		return 4;
	return 0;
}

} // namespace

Fingerprint makeFingerprint(const Binary& bin, const FuncMap& map, uint64_t fileOff, size_t nInsns) {
	Fingerprint fp;
	fp.site = map.classifyFile(bin, fileOff);
	if (fp.site.kind == SiteKind::Data) {
		fillVtableHint(fp, bin, fileOff);
		return fp;
	}
	walkRange(bin, map, fp, fileOff, nInsns);
	return fp;
}

void bindCalleeNames(Fingerprint& fp, const std::unordered_map<uint64_t, std::string>& names) {
	fp.calleeNames.clear();
	std::unordered_set<std::string> seen;
	for (uint64_t va : fp.callees) {
		auto it = names.find(va);
		if (it == names.end())
			continue;
		if (seen.insert(it->second).second)
			fp.calleeNames.push_back(it->second);
	}
}

int scoreWindow(const Fingerprint& origin, const Fingerprint& cand, size_t skipO, size_t skipC) {
	if (skipO >= origin.keys.size() || skipC >= cand.keys.size())
		return 0;
	const size_t n = std::min(origin.keys.size() - skipO, cand.keys.size() - skipC);
	int s = static_cast<int>(n);
	for (size_t i = 0; i < n; i++) {
		if (origin.classes[skipO + i] == cand.classes[skipC + i])
			s += 2;
		if (origin.keys[skipO + i] == cand.keys[skipC + i] && origin.keys[skipO + i] != 0)
			s += 3;
	}
	return s;
}

int scoreFingerprint(const Fingerprint& origin, const Fingerprint& cand) {
	int body = 0;
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 4; j++) {
			const int sc = scoreWindow(origin, cand, i, j);
			if (sc > body)
				body = sc;
		}
	}
	int s = body;
	if (origin.site.kind == cand.site.kind)
		s += 8;
	if (origin.site.hasParent && cand.site.hasParent) {
		if (origin.site.parentDelta == cand.site.parentDelta)
			s += 16;
		else {
			const uint64_t d = origin.site.parentDelta > cand.site.parentDelta
				? origin.site.parentDelta - cand.site.parentDelta
				: cand.site.parentDelta - origin.site.parentDelta;
			if (d < 16)
				s += 4;
		}
	}
	s += scoreCalls(origin.callCount, cand.callCount);
	s += scoreStrings(origin, cand);
	s += scoreSlot(origin.vtableSlot, cand.vtableSlot);
	return s;
}

int scoreBsim(const Fingerprint& origin, const Fingerprint& cand) {
	int oc[8]{};
	int cc[8]{};
	for (uint8_t c : origin.classes) {
		if (c < 8)
			oc[c]++;
	}
	for (uint8_t c : cand.classes) {
		if (c < 8)
			cc[c]++;
	}
	int inter = 0;
	int uni = 0;
	for (int i = 0; i < 8; i++) {
		inter += oc[i] < cc[i] ? oc[i] : cc[i];
		uni += oc[i] > cc[i] ? oc[i] : cc[i];
	}
	int s = uni ? (24 * inter) / uni : 0;
	if (!origin.strings.empty()) {
		int hit = 0;
		for (const auto& a : origin.strings) {
			if (contains(cand.strings, a))
				hit++;
		}
		s += (16 * hit) / static_cast<int>(origin.strings.size());
	}
	if (!origin.typeInfo.empty() && origin.typeInfo == cand.typeInfo)
		s += 12;
	return s;
}

int scoreNamedCallees(const Fingerprint& origin, const Fingerprint& cand,
	const std::unordered_map<std::string, uint64_t>& foundVa) {
	if (origin.calleeNames.empty() || foundVa.empty())
		return 0;
	int s = 0;
	for (const auto& name : origin.calleeNames) {
		auto it = foundVa.find(name);
		if (it == foundVa.end())
			continue;
		if (contains(cand.callees, it->second))
			s += 10;
		else
			s -= 4;
	}
	return s;
}

bool fingerprintAgrees(const Fingerprint& origin, const Fingerprint& cand, bool needKeys) {
	if (origin.keys.size() < 4)
		return !needKeys;
	int classHits = 0;
	int keyHits = 0;
	size_t nBest = 0;
	for (size_t i = 0; i < 4; i++) {
		for (size_t j = 0; j < 4; j++) {
			if (i >= origin.keys.size() || j >= cand.keys.size())
				continue;
			size_t n = std::min(origin.keys.size() - i, cand.keys.size() - j);
			if (needKeys && n > 4)
				n = 4;
			int ch = 0;
			int kh = 0;
			for (size_t k = 0; k < n; k++) {
				if (origin.classes[i + k] == cand.classes[j + k])
					ch++;
				if (origin.keys[i + k] == cand.keys[j + k] && origin.keys[i + k] != 0)
					kh++;
			}
			if (n > nBest || (n == nBest && ch + kh > classHits + keyHits)) {
				nBest = n;
				classHits = ch;
				keyHits = kh;
			}
		}
	}
	if (nBest < 4)
		return !needKeys;
	if (needKeys)
		return keyHits * 3 >= static_cast<int>(nBest);
	return classHits * 2 >= static_cast<int>(nBest) || keyHits * 3 >= static_cast<int>(nBest);
}

void buildFuncIndex(const Binary& bin, const FuncMap& map, size_t nInsns, FuncIndex& idx, const Logger* log) {
	idx.fileOffs.clear();
	idx.fps.clear();
	const auto& funcs = map.funcs();
	constexpr size_t kMaxFpIndex = 40000;
	if (funcs.size() > kMaxFpIndex) {
		if (log)
			log->info("fp index skip " + std::to_string(funcs.size()) + " funcs");
		return;
	}
	idx.fileOffs.reserve(funcs.size());
	idx.fps.reserve(funcs.size());
	if (log)
		log->info("fp index " + std::to_string(funcs.size()) + " funcs");
	for (const FuncRange& f : funcs) {
		idx.fileOffs.push_back(f.startFile);
		idx.fps.push_back(makeFingerprint(bin, map, f.startFile, nInsns));
	}
}

std::optional<uint64_t> locateByFingerprint(const Fingerprint& origin, const FuncIndex& idx,
	const std::unordered_map<std::string, uint64_t>& foundVa) {
	if (idx.fps.empty() || origin.keys.empty())
		return std::nullopt;
	int best = -1;
	int second = -1;
	int bestI = -1;
	for (size_t i = 0; i < idx.fps.size(); i++) {
		const Fingerprint& cand = idx.fps[i];
		if (callsTooLow(origin, cand))
			continue;
		const int sc = scoreFingerprint(origin, cand) + scoreNamedCallees(origin, cand, foundVa);
		if (sc > best) {
			second = best;
			best = sc;
			bestI = static_cast<int>(i);
		} else if (sc > second) {
			second = sc;
		}
	}
	if (bestI < 0 || best < 20 || best < second + 6)
		return std::nullopt;
	if (!fingerprintAgrees(origin, idx.fps[static_cast<size_t>(bestI)]))
		return std::nullopt;
	return idx.fileOffs[static_cast<size_t>(bestI)];
}

bool callsTooLow(const Fingerprint& origin, const Fingerprint& cand) {
	const uint32_t oldC = origin.callCount;
	const uint32_t newC = cand.callCount;
	if (oldC == 0)
		return false;
	if (oldC >= 4 && newC * 2 < oldC)
		return true;
	if (oldC >= 6 && newC <= 1)
		return true;
	return false;
}

bool callsTooHigh(const Fingerprint& origin, const Fingerprint& cand) {
	const uint32_t oldC = origin.callCount;
	const uint32_t newC = cand.callCount;
	if (oldC == 0)
		return false;
	return newC > oldC * 2u + 3u;
}

void applyFingerprint(SymbolRow& row, const Fingerprint& fp) {
	row.callCount = fp.callCount;
	row.vtableSlot = fp.vtableSlot;
	row.typeInfo = fp.typeInfo;
	row.strings = join(fp.strings, ';');
	row.callees = join(fp.calleeNames, ';');
}

Fingerprint hintsFromRow(const SymbolRow& row) {
	Fingerprint fp;
	fp.callCount = row.callCount;
	fp.vtableSlot = row.vtableSlot;
	fp.typeInfo = row.typeInfo;
	fp.strings = splitAny(row.strings, ";|");
	fp.calleeNames = splitAny(row.callees, ";|");
	if (row.siteKind == "func_start")
		fp.site.kind = SiteKind::FuncStart;
	else if (row.siteKind == "mid_func")
		fp.site.kind = SiteKind::MidFunc;
	else if (row.siteKind == "data")
		fp.site.kind = SiteKind::Data;
	else if (row.siteKind == "code")
		fp.site.kind = SiteKind::Code;
	return fp;
}

bool rowHasHints(const SymbolRow& row) {
	return row.callCount != 0 || row.vtableSlot >= 0 || !row.typeInfo.empty() || !row.strings.empty()
		|| !row.callees.empty();
}

}
