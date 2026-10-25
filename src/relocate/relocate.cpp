#include "bytescanner/relocate.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>

namespace bscan {

namespace {

bool groupIsData(std::string_view g) {
	if (g.empty())
		return false;
	const std::string s = asciiLowerCopy(std::string(g));
	return s.find("pointer") != std::string::npos || s == "data" || s == "ptrs";
}

uint64_t originOff(const Binary& origin, const SymbolRow& row) {
	const uint64_t addr = row.hasOldAddress ? row.oldAddress : row.address;
	auto r = origin.resolve(addr);
	if (!r)
		return UINT64_MAX;
	return r->fileOffset;
}

Fingerprint originFpOf(const Binary* origin, const FuncMap* oldMap, const SymbolRow& row, size_t nInsns,
	const std::unordered_map<uint64_t, std::string>& originNames) {
	Fingerprint fp = hintsFromRow(row);
	if (!origin || !oldMap)
		return fp;
	const uint64_t off = originOff(*origin, row);
	if (off == UINT64_MAX)
		return fp;
	Fingerprint full = makeFingerprint(*origin, *oldMap, off, nInsns);
	bindCalleeNames(full, originNames);
	if (full.typeInfo.empty())
		full.typeInfo = fp.typeInfo;
	if (full.strings.empty())
		full.strings = fp.strings;
	if (full.calleeNames.empty())
		full.calleeNames = fp.calleeNames;
	if (full.vtableSlot < 0)
		full.vtableSlot = fp.vtableSlot;
	if (full.callCount == 0)
		full.callCount = fp.callCount;
	return full;
}

int scoreHit(const Fingerprint& originFp, const Fingerprint& cand,
	const std::unordered_map<std::string, uint64_t>& foundVa, bool bsim) {
	int s = scoreFingerprint(originFp, cand) + scoreNamedCallees(originFp, cand, foundVa);
	if (bsim)
		s += scoreBsim(originFp, cand);
	return s;
}

int pickResolved(const std::vector<Match>& hits, const Binary& neu, const FuncMap& newMap,
	const Fingerprint& originFp, size_t nInsns, const std::unordered_map<std::string, uint64_t>& foundVa,
	int& bestScore, int& secondScore, bool bsim) {
	bestScore = -1;
	secondScore = -1;
	int best = -1;
	for (int i = 0; i < static_cast<int>(hits.size()); i++) {
		const Fingerprint fp = makeFingerprint(neu, newMap, hits[static_cast<size_t>(i)].fileOffset, nInsns);
		const int sc = scoreHit(originFp, fp, foundVa, bsim);
		if (sc > bestScore) {
			secondScore = bestScore;
			bestScore = sc;
			best = i;
		} else if (sc > secondScore) {
			secondScore = sc;
		}
	}
	return best;
}

void applyHit(WorkResult& r, const Binary& neu, const FuncMap& map, const Match& hit, AddressKind kind) {
	r.row.hasAddress = true;
	r.row.address = neu.emitAddr(ResolvedAddr{hit.fileOffset, hit.va, hit.rva, kind, 0}, kind);
	auto resolved = neu.resolve(hit.fileOffset, AddressKind::File);
	if (resolved)
		fillRowSite(r.row, neu, map.classify(neu, *resolved), kind);
}

void addNote(WorkResult& r, std::string_view s) {
	if (s.empty())
		return;
	if (!r.row.note.empty())
		r.row.note += "; ";
	r.row.note += s;
}

bool applyFileOff(WorkResult& r, const Binary& neu, const FuncMap& map, uint64_t fileOff, AddressKind kind,
	std::string_view why, size_t hits) {
	auto resolved = neu.resolve(fileOff, AddressKind::File);
	if (!resolved)
		return false;
	Match m;
	m.fileOffset = fileOff;
	m.va = resolved->va;
	m.rva = resolved->rva;
	r.status = "resolved";
	r.hits = hits;
	applyHit(r, neu, map, m, kind);
	addNote(r, why);
	return true;
}

bool hasFp(const Binary* origin, const SymbolRow& row) {
	return origin != nullptr || rowHasHints(row);
}

bool decisive(int best, int second) {
	return best >= 12 && best >= second + 4;
}

void noteBand(WorkResult& r, const Fingerprint& originFp, const Fingerprint& cand) {
	if (callsTooLow(originFp, cand))
		addNote(r, "callee count too low");
	else if (callsTooHigh(originFp, cand))
		addNote(r, "callee count high");
	else if (originFp.callCount && cand.callCount != originFp.callCount)
		addNote(r, "callee count close");
	if (originFp.vtableSlot >= 0 && cand.vtableSlot >= 0 && originFp.vtableSlot != cand.vtableSlot)
		addNote(r, "vtable slot hint");
}

bool bodyThin(const Fingerprint& originFp, const Fingerprint& cand) {
	if (originFp.callCount >= 2 && cand.callCount == 0)
		return true;
	return callsTooLow(originFp, cand);
}

bool fpOk(const Fingerprint& originFp, const Fingerprint& cand, bool useFp, bool strict) {
	if (!useFp)
		return true;
	if (strict && bodyThin(originFp, cand))
		return false;
	return !callsTooLow(originFp, cand) && fingerprintAgrees(originFp, cand);
}

bool vtableFpOk(const Fingerprint& originFp, const Fingerprint& cand) {
	if (bodyThin(originFp, cand) || callsTooLow(originFp, cand))
		return false;
	return fingerprintAgrees(originFp, cand, originFp.keys.size() >= 4);
}

bool dropLastInsn(Pattern& p, Arch arch, size_t minLen) {
	if (p.size() <= minLen)
		return false;
	size_t last = 0;
	size_t off = 0;
	const size_t align = insnAlign(arch);
	while (off < p.size()) {
		last = off;
		Insn insn = decodeInsn(arch, std::span<const uint8_t>(p.bytes.data() + off, p.size() - off));
		size_t n = insn.length ? insn.length : (align ? align : 1);
		if (n > p.size() - off)
			n = p.size() - off;
		if (n == 0)
			return false;
		off += n;
	}
	if (last == 0 || last < minLen)
		return false;
	p.bytes.resize(last);
	p.mask.resize(last);
	return p.hasExact();
}

std::optional<uint64_t> rankVtableAll(const Binary& neu, const FuncMap& newMap, uint64_t mapped,
	const Fingerprint& originFp, size_t nInsns, const std::unordered_map<std::string, uint64_t>& foundVa,
	const std::vector<uint64_t>& taken, const std::vector<uint64_t>& newAnchors, bool bsim) {
	auto vt = pickVtable(findVtables(neu, mapped), newAnchors);
	if (!vt)
		return mapped;
	int bestSc = -1;
	int secondSc = -1;
	uint64_t bestVa = 0;
	std::vector<uint64_t> seen;
	const size_t cap = vt->methods.size() < 1024 ? vt->methods.size() : 1024;
	for (size_t s = 0; s < cap; s++) {
		const uint64_t va = vt->methods[s];
		if (std::find(taken.begin(), taken.end(), va) != taken.end())
			continue;
		if (std::find(seen.begin(), seen.end(), va) != seen.end())
			continue;
		seen.push_back(va);
		auto at = neu.resolve(va);
		if (!at)
			continue;
		const Fingerprint cand = makeFingerprint(neu, newMap, at->fileOffset, nInsns);
		const int sc = scoreHit(originFp, cand, foundVa, bsim);
		if (sc > bestSc) {
			secondSc = bestSc;
			bestSc = sc;
			bestVa = va;
		} else if (sc > secondSc)
			secondSc = sc;
	}
	if (bestVa == 0)
		return mapped;
	if (decisive(bestSc, secondSc))
		return bestVa;
	return mapped;
}

bool isClassAnchor(const WorkResult& r) {
	if (!r.row.hasAddress)
		return false;
	if (r.status == "matched")
		return true;
	if (r.status != "resolved")
		return false;
	const std::string& n = r.row.note;
	if (n.find("sig shrink") != std::string::npos || n.find("frame wild") != std::string::npos
		|| n.find("parent delta") != std::string::npos)
		return false;
	if (n.find("vtable sibling") != std::string::npos || n.find("class cluster") != std::string::npos
		|| n.find("typeinfo") != std::string::npos)
		return true;
	return r.hits > 0 && r.hits <= 2;
}

bool applyVa(WorkResult& r, const Binary& neu, const FuncMap& map, uint64_t va, AddressKind kind,
	std::string_view why) {
	auto resolved = neu.resolve(va);
	if (!resolved)
		return false;
	Match m;
	m.fileOffset = resolved->fileOffset;
	m.va = resolved->va;
	m.rva = resolved->rva;
	r.status = "resolved";
	r.hits = std::max(r.hits, size_t{1});
	applyHit(r, neu, map, m, kind);
	addNote(r, why);
	return true;
}

uint64_t originVaOf(const Binary* origin, const SymbolRow& row) {
	if (!origin)
		return 0;
	const uint64_t addr = row.hasOldAddress ? row.oldAddress : row.address;
	auto r = origin->resolve(addr);
	return r ? r->va : 0;
}

bool tryFpLocate(WorkResult& r, const Binary& neu, const FuncMap& newMap, const Fingerprint& originFp,
	FuncIndex& idx, bool& indexed, const FindOptions& opt, const std::unordered_map<std::string, uint64_t>& foundVa,
	AddressKind kind) {
	if (!indexed) {
		buildFuncIndex(neu, newMap, opt.resolveInsns, idx, opt.log);
		indexed = true;
	}
	auto hitOff = locateByFingerprint(originFp, idx, foundVa);
	if (!hitOff)
		return false;
	return applyFileOff(r, neu, newMap, *hitOff, kind, "fingerprint locate", std::max(r.hits, size_t{1}));
}

bool tryTypeInfo(WorkResult& r, const Binary& neu, const FuncMap& newMap, const Fingerprint& originFp,
	AddressKind kind) {
	const bool wantData = originFp.site.kind == SiteKind::Data || r.row.siteKind == "data"
		|| groupIsData(r.row.group);
	auto hitOff = locateByTypeInfo(neu, newMap, originFp.typeInfo, wantData);
	if (!hitOff)
		return false;
	return applyFileOff(r, neu, newMap, *hitOff, kind, "typeinfo", 1);
}

bool tryStringXref(WorkResult& r, const Binary& neu, const FuncMap& newMap, const Fingerprint& originFp,
	AddressKind kind) {
	bool wantData = originFp.site.kind == SiteKind::Data || r.row.siteKind == "data"
		|| groupIsData(r.row.group);
	if (originFp.site.kind == SiteKind::MidFunc)
		wantData = false;
	auto hitOff = locateByStringXref(neu, newMap, originFp, wantData);
	if (!hitOff)
		return false;
	auto resolved = neu.resolve(*hitOff, AddressKind::File);
	if (!resolved)
		return false;
	uint64_t va = resolved->va;
	if (originFp.site.hasParent && originFp.site.parentDelta != 0)
		va += originFp.site.parentDelta;
	if (!applyVa(r, neu, newMap, va, kind, "string xref"))
		return false;
	if (originFp.site.parentDelta != 0)
		addNote(r, "parent delta");
	return true;
}

struct Pending {
	size_t index = 0;
	std::vector<Match> hits;
	Fingerprint originFp;
};

const Scanner& needAll(const Binary& bin, const FindOptions& opt, std::unique_ptr<Scanner>& all) {
	if (!all) {
		if (opt.log)
			opt.log->info("scan all");
		all = std::make_unique<Scanner>(bin, true, opt.mem, opt.log);
	}
	return *all;
}

bool tryPickHits(WorkResult& r, const Binary& neu, const FuncMap& newMap, std::vector<Match>& hits,
	const FindOptions& opt, const Fingerprint& originFp, const std::unordered_map<std::string, uint64_t>& foundVa,
	bool useFp, AddressKind kind, std::string_view why) {
	if (hits.size() == 1) {
		Fingerprint cand = makeFingerprint(neu, newMap, hits[0].fileOffset, opt.resolveInsns);
		if (!fpOk(originFp, cand, useFp, !why.empty()))
			return false;
		r.status = why.empty() ? "matched" : "resolved";
		r.hits = 1;
		applyHit(r, neu, newMap, hits[0], kind);
		addNote(r, why);
		if (useFp)
			noteBand(r, originFp, cand);
		return true;
	}
	if (hits.size() <= 1 || !useFp)
		return false;
	int bestSc = -1;
	int secondSc = -1;
	const int pick = pickResolved(hits, neu, newMap, originFp, opt.resolveInsns, foundVa, bestSc, secondSc,
		opt.fuzz);
	if (pick < 0 || !decisive(bestSc, secondSc))
		return false;
	Fingerprint cand = makeFingerprint(neu, newMap, hits[static_cast<size_t>(pick)].fileOffset, opt.resolveInsns);
	if (callsTooLow(originFp, cand))
		return false;
	r.status = "resolved";
	r.hits = hits.size();
	applyHit(r, neu, newMap, hits[static_cast<size_t>(pick)], kind);
	addNote(r, why.empty() ? "resolved " + std::to_string(hits.size()) + " hits" : why);
	noteBand(r, originFp, cand);
	if (originFp.site.kind == SiteKind::MidFunc)
		addNote(r, "origin mid-func");
	return true;
}

bool tryFuzzShrink(WorkResult& r, const Binary& neu, const FuncMap& newMap, const Scanner& sc,
	std::unique_ptr<Scanner>& scanAll, const FindOptions& opt, Pattern p, bool isData, bool useFp,
	const Fingerprint& originFp, const std::unordered_map<std::string, uint64_t>& foundVa,
	std::vector<Match>& hitsOut, AddressKind kind) {
	const Arch arch = neu.arch();
	applyArchWildcards(p, arch);
	const size_t align = insnAlign(arch);
	size_t minLen = align ? align * 2 : 4;
	if (minLen < 4)
		minLen = 4;
	const size_t cap = (useFp || opt.resolveConflicts) ? opt.hitCap : (opt.findAll ? 16 : 2);
	for (size_t step = 0; step < 32 && dropLastInsn(p, arch, minLen); step++) {
		hitsOut = sc.find(p, cap);
		if (hitsOut.empty() && !isData)
			hitsOut = needAll(neu, opt, scanAll).find(p, cap);
		r.hits = std::max(r.hits, hitsOut.size());
		if (hitsOut.empty() || hitsOut.size() == 1)
			continue;
		if (tryPickHits(r, neu, newMap, hitsOut, opt, originFp, foundVa, useFp, kind, "fuzz shrink"))
			return true;
		return false;
	}
	hitsOut.clear();
	return false;
}

WorkResult locateOne(const Binary& neu, const FuncMap& newMap, const Scanner& scanExec,
	std::unique_ptr<Scanner>& scanAll, const SymbolRow& row, const FindOptions& opt,
	const Fingerprint& originFp, const std::unordered_map<std::string, uint64_t>& foundVa,
	std::vector<Match>& hitsOut, FuncIndex& idx, bool& indexed) {
	WorkResult r;
	r.row = row;
	const uint64_t savedOld = row.hasOldAddress ? row.oldAddress : row.address;
	const bool hadOld = row.hasOldAddress || row.hasAddress;
	auto keepOld = [&]() {
		if (hadOld) {
			r.row.hasOldAddress = true;
			r.row.oldAddress = savedOld;
		}
	};
	if (!row.hasAddress && row.signature.empty()) {
		r.status = "group";
		return r;
	}
	if (row.signature.empty()) {
		if (hasFp(opt.origin, row) && tryTypeInfo(r, neu, newMap, originFp, row.kind)) {
			keepOld();
			return r;
		}
		if (hasFp(opt.origin, row) && tryStringXref(r, neu, newMap, originFp, row.kind)) {
			keepOld();
			return r;
		}
		r.status = "error";
		r.error = "missing signature";
		keepOld();
		return r;
	}
	Pattern p;
	try {
		p = parsePattern(row.signature);
	} catch (const std::exception& ex) {
		r.status = "error";
		r.error = ex.what();
		keepOld();
		return r;
	}
	const bool isData = groupIsData(row.group) || row.siteKind == "data";
	const Scanner& sc = (isData || opt.scopeAll) ? needAll(neu, opt, scanAll) : scanExec;
	const bool useFp = hasFp(opt.origin, row);
	const size_t cap = (useFp || opt.resolveConflicts) ? opt.hitCap : (opt.findAll ? 16 : 2);
	auto scanPat = [&](const Pattern& pat) {
		std::vector<Match> h = sc.find(pat, cap);
		if (h.empty() && !isData)
			h = needAll(neu, opt, scanAll).find(pat, cap);
		return h;
	};
	hitsOut = scanPat(p);
	r.hits = hitsOut.size();
	bool weakUnique = false;
	if (tryPickHits(r, neu, newMap, hitsOut, opt, originFp, foundVa, useFp, row.kind, {})) {
		keepOld();
		return r;
	}
	if (hitsOut.size() == 1 && useFp) {
		weakUnique = true;
		hitsOut.clear();
	}
	if ((hitsOut.empty() || weakUnique) && !isData) {
		Pattern loose = p;
		applyArchWildcards(loose, neu.arch());
		hitsOut = scanPat(loose);
		r.hits = std::max(r.hits, hitsOut.size());
		if (tryPickHits(r, neu, newMap, hitsOut, opt, originFp, foundVa, useFp, row.kind, "frame wild")) {
			keepOld();
			return r;
		}
	}
	if (opt.fuzz && (hitsOut.empty() || weakUnique) && !isData
		&& tryFuzzShrink(r, neu, newMap, sc, scanAll, opt, p, isData, useFp, originFp, foundVa, hitsOut,
			row.kind)) {
		keepOld();
		return r;
	}
	if (useFp && tryTypeInfo(r, neu, newMap, originFp, row.kind)) {
		keepOld();
		return r;
	}
	if (useFp && tryStringXref(r, neu, newMap, originFp, row.kind)) {
		keepOld();
		return r;
	}
	if (useFp && !isData
		&& tryFpLocate(r, neu, newMap, originFp, idx, indexed, opt, foundVa, row.kind)) {
		keepOld();
		return r;
	}
	if ((weakUnique && hitsOut.size() <= 1) || (hitsOut.size() == 1 && useFp)) {
		r.status = "mismatch";
		r.row.hasAddress = false;
		r.row.note = "fingerprint disagree";
		keepOld();
		return r;
	}
	if (hitsOut.empty()) {
		r.status = "no_match";
		r.row.hasAddress = false;
		r.row.note = r.row.note.empty() ? "no valid hits" : r.row.note;
		keepOld();
		return r;
	}
	if (opt.findAll) {
		r.status = "ambiguous";
		applyHit(r, neu, newMap, hitsOut[0], row.kind);
		r.row.note = "first of " + std::to_string(hitsOut.size());
	} else {
		r.status = "ambiguous";
		r.row.hasAddress = false;
		r.row.note = std::to_string(hitsOut.size()) + " hits, pass --resolve-conflicts";
	}
	keepOld();
	return r;
}

bool isFound(const WorkResult& r) {
	return r.status == "matched" || r.status == "resolved";
}

bool canHunt(const WorkResult& r) {
	return r.status == "no_match" || r.status == "mismatch" || r.status == "ambiguous";
}

void recoverClasses(std::vector<WorkResult>& out, const std::vector<SymbolRow>& rows, const Binary& neu,
	const FuncMap& newMap, const Binary* origin, const FuncMap* oldMap, size_t nInsns, bool fuzz,
	const std::unordered_map<uint64_t, std::string>& originNames,
	std::unordered_map<std::string, uint64_t>& foundVa) {
	std::unordered_map<std::string, std::vector<size_t>> groups;
	for (size_t i = 0; i < rows.size(); i++) {
		if (out[i].status == "group" || out[i].status == "error" || out[i].status == "out_of_range")
			continue;
		const std::string key = classKey(rows[i].name);
		if (!key.empty())
			groups[key].push_back(i);
	}
	bool progressed = true;
	while (progressed) {
		progressed = false;
		for (auto& g : groups) {
			std::vector<uint64_t> newAnchors;
			std::vector<uint64_t> oldAnchors;
			std::vector<uint64_t> taken;
			std::vector<size_t> missing;
			for (const auto& kv : foundVa)
				taken.push_back(kv.second);
			for (size_t i : g.second) {
				if (isClassAnchor(out[i])) {
					auto got = neu.resolve(out[i].row.address);
					if (got)
						newAnchors.push_back(got->va);
					const uint64_t ov = originVaOf(origin, rows[i]);
					if (ov)
						oldAnchors.push_back(ov);
				} else if (canHunt(out[i]))
					missing.push_back(i);
			}
			const bool hadAnchor = !newAnchors.empty();
			for (size_t i : missing) {
				Fingerprint originFp = originFpOf(origin, oldMap, rows[i], nInsns, originNames);
				Fingerprint huntFp = originFp;
				uint64_t oldTarget = originVaOf(origin, rows[i]);
				uint64_t delta = 0;
				if (originFp.site.hasParent && originFp.site.parentDelta != 0) {
					oldTarget = originFp.site.parentVa;
					delta = originFp.site.parentDelta;
					if (origin && oldMap)
						huntFp = makeFingerprint(*origin, *oldMap, originFp.site.parentFile, nInsns);
				}
				auto hit = huntClassMethod(neu, origin, g.first, oldTarget, newAnchors, oldAnchors, taken,
					true);
				if (!hit)
					continue;
				const uint64_t mapped = *hit;
				auto ranked = rankVtableAll(neu, newMap, mapped, huntFp, nInsns, foundVa, taken, newAnchors,
					fuzz);
				if (ranked)
					hit = ranked;
				auto at = neu.resolve(*hit);
				if (!at)
					continue;
				Fingerprint cand = makeFingerprint(neu, newMap, at->fileOffset, nInsns);
				if (!vtableFpOk(huntFp, cand))
					continue;
				const uint64_t siteVa = *hit + delta;
				const char* why = hadAnchor ? "vtable sibling" : "class cluster";
				if (!applyVa(out[i], neu, newMap, siteVa, rows[i].kind, why))
					continue;
				if (*hit != mapped)
					addNote(out[i], "vtable rank");
				if (delta)
					addNote(out[i], "parent delta");
				foundVa[out[i].row.name] = siteVa;
				taken.push_back(siteVa);
				newAnchors.push_back(*hit);
				progressed = true;
			}
		}
	}
}

void recoverParentDeltas(std::vector<WorkResult>& out, const std::vector<SymbolRow>& rows, const Binary& neu,
	const FuncMap& newMap, const Binary* origin, const FuncMap* oldMap, size_t nInsns,
	const std::unordered_map<uint64_t, std::string>& originNames,
	std::unordered_map<std::string, uint64_t>& foundVa) {
	for (size_t i = 0; i < rows.size(); i++) {
		if (!canHunt(out[i]))
			continue;
		Fingerprint originFp = originFpOf(origin, oldMap, rows[i], nInsns, originNames);
		if (!originFp.site.hasParent || originFp.site.parentDelta == 0)
			continue;
		const uint64_t parentOld = originFp.site.parentVa;
		std::optional<uint64_t> parentNew;
		for (size_t j = 0; j < rows.size(); j++) {
			if (i == j || !isFound(out[j]) || !out[j].row.hasAddress)
				continue;
			if (originVaOf(origin, rows[j]) != parentOld)
				continue;
			auto got = neu.resolve(out[j].row.address);
			if (got) {
				parentNew = got->va;
				break;
			}
		}
		if (!parentNew)
			continue;
		if (!applyVa(out[i], neu, newMap, *parentNew + originFp.site.parentDelta, rows[i].kind, "parent delta"))
			continue;
		foundVa[out[i].row.name] = *parentNew + originFp.site.parentDelta;
	}
}

} // namespace

std::vector<WorkResult> relocateSigs(const Binary& bin, const std::vector<SymbolRow>& rows,
	const FindOptions& opt) {
	if (opt.log)
		opt.log->info("scan exec");
	Scanner scanExec(bin, false, opt.mem, opt.log);
	std::unique_ptr<Scanner> scanAll;
	FuncIndex fpIndex;
	bool indexed = false;
	FuncMap newMap;
	newMap.build(bin, opt.log);
	FuncMap oldMap;
	if (opt.origin) {
		if (opt.log)
			opt.log->info("func map old");
		oldMap.build(*opt.origin, opt.log);
	}
	std::unordered_map<uint64_t, std::string> originNames;
	if (opt.origin) {
		for (const SymbolRow& row : rows) {
			if (row.name.empty())
				continue;
			const uint64_t off = originOff(*opt.origin, row);
			if (off == UINT64_MAX)
				continue;
			auto r = opt.origin->resolve(off, AddressKind::File);
			if (r)
				originNames[r->va] = row.name;
		}
	}
	std::vector<WorkResult> out(rows.size());
	std::vector<Pending> pending;
	std::unordered_map<std::string, uint64_t> foundVa;
	for (size_t i = 0; i < rows.size(); i++) {
		Fingerprint originFp = originFpOf(opt.origin, opt.origin ? &oldMap : nullptr, rows[i], opt.resolveInsns,
			originNames);
		std::vector<Match> hits;
		if (opt.log)
			opt.log->progress(i + 1, rows.size(), rows[i].name);
		out[i] = locateOne(bin, newMap, scanExec, scanAll, rows[i], opt, originFp, foundVa, hits, fpIndex,
			indexed);
		if (opt.log)
			opt.log->progress(i + 1, rows.size(), rows[i].name + " " + out[i].status);
		if (isFound(out[i])) {
			auto r = bin.resolve(out[i].row.address);
			if (r)
				foundVa[out[i].row.name] = r->va;
		} else if (out[i].status == "ambiguous" && hasFp(opt.origin, rows[i]) && !hits.empty()) {
			Pending p;
			p.index = i;
			p.hits = std::move(hits);
			p.originFp = std::move(originFp);
			pending.push_back(std::move(p));
		}
	}
	bool progressed = true;
	while (progressed && !pending.empty()) {
		progressed = false;
		std::vector<Pending> left;
		for (Pending& p : pending) {
			int bestSc = -1;
			int secondSc = -1;
			const int pick = pickResolved(p.hits, bin, newMap, p.originFp, opt.resolveInsns, foundVa, bestSc,
				secondSc, opt.fuzz);
			if (pick >= 0 && decisive(bestSc, secondSc)) {
				Fingerprint cand = makeFingerprint(bin, newMap, p.hits[static_cast<size_t>(pick)].fileOffset,
					opt.resolveInsns);
				if (!callsTooLow(p.originFp, cand)) {
					WorkResult& r = out[p.index];
					r.status = "resolved";
					r.hits = p.hits.size();
					applyHit(r, bin, newMap, p.hits[static_cast<size_t>(pick)], rows[p.index].kind);
					r.row.note = "resolved " + std::to_string(p.hits.size()) + " hits";
					noteBand(r, p.originFp, cand);
					auto got = bin.resolve(r.row.address);
					if (got)
						foundVa[r.row.name] = got->va;
					progressed = true;
					continue;
				}
			}
			left.push_back(std::move(p));
		}
		pending = std::move(left);
	}
	recoverClasses(out, rows, bin, newMap, opt.origin, opt.origin ? &oldMap : nullptr, opt.resolveInsns,
		opt.fuzz, originNames, foundVa);
	recoverParentDeltas(out, rows, bin, newMap, opt.origin, opt.origin ? &oldMap : nullptr, opt.resolveInsns,
		originNames, foundVa);
	std::unordered_map<uint64_t, std::string> newNames;
	for (const WorkResult& r : out) {
		if (!isFound(r) || !r.row.hasAddress)
			continue;
		auto got = bin.resolve(r.row.address);
		if (got)
			newNames[got->va] = r.row.name;
	}
	for (WorkResult& r : out) {
		if (!isFound(r) || !r.row.hasAddress)
			continue;
		auto got = bin.resolve(r.row.address);
		if (!got)
			continue;
		Fingerprint fp = makeFingerprint(bin, newMap, got->fileOffset, opt.resolveInsns);
		bindCalleeNames(fp, newNames);
		applyFingerprint(r.row, fp);
	}
	if (opt.log) {
		opt.log->finish();
		opt.log->ok("find done");
	}
	return out;
}

}
