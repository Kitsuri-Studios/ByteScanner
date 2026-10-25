#include "bytescanner/func.hpp"
#include "bytescanner/csv.hpp"
#include "bytescanner/mem.hpp"

#include <algorithm>
#include <string>

namespace bscan {

namespace {

bool isPadByte(Arch arch, uint8_t b) {
	if (b == 0x00 || b == 0xCC || b == 0x90)
		return true;
	if (arch == Arch::Arm64 && b == 0x1F)
		return true;
	return false;
}

std::span<const uint8_t> prevAt(const Binary& bin, const Section& sec, uint64_t va) {
	if (va < sec.va + 4)
		return {};
	return bin.sliceFile(sec.fileOffset + (va - sec.va) - 4, 4);
}

uint64_t walkEnd(const Binary& bin, const Section& sec, uint64_t startVa, uint64_t limitVa) {
	uint64_t va = startVa;
	size_t steps = 0;
	const Arch arch = bin.arch();
	while (va < limitVa && steps < 0x10000) {
		if (va != startVa
			&& isPrelude(arch, bin.sliceFile(sec.fileOffset + (va - sec.va), 16), prevAt(bin, sec, va)))
			break;
		Insn insn = decodeInsn(arch, bin.sliceFile(sec.fileOffset + (va - sec.va), 16));
		if (insn.length == 0)
			break;
		va += insn.length;
		steps++;
		if (insn.cls == InsnClass::Ret) {
			while (va < limitVa) {
				const auto sl = bin.sliceFile(sec.fileOffset + (va - sec.va), 1);
				if (sl.empty() || !isPadByte(arch, sl[0]))
					break;
				va++;
			}
			break;
		}
	}
	if (va <= startVa)
		va = startVa + insnAlign(arch);
	if (va > limitVa)
		va = limitVa;
	return va;
}

} // namespace

void FuncMap::build(const Binary& bin, const Logger* log) {
	funcs_.clear();
	if (log)
		log->info("func map");
	const Arch arch = bin.arch();
	const size_t step = insnAlign(arch);
	for (size_t si = 0; si < bin.sections().size(); si++) {
		const Section& sec = bin.sections()[si];
		if (!sec.isExec || sec.fileSize < step)
			continue;
		std::vector<uint64_t> starts;
		const uint8_t zeroPrev[4]{};
		for (uint64_t off = 0; off + 4 <= sec.fileSize; off += step) {
			const auto sl = bin.sliceFile(sec.fileOffset + off, 16);
			std::span<const uint8_t> prev = off >= 4 ? bin.sliceFile(sec.fileOffset + off - 4, 4)
												   : std::span<const uint8_t>(zeroPrev, 4);
			if (isPrelude(arch, sl, prev))
				starts.push_back(sec.va + off);
		}
		const uint64_t secEnd = sec.va + (sec.virtSize ? sec.virtSize : sec.fileSize);
		for (size_t i = 0; i < starts.size(); i++) {
			FuncRange f;
			f.startVa = starts[i];
			f.startFile = sec.fileOffset + (starts[i] - sec.va);
			f.sectionIndex = si;
			const uint64_t lim = (i + 1 < starts.size()) ? starts[i + 1] : secEnd;
			f.endVa = walkEnd(bin, sec, f.startVa, lim);
			if (f.endVa > f.startVa)
				funcs_.push_back(f);
		}
	}
	std::sort(funcs_.begin(), funcs_.end(),
		[](const FuncRange& a, const FuncRange& b) { return a.startVa < b.startVa; });
	if (log)
		log->info("func map " + std::to_string(funcs_.size()) + " funcs");
}

std::optional<FuncRange> FuncMap::containing(uint64_t va) const {
	if (funcs_.empty())
		return std::nullopt;
	size_t lo = 0;
	size_t hi = funcs_.size();
	std::optional<FuncRange> best;
	while (lo < hi) {
		const size_t mid = lo + (hi - lo) / 2;
		if (funcs_[mid].startVa <= va) {
			best = funcs_[mid];
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (!best)
		return std::nullopt;
	if (va >= best->startVa && va < best->endVa)
		return best;
	return std::nullopt;
}

SiteInfo FuncMap::classify(const Binary& bin, const ResolvedAddr& addr) const {
	SiteInfo info;
	if (addr.sectionIndex < bin.sections().size()) {
		const Section& s = bin.sections()[addr.sectionIndex];
		info.section = s.name;
		info.isExec = s.isExec;
	}
	if (!info.isExec) {
		info.kind = SiteKind::Data;
		return info;
	}
	auto fn = containing(addr.va);
	if (!fn) {
		info.kind = SiteKind::Code;
		return info;
	}
	info.hasParent = true;
	info.parentVa = fn->startVa;
	info.parentFile = fn->startFile;
	info.parentDelta = addr.va - fn->startVa;
	info.kind = (addr.va == fn->startVa) ? SiteKind::FuncStart : SiteKind::MidFunc;
	return info;
}

SiteInfo FuncMap::classifyFile(const Binary& bin, uint64_t fileOff) const {
	auto r = bin.resolve(fileOff, AddressKind::File);
	if (!r) {
		SiteInfo info;
		info.kind = SiteKind::Unmapped;
		return info;
	}
	return classify(bin, *r);
}

void fillRowSite(SymbolRow& row, const Binary& bin, const SiteInfo& info, AddressKind emitKind) {
	row.siteKind = std::string(siteKindName(info.kind));
	row.section = info.section;
	if (info.hasParent) {
		ResolvedAddr p;
		p.va = info.parentVa;
		p.fileOffset = info.parentFile;
		p.rva = info.parentVa - bin.imageBase();
		p.kind = emitKind;
		row.parent = formatHex(bin.emitAddr(p, emitKind));
		if (info.kind == SiteKind::MidFunc) {
			row.note = "mid-func +" + formatHex(info.parentDelta);
		}
	} else if (info.kind == SiteKind::Data) {
		row.note = info.section.empty() ? "non-exec" : "section " + info.section;
	} else if (info.kind == SiteKind::Code) {
		row.note = "code, no parent func";
	}
}

}
