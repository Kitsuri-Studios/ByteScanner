#include "bytescanner/siggen.hpp"

#include "bytescanner/arch.hpp"
#include "bytescanner/func.hpp"

#include <memory>
#include <string>
#include <unordered_map>

namespace bscan {

namespace {

bool groupIsData(std::string_view g) {
	if (g.empty())
		return false;
	std::string s(g);
	for (char& c : s) {
		if (c >= 'A' && c <= 'Z')
			c = static_cast<char>(c - 'A' + 'a');
	}
	return s.find("pointer") != std::string::npos || s == "data" || s == "ptrs";
}

void applyRelocs(const Binary& bin, uint64_t fileOff, Insn& insn) {
	for (uint8_t i = 0; i < insn.length; i++) {
		if (bin.isRelocByte(fileOff + i))
			insn.mask[i] = 0;
	}
}

Arch pickArch(const Binary& bin, uint64_t addr, bool isData) {
	if (isData)
		return Arch::Unknown;
	if (bin.arch() == Arch::Arm32 && (addr & 1))
		return Arch::Thumb;
	return bin.arch();
}

} // namespace

Pattern generateAt(const Binary& bin, const Scanner& scanner, uint64_t fileOff, bool isData,
	const GenOptions& opt, size_t& hitsOut) {
	Pattern p;
	hitsOut = 0;
	const Arch arch = pickArch(bin, fileOff, isData);
	const size_t minLen = opt.minLen ? opt.minLen : minSigLen(arch);
	const size_t maxLen = opt.maxLen ? opt.maxLen : 64;
	const size_t align = insnAlign(arch);
	while (p.size() < maxLen) {
		const auto slice = bin.sliceFile(fileOff + p.size(), 16);
		if (slice.empty())
			break;
		Insn insn = decodeInsn(arch, slice);
		if (insn.length == 0) {
			insn.length = static_cast<uint8_t>(align ? align : 1);
			if (insn.length > slice.size())
				insn.length = static_cast<uint8_t>(slice.size());
			for (uint8_t i = 0; i < insn.length; i++)
				insn.mask[i] = 0xFF;
		}
		size_t n = insn.length;
		if (p.size() + n > maxLen)
			n = maxLen - p.size();
		applyRelocs(bin, fileOff + p.size(), insn);
		for (size_t i = 0; i < n; i++)
			p.append(slice[i], insn.mask[i]);
		if (p.size() < minLen || !p.hasExact())
			continue;
		hitsOut = scanner.count(p, 2);
		if (hitsOut == 1)
			return p;
	}
	if (p.hasExact())
		hitsOut = scanner.count(p, 3);
	return p;
}

std::vector<WorkResult> generateSigs(const Binary& bin, const std::vector<SymbolRow>& rows,
	const GenOptions& opt) {
	if (opt.log)
		opt.log->info("scan exec");
	Scanner scanExec(bin, false, opt.mem, opt.log);
	std::unique_ptr<Scanner> scanAll;
	auto all = [&]() -> const Scanner& {
		if (!scanAll) {
			if (opt.log)
				opt.log->info("scan all");
			scanAll = std::make_unique<Scanner>(bin, true, opt.mem, opt.log);
		}
		return *scanAll;
	};
	FuncMap fmap;
	fmap.build(bin, opt.log);
	std::vector<WorkResult> out;
	out.reserve(rows.size());
	size_t done = 0;
	const size_t total = rows.size();
	for (const SymbolRow& row : rows) {
		WorkResult r;
		r.row = row;
		if (!row.hasAddress && row.signature.empty()) {
			r.status = "group";
			out.push_back(std::move(r));
			continue;
		}
		if (!row.hasAddress) {
			r.status = "error";
			r.error = "missing address";
			r.row.siteKind = "out_of_range";
			out.push_back(std::move(r));
			continue;
		}
		auto resolved = bin.resolve(row.address);
		if (!resolved) {
			r.status = "out_of_range";
			r.error = "address not in image";
			r.row.siteKind = "out_of_range";
			r.row.note = "address not in image";
			out.push_back(std::move(r));
			continue;
		}
		const SiteInfo site = fmap.classify(bin, *resolved);
		fillRowSite(r.row, bin, site, row.kind);
		const bool isData = groupIsData(row.group) || site.kind == SiteKind::Data;
		const Scanner& sc = (isData || opt.scopeAll) ? all() : scanExec;
		if (!sc.containsFileOffset(resolved->fileOffset) && !opt.scopeAll) {
			if (!all().containsFileOffset(resolved->fileOffset)) {
				r.status = "missing";
				r.error = "offset not mapped";
				out.push_back(std::move(r));
				continue;
			}
		}
		const Scanner& used = sc.containsFileOffset(resolved->fileOffset) ? sc : all();
		++done;
		if (opt.log)
			opt.log->progress(done, total, row.name);
		size_t hits = 0;
		Pattern p = generateAt(bin, used, resolved->fileOffset, isData, opt, hits);
		r.hits = hits;
		if (!p.hasExact()) {
			r.status = "error";
			r.error = "no exact byte";
			out.push_back(std::move(r));
			continue;
		}
		r.row.signature = formatPattern(p, opt.format);
		if (hits == 1)
			r.status = "unique";
		else if (hits == 0)
			r.status = "error";
		else
			r.status = "ambiguous";
		if (opt.log)
			opt.log->progress(done, total, row.name + " " + r.status);
		out.push_back(std::move(r));
	}
	std::unordered_map<uint64_t, std::string> names;
	for (const WorkResult& r : out) {
		if (!r.row.hasAddress)
			continue;
		auto res = bin.resolve(r.row.address);
		if (res)
			names[res->va] = r.row.name;
	}
	for (WorkResult& r : out) {
		if (!r.row.hasAddress || r.status == "out_of_range" || r.status == "group")
			continue;
		auto res = bin.resolve(r.row.address);
		if (!res)
			continue;
		Fingerprint fp = makeFingerprint(bin, fmap, res->fileOffset, 64);
		bindCalleeNames(fp, names);
		applyFingerprint(r.row, fp);
	}
	if (opt.log) {
		opt.log->finish();
		opt.log->ok("gen done");
	}
	return out;
}

}
