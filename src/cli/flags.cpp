#include "bytescanner/cli.hpp"
#include "bytescanner/mem.hpp"
#include "bytescanner/relocate.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace bscan {

std::string usage() {
	const bool col = wantColor(stdout);
	auto wrap = [&](const char* code, std::string_view s) {
		if (!col)
			return std::string(s);
		return std::string(code) + std::string(s) + "\033[0m";
	};
	auto bold = [&](std::string_view s) { return wrap("\033[1m", s); };
	auto dim = [&](std::string_view s) { return wrap("\033[2m", s); };
	auto head = [&](std::string_view s) { return wrap("\033[36;1m", s); };
	auto flag = [&](std::string_view f, std::string_view h) {
		std::string o = "  ";
		o += bold(f);
		const size_t vis = f.size();
		o.append(vis >= 24 ? 1 : 24 - vis, ' ');
		o += dim(h);
		o += "\n";
		return o;
	};
	std::string o;
	o += bold("bytescanner");
	o += "  ";
	o += dim("makes unique byte signatures from a pe elf or raw file on disk");
	o += "\n\n";
	o += head("usage");
	o += "\n";
	o += "  bytescanner gen   --bin <old> (--csv <file> | --offsets 0xA,0xB) [--new <new>] [opts]\n";
	o += "  bytescanner find  --bin <new> --csv <file> [--old <old>] [opts]\n";
	o += "  bytescanner --bin <old> --new <new> --csv <file>\n";
	o += "\n";
	o += head("commands");
	o += "\n";
	o += flag("gen", "make unique byte signatures from the offsets you already know");
	o += flag("find", "look those signatures up in a newer binary and write the new offsets");
	o += "\n";
	o += head("input");
	o += "\n";
	o += flag("--bin, -b PATH", "this is the file you scan on gen it is the old binary and on find it is the new one");
	o += flag("--new PATH", "path to a newer binary so gen can make signatures then find them in that file in one go");
	o += flag("--old PATH", "path to the old binary on find so fingerprints have something to compare against");
	o += flag("--csv, -c PATH", "csv of names and addresses and maybe signatures you already have");
	o += flag("--offsets, -s LIST", "comma list of hex offsets when you do not have a csv");
	o += "\n";
	o += head("output");
	o += "\n";
	o += flag("--out, -o PATH", "write the name and address csv here or print it to stdout if you skip this");
	o += flag("--json PATH", "write extra details to this json file or next to the csv with a json ending");
	o += flag("--format FMT", "how the signature text looks pick ida or x64dbg");
	o += "\n";
	o += head("hunt");
	o += "\n";
	o += flag("--arch ARCH", "force the cpu kind or leave auto so the file header picks it");
	o += flag("--min-len N", "do not let a signature be shorter than this many bytes");
	o += flag("--max-len N", "stop growing a signature after this many bytes");
	o += flag("--scope exec|all", "search only code sections or the whole mapped file");
	o += flag("--all", "if more than one place matches keep the first hit anyway");
	o += flag("--resolve-conflicts", "when hits clash compare instruction shape to the old binary and pick one");
	o += flag("--fuzz", "extra guessy hunt that chops the signature shorter and ranks by fingerprint overlap off unless you pass it");
	o += "\n";
	o += head("runtime");
	o += "\n";
	o += flag("--mem SIZE", "how much ram the scan index may use default is 1G you can pass 512M or 50 percent");
	o += flag("--color WHEN", "color on a tty with auto or force it with always or turn it off with never");
	o += flag("--quiet", "do not print progress on stderr");
	o += flag("--help, -h", "print this help");
	return o;
}

Options parseArgs(const std::vector<std::string>& args) {
	Options opt;
	if (args.size() < 2) {
		opt.command = Command::Help;
		return opt;
	}
	bool sawNew = false;
	for (size_t i = 1; i < args.size(); i++) {
		if (args[i] == "--new")
			sawNew = true;
	}
	size_t i = 1;
	const std::string& first = args[1];
	if (first == "gen") {
		opt.command = Command::Gen;
		i = 2;
	} else if (first == "find") {
		opt.command = Command::Find;
		i = 2;
	} else if (first == "--help" || first == "-h" || first == "help") {
		opt.command = Command::Help;
		return opt;
	} else if (!first.empty() && first[0] == '-' && sawNew) {
		opt.command = Command::Gen;
		i = 1;
	} else {
		throw ScanError("need gen or find");
	}
	auto need = [&](const std::string& flag) -> const std::string& {
		if (i + 1 >= args.size())
			throw ScanError("missing value for " + flag);
		return args[++i];
	};
	for (; i < args.size(); i++) {
		const std::string& a = args[i];
		if (a == "--bin" || a == "-b")
			opt.binPath = need(a);
		else if (a == "--new")
			opt.newPath = need(a);
		else if (a == "--old")
			opt.oldPath = need(a);
		else if (a == "--csv" || a == "-c")
			opt.csvPath = need(a);
		else if (a == "--offsets" || a == "-s")
			opt.offsets = need(a);
		else if (a == "--out" || a == "-o")
			opt.outPath = need(a);
		else if (a == "--json")
			opt.jsonPath = need(a);
		else if (a == "--arch")
			opt.arch = need(a);
		else if (a == "--format")
			opt.gen.format = parseSigFormat(need(a));
		else if (a == "--min-len")
			opt.gen.minLen = static_cast<size_t>(parseHexU64(need(a)));
		else if (a == "--max-len")
			opt.gen.maxLen = static_cast<size_t>(parseHexU64(need(a)));
		else if (a == "--scope") {
			const std::string& v = need(a);
			if (v == "all")
				opt.gen.scopeAll = true;
			else if (v == "exec")
				opt.gen.scopeAll = false;
			else
				throw ScanError("scope wants exec|all");
		} else if (a == "--all")
			opt.findAll = true;
		else if (a == "--resolve-conflicts")
			opt.resolveConflicts = true;
		else if (a == "--fuzz")
			opt.fuzz = true;
		else if (a == "--mem")
			opt.memSpec = need(a);
		else if (a == "--color") {
			const std::string& v = need(a);
			if (v == "auto")
				opt.color = ColorMode::Auto;
			else if (v == "always")
				opt.color = ColorMode::Always;
			else if (v == "never")
				opt.color = ColorMode::Never;
			else
				throw ScanError("color wants auto|always|never");
		} else if (a == "--quiet") {
			opt.withStatus = false;
			opt.logProgress = false;
		} else if (a == "--help" || a == "-h")
			opt.command = Command::Help;
		else
			throw ScanError("unknown flag " + a);
	}
	if (opt.gen.maxLen && opt.gen.minLen > opt.gen.maxLen)
		throw ScanError("min-len above max-len");
	return opt;
}

namespace {

void emitCsv(const Options& opt, const std::string& text) {
	if (opt.outPath.empty() || opt.outPath == "-")
		std::cout << text;
	else
		writeTextFile(opt.outPath, text);
}

void emitReport(const Options& opt, const std::vector<WorkResult>& results, bool withNew, Logger& log) {
	const ResultSummary sum = summarize(results);
	emitCsv(opt, formatResults(results));
	std::string jsonPath = opt.jsonPath;
	if (jsonPath.empty())
		jsonPath = jsonPathFromOut(opt.outPath);
	if (!jsonPath.empty() && jsonPath != "-") {
		writeTextFile(jsonPath, formatJson(results, sum, withNew));
		log.info("json " + jsonPath);
	}
	log.ok(formatSummary(sum));
}

void setArch(Binary& bin, const Options& opt) {
	if (!opt.arch.empty())
		bin.setArch(parseArch(opt.arch));
}

std::vector<SymbolRow> loadRows(const Options& opt) {
	std::vector<SymbolRow> rows;
	if (!opt.csvPath.empty()) {
		CsvFile csv = loadCsv(opt.csvPath);
		rows = std::move(csv.rows);
	}
	if (!opt.offsets.empty()) {
		auto extra = parseOffsetList(opt.offsets);
		rows.insert(rows.end(), extra.begin(), extra.end());
	}
	if (rows.empty())
		throw ScanError("need --csv or --offsets");
	return rows;
}

int failCount(const std::vector<WorkResult>& results, bool gen) {
	int bad = 0;
	for (const WorkResult& r : results) {
		if (gen) {
			if (r.status == "error" || r.status == "missing" || r.status == "out_of_range")
				bad++;
		} else if (r.status == "error" || r.status == "no_match" || r.status == "mismatch") {
				bad++;
			}
	}
	return bad;
}

std::vector<WorkResult> runFind(const Binary& neu, const std::vector<SymbolRow>& rows, const Options& opt,
	const Binary* origin, MemBudget* mem, const Logger* log) {
	FindOptions fo;
	fo.scopeAll = opt.gen.scopeAll;
	fo.findAll = opt.findAll;
	fo.resolveConflicts = opt.resolveConflicts;
	fo.fuzz = opt.fuzz;
	fo.origin = origin;
	fo.mem = mem;
	fo.log = log;
	return relocateSigs(neu, rows, fo);
}

std::vector<SymbolRow> rowsFromGen(const std::vector<WorkResult>& gen) {
	std::vector<SymbolRow> rows;
	rows.reserve(gen.size());
	for (const WorkResult& r : gen) {
		SymbolRow row = r.row;
		if (row.hasAddress) {
			row.hasOldAddress = true;
			row.oldAddress = row.address;
		}
		rows.push_back(std::move(row));
	}
	return rows;
}

} // namespace

int run(const Options& opt) {
	if (opt.command == Command::Help || opt.command == Command::None) {
		std::cout << usage();
		return opt.command == Command::Help ? 0 : 2;
	}
	if (opt.binPath.empty())
		throw ScanError("need --bin");
	Logger log;
	log.silent = !opt.logProgress;
	enableVt(stderr);
	enableVt(stdout);
	if (opt.color == ColorMode::Never)
		log.color = false;
	else if (opt.color == ColorMode::Always)
		log.color = true;
	else
		log.color = wantColor(stderr);
	const uint64_t avail = physAvail();
	const uint64_t want = opt.memSpec.empty() ? 0 : parseMemSize(opt.memSpec, avail);
	const uint64_t cap = pickBudget(avail, want);
	MemBudget budget(cap);
	log.info("mem avail=" + formatMem(avail) + " total=" + formatMem(physTotal()) + " budget="
		+ formatMem(cap));
	GenOptions gopt = opt.gen;
	gopt.mem = &budget;
	gopt.log = &log;
	auto rows = loadRows(opt);
	if (opt.command == Command::Gen) {
		log.info("load " + opt.binPath);
		Binary oldBin = Binary::load(opt.binPath);
		setArch(oldBin, opt);
		log.info(std::string(fileKindName(oldBin.kind())) + " " + std::string(archName(oldBin.arch())) + " "
			+ formatMem(oldBin.bytes().size()));
		auto generated = generateSigs(oldBin, rows, gopt);
		if (opt.newPath.empty()) {
			emitReport(opt, generated, false, log);
			return failCount(generated, true) ? 1 : 0;
		}
		log.info("load " + opt.newPath);
		Binary newBin = Binary::load(opt.newPath);
		setArch(newBin, opt);
		log.info(std::string(fileKindName(newBin.kind())) + " " + std::string(archName(newBin.arch())) + " "
			+ formatMem(newBin.bytes().size()));
		auto found = runFind(newBin, rowsFromGen(generated), opt, &oldBin, &budget, &log);
		for (size_t i = 0; i < found.size() && i < generated.size(); i++) {
			if (!found[i].row.hasOldAddress && generated[i].row.hasAddress) {
				found[i].row.hasOldAddress = true;
				found[i].row.oldAddress = generated[i].row.address;
			}
			if (found[i].row.signature.empty())
				found[i].row.signature = generated[i].row.signature;
		}
		emitReport(opt, found, true, log);
		return failCount(found, false) ? 1 : 0;
	}
	log.info("load " + opt.binPath);
	Binary neu = Binary::load(opt.binPath);
	setArch(neu, opt);
	log.info(std::string(fileKindName(neu.kind())) + " " + std::string(archName(neu.arch())) + " "
		+ formatMem(neu.bytes().size()));
	const Binary* origin = nullptr;
	Binary oldStore;
	if (!opt.oldPath.empty()) {
		log.info("load " + opt.oldPath);
		oldStore = Binary::load(opt.oldPath);
		setArch(oldStore, opt);
		origin = &oldStore;
	}
	if (opt.resolveConflicts && !origin)
		throw ScanError("--resolve-conflicts needs --old or --new");
	auto found = runFind(neu, rows, opt, origin, &budget, &log);
	emitReport(opt, found, origin != nullptr, log);
	return failCount(found, false) ? 1 : 0;
}

}
