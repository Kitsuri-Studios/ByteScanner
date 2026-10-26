#include "harness.hpp"
#include "bytescanner/cli.hpp"
#include "bytescanner/relocate.hpp"
#include "bytescanner/siggen.hpp"
#include "x64bin.hpp"

#include <cstring>

using namespace bscan;
using namespace tfix;

TEST(Siggen, UniquePrologGrowsPastDupes) {
	std::vector<uint8_t> img(512, 0x00);
	const uint8_t fn[] = {0x41, 0x57, 0x41, 0x56, 0x55, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0xC3, 0xC3};
	const uint8_t prolog[] = {0x41, 0x57, 0x41, 0x56, 0x55};
	for (size_t i = 0; i + sizeof(prolog) <= 32; i += sizeof(prolog))
		std::memcpy(img.data() + i, prolog, sizeof(prolog));
	std::memcpy(img.data() + 32, fn, sizeof(fn));
	std::memcpy(img.data() + 200, prolog, sizeof(prolog));
	Binary bin = loadX64(img);
	auto gen = generateSigs(bin, {fileRow("fn", 32)}, genAll());
	REQUIRE_EQ(gen.size(), size_t{1});
	CHECK_EQ(gen[0].status, std::string("unique"));
	CHECK(!gen[0].row.signature.empty());
	CHECK(gen[0].row.signature.find("E8") != std::string::npos);
	CHECK(gen[0].row.signature.find('?') != std::string::npos);
	std::vector<uint8_t> img2(768, 0x00);
	std::memcpy(img2.data() + 100, fn, sizeof(fn));
	SymbolRow sig = gen[0].row;
	sig.kind = AddressKind::File;
	auto found = relocateSigs(loadX64(img2), {sig}, hunt(nullptr));
	REQUIRE_EQ(found.size(), size_t{1});
	CHECK_EQ(found[0].status, std::string("matched"));
	CHECK_EQ(found[0].row.address, 100ull);
}

TEST(Siggen, Arm64BlWildcard) {
	std::vector<uint8_t> arm(64, 0x1F);
	arm[8] = 0x03;
	arm[9] = 0x00;
	arm[10] = 0x00;
	arm[11] = 0x94;
	arm[12] = 0xC0;
	arm[13] = 0x03;
	arm[14] = 0x5F;
	arm[15] = 0xD6;
	Binary a64 = loadArm64(arm);
	size_t hits = 0;
	Scanner sc(a64, true);
	Pattern p = generateAt(a64, sc, 8, false, genAll(), hits);
	CHECK(p.size() >= 4);
	CHECK(p.mask.size() >= 4);
	CHECK_EQ(p.mask[0], 0);
}

TEST(Cli, ParseGenFind) {
	try {
		parseArgs({"bytescanner"});
		CHECK(true);
	} catch (...) {
		CHECK(false);
	}
	Options o = parseArgs({"bytescanner", "gen", "-b", "a.so", "-s", "0x1,0x2", "--format", "ida"});
	CHECK(o.command == Command::Gen);
	CHECK_EQ(o.binPath, std::string("a.so"));
	CHECK_EQ(o.offsets, std::string("0x1,0x2"));
	Options f = parseArgs({"bytescanner", "find", "--bin", "b.dll", "--csv", "s.csv", "--out", "o.csv"});
	CHECK(f.command == Command::Find);
	CHECK_EQ(f.outPath, std::string("o.csv"));
}

TEST(Cli, Flags) {
	Options n = parseArgs(
		{"bytescanner", "--bin", "old.so", "--new", "new.so", "--offsets", "0x1", "--resolve-conflicts"});
	CHECK(n.command == Command::Gen);
	CHECK_EQ(n.newPath, std::string("new.so"));
	CHECK(n.resolveConflicts);
	Options fz = parseArgs({"bytescanner", "find", "-b", "n.so", "-c", "s.csv", "--fuzz"});
	CHECK(fz.fuzz);
	Options fo = parseArgs({"bytescanner", "find", "-b", "n.so", "-c", "s.csv", "--old", "o.so"});
	CHECK_EQ(fo.oldPath, std::string("o.so"));
	Options mem = parseArgs({"bytescanner", "gen", "-b", "a.so", "-s", "0x1", "--mem", "64M"});
	CHECK_EQ(mem.memSpec, std::string("64M"));
	Options j = parseArgs({"bytescanner", "find", "-b", "n.so", "-c", "s.csv", "--out", "o.csv", "--json", "r.json"});
	CHECK_EQ(j.jsonPath, std::string("r.json"));
	CHECK(!usage().empty());
	CHECK(usage().find("commands") != std::string::npos);
	Options col = parseArgs({"bytescanner", "gen", "-b", "a.so", "-s", "0x1", "--color", "never"});
	CHECK(col.color == ColorMode::Never);
	CHECK_THROWS(parseArgs({"bytescanner", "nope"}));
	CHECK_THROWS(parseArgs({"bytescanner", "gen", "-b", "a.so", "-s", "0x1", "--min-len", "32", "--max-len", "16"}));
}
