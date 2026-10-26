#include "harness.hpp"
#include "bytescanner/csv.hpp"

using namespace bscan;

TEST(Csv, GroupsAndAddress) {
	const char* text =
		"Name,Address\n"
		"Functions,\n"
		"_ZN3Foo3barEv,0xAE309D8\n"
		"Pointers,\n"
		"gThing,0x100\n";
	CsvFile f = parseCsv(text);
	REQUIRE_EQ(f.rows.size(), size_t{4});
	CHECK_EQ(f.rows[0].name, std::string("Functions"));
	CHECK(!f.rows[0].hasAddress);
	CHECK_EQ(f.rows[1].name, std::string("_ZN3Foo3barEv"));
	CHECK(f.rows[1].hasAddress);
	CHECK_EQ(f.rows[1].address, 0xAE309D8ull);
	CHECK_EQ(f.rows[1].group, std::string("Functions"));
	CHECK_EQ(f.rows[3].group, std::string("Pointers"));
}

TEST(Csv, OffsetList) {
	auto offs = parseOffsetList("0x10,0x20,30");
	REQUIRE_EQ(offs.size(), size_t{3});
	CHECK_EQ(offs[0].address, 0x10ull);
	CHECK_EQ(offs[2].address, 30ull);
}

TEST(Csv, SignatureColumn) {
	CsvFile g = parseCsv("n,0x1,E8 ? ? ? ?\n");
	CHECK(g.hasSignatureColumn);
	CHECK_EQ(g.rows[0].signature, std::string("E8 ? ? ? ?"));
}

TEST(Csv, Roundtrip) {
	CsvFile f = parseCsv("Name,Address\nFunctions,\n_ZN3Foo3barEv,0xAE309D8\n");
	std::string out = formatCsv(f.rows, false, false);
	CHECK_EQ(out.find("Name,Address"), size_t{0});
	CHECK(out.find("_ZN3Foo3barEv") != std::string::npos);
}

TEST(Csv, HintColumns) {
	CsvFile h = parseCsv(
		"Name,Address,Calls,TypeInfo,Strings,VSlot,Callees\n"
		"foo,0x10,6,.?AVBar@@,hello;world,2,baz\n");
	REQUIRE_EQ(h.rows.size(), size_t{1});
	CHECK_EQ(h.rows[0].callCount, 6u);
	CHECK_EQ(h.rows[0].typeInfo, std::string(".?AVBar@@"));
	CHECK_EQ(h.rows[0].strings, std::string("hello;world"));
	CHECK_EQ(h.rows[0].vtableSlot, 2);
	CHECK_EQ(h.rows[0].callees, std::string("baz"));
	CHECK(rowHasHints(h.rows[0]));
}

TEST(Csv, ResultsKeepSignature) {
	WorkResult a;
	a.row.name = "main";
	a.row.hasAddress = true;
	a.row.address = 0x1060;
	a.row.signature = "48 83 EC 38 B9 05 00 00 00";
	a.status = "unique";
	auto csv = formatResults({a});
	CHECK_EQ(csv.find("Name,Address,Signature"), size_t{0});
	CHECK(csv.find("48 83 EC 38 B9 05 00 00 00") != std::string::npos);
	auto back = parseCsv(csv);
	REQUIRE_EQ(back.rows.size(), size_t{1});
	CHECK_EQ(back.rows[0].signature, a.row.signature);
	CHECK_EQ(back.rows[0].address, a.row.address);
}

TEST(Csv, ResultsAndSummary) {
	WorkResult grp;
	grp.row.name = "Functions";
	grp.status = "group";
	WorkResult a;
	a.row.name = "_ZN3Foo3barEv";
	a.row.hasAddress = true;
	a.row.address = 0xAE309D8ull;
	a.status = "matched";
	WorkResult b;
	b.row.name = "miss";
	b.status = "ambiguous";
	auto csv = formatResults({grp, a, b});
	CHECK_EQ(csv.find("Name,Address"), size_t{0});
	CHECK(csv.find("Kind") == std::string::npos);
	CHECK(csv.find("Functions,") != std::string::npos);
	CHECK(csv.find("_ZN3Foo3barEv,0xAE309D8") != std::string::npos);
	CHECK(csv.find("miss,") != std::string::npos);
	auto sum = summarize({grp, a, b});
	CHECK_EQ(sum.work, size_t{2});
	CHECK_EQ(sum.exact, size_t{1});
	CHECK_EQ(sum.ambiguous, size_t{1});
	CHECK_EQ(sum.confidence, 50.0);
	CHECK(formatSummary(sum).find("exact=1") != std::string::npos);
	auto js = formatJson({grp, a, b}, sum, false);
	CHECK(js.find("\"status\": \"matched\"") != std::string::npos);
	CHECK(js.find("\"confidence\": 50.0") != std::string::npos);
	CHECK_EQ(jsonPathFromOut("out.csv"), std::string("out.json"));
}
