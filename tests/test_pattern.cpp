#include "harness.hpp"
#include "bytescanner/pattern.hpp"

using namespace bscan;

TEST(Pattern, IdaWildcards) {
	Pattern p = compilePattern<"E8 ? ? ? ? 45 33 F6">();
	CHECK_EQ(p.size(), size_t{8});
	CHECK_EQ(p.mask[0], 0xFF);
	CHECK_EQ(p.bytes[0], 0xE8);
	CHECK_EQ(p.mask[1], 0);
	CHECK_EQ(p.mask[5], 0xFF);
	CHECK_EQ(formatPattern(p, SigFormat::Ida), std::string("E8 ? ? ? ? 45 33 F6"));
	CHECK_EQ(formatPattern(p, SigFormat::X64dbg), std::string("E8 ?? ?? ?? ?? 45 33 F6"));
}

TEST(Pattern, NibbleMask) {
	Pattern n = parsePattern("48 4? ?F 90");
	CHECK_EQ(n.size(), size_t{4});
	CHECK_EQ(n.mask[1], 0xF0);
	CHECK_EQ(n.mask[2], 0x0F);
}

TEST(Pattern, Compact) {
	Pattern c = parsePattern("E8????4533F6");
	CHECK_EQ(c.size(), size_t{6});
	CHECK_EQ(c.bytes[0], 0xE8);
	CHECK_EQ(c.mask[1], 0);
}

TEST(Pattern, Matches) {
	Pattern p = compilePattern<"E8 ? ? ? ? 45 33 F6">();
	uint8_t hay[] = {0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x45, 0x33, 0xF6};
	CHECK(p.matches(std::span<const uint8_t>(hay + 1, 8)));
}

TEST(Pattern, RejectsAllWild) {
	CHECK_THROWS(parsePattern("?? ??"));
}

TEST(Pattern, FormatName) {
	CHECK(parseSigFormat("ida") == SigFormat::Ida);
}
