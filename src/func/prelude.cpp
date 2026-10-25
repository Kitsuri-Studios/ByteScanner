#include "bytescanner/func.hpp"

#include <initializer_list>

namespace bscan {

namespace {

bool startsWith(std::span<const uint8_t> b, std::initializer_list<uint8_t> p) {
	if (b.size() < p.size())
		return false;
	size_t i = 0;
	for (uint8_t v : p) {
		if (b[i++] != v)
			return false;
	}
	return true;
}

bool preludeX86(std::span<const uint8_t> b) {
	if (startsWith(b, {0x55, 0x48, 0x89, 0xE5}))
		return true;
	if (startsWith(b, {0x55, 0x48, 0x8B, 0xEC}))
		return true;
	if (startsWith(b, {0x55, 0x89, 0xE5}))
		return true;
	if (startsWith(b, {0x55, 0x57, 0x56, 0x53}))
		return true;
	if (startsWith(b, {0x55, 0x41, 0x57, 0x41, 0x56}))
		return true;
	if (startsWith(b, {0x41, 0x57, 0x41, 0x56, 0x41, 0x54}))
		return true;
	if (startsWith(b, {0x56, 0x53, 0x48, 0x83}))
		return true;
	if (startsWith(b, {0x8B, 0xFF, 0x55, 0x8B, 0xEC}))
		return true;
	if (startsWith(b, {0xF3, 0x0F, 0x1E, 0xFA}))
		return true;
	if (startsWith(b, {0xF3, 0x0F, 0x1E, 0xFB}))
		return true;
	if (startsWith(b, {0x48, 0x83, 0xEC}))
		return true;
	if (startsWith(b, {0x48, 0x89, 0x5C, 0x24}))
		return true;
	if (startsWith(b, {0x40, 0x53}) || startsWith(b, {0x40, 0x55}) || startsWith(b, {0x40, 0x56})
		|| startsWith(b, {0x40, 0x57}))
		return true;
	return false;
}

bool arm64HardFrame(uint32_t w) {
	if ((w & 0xFFC07FFF) == 0xA9007BFD)
		return true;
	const uint32_t rn = (w >> 5) & 31;
	const uint32_t op22 = w >> 22;
	if (rn == 31 && (op22 == 0x2A6 || op22 == 0x1B6))
		return true;
	if (w == 0x910003FD || w == 0x910003BF)
		return true;
	return false;
}

bool arm64SubSp(uint32_t w) {
	return (w & 0xFF0003FF) == 0xD10003FF;
}

bool arm64Boundary(uint32_t w) {
	if (w == 0 || w == 0xD503201F)
		return true;
	if (w == 0xD65F03C0)
		return true;
	if ((w & 0xFFFFFC1F) == 0xD61F0000)
		return true;
	if ((w >> 26) == 0x05)
		return true;
	return false;
}

bool preludeArm64(std::span<const uint8_t> b, std::span<const uint8_t> prev) {
	if (b.size() < 4)
		return false;
	const uint32_t w = loadU32le(b.data());
	if (w == 0xD503233F || w == 0xD503237F)
		return true;
	if (w == 0xD503245F || w == 0xD503249F || w == 0xD50324DF)
		return true;
	if (arm64HardFrame(w))
		return true;
	if (arm64SubSp(w)) {
		if (prev.size() < 4)
			return false;
		return arm64Boundary(loadU32le(prev.data()));
	}
	if ((w & 0xFFFFFFE0) == 0xD53BD040 || (w & 0xFFFFFFE0) == 0xD53BE040) {
		if (b.size() < 8)
			return false;
		return arm64HardFrame(loadU32le(b.data() + 4)) || arm64SubSp(loadU32le(b.data() + 4));
	}
	return false;
}

bool preludeArm32(std::span<const uint8_t> b) {
	if (b.size() < 4)
		return false;
	const uint32_t w = loadU32le(b.data());
	if ((w & 0xFFFF4000) == 0xE92D4000)
		return true;
	if (w == 0xE52DE004)
		return true;
	return false;
}

bool preludeThumb(std::span<const uint8_t> b) {
	if (b.size() < 2)
		return false;
	const uint16_t h = loadU16le(b.data());
	if ((h & 0xFF00) == 0xB500)
		return true;
	return false;
}

bool preludeRiscv(std::span<const uint8_t> b) {
	if (b.size() < 2)
		return false;
	const uint16_t h = loadU16le(b.data());
	if ((h & 0xEF83) == 0x6101)
		return true;
	if (b.size() < 4)
		return false;
	const uint32_t w = loadU32le(b.data());
	if ((w & 0x000FFFFF) == 0x00010113)
		return true;
	if ((w & 0x7Fu) == 0x23 && ((w >> 20) & 0x1F) == 1)
		return true;
	return false;
}

bool preludeMips(std::span<const uint8_t> b) {
	if (b.size() < 4)
		return false;
	const uint32_t w = loadU32le(b.data());
	if ((w & 0xFFFF0000) == 0x27BD0000)
		return true;
	if ((w & 0xFC1F0000) == 0xAC1F0000)
		return true;
	return false;
}

} // namespace

bool isPrelude(Arch arch, std::span<const uint8_t> bytes, std::span<const uint8_t> prev) {
	switch (arch) {
	case Arch::X86:
	case Arch::X64:
		return preludeX86(bytes);
	case Arch::Arm64:
		return preludeArm64(bytes, prev);
	case Arch::Arm32:
		return preludeArm32(bytes);
	case Arch::Thumb:
		return preludeThumb(bytes);
	case Arch::Riscv32:
	case Arch::Riscv64:
		return preludeRiscv(bytes);
	case Arch::Mips32:
	case Arch::Mips64:
		return preludeMips(bytes);
	default:
		return false;
	}
}

bool isPrelude(Arch arch, std::span<const uint8_t> bytes) {
	return isPrelude(arch, bytes, {});
}

std::string_view siteKindName(SiteKind k) {
	switch (k) {
	case SiteKind::OutOfRange:
		return "out_of_range";
	case SiteKind::Data:
		return "data";
	case SiteKind::Code:
		return "code";
	case SiteKind::FuncStart:
		return "func_start";
	case SiteKind::MidFunc:
		return "mid_func";
	default:
		return "unmapped";
	}
}

}
