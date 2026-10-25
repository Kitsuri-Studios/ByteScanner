#include "bytescanner/image.hpp"

#include <algorithm>
#include <cstring>

namespace bscan {

namespace {

constexpr uint16_t MACHINE_I386 = 0x14C;
constexpr uint16_t MACHINE_AMD64 = 0x8664;
constexpr uint16_t MACHINE_ARM = 0x1C0;
constexpr uint16_t MACHINE_ARMNT = 0x1C4;
constexpr uint16_t MACHINE_ARM64 = 0xAA64;
constexpr uint32_t SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t SCN_MEM_READ = 0x40000000;
constexpr uint32_t SCN_MEM_WRITE = 0x80000000;
constexpr uint16_t REL_HIGHLOW = 3;
constexpr uint16_t REL_DIR64 = 10;

Arch peMachine(uint16_t m) {
	switch (m) {
	case MACHINE_I386:
		return Arch::X86;
	case MACHINE_AMD64:
		return Arch::X64;
	case MACHINE_ARM:
		return Arch::Arm32;
	case MACHINE_ARMNT:
		return Arch::Thumb;
	case MACHINE_ARM64:
		return Arch::Arm64;
	default:
		return Arch::Unknown;
	}
}

size_t peRelocWidth(uint16_t type, Arch arch) {
	if (type == REL_DIR64)
		return 8;
	if (type == REL_HIGHLOW)
		return 4;
	if (type == 0)
		return 0;
	if (arch == Arch::Arm64)
		return 4;
	return 4;
}

uint64_t rvaToFile(const Binary& bin, uint64_t rva) {
	const uint64_t va = bin.imageBase() + rva;
	auto i = bin.sectionAtVa(va);
	if (!i)
		return UINT64_MAX;
	const Section& s = bin.sections()[*i];
	const uint64_t delta = va - s.va;
	if (delta >= s.fileSize)
		return UINT64_MAX;
	return s.fileOffset + delta;
}

} // namespace

void parsePe(Binary& bin) {
	auto bytes = bin.bytes();
	if (bytes.size() < 0x40)
		throw ScanError("truncated PE");
	const uint32_t lfanew = loadU32le(bytes.data() + 0x3C);
	if (!inRange(lfanew, 24, bytes.size()))
		throw ScanError("bad PE offset");
	const uint8_t* pe = bytes.data() + lfanew;
	const uint16_t machine = loadU16le(pe + 4);
	const uint16_t nsec = loadU16le(pe + 6);
	const uint16_t optSize = loadU16le(pe + 20);
	bin.setArch(peMachine(machine));
	bin.setLittleEndian(true);
	if (!inRange(lfanew + 24, optSize, bytes.size()))
		throw ScanError("truncated PE optional");
	const uint8_t* opt = pe + 24;
	const uint16_t magic = loadU16le(opt);
	const bool is64 = magic == 0x20B;
	if (magic != 0x10B && magic != 0x20B)
		throw ScanError("bad PE magic");
	bin.setKind(is64 ? FileKind::Pe64 : FileKind::Pe32);
	const uint64_t imageBase = is64 ? loadU64le(opt + 24) : loadU32le(opt + 28);
	bin.setImageBase(imageBase);
	uint32_t relocRva = 0;
	uint32_t relocSz = 0;
	const uint32_t ddOff = is64 ? 112 : 96;
	if (optSize >= ddOff + 8) {
		relocRva = loadU32le(opt + ddOff + 5 * 8);
		relocSz = loadU32le(opt + ddOff + 5 * 8 + 4);
	}
	const uint8_t* sec = opt + optSize;
	for (uint16_t i = 0; i < nsec; i++) {
		const uint8_t* s = sec + static_cast<size_t>(i) * 40;
		if (!inRange(static_cast<size_t>(s - bytes.data()), 40, bytes.size()))
			break;
		Section sc;
		char name[9]{};
		std::memcpy(name, s, 8);
		sc.name = name;
		sc.virtSize = loadU32le(s + 8);
		const uint32_t va = loadU32le(s + 12);
		sc.va = imageBase + va;
		sc.fileSize = loadU32le(s + 16);
		sc.fileOffset = loadU32le(s + 20);
		const uint32_t ch = loadU32le(s + 36);
		sc.isExec = (ch & SCN_MEM_EXECUTE) != 0;
		sc.isRead = (ch & SCN_MEM_READ) != 0;
		sc.isWrite = (ch & SCN_MEM_WRITE) != 0;
		if (sc.fileOffset < bytes.size()) {
			sc.fileSize = std::min<uint64_t>(sc.fileSize, bytes.size() - sc.fileOffset);
			bin.addSection(std::move(sc));
		}
	}
	if (relocRva && relocSz) {
		const uint64_t f = rvaToFile(bin, relocRva);
		if (f != UINT64_MAX) {
			size_t off = static_cast<size_t>(f);
			size_t left = static_cast<size_t>(relocSz);
			while (left >= 8 && inRange(off, 8, bytes.size())) {
				const uint32_t pageRva = loadU32le(bytes.data() + off);
				const uint32_t blockSz = loadU32le(bytes.data() + off + 4);
				if (blockSz < 8 || blockSz > left)
					break;
				const size_t n = (blockSz - 8) / 2;
				for (size_t i = 0; i < n; i++) {
					if (!inRange(off + 8 + i * 2, 2, bytes.size()))
						break;
					const uint16_t e = loadU16le(bytes.data() + off + 8 + i * 2);
					const uint16_t type = static_cast<uint16_t>(e >> 12);
					const uint16_t pageOff = static_cast<uint16_t>(e & 0xFFF);
					const size_t w = peRelocWidth(type, bin.arch());
					if (w == 0)
						continue;
					const uint64_t rf = rvaToFile(bin, static_cast<uint64_t>(pageRva) + pageOff);
					if (rf != UINT64_MAX)
						bin.markReloc(rf, w);
				}
				off += blockSz;
				left -= blockSz;
			}
		}
	}
	if (bin.sections().empty())
		parseRaw(bin);
}

}
