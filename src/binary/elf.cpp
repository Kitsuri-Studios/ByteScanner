#include "bytescanner/image.hpp"

#include <algorithm>
#include <cstdio>

namespace bscan {

namespace {

constexpr uint16_t PT_LOAD = 1;
constexpr uint16_t PT_DYNAMIC = 2;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_RELR = 19;
constexpr uint32_t SHF_EXECINSTR = 0x4;
constexpr uint32_t SHF_WRITE = 0x1;
constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;
constexpr int64_t DT_NULL = 0;
constexpr int64_t DT_RELA = 7;
constexpr int64_t DT_RELASZ = 8;
constexpr int64_t DT_RELAENT = 9;
constexpr int64_t DT_REL = 17;
constexpr int64_t DT_RELSZ = 18;
constexpr int64_t DT_RELENT = 19;
constexpr int64_t DT_RELR = 36;
constexpr int64_t DT_RELRSZ = 35;
constexpr int64_t DT_RELRENT = 37;

Arch elfMachine(uint16_t em, uint8_t cls) {
	switch (em) {
	case 3:
		return Arch::X86;
	case 62:
		return Arch::X64;
	case 40:
		return Arch::Arm32;
	case 183:
		return Arch::Arm64;
	case 8:
		return cls == 2 ? Arch::Mips64 : Arch::Mips32;
	case 243:
		return cls == 2 ? Arch::Riscv64 : Arch::Riscv32;
	default:
		return Arch::Unknown;
	}
}

bool isRelativeReloc(Arch arch, uint32_t type) {
	if (arch == Arch::X64)
		return type == 8;
	if (arch == Arch::Arm64)
		return type == 1027;
	if (arch == Arch::X86)
		return type == 8;
	if (arch == Arch::Arm32)
		return type == 23;
	return false;
}

size_t relocWidth(Arch arch, uint32_t type) {
	if (arch == Arch::X64) {
		if (type == 1 || type == 8)
			return 8;
		return 4;
	}
	if (arch == Arch::Arm64) {
		if (type == 257 || type == 1025 || type == 1026 || type == 1027)
			return 8;
		return 4;
	}
	if (arch == Arch::X86 || arch == Arch::Arm32 || arch == Arch::Mips32 || arch == Arch::Riscv32)
		return 4;
	if (arch == Arch::Mips64 || arch == Arch::Riscv64)
		return type == 2 || type == 1 ? 8 : 4;
	return 4;
}

uint64_t vaToFile(const Binary& bin, uint64_t va) {
	auto i = bin.sectionAtVa(va);
	if (!i)
		return UINT64_MAX;
	const Section& s = bin.sections()[*i];
	const uint64_t delta = va - s.va;
	if (delta >= s.fileSize)
		return UINT64_MAX;
	return s.fileOffset + delta;
}

void markVaReloc(Binary& bin, uint64_t va, size_t width) {
	const uint64_t off = vaToFile(bin, va);
	if (off == UINT64_MAX)
		return;
	bin.markReloc(off, width);
}

void parseRelA(Binary& bin, std::span<const uint8_t> bytes, size_t off, size_t sz, size_t ent,
	bool is64, bool be, bool withAddend) {
	if (ent == 0)
		ent = withAddend ? (is64 ? 24 : 12) : (is64 ? 16 : 8);
	if (ent == 0)
		return;
	for (size_t i = 0; i + ent <= sz; i += ent) {
		if (!inRange(off + i, ent, bytes.size()))
			break;
		const uint8_t* p = bytes.data() + off + i;
		uint64_t roff;
		uint64_t info;
		if (is64) {
			roff = loadU64(p, be);
			info = loadU64(p + 8, be);
		} else {
			roff = loadU32(p, be);
			info = loadU32(p + 4, be);
		}
		const uint32_t type = is64 ? static_cast<uint32_t>(info & 0xFFFFFFFFu) : static_cast<uint32_t>(info & 0xFFu);
		const size_t width = relocWidth(bin.arch(), type);
		markVaReloc(bin, roff, width);
		if (withAddend && isRelativeReloc(bin.arch(), type)) {
			int64_t addend = 0;
			if (is64 && ent >= 24)
				addend = static_cast<int64_t>(loadU64(p + 16, be));
			else if (!is64 && ent >= 12)
				addend = static_cast<int32_t>(loadU32(p + 8, be));
			const uint64_t fileOff = vaToFile(bin, roff);
			if (fileOff != UINT64_MAX)
				bin.markRelocValue(fileOff, static_cast<uint64_t>(addend));
		}
	}
}

void parseRelr(Binary& bin, std::span<const uint8_t> bytes, size_t off, size_t sz, bool is64, bool be) {
	const size_t wsz = is64 ? 8 : 4;
	if (sz < wsz)
		return;
	uint64_t addr = 0;
	for (size_t i = 0; i + wsz <= sz; i += wsz) {
		if (!inRange(off + i, wsz, bytes.size()))
			break;
		const uint8_t* p = bytes.data() + off + i;
		const uint64_t w = is64 ? loadU64(p, be) : loadU32(p, be);
		if ((w & 1) == 0) {
			addr = w;
			markVaReloc(bin, addr, wsz);
			addr += wsz;
		} else {
			uint64_t bits = w >> 1;
			while (bits) {
				if (bits & 1)
					markVaReloc(bin, addr, wsz);
				bits >>= 1;
				addr += wsz;
			}
		}
	}
}

void parseDynamic(Binary& bin, std::span<const uint8_t> bytes, uint64_t dynVa, uint64_t dynSz, bool is64,
	bool be) {
	const uint64_t dynFile = vaToFile(bin, dynVa);
	if (dynFile == UINT64_MAX)
		return;
	const size_t ent = is64 ? 16 : 8;
	uint64_t rela = 0, relasz = 0, relaent = 0;
	uint64_t rel = 0, relsz = 0, relent = 0;
	uint64_t relr = 0, relrsz = 0;
	for (size_t i = 0; i + ent <= dynSz; i += ent) {
		if (!inRange(static_cast<size_t>(dynFile) + i, ent, bytes.size()))
			break;
		const uint8_t* p = bytes.data() + static_cast<size_t>(dynFile) + i;
		int64_t tag;
		uint64_t val;
		if (is64) {
			tag = static_cast<int64_t>(loadU64(p, be));
			val = loadU64(p + 8, be);
		} else {
			tag = static_cast<int32_t>(loadU32(p, be));
			val = loadU32(p + 4, be);
		}
		if (tag == DT_NULL)
			break;
		if (tag == DT_RELA)
			rela = val;
		else if (tag == DT_RELASZ)
			relasz = val;
		else if (tag == DT_RELAENT)
			relaent = val;
		else if (tag == DT_REL)
			rel = val;
		else if (tag == DT_RELSZ)
			relsz = val;
		else if (tag == DT_RELENT)
			relent = val;
		else if (tag == DT_RELR)
			relr = val;
		else if (tag == DT_RELRSZ)
			relrsz = val;
	}
	if (rela && relasz) {
		const uint64_t f = vaToFile(bin, rela);
		if (f != UINT64_MAX)
			parseRelA(bin, bytes, static_cast<size_t>(f), static_cast<size_t>(relasz), static_cast<size_t>(relaent),
				is64, be, true);
	}
	if (rel && relsz) {
		const uint64_t f = vaToFile(bin, rel);
		if (f != UINT64_MAX)
			parseRelA(bin, bytes, static_cast<size_t>(f), static_cast<size_t>(relsz), static_cast<size_t>(relent), is64,
				be, false);
	}
	if (relr && relrsz) {
		const uint64_t f = vaToFile(bin, relr);
		if (f != UINT64_MAX)
			parseRelr(bin, bytes, static_cast<size_t>(f), static_cast<size_t>(relrsz), is64, be);
	}
}

void addLoad(Binary& bin, uint64_t off, uint64_t va, uint64_t filesz, uint64_t memsz, uint32_t flags,
	const char* name) {
	Section s;
	s.name = name;
	s.va = va;
	s.fileOffset = off;
	s.fileSize = filesz;
	s.virtSize = memsz ? memsz : filesz;
	s.isExec = (flags & PF_X) != 0;
	s.isWrite = (flags & PF_W) != 0;
	s.isRead = (flags & PF_R) != 0;
	bin.addSection(std::move(s));
}

} // namespace

void parseElf(Binary& bin) {
	auto bytes = bin.bytes();
	if (bytes.size() < 52)
		throw ScanError("truncated ELF");
	const uint8_t cls = bytes[4];
	const bool be = bytes[5] == 2;
	const bool is64 = cls == 2;
	bin.setLittleEndian(!be);
	bin.setKind(is64 ? FileKind::Elf64 : FileKind::Elf32);
	if (is64 && bytes.size() < 64)
		throw ScanError("truncated ELF64");
	const uint16_t em = loadU16(bytes.data() + 18, be);
	bin.setArch(elfMachine(em, cls));
	const uint64_t phoff = is64 ? loadU64(bytes.data() + 32, be) : loadU32(bytes.data() + 28, be);
	const uint64_t shoff = is64 ? loadU64(bytes.data() + 40, be) : loadU32(bytes.data() + 32, be);
	const uint16_t phentsize = loadU16(bytes.data() + (is64 ? 54 : 42), be);
	const uint16_t phnum = loadU16(bytes.data() + (is64 ? 56 : 44), be);
	const uint16_t shentsize = loadU16(bytes.data() + (is64 ? 58 : 46), be);
	const uint16_t shnum = loadU16(bytes.data() + (is64 ? 60 : 48), be);
	const uint16_t shstrndx = loadU16(bytes.data() + (is64 ? 62 : 50), be);
	uint64_t dynVa = 0;
	uint64_t dynSz = 0;
	uint64_t minVa = UINT64_MAX;
	const size_t phSize = is64 ? 56 : 32;
	if (phentsize < phSize)
		throw ScanError("bad ELF phentsize");
	for (uint16_t i = 0; i < phnum; i++) {
		const uint64_t o = phoff + static_cast<uint64_t>(i) * phentsize;
		if (!inRange(static_cast<size_t>(o), phSize, bytes.size()))
			break;
		const uint8_t* p = bytes.data() + static_cast<size_t>(o);
		const uint32_t type = loadU32(p, be);
		uint32_t flags;
		uint64_t off, va, filesz, memsz;
		if (is64) {
			flags = loadU32(p + 4, be);
			off = loadU64(p + 8, be);
			va = loadU64(p + 16, be);
			filesz = loadU64(p + 32, be);
			memsz = loadU64(p + 40, be);
		} else {
			off = loadU32(p + 4, be);
			va = loadU32(p + 8, be);
			filesz = loadU32(p + 16, be);
			memsz = loadU32(p + 20, be);
			flags = loadU32(p + 24, be);
		}
		if (type == PT_LOAD) {
			if (va < minVa)
				minVa = va;
			char name[16];
			std::snprintf(name, sizeof(name), "load%u", i);
			addLoad(bin, off, va, filesz, memsz, flags, name);
		} else if (type == PT_DYNAMIC) {
			dynVa = va;
			dynSz = filesz;
		}
	}
	if (minVa != UINT64_MAX)
		bin.setImageBase(minVa);
	const size_t shSize = is64 ? 64 : 40;
	if (shoff && shnum && shentsize >= shSize) {
		std::string strtab;
		if (shstrndx < shnum) {
			const uint64_t so = shoff + static_cast<uint64_t>(shstrndx) * shentsize;
			if (inRange(static_cast<size_t>(so), shSize, bytes.size())) {
				const uint8_t* p = bytes.data() + static_cast<size_t>(so);
				const uint64_t sOff = is64 ? loadU64(p + 24, be) : loadU32(p + 16, be);
				const uint64_t sSz = is64 ? loadU64(p + 32, be) : loadU32(p + 20, be);
				if (inRange(static_cast<size_t>(sOff), static_cast<size_t>(sSz), bytes.size())) {
					strtab.assign(reinterpret_cast<const char*>(bytes.data() + sOff), static_cast<size_t>(sSz));
				}
			}
		}
		if (!strtab.empty() || shnum > 0) {
			std::vector<Section> named;
			for (uint16_t i = 0; i < shnum; i++) {
				const uint64_t o = shoff + static_cast<uint64_t>(i) * shentsize;
				if (!inRange(static_cast<size_t>(o), shSize, bytes.size()))
					break;
				const uint8_t* p = bytes.data() + static_cast<size_t>(o);
				const uint32_t nameOff = loadU32(p, be);
				const uint32_t type = loadU32(p + 4, be);
				const uint64_t flags = is64 ? loadU64(p + 8, be) : loadU32(p + 8, be);
				const uint64_t va = is64 ? loadU64(p + 16, be) : loadU32(p + 12, be);
				const uint64_t off = is64 ? loadU64(p + 24, be) : loadU32(p + 16, be);
				const uint64_t sz = is64 ? loadU64(p + 32, be) : loadU32(p + 20, be);
				if (type == SHT_RELA)
					parseRelA(bin, bytes, static_cast<size_t>(off), static_cast<size_t>(sz), 0, is64, be, true);
				else if (type == SHT_REL)
					parseRelA(bin, bytes, static_cast<size_t>(off), static_cast<size_t>(sz), 0, is64, be, false);
				else if (type == SHT_RELR)
					parseRelr(bin, bytes, static_cast<size_t>(off), static_cast<size_t>(sz), is64, be);
				if (type == 0 || sz == 0)
					continue;
				if (off >= bytes.size())
					continue;
				Section s;
				if (nameOff < strtab.size())
					s.name = strtab.c_str() + nameOff;
				else
					s.name = "sht";
				s.va = va;
				s.fileOffset = off;
				s.fileSize = std::min<uint64_t>(sz, bytes.size() - off);
				s.virtSize = sz;
				s.isExec = (flags & SHF_EXECINSTR) != 0;
				s.isWrite = (flags & SHF_WRITE) != 0;
				s.isRead = true;
				if (s.fileSize)
					named.push_back(std::move(s));
			}
			if (!named.empty()) {
				bin.clearSections();
				for (auto& s : named)
					bin.addSection(std::move(s));
			}
		}
	}
	if (dynVa && dynSz)
		parseDynamic(bin, bytes, dynVa, dynSz, is64, be);
	if (bin.sections().empty())
		parseRaw(bin);
}

}
