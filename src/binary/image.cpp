#include "bytescanner/image.hpp"

#include <algorithm>
#include <cstring>

namespace bscan {

namespace {

bool looksElf(std::span<const uint8_t> b) {
	return b.size() >= 4 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F';
}

bool looksPe(std::span<const uint8_t> b) {
	if (b.size() < 0x40)
		return false;
	if (b[0] != 'M' || b[1] != 'Z')
		return false;
	const uint32_t off = loadU32le(b.data() + 0x3C);
	if (!inRange(off, 4, b.size()))
		return false;
	return b[off] == 'P' && b[off + 1] == 'E' && b[off + 2] == 0 && b[off + 3] == 0;
}

} // namespace

void Binary::initMask() {
	relocBits_.clear();
	relocVal_.clear();
}

bool Binary::is64() const {
	switch (arch_) {
	case Arch::X64:
	case Arch::Arm64:
	case Arch::Mips64:
	case Arch::Riscv64:
		return true;
	default:
		return kind_ == FileKind::Elf64 || kind_ == FileKind::Pe64;
	}
}

bool Binary::isExecVa(uint64_t va) const {
	auto i = sectionAtVa(va);
	return i && sections_[*i].isExec;
}

std::optional<uint64_t> Binary::readPtr(uint64_t fileOff) const {
	if (auto rel = relocValue(fileOff))
		return rel;
	const size_t n = ptrWidth();
	auto sl = sliceFile(fileOff, n);
	if (sl.size() < n)
		return std::nullopt;
	if (n == 8)
		return isLittleEndian() ? loadU64le(sl.data()) : loadU64be(sl.data());
	return isLittleEndian() ? loadU32le(sl.data()) : loadU32be(sl.data());
}

bool Binary::isRelocByte(uint64_t fileOffset) const {
	if (relocBits_.empty() || fileOffset >= bytes_.size())
		return false;
	const size_t i = static_cast<size_t>(fileOffset);
	return (relocBits_[i >> 6] >> (i & 63)) & 1ull;
}

void Binary::markReloc(uint64_t fileOffset, size_t width) {
	if (width == 0 || !inRange(static_cast<size_t>(fileOffset), width, bytes_.size()))
		return;
	const size_t words = (bytes_.size() + 63) / 64;
	if (relocBits_.size() < words)
		relocBits_.assign(words, 0);
	for (size_t i = 0; i < width; i++) {
		const size_t at = static_cast<size_t>(fileOffset) + i;
		relocBits_[at >> 6] |= 1ull << (at & 63);
	}
}

void Binary::markRelocValue(uint64_t fileOffset, uint64_t value) {
	relocVal_[fileOffset] = value;
}

std::optional<uint64_t> Binary::relocValue(uint64_t fileOffset) const {
	auto it = relocVal_.find(fileOffset);
	if (it == relocVal_.end())
		return std::nullopt;
	return it->second;
}

void Binary::addSection(Section s) {
	if (s.virtSize < s.fileSize)
		s.virtSize = s.fileSize;
	sections_.push_back(std::move(s));
}

std::optional<size_t> Binary::sectionAtVa(uint64_t va) const {
	for (size_t i = 0; i < sections_.size(); i++) {
		const Section& s = sections_[i];
		const uint64_t span = s.virtSize ? s.virtSize : s.fileSize;
		if (va >= s.va && va < s.va + span)
			return i;
	}
	return std::nullopt;
}

std::optional<size_t> Binary::sectionAtFile(uint64_t fileOffset) const {
	for (size_t i = 0; i < sections_.size(); i++) {
		const Section& s = sections_[i];
		if (fileOffset >= s.fileOffset && fileOffset < s.fileOffset + s.fileSize)
			return i;
	}
	return std::nullopt;
}

std::optional<ResolvedAddr> Binary::fromSection(size_t i, uint64_t va, AddressKind kind) const {
	const Section& s = sections_[i];
	if (va < s.va)
		return std::nullopt;
	const uint64_t delta = va - s.va;
	if (delta >= s.fileSize)
		return std::nullopt;
	ResolvedAddr r;
	r.sectionIndex = i;
	r.va = va;
	r.rva = va - imageBase_;
	r.fileOffset = s.fileOffset + delta;
	r.kind = kind;
	return r;
}

std::optional<ResolvedAddr> Binary::resolve(uint64_t addr, AddressKind kind) const {
	if (kind == AddressKind::File) {
		auto i = sectionAtFile(addr);
		if (!i && addr < bytes_.size()) {
			ResolvedAddr r;
			r.fileOffset = addr;
			r.va = addr;
			r.rva = addr;
			r.kind = AddressKind::File;
			return r;
		}
		if (!i)
			return std::nullopt;
		const Section& s = sections_[*i];
		ResolvedAddr r;
		r.sectionIndex = *i;
		r.fileOffset = addr;
		r.va = s.va + (addr - s.fileOffset);
		r.rva = r.va - imageBase_;
		r.kind = AddressKind::File;
		return r;
	}
	uint64_t va = addr;
	if (kind == AddressKind::Rva)
		va = imageBase_ + addr;
	auto i = sectionAtVa(va);
	if (!i)
		return std::nullopt;
	return fromSection(*i, va, kind);
}

std::optional<ResolvedAddr> Binary::resolve(uint64_t addr) const {
	if (auto r = resolve(addr, AddressKind::Va))
		return r;
	if (imageBase_ != 0) {
		if (auto r = resolve(addr, AddressKind::Rva))
			return r;
	}
	if (auto r = resolve(addr, AddressKind::File))
		return r;
	return std::nullopt;
}

uint64_t Binary::emitAddr(const ResolvedAddr& a, AddressKind kind) const {
	switch (kind) {
	case AddressKind::File:
		return a.fileOffset;
	case AddressKind::Rva:
		return a.rva;
	default:
		return a.va;
	}
}

std::span<const uint8_t> Binary::sliceFile(uint64_t fileOffset, size_t n) const {
	return subspan(bytes_, static_cast<size_t>(fileOffset), n);
}

Binary Binary::loadBytes(std::vector<uint8_t> bytes, Arch arch) {
	Binary b;
	b.bytes_ = std::move(bytes);
	b.initMask();
	b.arch_ = arch;
	auto view = std::span<const uint8_t>(b.bytes_);
	if (looksElf(view))
		parseElf(b);
	else if (looksPe(view))
		parsePe(b);
	else
		parseRaw(b);
	if (arch != Arch::Unknown)
		b.arch_ = arch;
	return b;
}

Binary Binary::load(const std::string& path) {
	return loadBytes(readFileBytes(path));
}

void parseRaw(Binary& bin) {
	bin.setKind(FileKind::Unknown);
	Section s;
	s.name = ".raw";
	s.va = 0;
	s.fileOffset = 0;
	s.fileSize = bin.bytes().size();
	s.virtSize = s.fileSize;
	s.isExec = true;
	s.isRead = true;
	bin.addSection(std::move(s));
	bin.setImageBase(0);
}

std::string_view archName(Arch a) {
	switch (a) {
	case Arch::X86:
		return "x86";
	case Arch::X64:
		return "x86_64";
	case Arch::Arm32:
		return "arm";
	case Arch::Arm64:
		return "arm64";
	case Arch::Thumb:
		return "thumb";
	case Arch::Mips32:
		return "mips";
	case Arch::Mips64:
		return "mips64";
	case Arch::Riscv32:
		return "riscv32";
	case Arch::Riscv64:
		return "riscv64";
	default:
		return "unknown";
	}
}

Arch parseArch(std::string_view s) {
	if (s == "x86" || s == "i386" || s == "ia32")
		return Arch::X86;
	if (s == "x64" || s == "x86_64" || s == "amd64")
		return Arch::X64;
	if (s == "arm" || s == "arm32" || s == "aarch32")
		return Arch::Arm32;
	if (s == "arm64" || s == "aarch64")
		return Arch::Arm64;
	if (s == "thumb")
		return Arch::Thumb;
	if (s == "mips")
		return Arch::Mips32;
	if (s == "mips64")
		return Arch::Mips64;
	if (s == "riscv" || s == "riscv32")
		return Arch::Riscv32;
	if (s == "riscv64")
		return Arch::Riscv64;
	if (s == "auto" || s.empty())
		return Arch::Unknown;
	throw ScanError("unknown arch " + std::string(s));
}

std::string_view fileKindName(FileKind k) {
	switch (k) {
	case FileKind::Elf32:
		return "ELF32";
	case FileKind::Elf64:
		return "ELF64";
	case FileKind::Pe32:
		return "PE32";
	case FileKind::Pe64:
		return "PE32+";
	default:
		return "raw";
	}
}

bool isCodeArch(Arch a) {
	return a != Arch::Unknown;
}

}
