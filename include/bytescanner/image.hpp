#pragma once

#include "bytes.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bscan {

enum class FileKind {
	Unknown,
	Elf32,
	Elf64,
	Pe32,
	Pe64,
};

enum class Arch {
	Unknown,
	X86,
	X64,
	Arm32,
	Arm64,
	Thumb,
	Mips32,
	Mips64,
	Riscv32,
	Riscv64,
};

enum class AddressKind {
	Va,
	Rva,
	File,
};

struct Section {
	std::string name;
	uint64_t va = 0;
	uint64_t fileOffset = 0;
	uint64_t fileSize = 0;
	uint64_t virtSize = 0;
	bool isExec = false;
	bool isWrite = false;
	bool isRead = true;
};

struct ResolvedAddr {
	uint64_t fileOffset = 0;
	uint64_t va = 0;
	uint64_t rva = 0;
	AddressKind kind = AddressKind::Va;
	size_t sectionIndex = 0;
};

class Binary {
public:
	static Binary load(const std::string& path);
	static Binary loadBytes(std::vector<uint8_t> bytes, Arch arch = Arch::Unknown);

	FileKind kind() const { return kind_; }
	Arch arch() const { return arch_; }
	void setArch(Arch arch) { arch_ = arch; }
	uint64_t imageBase() const { return imageBase_; }
	bool isLittleEndian() const { return isLittle_; }
	bool is64() const;
	size_t ptrWidth() const { return is64() ? 8 : 4; }
	bool isExecVa(uint64_t va) const;
	std::optional<uint64_t> readPtr(uint64_t fileOff) const;
	std::span<const uint8_t> bytes() const { return bytes_; }
	const std::vector<Section>& sections() const { return sections_; }
	bool isRelocByte(uint64_t fileOffset) const;
	void markReloc(uint64_t fileOffset, size_t width);
	void markRelocValue(uint64_t fileOffset, uint64_t value);
	std::optional<uint64_t> relocValue(uint64_t fileOffset) const;
	const std::unordered_map<uint64_t, uint64_t>& relocValues() const { return relocVal_; }

	std::optional<ResolvedAddr> resolve(uint64_t addr) const;
	std::optional<ResolvedAddr> resolve(uint64_t addr, AddressKind kind) const;
	uint64_t emitAddr(const ResolvedAddr& a, AddressKind kind) const;
	std::span<const uint8_t> sliceFile(uint64_t fileOffset, size_t n) const;
	std::optional<size_t> sectionAtFile(uint64_t fileOffset) const;
	std::optional<size_t> sectionAtVa(uint64_t va) const;

	void addSection(Section s);
	void clearSections() { sections_.clear(); }
	void setKind(FileKind k) { kind_ = k; }
	void setImageBase(uint64_t b) { imageBase_ = b; }
	void setLittleEndian(bool v) { isLittle_ = v; }

private:
	std::vector<uint8_t> bytes_;
	std::vector<uint64_t> relocBits_;
	std::unordered_map<uint64_t, uint64_t> relocVal_;
	std::vector<Section> sections_;
	FileKind kind_ = FileKind::Unknown;
	Arch arch_ = Arch::Unknown;
	uint64_t imageBase_ = 0;
	bool isLittle_ = true;

	void initMask();
	std::optional<ResolvedAddr> fromSection(size_t i, uint64_t va, AddressKind kind) const;
};

void parseElf(Binary& bin);
void parsePe(Binary& bin);
void parseRaw(Binary& bin);

std::string_view archName(Arch a);
Arch parseArch(std::string_view s);
std::string_view fileKindName(FileKind k);
bool isCodeArch(Arch a);

}
