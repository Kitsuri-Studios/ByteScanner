#pragma once

#include "arch.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bscan {

enum class SiteKind {
	OutOfRange,
	Unmapped,
	Data,
	Code,
	FuncStart,
	MidFunc,
};

struct FuncRange {
	uint64_t startVa = 0;
	uint64_t endVa = 0;
	uint64_t startFile = 0;
	size_t sectionIndex = 0;
};

struct SiteInfo {
	SiteKind kind = SiteKind::Unmapped;
	std::string section;
	uint64_t parentVa = 0;
	uint64_t parentFile = 0;
	uint64_t parentDelta = 0;
	bool hasParent = false;
	bool isExec = false;
};

struct Fingerprint {
	std::vector<uint32_t> keys;
	std::vector<uint8_t> classes;
	std::vector<uint64_t> callees;
	std::vector<std::string> strings;
	std::vector<std::string> calleeNames;
	SiteInfo site;
	std::string typeInfo;
	uint32_t callCount = 0;
	uint32_t callUnique = 0;
	uint32_t xrefCount = 0;
	int vtableSlot = -1;
};

class Logger;

class FuncMap {
public:
	void build(const Binary& bin, const Logger* log = nullptr);
	SiteInfo classify(const Binary& bin, const ResolvedAddr& addr) const;
	SiteInfo classifyFile(const Binary& bin, uint64_t fileOff) const;
	std::optional<FuncRange> containing(uint64_t va) const;
	const std::vector<FuncRange>& funcs() const { return funcs_; }

private:
	std::vector<FuncRange> funcs_;
};

bool isPrelude(Arch arch, std::span<const uint8_t> bytes);
bool isPrelude(Arch arch, std::span<const uint8_t> bytes, std::span<const uint8_t> prev);
void classifyInsn(Arch arch, std::span<const uint8_t> bytes, Insn& insn);
std::string_view siteKindName(SiteKind k);
struct FuncIndex {
	std::vector<uint64_t> fileOffs;
	std::vector<Fingerprint> fps;
};

Fingerprint makeFingerprint(const Binary& bin, const FuncMap& map, uint64_t fileOff, size_t nInsns);
void bindCalleeNames(Fingerprint& fp, const std::unordered_map<uint64_t, std::string>& names);
int scoreFingerprint(const Fingerprint& origin, const Fingerprint& cand);
int scoreBsim(const Fingerprint& origin, const Fingerprint& cand);
int scoreNamedCallees(const Fingerprint& origin, const Fingerprint& cand,
	const std::unordered_map<std::string, uint64_t>& foundVa);
bool callsTooLow(const Fingerprint& origin, const Fingerprint& cand);
bool callsTooHigh(const Fingerprint& origin, const Fingerprint& cand);
bool fingerprintAgrees(const Fingerprint& origin, const Fingerprint& cand, bool needKeys = false);
void buildFuncIndex(const Binary& bin, const FuncMap& map, size_t nInsns, FuncIndex& idx, const Logger* log);
std::optional<uint64_t> locateByFingerprint(const Fingerprint& origin, const FuncIndex& idx,
	const std::unordered_map<std::string, uint64_t>& foundVa);
std::optional<uint64_t> locateByTypeInfo(const Binary& bin, const FuncMap& map, std::string_view typeInfo,
	bool wantData);
std::optional<uint64_t> locateByStringXref(const Binary& bin, const FuncMap& map, const Fingerprint& origin,
	bool wantData);

struct Vtable {
	uint64_t fileOff = 0;
	std::vector<uint64_t> methods;
};

std::string classKey(std::string_view name);
std::vector<Vtable> findVtables(const Binary& bin, uint64_t methodVa);
std::optional<Vtable> pickVtable(const std::vector<Vtable>& vts, const std::vector<uint64_t>& anchors);
std::optional<Vtable> findClassVtable(const Binary& bin, std::string_view key, bool allowMany = false);
int vtableSlot(const Vtable& vt, uint64_t methodVa);
std::optional<uint64_t> mapVtableTarget(const Vtable* oldVt, uint64_t oldTarget, uint64_t oldAnchor,
	const Vtable& neuVt, uint64_t newAnchor);
std::optional<uint64_t> huntClassMethod(const Binary& neu, const Binary* origin, std::string_view key,
	uint64_t oldTargetVa, const std::vector<uint64_t>& newAnchors, const std::vector<uint64_t>& oldAnchors,
	const std::vector<uint64_t>& takenVas, bool allowMany = false);

}
