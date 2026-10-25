#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace bscan {

constexpr uint64_t kDefaultMemCap = 1024ull * 1024 * 1024;
constexpr uint64_t kMinMemCap = 64ull * 1024 * 1024;

uint64_t physAvail();
uint64_t physTotal();
uint64_t rssBytes();
uint64_t parseMemSize(std::string_view s, uint64_t avail);
std::string formatMem(uint64_t n);
uint64_t pickBudget(uint64_t avail, uint64_t want);

class MemBudget {
public:
	explicit MemBudget(uint64_t cap);
	bool tryReserve(uint64_t n);
	void release(uint64_t n);
	uint64_t cap() const { return cap_; }
	uint64_t used() const { return used_; }
	uint64_t left() const { return used_ >= cap_ ? 0 : cap_ - used_; }

private:
	uint64_t cap_ = 0;
	uint64_t used_ = 0;
};

bool streamIsTty(FILE* f);
void enableVt(FILE* f);
bool wantColor(FILE* f);

class Logger {
public:
	bool silent = false;
	bool color = false;
	void info(std::string_view msg) const;
	void ok(std::string_view msg) const;
	void warn(std::string_view msg) const;
	void progress(size_t i, size_t n, std::string_view name) const;
	void finish() const;

private:
	mutable bool spin_ = false;
	const char* paint(const char* code) const;
	void say(const char* tagCol, std::string_view msg) const;
};

}
