cmake_minimum_required(VERSION 3.20)
project(ByteScanner LANGUAGES CXX)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.31)
	set(CMAKE_CXX_STANDARD 26)
else()
	set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED OFF)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type" FORCE)
	set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(BSCAN_AVX2 "avx2 kernels on x64" ON)
option(BSCAN_NATIVE "gcc/clang -march=native" OFF)
option(BSCAN_WERROR "warnings as errors" OFF)
option(BSCAN_SANITIZE "asan+ubsan (gcc/clang)" OFF)
option(BSCAN_LTO "link time optimization" OFF)

function(bscan_tune tgt)
	if(MSVC)
		target_compile_options(${tgt} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
		if(BSCAN_WERROR)
			target_compile_options(${tgt} PRIVATE /WX)
		endif()
		if(BSCAN_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|amd64")
			target_compile_options(${tgt} PRIVATE /arch:AVX2)
		endif()
	else()
		target_compile_options(${tgt} PRIVATE -Wall -Wextra)
		if(BSCAN_WERROR)
			target_compile_options(${tgt} PRIVATE -Werror)
		endif()
		if(BSCAN_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
			target_compile_options(${tgt} PRIVATE -mavx2)
		endif()
		if(BSCAN_NATIVE)
			target_compile_options(${tgt} PRIVATE -march=native)
		endif()
		if(BSCAN_SANITIZE)
			target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
			target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
		endif()
	endif()
	if(BSCAN_LTO)
		set_property(TARGET ${tgt} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
	endif()
endfunction()

set(BSCAN_SOURCES
	src/core/bytes.cpp
	src/core/mem.cpp
	src/binary/image.cpp
	src/binary/elf.cpp
	src/binary/pe.cpp
	src/pattern/pattern.cpp
	src/arch/wildcard.cpp
	src/arch/classify.cpp
	src/arch/x86.cpp
	src/arch/arm64.cpp
	src/arch/arm32.cpp
	src/arch/mips.cpp
	src/arch/riscv.cpp
	src/func/prelude.cpp
	src/func/map.cpp
	src/func/fingerprint.cpp
	src/func/vtable.cpp
	src/func/xref.cpp
	src/scan/hybrid.cpp
	src/scan/scanner.cpp
	src/csv/csv.cpp
	src/siggen/generate.cpp
	src/relocate/relocate.cpp
	src/cli/flags.cpp
)

add_library(bscan STATIC ${BSCAN_SOURCES})
target_include_directories(bscan PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(WIN32)
	target_link_libraries(bscan PUBLIC psapi)
endif()
bscan_tune(bscan)

add_executable(bytescanner src/cli/main.cpp)
target_link_libraries(bytescanner PRIVATE bscan)
bscan_tune(bytescanner)

add_executable(bytescanner_test
	tests/test_main.cpp
	tests/test_bytes.cpp
	tests/test_pattern.cpp
	tests/test_scan.cpp
	tests/test_csv.cpp
	tests/test_binary.cpp
	tests/test_arch.cpp
	tests/test_siggen.cpp
	tests/test_func.cpp
	tests/test_mem.cpp
)
target_include_directories(bytescanner_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(bytescanner_test PRIVATE bscan)
bscan_tune(bytescanner_test)

enable_testing()
add_test(NAME bytescanner_test COMMAND bytescanner_test)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT bytescanner)
