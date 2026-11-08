#pragma once
/*
 * PE (Windows-side) frames of Wine threads (docs/LINUX.md "PE frames"): PE files parsed from disk, the
 * images mapped in a process, and an x64 unwinder over the PE stack copied by pe.bpf.h. No session.h
 * types, so tests/linux_pe_test.cpp links pe.cpp alone.
 */
#include <cstdint>
#include <istream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/* One PE file: its size in memory, executable sections and (x64) .pdata/.xdata. */
struct PeImage {
    struct Function {
        uint32_t begin, end, unwind;   /* RUNTIME_FUNCTION RVAs */
    };
    uint16_t machine = 0;              /* 0x8664 x64, 0x14c i386 */
    uint32_t sizeOfImage = 0;
    std::vector<Function> functions;   /* sorted by begin; x64 only */
    std::vector<std::pair<uint32_t, uint32_t>> code;          /* executable sections [begin, end) */
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> data;   /* sections holding UNWIND_INFO: rva, bytes */

    const Function* Find(uint32_t rva) const;
    bool Code(uint32_t rva) const;
    const uint8_t* At(uint32_t rva, uint32_t size) const;   /* size bytes of data at rva, or nullptr */
};

/* The parsed PE file at path, or nullptr (not a regular PE file, or not the file with that inode any more).
 * Parsed once per path, inode, size and mtime and cached. */
std::shared_ptr<const PeImage> PeOpen(const std::string& path, uint64_t inode = 0);

/* One image in /proc/<pid>/maps. A PE image is one per load: base = the mapping of its header (file offset
 * 0), size = SizeOfImage. Any other file is one per path: lowest address and span to the highest. */
struct MappedImage {
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
    bool executable = false;   /* a mapping inside it is executable (Wine mprotects PE code later) */
    std::shared_ptr<const PeImage> pe;
};
std::vector<MappedImage> MappedImages(std::istream& maps);   /* sorted by base */

/* A process's executable PE images, sorted by base. */
struct PeRanges {
    struct Range {
        uint64_t base, end;
        std::shared_ptr<const PeImage> image;
    };
    std::vector<Range> ranges;
    const Range* Find(uint64_t address) const;
};

/* Appends to out (at most max entries) the PE frames of one Wine syscall: rip, then the return addresses
 * unwound from the stack bytes copied at rsp, then the words of the rest of the stack that lie in PE code. */
struct PeWalkResult {
    uint32_t frames = 0;    /* entries appended */
    uint32_t scanned = 0;   /* of them, found by the stack scan */
};
PeWalkResult PeWalk(const PeRanges& images, uint64_t rip, uint64_t rsp, uint64_t rbp, const uint8_t* stack,
                    uint32_t bytes, std::vector<uint64_t>& out, size_t max);

/* images.cpp: the PE images of a tracked process as of its last maps scan, or nullptr. */
std::shared_ptr<const PeRanges> ImagesPe(uint32_t pid, uint64_t start);
