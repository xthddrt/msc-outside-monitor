#include "session.h"
#include "pe.h"
#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <tuple>

/*
 * image_load from /proc/<pid>/maps (pe.cpp MappedImages): one record per load of a PE image (value0 = the
 * mapping of its header, value1 = SizeOfImage) and per other executable file (value0 = lowest address of its
 * mappings, value1 = span to the highest). Polled on track, on an executable mmap/mprotect and every two
 * seconds, so a library loaded and unloaded between polls is missed. The scan also keeps each process's PE
 * images for the PE frames of its syscall records (ImagesPe).
 */

static std::mutex gMutex;
static std::set<std::tuple<DWORD, uint64_t, uint64_t, std::string>> gSeen;
static std::map<std::pair<DWORD, uint64_t>, std::pair<uint64_t, std::shared_ptr<const PeRanges>>> gPe;   /* scan, ranges */
static uint64_t gScan;

void ImagesReset()
{
    std::lock_guard<std::mutex> lock(gMutex);
    gSeen.clear();
    gPe.clear();
}

void ImagesForget(DWORD pid)
{
    std::lock_guard<std::mutex> lock(gMutex);
    for (auto it = gSeen.begin(); it != gSeen.end();) {
        it = std::get<0>(*it) == pid ? gSeen.erase(it) : std::next(it);
    }
    for (auto it = gPe.begin(); it != gPe.end();) {
        it = it->first.first == pid ? gPe.erase(it) : std::next(it);
    }
}

std::shared_ptr<const PeRanges> ImagesPe(uint32_t pid, uint64_t start)
{
    std::lock_guard<std::mutex> lock(gMutex);
    auto found = gPe.find({pid, start});
    return found == gPe.end() ? nullptr : found->second.second;
}

void ImagesScan(LinuxSession& session, DWORD pid, uint64_t start)
{
    session.Enter(MSMON_SENSOR_LINUX_MAPS_POLL);
    uint64_t scan;
    {
        std::lock_guard<std::mutex> lock(gMutex);
        scan = ++gScan;
    }
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    const std::vector<MappedImage> images = MappedImages(maps);
    /* A reused PID's maps belong to another process. */
    if (images.empty() || LinuxProcessStart(pid) != start) return;
    auto pe = std::make_shared<PeRanges>();
    for (const MappedImage& image : images) {
        if (!image.executable) continue;
        if (image.pe) pe->ranges.push_back({image.base, image.base + image.size, image.pe});
        {
            std::lock_guard<std::mutex> lock(gMutex);
            if (!gSeen.emplace(pid, start, image.base, image.path).second) continue;
        }
        session.Log(MSMON_SENSOR_LINUX_MAPS_POLL, MsMonImageLoad, pid, start, 0, image.base, image.size,
                    LinuxWide(image.path));
    }
    std::lock_guard<std::mutex> lock(gMutex);
    /* The poll and ring threads scan concurrently: a scan that read maps earlier never replaces a later one. */
    auto& slot = gPe[{pid, start}];
    if (scan > slot.first) slot = {scan, std::move(pe)};
}
