#include "session.h"
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <tuple>

/*
 * image_load from /proc/<pid>/maps: one record per executable file mapping, with
 * Value0 = lowest address of that file's mappings and Value1 = span to the highest.
 * Polled on track and every two seconds, so a library loaded and unloaded between
 * polls is missed.
 */

static std::mutex gMutex;
static std::set<std::tuple<DWORD, uint64_t, uint64_t, std::string>> gSeen;

void ImagesReset()
{
    std::lock_guard<std::mutex> lock(gMutex);
    gSeen.clear();
}

void ImagesForget(DWORD pid)
{
    std::lock_guard<std::mutex> lock(gMutex);
    for (auto it = gSeen.begin(); it != gSeen.end();) {
        it = std::get<0>(*it) == pid ? gSeen.erase(it) : std::next(it);
    }
}

void ImagesScan(LinuxSession& session, DWORD pid, uint64_t start)
{
    session.Enter(MSMON_SENSOR_LINUX_MAPS_POLL);
    struct Image {
        uint64_t low = ~0ull;
        uint64_t high = 0;
        bool executable = false;
    };
    std::map<std::string, Image> images;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        std::istringstream fields(line);
        std::string range, perms, offset, device, inode, path;
        if (!(fields >> range >> perms >> offset >> device >> inode)) continue;
        std::getline(fields >> std::ws, path);
        if (path.empty() || path[0] != '/') continue;
        size_t dash = range.find('-');
        if (dash == std::string::npos) continue;
        Image& image = images[path];
        image.low = std::min<uint64_t>(image.low, std::stoull(range.substr(0, dash), nullptr, 16));
        image.high = std::max<uint64_t>(image.high, std::stoull(range.substr(dash + 1), nullptr, 16));
        if (perms.size() > 2 && perms[2] == 'x') image.executable = true;
    }
    /* A reused PID's maps belong to another process. */
    if (images.empty() || LinuxProcessStart(pid) != start) return;
    for (const auto& item : images) {
        if (!item.second.executable) continue;
        {
            std::lock_guard<std::mutex> lock(gMutex);
            if (!gSeen.emplace(pid, start, item.second.low, item.first).second) continue;
        }
        session.Log(MSMON_SENSOR_LINUX_MAPS_POLL, MsMonImageLoad, pid, start, 0, item.second.low,
                    item.second.high - item.second.low, LinuxWide(item.first));
    }
}
