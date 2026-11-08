/* pecaller: the PE (Windows-side) frames of a Wine thread's syscall (pe.bpf.h copies them, pe.cpp unwinds
 * them; docs/LINUX.md "PE frames"). Included by bpf.cpp at global scope after Record/Repeated/FlushRepeats. */
#include "pe.h"

namespace {
constexpr size_t kPeFrames = MSMON_MAX_STACK_FRAMES - MM_FRAMES;

/* record.stack = the PE frames (when pe.rip != 0), then the unix frames. Also used for wineserver-request
 * records, so it relies on pe and the frames only. */
void PeFrames(const mm_pe& pe, DWORD tgid, uint64_t start, const __u64* frames, uint32_t count, LinuxRecord& record)
{
    record.stack.clear();
    if (pe.rip != 0) {
        static const PeRanges kNone;
        const std::shared_ptr<const PeRanges> images = ImagesPe(tgid, start);
        const PeWalkResult walk = PeWalk(images ? *images : kNone, pe.rip, pe.rsp, pe.rbp, pe.stack,
                                         std::min<uint32_t>(pe.bytes, MM_PE_BYTES), record.stack, kPeFrames);
        if (walk.frames) {
            record.detail += L";pe_frames=" + std::to_wstring(walk.frames);
            if (walk.scanned) record.detail += L";pe_scanned=" + std::to_wstring(walk.scanned);
        }
    }
    record.stack.insert(record.stack.end(), frames, frames + count);
}

int PeOpened(std::wstring& detail, unsigned&)
{
    detail += L";pe_frames=" + std::to_wstring(kPeFrames) + L";pe_stack_bytes=" + std::to_wstring(MM_PE_BYTES);
    return 0;
}

void PeNotes(Notes& notes)
{
    notes.push_back({L"pe_frames",
                     L"syscall records of x64 Wine threads put up to " + std::to_wstring(kPeFrames) +
                         L" PE (Windows-side) frames before the unix frames: the NtXxx stub in ntdll.dll, the return"
                         L" addresses unwound with the images' .pdata/.xdata from " + std::to_wstring(MM_PE_BYTES) +
                         L" bytes of the PE stack (detail pe_frames=N), then words of that stack inside PE code"
                         L" (pe_scanned=M, may be stale); WoW64 threads show their 64-bit side; frames are resolved"
                         L" against image_load of the last maps scan; modules lists the first 8 images"});
}
}  // namespace
