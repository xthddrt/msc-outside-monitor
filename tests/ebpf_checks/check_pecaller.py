"""pecaller (PE frames) checks, called by tests/linux_ebpf_test.sh check(). In every mode the ebpf_active detail
names pe_frames=16. In the ebpf session, once pecaller.sh ran `wine cmd /c exit` under the probe (wine-ran next to
path): x64 ntdll.dll is an image_load spanning its SizeOfImage, no image spans 4 GiB or more, and a syscall
record of the probe's Wine descendants has PE frames with ntdll.dll first in modules."""
import os
import re
import struct

NTDLL = "/x86_64-windows/ntdll.dll"


def size_of_image(path):
    with open(path, "rb") as stream:
        data = stream.read(4096)
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<I", data, nt + 24 + 56)[0]


def check(mode, path, events, mine, pids, coverage, problems):
    active = [e for e in events if e.get("type") == "coverage" and e.get("text") == "ebpf_active"]
    if active and not any("pe_frames=16" in e.get("detail", "") for e in active):
        problems.append("pecaller: ebpf_active has no pe_frames=16")
    if mode != "ebpf" or not os.path.exists(os.path.join(os.path.dirname(path), "wine-ran")):
        return
    # pids is one level deep; Wine's processes are grandchildren and further down.
    closure = set(pids)
    while True:
        more = {e["process_id"] for e in events
                if e["type"] == "process_start" and e.get("parent_process_id") in closure} - closure
        if not more:
            break
        closure |= more
    wine = [e for e in events if e.get("process_id") in closure]
    loads = [e for e in wine if e["type"] == "image_load" and e.get("text", "").endswith(NTDLL)]
    if not loads:
        problems.append("pecaller: no image_load of x64 ntdll.dll from the probe's Wine processes")
    elif not any(e["value1"] == size_of_image(e["text"]) for e in loads if os.path.exists(e["text"])):
        problems.append("pecaller: ntdll.dll image_load does not span SizeOfImage: %s" % [hex(e["value1"]) for e in loads])
    wide = [e["text"] for e in events if e["type"] == "image_load" and e["value1"] > 2 ** 32]
    if wide:
        problems.append("pecaller: image_load spans over 4 GiB: %s" % wide[:3])

    def frames(e):
        found = re.search(r";pe_frames=(\d+)", e.get("detail", ""))
        return int(found.group(1)) if found else 0
    if not any(frames(e) >= 2 and (e.get("modules") or [""])[0].endswith("/ntdll.dll") for e in wine):
        with_pe = [e for e in wine if frames(e)]
        problems.append("pecaller: no Wine record with pe_frames>=2 and ntdll.dll first in modules (%d with PE frames%s)"
                        % (len(with_pe), "; e.g. %s %s" % (with_pe[0]["detail"][-60:], with_pe[0].get("modules"))
                           if with_pe else ""))
