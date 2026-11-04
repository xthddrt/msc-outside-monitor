#include "session.h"
#include <linux/cn_proc.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <poll.h>
#include <sys/socket.h>

/*
 * process_start / process_exit from the kernel process-events connector, mirroring the
 * driver's process callback: a fork from a tracked process is tracked as inherited, an
 * exec of an image under a root is tracked as explicit, and a tracked exec is logged again
 * with its new image (Value1 = 1).  Identity is PID plus /proc start time.
 */

static int gSocket = -1;

int ProcConnectorOpen(std::wstring& detail)
{
    gSocket = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_CONNECTOR);
    if (gSocket < 0) {
        detail = L"socket(NETLINK_CONNECTOR) failed";
        return errno;
    }
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    address.nl_groups = CN_IDX_PROC;
    address.nl_pid = 0;
    if (bind(gSocket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const int error = errno;
        detail = L"bind(CN_IDX_PROC) failed";
        ProcConnectorClose();
        return error;
    }
    alignas(nlmsghdr) char request[NLMSG_SPACE(sizeof(cn_msg) + sizeof(proc_cn_mcast_op))]{};
    auto* header = reinterpret_cast<nlmsghdr*>(request);
    header->nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_cn_mcast_op));
    header->nlmsg_type = NLMSG_DONE;
    header->nlmsg_pid = static_cast<uint32_t>(getpid());
    auto* message = static_cast<cn_msg*>(NLMSG_DATA(header));
    message->id.idx = CN_IDX_PROC;
    message->id.val = CN_VAL_PROC;
    message->len = sizeof(proc_cn_mcast_op);
    message->seq = static_cast<uint32_t>(getpid());
    const proc_cn_mcast_op operation = PROC_CN_MCAST_LISTEN;
    std::memcpy(message->data, &operation, sizeof(operation));
    if (send(gSocket, request, header->nlmsg_len, 0) != static_cast<ssize_t>(header->nlmsg_len)) {
        const int error = errno;
        detail = L"PROC_CN_MCAST_LISTEN failed";
        ProcConnectorClose();
        return error;
    }
    /*
     * The send succeeds even when the kernel refuses the subscription (no CAP_NET_ADMIN);
     * the verdict arrives as a PROC_EVENT_NONE acknowledgement, and none arrives when the
     * refused request leaves no listener at all.
     */
    const uint64_t deadline = GetTickCount64() + 1000;
    alignas(nlmsghdr) char buffer[4096];
    pollfd descriptor{gSocket, POLLIN, 0};
    while (GetTickCount64() < deadline) {
        if (poll(&descriptor, 1, 100) <= 0) continue;
        ssize_t length = recv(gSocket, buffer, sizeof(buffer), 0);
        if (length < static_cast<ssize_t>(NLMSG_LENGTH(sizeof(cn_msg) + sizeof(proc_event)))) continue;
        auto* reply = static_cast<cn_msg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(buffer)));
        auto* event = reinterpret_cast<proc_event*>(reply->data);
        if (event->what != PROC_EVENT_NONE || reply->seq != message->seq || reply->ack != 1) continue;
        if (event->event_data.ack.err != 0) {
            detail = L"PROC_CN_MCAST_LISTEN refused";
            ProcConnectorClose();
            return static_cast<int>(event->event_data.ack.err);
        }
        detail = L"fork,exec,exit";
        return 0;
    }
    detail = L"PROC_CN_MCAST_LISTEN not acknowledged";
    ProcConnectorClose();
    return EPERM;
}

void ProcConnectorClose()
{
    if (gSocket >= 0) close(gSocket);
    gSocket = -1;
}

static std::wstring ImagePath(DWORD pid)
{
    std::wstring path;
    uint64_t start = 0;
    return LinuxProcessIdentity(pid, path, start) ? path : std::wstring();
}

static void OnFork(LinuxSession& session, DWORD parent, DWORD child)
{
    uint64_t parentStart = 0;
    ULONG parentFlags = 0;
    if (!session.Tracked(parent, parentStart, parentFlags)) return;
    const uint64_t start = LinuxProcessStart(child);
    /* The child already exited, or tracking stopped: the driver counts this as a drop. */
    if (start == 0 || !session.Admit(child, start, MsMonFlagInheritedTrack)) {
        session.NoteDropped();
        return;
    }
    session.Log(MSMON_SENSOR_LINUX_PROC_CONNECTOR, MsMonProcessStart, child, start, MsMonFlagInheritedTrack, start, 0,
                ImagePath(child), ProcessCommandLine(child), parent);
    ImagesScan(session, child, start);
}

static void OnExec(LinuxSession& session, DWORD pid)
{
    std::wstring path;
    uint64_t start = 0;
    if (!LinuxProcessIdentity(pid, path, start)) return;
    uint64_t trackedStart = 0;
    ULONG flags = 0;
    DWORD parent = 0;
    (void)LinuxProcessStart(pid, &parent);
    if (session.Tracked(pid, trackedStart, flags) && trackedStart == start) {
        session.Log(MSMON_SENSOR_LINUX_PROC_CONNECTOR, MsMonProcessStart, pid, start, flags, start, 1, path,
                    ProcessCommandLine(pid), parent);
    } else if (session.UnderRoot(path) && session.Admit(pid, start, MsMonFlagExplicitTrack)) {
        session.Log(MSMON_SENSOR_LINUX_PROC_CONNECTOR, MsMonProcessStart, pid, start, MsMonFlagExplicitTrack, start, 0,
                    path, ProcessCommandLine(pid), parent);
    } else {
        return;
    }
    ImagesScan(session, pid, start);
}

static void OnExit(LinuxSession& session, DWORD pid)
{
    uint64_t start = 0;
    ULONG flags = 0;
    if (!session.Tracked(pid, start, flags)) return;
    session.Log(MSMON_SENSOR_LINUX_PROC_CONNECTOR, MsMonProcessExit, pid, start, 0, start, 0, {});
    session.Forget(pid, start);
    ImagesForget(pid);
}

void ProcConnectorRun(LinuxSession& session)
{
    alignas(nlmsghdr) char buffer[8192];
    pollfd descriptor{gSocket, POLLIN, 0};
    while (!session.Stopping()) {
        if (poll(&descriptor, 1, 200) <= 0) continue;
        ssize_t length = recv(gSocket, buffer, sizeof(buffer), 0);
        if (length < 0) {
            /* The socket buffer overflowed and process events were lost. */
            if (errno == ENOBUFS) session.NoteDropped();
            continue;
        }
        int remaining = static_cast<int>(length);
        for (auto* header = reinterpret_cast<nlmsghdr*>(buffer); NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type != NLMSG_DONE) continue;
            auto* message = static_cast<cn_msg*>(NLMSG_DATA(header));
            if (message->id.idx != CN_IDX_PROC || message->id.val != CN_VAL_PROC) continue;
            auto* event = reinterpret_cast<proc_event*>(message->data);
            session.Enter(MSMON_SENSOR_LINUX_PROC_CONNECTOR);
            switch (event->what) {
            case PROC_EVENT_FORK:
                /* A new thread shares its tgid; only a new process has pid == tgid. */
                if (event->event_data.fork.child_pid == event->event_data.fork.child_tgid) {
                    OnFork(session, static_cast<DWORD>(event->event_data.fork.parent_tgid),
                           static_cast<DWORD>(event->event_data.fork.child_tgid));
                }
                break;
            case PROC_EVENT_EXEC:
                OnExec(session, static_cast<DWORD>(event->event_data.exec.process_tgid));
                break;
            case PROC_EVENT_EXIT:
                if (event->event_data.exit.process_pid == event->event_data.exit.process_tgid) {
                    OnExit(session, static_cast<DWORD>(event->event_data.exit.process_tgid));
                }
                break;
            default:
                break;
            }
        }
    }
}
