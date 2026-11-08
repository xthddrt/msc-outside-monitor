/* One of each action tests/linux_ebpf_test.sh expects the eBPF sensors to record:
 * create/write/read/close, rename, chmod, an executable file mapping, unlink, a failed
 * open, a TCP connect/accept on loopback, a thread, a forked child and a memory read
 * of that child. Then: 100 reads of one file (collapsed into repeat counts), a failing
 * open of a path that just opened fine, a UDP sendmsg/recvmsg with addresses, prctl,
 * pidfd_open, uname, sysinfo, a TCP shutdown, inotify_add_watch, memfd_create, fsync,
 * shmget/shmat, and a child that execs a native program outside the scope (untracked).
 * The kernel-sensor upgrades add their own actions in probe_<upgrade>.h (exit codes: payload 30-39,
 * netattr 40-49, tcp 50-59, packets 60-69).
 * Usage: linux_ebpf_probe DIRECTORY, or linux_ebpf_probe --exec PROGRAM ARGS... (exec it: a tracked
 * program the test starts from the scope, e.g. wine) */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "probe_payload.h"
#include "probe_netattr.h"
#include "probe_tcp.h"
#include "probe_packets.h"

static void* thread_main(void* unused)
{
    (void)unused;
    int fd = open("/proc/self/stat", O_RDONLY);
    if (fd >= 0) close(fd);
    return NULL;
}

int main(int argc, char** argv)
{
    char buffer[64];
    if (argc >= 3 && strcmp(argv[1], "--exec") == 0) {
        execvp(argv[2], argv + 2);
        return 127;
    }
    if (argc != 2 || chdir(argv[1]) != 0) return 2;

    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_main, NULL) == 0) pthread_join(thread, NULL);

    int fd = open("probe-a.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "hello from the probe\n", 21) != 21) return 3;
    close(fd);
    fd = open("probe-a.txt", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) <= 0) return 4;
    close(fd);
    if (rename("probe-a.txt", "probe-b.txt") != 0) return 5;
    if (chmod("probe-b.txt", 0644) != 0) return 6;
    fd = open("probe-b.txt", O_RDONLY);
    void* mapping = fd >= 0 ? mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) : MAP_FAILED;
    if (mapping == MAP_FAILED) return 7;
    /* image_load comes from the 2 s /proc/<pid>/maps poll now, so let one tick see it. */
    sleep(3);
    munmap(mapping, 4096);
    close(fd);
    if (unlink("probe-b.txt") != 0) return 8;
    if (open("probe-missing.txt", O_RDONLY) >= 0) return 9;

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(address);
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0) return 10;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 11;
    struct sockaddr_in peer;
    socklen_t peerLength = sizeof(peer);
    int accepted = accept(listener, (struct sockaddr*)&peer, &peerLength);
    if (accepted < 0) return 12;
    if (shutdown(client, SHUT_WR) != 0) return 21;
    close(accepted);
    close(client);
    close(listener);

    int pipeFds[2];
    if (pipe(pipeFds) != 0) return 13;
    pid_t child = fork();
    if (child == 0) {
        close(pipeFds[0]);
        fd = open("probe-child.txt", O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) close(fd);
        unlink("probe-child.txt");
        if (write(pipeFds[1], "x", 1) != 1) _exit(1);
        sleep(1);
        _exit(0);
    }
    close(pipeFds[1]);
    if (read(pipeFds[0], buffer, 1) != 1) return 14;
    struct iovec local = {buffer, 8}, remote = {&address, 8};
    (void)process_vm_readv(child, &local, 1, &remote, 1, 0);
    int status = 0;
    waitpid(child, &status, 0);

    fd = open("probe-burst.txt", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "burst", 5) != 5) return 15;
    for (int index = 0; index < 100; index++) {
        if (pread(fd, buffer, 5, 0) != 5) return 15;
    }
    close(fd);
    /* The same open (path and flags) succeeds, then fails within a second: both are recorded. */
    fd = open("probe-burst.txt", O_RDONLY);
    if (fd < 0) return 16;
    close(fd);
    if (unlink("probe-burst.txt") != 0 || open("probe-burst.txt", O_RDONLY) >= 0) return 17;

    int receiver = socket(AF_INET, SOCK_DGRAM, 0), sender = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in udp;
    memset(&udp, 0, sizeof(udp));
    udp.sin_family = AF_INET;
    udp.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t udpLength = sizeof(udp);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr*)&udp, sizeof(udp)) != 0 ||
        getsockname(receiver, (struct sockaddr*)&udp, &udpLength) != 0) return 18;
    struct iovec datagram = {buffer, 4};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = &udp;
    message.msg_namelen = sizeof(udp);
    message.msg_iov = &datagram;
    message.msg_iovlen = 1;
    if (sendmsg(sender, &message, 0) != 4) return 19;
    struct sockaddr_in from;
    memset(&message, 0, sizeof(message));
    message.msg_name = &from;
    message.msg_namelen = sizeof(from);
    message.msg_iov = &datagram;
    message.msg_iovlen = 1;
    if (recvmsg(receiver, &message, 0) != 4) return 20;
    close(sender);
    close(receiver);

    struct utsname uts;
    struct sysinfo info;
    if (uname(&uts) != 0 || sysinfo(&info) != 0) return 22;
    int watcher = inotify_init1(0);
    if (watcher < 0 || inotify_add_watch(watcher, ".", IN_CREATE) < 0) return 23;
    close(watcher);
    int memory = memfd_create("probe-memfd", 0);
    if (memory < 0) return 24;
    close(memory);
    fd = open("probe-sync.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "x", 1) != 1 || fsync(fd) != 0) return 25;
    close(fd);
    unlink("probe-sync.txt");
    int segment = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    void* attached = segment >= 0 ? shmat(segment, NULL, 0) : (void*)-1;
    if (attached == (void*)-1) return 26;
    shmdt(attached);
    shmctl(segment, IPC_RMID, NULL);

    int code = probe_payload();
    if (code == 0) code = probe_netattr();
    if (code == 0) code = probe_tcp();
    if (code == 0) code = probe_packets();
    if (code != 0) return code;

    (void)prctl(PR_SET_PTRACER, 0, 0, 0, 0);
    child = fork();
    if (child == 0) {
        execl("/bin/true", "true", (char*)NULL);
        _exit(1);
    }
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
    if (pidfd >= 0) close(pidfd);
    waitpid(child, &status, 0);
    /* The native child is untracked: its files must not appear. */
    return 0;
}
