/* One of each action tests/linux_ebpf_test.sh expects the eBPF sensors to record:
 * create/write/read/close, rename, chmod, an executable file mapping, unlink, a failed
 * open, a TCP connect/accept on loopback, a thread, a forked child and a memory read
 * of that child. Usage: linux_ebpf_probe DIRECTORY */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

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
    return 0;
}
