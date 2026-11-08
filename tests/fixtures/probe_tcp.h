/* TCP lifecycle actions (tcp upgrade; tests/ebpf_checks/check_tcp.py, exit codes 50-59), on a listener of
 * their own on 127.0.0.1: a pair half-closed with shutdown(SHUT_WR) then closed (connect_completed,
 * accept_completed, close_issued, fin_received, disconnect_completed), a pair closed with unread data
 * (abort_issued, reset_sent at the accepted end, reset_received at the client) and a connect to the port
 * once nobody listens (reset_received in SYN_SENT, connect_failed). */
#include <errno.h>
#include <poll.h>

static int probe_tcp(void)
{
    struct sockaddr_in address = {0};
    socklen_t length = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr*)&address, sizeof(address)) != 0 || listen(listener, 4) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0)
        return 50;

    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr*)&address, sizeof(address)) != 0) return 51;
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0 || shutdown(client, SHUT_WR) != 0) return 52;
    close(accepted);
    close(client);

    int client2 = socket(AF_INET, SOCK_STREAM, 0);
    if (client2 < 0 || connect(client2, (struct sockaddr*)&address, sizeof(address)) != 0) return 53;
    int accepted2 = accept(listener, NULL, NULL);
    struct pollfd readable = {accepted2, POLLIN, 0};
    if (accepted2 < 0 || write(client2, "x", 1) != 1 || poll(&readable, 1, 1000) != 1) return 54;
    close(accepted2);   /* unread data: RST */
    close(client2);
    close(listener);

    int refused = socket(AF_INET, SOCK_STREAM, 0);
    if (refused < 0 || connect(refused, (struct sockaddr*)&address, sizeof(address)) == 0 || errno != ECONNREFUSED)
        return 55;
    close(refused);
    return 0;
}
