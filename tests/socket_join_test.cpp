/* Self-test of agent/linux/socket_join.h (run by build.sh): the Wine sequence seen in a real
 * session (wineserver socket/connect/close, the game's I/O and its per-call fd closes), shared
 * sockets, exits, inode reuse and the session-end flush. */
#include "../agent/linux/socket_join.h"
#include <cstdio>
#include <cstdlib>
#include <cwchar>

#define CHECK(condition)                                                    \
    do {                                                                    \
        if (!(condition)) {                                                 \
            std::fprintf(stderr, "socket_join_test:%d: %s\n", __LINE__, #condition); \
            std::exit(1);                                                   \
        }                                                                   \
    } while (0)

int main()
{
    const SocketJoin::Who wineserver{100, 1}, game{200, 2}, helper{300, 3}, gameAgain{200, 9};
    const std::wstring server = L"54.68.216.33:47611";
    SocketJoin join;
    SocketJoin::Socket socket;
    SocketJoin::Who user;

    /* wineserver: socket(), the game's early fd close, connect() -> EINPROGRESS. */
    CHECK(join.Made(7, wineserver, SocketJoin::kSocket, 2, 1, 0, L"", 0, 10).empty());
    CHECK(join.Closed(7, game, 11).empty());                 /* a user's close ends nothing */
    CHECK(join.Io(7, game, 5, 0, 11).empty());               /* no endpoint yet: not joined */
    CHECK(join.Made(7, wineserver, SocketJoin::kConnect, 2, 0, 47611, server, -115, 12).empty());
    CHECK(join.Lookup(7, socket, user) && user.pid == 0 && socket.creator == wineserver && socket.type == 1);

    /* The game's first I/O attaches it once; wineserver's own MSG_PEEK reads are not the game's. */
    SocketJoin::Changes changes = join.Io(7, game, 821, 0, 20);
    CHECK(changes.size() == 1 && changes[0].opened && changes[0].use.who == game && changes[0].inode == 7);
    CHECK(changes[0].socket.endpoint == server && changes[0].socket.status == -115 && changes[0].socket.time == 12);
    CHECK(changes[0].socket.via == SocketJoin::kConnect && changes[0].time == 20);
    CHECK(join.Io(7, game, 0, 4, 21).empty() && join.Io(7, game, 0, 824, 22).empty());
    CHECK(join.Io(7, wineserver, 0, 1, 22).empty());
    CHECK(join.Lookup(7, socket, user) && user == game);

    /* wineserver's close ends the socket for the game, with its totals; the game's close after it is nothing. */
    changes = join.Closed(7, wineserver, 30);
    CHECK(changes.size() == 1 && !changes[0].opened && changes[0].use.who == game);
    CHECK(changes[0].use.sent == 821 && changes[0].use.received == 828 && changes[0].time == 30);
    CHECK(std::wcscmp(changes[0].reason, L"socket_closed") == 0);
    CHECK(join.Closed(7, game, 31).empty() && !join.Lookup(7, socket, user));

    /* Two users of one accepted socket: each is attached once and keeps its own bytes. */
    CHECK(join.Made(8, wineserver, SocketJoin::kAccept, 2, 1, 33912, L"127.0.0.1:33912", 0, 40).empty());
    CHECK(join.Io(8, game, 3, 0, 41).size() == 1);
    changes = join.Io(8, helper, 0, 9, 42);
    CHECK(changes.size() == 1 && changes[0].use.who == helper && changes[0].socket.via == SocketJoin::kAccept);
    CHECK(join.Lookup(8, socket, user) && user == game);   /* the first user owns it */
    /* The game exits: only its use ends; the helper keeps its own. */
    changes = join.Gone(game, L"process_exit", 50);
    CHECK(changes.size() == 1 && changes[0].use.who == game && changes[0].use.sent == 3);
    CHECK(std::wcscmp(changes[0].reason, L"process_exit") == 0 && changes[0].time == 50);
    CHECK(join.Lookup(8, socket, user) && user == helper);
    /* A new process with the game's pid is another process. */
    CHECK(join.Io(8, gameAgain, 1, 0, 51).size() == 1);

    /* The number comes back from socket(): the old socket is dead (inode_reused). */
    changes = join.Made(8, wineserver, SocketJoin::kSocket, 2, 2, 0, L"", 0, 60);
    CHECK(changes.size() == 2 && std::wcscmp(changes[0].reason, L"inode_reused") == 0 && changes[0].time == 60);
    CHECK(changes[0].use.received + changes[1].use.received == 9);
    CHECK(join.Lookup(8, socket, user) && user.pid == 0 && socket.endpoint.empty() && socket.type == 2);

    /* bind then listen keeps the bound endpoint (local port); a bound UDP socket joins on I/O. */
    CHECK(join.Made(8, wineserver, SocketJoin::kBind, 2, 0, 5000, L"0.0.0.0:5000", 0, 61).empty());
    CHECK(join.Made(8, wineserver, SocketJoin::kListen, 0, 0, 0, L"", 0, 62).empty());
    changes = join.Io(8, game, 0, 0, 63);   /* a failed I/O (EAGAIN) still attaches */
    CHECK(changes.size() == 1 && changes[0].socket.via == SocketJoin::kListen &&
          changes[0].socket.endpoint == L"0.0.0.0:5000" && changes[0].socket.port == 5000);

    /* The creator exits: the sockets it made end (socket_closed) and are forgotten. */
    changes = join.Gone(wineserver, L"process_exit", 70);
    CHECK(changes.size() == 1 && changes[0].use.who == game && std::wcscmp(changes[0].reason, L"socket_closed") == 0);
    CHECK(!join.Lookup(8, socket, user));

    /* The creator only leaves scope: the socket may live on, so its users' flows end untracked. */
    CHECK(join.Made(10, wineserver, SocketJoin::kConnect, 2, 0, 80, L"10.0.0.1:80", -115, 75).empty());
    CHECK(join.Io(10, game, 1, 0, 76).size() == 1);
    changes = join.Gone(wineserver, L"untracked", 77);
    CHECK(changes.size() == 1 && std::wcscmp(changes[0].reason, L"untracked") == 0 && !join.Lookup(10, socket, user));

    /* Session end: what is still in use is flushed (session_end), then nothing is kept. */
    CHECK(join.Made(9, wineserver, SocketJoin::kConnect, 10, 0, 443, L"[2001:db8::1]:443", 0, 80).empty());
    CHECK(join.Io(9, game, 100, 200, 81).size() == 1);
    changes = join.Flush(0);
    CHECK(changes.size() == 1 && changes[0].use.sent == 100 && changes[0].use.received == 200);
    CHECK(std::wcscmp(changes[0].reason, L"session_end") == 0 && !join.Lookup(9, socket, user));

    std::puts("socket_join_test: ok");
    return 0;
}
