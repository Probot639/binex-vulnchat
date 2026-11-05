/* room_win.cpp
 *
 * room table is shared across threads (unlike linux where fork gives each
 * child its own copy), so the public functions grab a lock.
 */
#include "chatd.h"

#include <winsock2.h>
#include <cstring>

struct chat_room {
    char name[32];
    int members[CHAT_ROOM_MAX];
    int nmembers;
};

static struct chat_room rooms[8];
static int nrooms = 0;
static CRITICAL_SECTION rooms_cs;

/* called once from main before any threads start */
extern "C" void room_init(void)
{
    InitializeCriticalSection(&rooms_cs);
}

static struct chat_room *room_find(const char *name)
{
    for (int i = 0; i < nrooms; i++) {
        if (strcmp(rooms[i].name, name) == 0)
            return &rooms[i];
    }
    return nullptr;
}

extern "C" struct chat_room *room_create(const char *name)
{
    if (nrooms >= 8)
        return nullptr;
    struct chat_room *r = &rooms[nrooms++];
    memset(r, 0, sizeof(*r));
    strncpy(r->name, name, sizeof(r->name) - 1);
    return r;
}

extern "C" struct chat_room *room_join(const char *name, int fd)
{
    EnterCriticalSection(&rooms_cs);

    struct chat_room *r = room_find(name);
    if (!r)
        r = room_create(name);
    if (!r) {
        LeaveCriticalSection(&rooms_cs);
        return nullptr;
    }

    if (r->nmembers >= CHAT_ROOM_MAX) {
        LeaveCriticalSection(&rooms_cs);
        return nullptr;
    }
    r->members[r->nmembers++] = fd;

    LeaveCriticalSection(&rooms_cs);
    return r;
}

extern "C" void room_leave(struct chat_room *r, int fd)
{
    EnterCriticalSection(&rooms_cs);
    for (int i = 0; i < r->nmembers; i++) {
        if (r->members[i] == fd) {
            r->members[i] = r->members[--r->nmembers];
            break;
        }
    }
    LeaveCriticalSection(&rooms_cs);
}

extern "C" int room_broadcast(struct chat_room *r, const struct chat_msg *m)
{
    uint32_t net_len = htonl(m->len);
    int fds[CHAT_ROOM_MAX];
    int count;

    EnterCriticalSection(&rooms_cs);
    count = r->nmembers;
    memcpy(fds, r->members, count * sizeof(int));
    LeaveCriticalSection(&rooms_cs);

    for (int i = 0; i < count; i++) {
        SOCKET s = (SOCKET)fds[i];
        send(s, (const char *)&net_len, sizeof(net_len), 0);
        send(s, m->body, m->len, 0);
    }
    return 0;
}
