/* room.cpp
 *
 * room table is per-process (fork), so anything that needs to survive
 * a connection goes through db.c
 */
#include "chatd.h"

#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

struct chat_room {
    char name[32];
    int members[CHAT_ROOM_MAX];
    int nmembers;
};

static struct chat_room rooms[8];
static int nrooms = 0;

static struct chat_room *room_find(const char *name)
{
    for (int i = 0; i < nrooms; i++) {
        if (strcmp(rooms[i].name, name) == 0)
            return &rooms[i];
    }
    return nullptr;
}

struct chat_room *room_create(const char *name)
{
    if (nrooms >= 8)
        return nullptr;
    struct chat_room *r = &rooms[nrooms++];
    memset(r, 0, sizeof(*r));
    strncpy(r->name, name, sizeof(r->name) - 1);
    return r;
}

struct chat_room *room_join(const char *name, int fd)
{
    struct chat_room *r = room_find(name);
    if (!r)
        r = room_create(name);
    if (!r)
        return nullptr;

    if (r->nmembers >= CHAT_ROOM_MAX)
        return nullptr;
    r->members[r->nmembers++] = fd;
    return r;
}

/* TODO(human): implement room_broadcast */
int room_broadcast(struct chat_room *r, const struct chat_msg *m)
{
    uint32_t net_len = htonl(m->len);

    for (int i = 0; i < r->nmembers; i++) {
        int fd = r->members[i];

        write(fd, &net_len, sizeof(net_len));

        write(fd, m->body, m->len);
    }
    return 0;
}
