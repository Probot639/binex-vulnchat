/* room.c
 *
 * room table is per-process (fork), so anything that needs to survive
 * a connection goes through db.c
 */
#include "chatd.h"

struct chat_room {
    char name[32];
    int members[CHAT_ROOM_MAX];
    int nmembers;
};

int room_broadcast(struct chat_room *r, const struct chat_msg *m)
{
    (void)r;
    (void)m;
    return 0;
}
