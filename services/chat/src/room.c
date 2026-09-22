/* room.c - who's in which room, and getting messages out to them.
 *
 * the room table lives in the parent process, so each forked child is
 * working off its own copy. anything that has to outlive a connection
 * needs to go through db.c instead.
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

    /* walk members[] and push the frame to each, skipping dead fds */
    return 0;
}
