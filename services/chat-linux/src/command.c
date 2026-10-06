/* command.c
 * handlers are separate functions so each gets its own stack frame */
#include "chatd.h"

/* /nick /me /who /join /help */

int cmd_dispatch(struct chat_msg *m, const char *line, uint32_t len)
{
    (void)m;
    (void)line;
    (void)len;

    /* TODO: strcmp chain? only five commands, probably not worth a table */

    return 0;
}
