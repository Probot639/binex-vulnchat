/* command.c - the "/" commands.
 *
 * split the line into a verb plus the rest, look up the verb, call it.
 * handlers stay separate functions so each one gets its own stack frame.
 */
#include "chatd.h"

/* /nick /me /who /join /help is what we said we'd support */

int cmd_dispatch(struct chat_msg *m, const char *line, uint32_t len)
{
    (void)m;
    (void)line;
    (void)len;

    /* TODO find the first space, verb is everything before it */
    /* TODO table of {name, fn} and loop it, or just a strcmp chain?
     *      there's only five commands, probably not worth the table */

    return 0;
}
