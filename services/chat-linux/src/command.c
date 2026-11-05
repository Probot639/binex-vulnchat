/* command.c
 * handlers are separate functions so each gets its own stack frame */
#include "chatd.h"
#include <string.h>
#include <stdio.h>

/* /nick /me /who /join /help */

static int cmd_nick(struct chat_msg *m, const char *arg, uint32_t len)
{
    char tmp[64];

    if (!arg)
        return -1;

    memcpy(tmp, arg, len);
    strncpy(m->author, tmp, CHAT_USER_MAX - 1);

    return 0;
}

static int cmd_me(struct chat_msg *m, const char *arg, uint32_t len)
{
    if (!arg)
        return -1;
    msg_set_body(m, arg, len);
    return 0;
}

static int cmd_who(struct chat_msg *m)
{
    (void)m;
    fprintf(stderr, "not implemented\n");
    return 0;
}

static int cmd_join(struct chat_msg *m, const char *arg)
{
    (void)m;
    (void)arg;
    /* TODO: needs room table wired up */
    return 0;
}

static int cmd_help(struct chat_msg *m)
{
    const char *text = "commands: /nick /me /who /join /repeat /help";
    msg_set_body(m, text, (uint32_t)strlen(text));
    return 0;
}

int cmd_dispatch(struct chat_msg *m, const char *line, uint32_t len)
{
    const char *p, *arg;
    uint32_t arg_len;
    char verb[16];
    int vlen;

    if (len < 2 || line[0] != '/')
        return -1;

    p = line + 1;
    arg = memchr(p, ' ', len - 1);
    if (arg) {
        vlen = arg - p;
        arg++;
        arg_len = len - (uint32_t)(arg - line);
    } else {
        vlen = len - 1;
        arg = NULL;
        arg_len = 0;
    }

    if (vlen <= 0 || vlen >= (int)sizeof(verb))
        return -1;

    memcpy(verb, p, vlen);
    verb[vlen] = '\0';

    if (strcmp(verb, "nick") == 0)
        return cmd_nick(m, arg, arg_len);
    if (strcmp(verb, "me") == 0)
        return cmd_me(m, arg, arg_len);
    if (strcmp(verb, "who") == 0)
        return cmd_who(m);
    if (strcmp(verb, "join") == 0)
        return cmd_join(m, arg);
    if (strcmp(verb, "help") == 0)
        return cmd_help(m);

    return -1;
}
