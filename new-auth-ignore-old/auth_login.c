/* auth_login.c -- THE VULNERABLE TRANSLATION UNIT.
 *
 * Compiled at -O0 -fno-stack-protector in its own .o so the frame layout
 * is simple and fixed: user[64] sits a short, constant distance below the
 * saved return address, no canary in between.
 *
 * Two handlers:
 *   handle_login  -- the pre-auth stack overflow (the primary vuln)
 *   handle_debug  -- the stack-address leak the DEP bypass needs
 */
#include "auth.h"
#include "net.h"
#include "token.h"
#include "user_table.h"
#include "proto.h"

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>      /* ntohs */

static uint16_t rd_u16(const uint8_t *p) { return ntohs(*(const uint16_t *)p); }

/* ------------------------------------------------------------------ *
 *  handle_login  --  LOGIN (0x01)
 *
 *  char user[64] is overflowed by an attacker-chosen user_len (up to the
 *  frame cap, ~8 KB) via memcpy with NO check against sizeof(user). The
 *  copy runs BEFORE user_lookup(), so the overflow is PRE-AUTH: the
 *  smashed return address fires when handle_login returns and the
 *  credential check is never reached. On a legitimate (short) username it
 *  behaves normally and issues a JWT, so the service still does its job.
 * ------------------------------------------------------------------ */
int handle_login(int fd, const uint8_t *payload, uint32_t payload_len)
{
    char     user[AUTH_USER_MAX];        /* <<< overflow target (64 bytes) */
    uint16_t user_len, secret_len;
    const uint8_t *p;

    if (payload_len < 3 || payload[0] != OP_LOGIN)
        return -1;

    user_len = rd_u16(payload + 1);

    /* Bounds check -- but against the FRAME, not sizeof(user). The classic
     * "checked the wrong bound" bug: it keeps the copy inside the bytes the
     * attacker actually sent (so it's a clean, deterministic write overflow
     * with no secondary OOB read) while still letting user_len run far past
     * 64. */
    if ((uint32_t)3 + user_len > payload_len)
        return -1;

    /* === THE BUG: memcpy, attacker length, 64-byte stack dest, NUL-safe ===*/
    memcpy(user, payload + 3, user_len);
    user[user_len % sizeof(user)] = '\0';   /* cosmetic; dead in exploit path */

    /* ---- legitimate path below (unreachable once you smash the return) ---*/
    p = payload + 3 + user_len;
    if ((uint32_t)(p - payload) + 2 > payload_len)
        return -1;
    secret_len = rd_u16(p);
    const uint8_t *secret = p + 2;
    if ((uint32_t)(secret - payload) + secret_len > payload_len)
        return -1;

    if (!user_lookup(user, secret, secret_len)) {
        send_frame(fd, "ERR auth", 8);
        return 0;
    }
    return issue_token(fd, user);        /* success -> mint (separate frame) */
}

/* ------------------------------------------------------------------ *
 *  handle_debug  --  DEBUG (0x7F)  --  the "essfunc.dll"-style artifact.
 *
 *  Leaks the address of a stack buffer. Because the parent forks per
 *  connection and fork() does not re-randomize, the address leaked on one
 *  connection is valid for the overflow on the next. handle_debug and
 *  handle_login are both called at the same depth from the session loop,
 *  so &probe here sits a FIXED per-build offset (DELTA) from
 *  handle_login's user[]: pin DELTA once with a cyclic pattern, then
 *  &user = leaked + DELTA on every subsequent child.
 *
 *  Reply: 8 raw little-endian bytes of the pointer (x86-64 memory order).
 * ------------------------------------------------------------------ */
int handle_debug(int fd)
{
    char probe[AUTH_USER_MAX];
    memset(probe, 0, sizeof probe);

    void *leak = (void *)probe;
    unsigned char out[8];
    memcpy(out, &leak, sizeof out);      /* native LE on x86-64 */

    return send_frame(fd, out, sizeof out);
}
