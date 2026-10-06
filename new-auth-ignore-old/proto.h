/* proto.h - wire protocol shared by net.c and the handlers.
 *
 * Outer frame (identical to the chat server's framing so both services
 * speak the same dialect):
 *
 *     [ uint32_t length  (network byte order) ][ length bytes payload ]
 *
 * The payload's first byte is an opcode. Everything after it is
 * opcode-specific and documented below.
 */
#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

#define AUTH_DEFAULT_PORT 4001        /* chat server is 4002 */
#define AUTH_USER_MAX     64          /* must match CHAT_USER_MAX in chatd.h */
#define AUTH_FRAME_MAX    8192         /* generous: room for a ROP chain + shellcode */

/* ---- opcodes (payload[0]) ---- */
#define OP_LOGIN 0x01
/*
 * LOGIN payload layout:
 *   off 0 : u8   opcode = 0x01
 *   off 1 : u16  user_len     (big-endian)   <-- ATTACKER CONTROLLED
 *   off 3 : u8   user[user_len]
 *   ...   : u16  secret_len    (big-endian)
 *   ...   : u8   secret[secret_len]
 *
 * Binary + length-delimited (not "LOGIN <user> <secret>\n") on purpose:
 * a length field lets the attacker send a user field containing NUL
 * bytes, which a space/newline-delimited text parse cannot. An x86-64
 * ROP chain is a run of 8-byte addresses whose high bytes are 0x00, so
 * NUL-transparency is what makes the chain survivable in the buffer.
 */

#define OP_DEBUG 0x7F
/*
 * DEBUG payload layout:
 *   off 0 : u8 opcode = 0x7F   (no further fields)
 *
 * Response: an 8-byte raw little-endian stack address (see auth_login.c).
 * This is the deliberate, VulnServer-style "unrealistic artifact" that
 * gives the attacker the stack leak the DEP-bypass chain needs. Gate it
 * behind a build flag for the release if you want it out of the "real"
 * service; keep it in for the exploit proof.
 */

#endif
