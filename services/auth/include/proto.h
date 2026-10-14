/* proto.h - wire protocol shared by net.c and the handlers.
 *
 * Outer frame (identical to the chat server's framing so both services
 * speak the same dialect):
 *
 *     [ uint32_t length  (network byte order) ][ length bytes payload ]
 *
 * payload[0] is an opcode; the rest is opcode-specific (below).
 */
#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>

#define AUTH_DEFAULT_PORT 4001        /* chat-linux is 4002 */
#define AUTH_USER_MAX     64          /* matches CHAT_USER_MAX and users.name CHECK(<=63) */
#define AUTH_FRAME_MAX    8192        /* room for a ROP chain + shellcode */

#define OP_LOGIN 0x01
/* LOGIN: u8 op | u16 user_len(BE) | user[] | u16 secret_len(BE) | secret[]
 * user_len is ATTACKER CONTROLLED. Binary + length-delimited so the user
 * field may contain NUL bytes -- an x86-64 ROP chain is 8-byte addresses
 * with 0x00 high bytes, so NUL-transparency is what lets the chain survive. */

#define OP_DEBUG 0x7F
/* DEBUG: u8 op (no args). Reply: 8 raw LE bytes = a live stack address.
 * The deliberate VulnServer/essfunc-style artifact for the DEP-bypass leak. */
#endif
