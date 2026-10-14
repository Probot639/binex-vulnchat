/* @file auth_login.c
 *
 * VULNERABLE COMPONENT
 * 
 * Unchanged by the storage swap: it calls user_lookup() exactly as before;
 * whether that is backed by an array or by SQLite is invisible here. The
 * overflow fires BEFORE the lookup, so the database is never even reached
 * on the exploit path.
 *
 * Built at -O0 -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE in its own .o:
 * simple fixed frame, user[64] a short constant distance below saved RIP,
 * no canary, and fortify disabled so memcpy stays a real memcpy.
 */
#include "auth.h"
#include "net.h"
#include "token.h"
#include "db.h"
#include "proto.h"

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>      /* ntohs */

/* 
 * reads the 2 bytes at p as a big endian 16-bit number
 * raw load gets bytes in little-endian order (bc cpu stuff), so ntohs swaps
 * it back. 
 */
static uint16_t rd_u16(const uint8_t *p) { return ntohs(*(const uint16_t *)p); }

/*
* handles login requests
*/
int handle_login(int fd, const uint8_t *payload, uint32_t payload_len)
{

    // target of the overflow, the user
    char user[AUTH_USER_MAX];
    uint16_t user_len, secret_len;
    const uint8_t *p;

    // verify that the goal is to login
    if (payload_len < 3 || payload[0] != OP_LOGIN)
        return -1;

    // read the client-supplied user_len
    user_len = rd_u16(payload + 1);

    // checks to see if the user length is not longer than the PAYLOAD length,
    // not that it would fit within the AUTH_USER_MAX value of 64
    if ((uint32_t)3 + user_len > payload_len)
        return -1;

    // use the client set bounds to copy memory into a variable of a set length
    //      !!! BUFFER OVERFLOW VULNERABILITY IS IN memcpy
    memcpy(user, payload + 3, user_len);
    user[user_len % sizeof(user)] = '\0';       // null terminates user

    // points p at the secret_len field after the username
    p = payload + 3 + user_len;

    // secret len should have at least 2 bytes remaining
    if ((uint32_t)(p - payload) + 2 > payload_len) return -1;

    // get the secret length from p in the correct order
    secret_len = rd_u16(p);

    // point at the secret and make sure it's not too long
    const uint8_t *secret = p + 2;
    if ((uint32_t)(secret - payload) + secret_len > payload_len) return -1;

    // check the username and password against the one stored in the
    // database to make sure it's a valid login
    if (!user_lookup(user, secret, secret_len)) {

        // wrong login
        send_frame(fd, "ERR auth", 8);
        return 0;
    }

    // issue a token if login correct
    return issue_token(fd, user);
}

// this is the function used to send the client a stack address
int handle_debug(int fd)
{

    // function frame (contents do not matter, address does)
    char probe[AUTH_USER_MAX];
    memset(probe, 0, sizeof probe);

    // get the address of the probe (stack address), save it
    void *leak = (void *)probe;
    unsigned char out[8];
    memcpy(out, &leak, sizeof out);
    
    // send the stack address to the "authenticating" client
    return send_frame(fd, out, sizeof out);
}
