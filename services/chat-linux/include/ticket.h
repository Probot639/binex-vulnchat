/* ticket.h - JWT verification for auth server tickets (Ed25519/EdDSA). */
#ifndef TICKET_H
#define TICKET_H

#include <stdint.h>

#define TICKET_SUB_MAX 64

#ifdef __cplusplus
extern "C" {
#endif

int ticket_init(const char *pk_path);
int ticket_verify(const char *jwt, uint32_t jwt_len,
                  char *sub_out, uint32_t sub_cap);

#ifdef __cplusplus
}
#endif

#endif
