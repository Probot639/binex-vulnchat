/* auth.h - the vulnerable request handlers. */
#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>

/* Dispatched from the session loop in net.c. Both receive a pointer into
 * the session read buffer plus the frame's payload length. */
int handle_login(int fd, const uint8_t *payload, uint32_t payload_len);   /* THE BUG  */
int handle_debug(int fd);                                                 /* THE LEAK */

#endif
