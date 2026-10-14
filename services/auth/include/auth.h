/* auth.h - the vulnerable request handlers. */
#ifndef AUTH_H
#define AUTH_H
#include <stdint.h>
int handle_login(int fd, const uint8_t *payload, uint32_t payload_len);  /* THE BUG  */
int handle_debug(int fd);                                                /* THE LEAK */
#endif
