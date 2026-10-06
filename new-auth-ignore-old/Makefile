# Auth server (IdP): framed TCP, Ed25519-signed JWTs, intentional vuln.
#
# Hardening is deliberately OFF so the user-ID overflow in auth_login.c is
# exploitable as designed:
#   -fno-stack-protector   no stack canaries
#   -no-pie                fixed .text/.plt/.got.plt (leak only the stack)
#   -z noexecstack         NX on  -> forces the DEP-bypass ROP (mprotect)
#   -z relro -z lazy       partial RELRO, lazy binding: libc GOT entries get
#                          populated on first call, ready to deref for the
#                          mprotect-delta trick
#   -O0                    simple, fixed frames; no inlining of the vuln
CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -g -O0 -fno-stack-protector \
          -Iinclude $(shell pkg-config --cflags libsodium)
LDFLAGS = -no-pie -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,lazy
LDLIBS  = $(shell pkg-config --libs libsodium)

SRC = src/main.c src/net.c src/auth_login.c src/token.c \
      src/user_table.c src/b64url.c
OBJ = $(SRC:.c=.o)

all: authd keygen

authd: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

keygen: src/keygen.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# One-shot lab setup: signing keypair + a seeded user (alice / password123).
setup: keygen
	./keygen keys
	./keygen adduser alice password123 > users.tbl
	@echo "seeded users.tbl with alice/password123"

# Prove the binary meets the exploitability requirements.
check: authd
	@echo "== NX (GNU_STACK should be RW, not RWE) =="; \
	 readelf -lW authd | grep GNU_STACK || true
	@echo "== PIE (Type should be EXEC, not DYN) =="; \
	 readelf -hW authd | grep Type
	@echo "== canary (should print nothing) =="; \
	 nm authd 2>/dev/null | grep -i stack_chk || echo "  (no stack canary - good)"

clean:
	rm -f $(OBJ) src/keygen.o authd keygen

.PHONY: all setup check clean
