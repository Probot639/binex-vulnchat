# chat server notes

Scratch file for my half of the project. Not the writeup.

## state

Skeleton only - every function is a stub, nothing runs yet.
`make` builds clean, `make check` confirms the mitigation flags.

## order I'm doing this in

1. net.c - listen/accept + frame read/write
2. main.c - accept loop, fork per connection
3. session.c - join handshake, frame loop
4. room.c - membership, broadcast
5. command.c - `/` commands
6. message.c - the inline -> heap promotion
7. db.c - persistence, last because everything above works without it

Get it working as an actual chat server first. Adding the bugs before
that means not being able to tell a broken exploit from a broken server.

## blocked on / need to ask

- frame header layout - magic, type, length, byte order. needs to be
  settled before net.c is worth writing.
- exact ticket bytes from the auth server (darwin)
- mac verification - gavin said placeholder for now, what does the chat
  side actually check in the meantime?
- are we agreed the header is packed byte at a time rather than memcpy'd
  over a struct? the windows client will not have the same padding.

## don't forget

- fork per connection, no exec. children inherit the parent's layout so
  a leak from one connection is still good in the next one - that's what
  makes the whole leak-then-ROP thing possible.
- length is validated in net.c only.
- once the bugs are in, write a test that runs the exploits, otherwise
  someone tidies up message.c and the UAF quietly disappears.
