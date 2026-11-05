#!/usr/bin/env python3
"""IRC-style terminal chat client for vulnchat.

Usage: python3 demo_client.py <auth_host> <auth_port> <chat_host> <chat_port> <user> <password>

Authenticates with the auth server to get a JWT, then connects to the
chat server using that token. Curses-based split view with scrolling
message area and input bar.
"""

import curses
import socket
import struct
import sys
import threading
import time

NICK_COLORS = [
    curses.COLOR_RED,
    curses.COLOR_GREEN,
    curses.COLOR_YELLOW,
    curses.COLOR_BLUE,
    curses.COLOR_MAGENTA,
    curses.COLOR_CYAN,
]


def nick_color(nick):
    h = 0
    for c in nick.lower():
        h = h * 31 + ord(c)
    return (h % len(NICK_COLORS)) + 1


# -- wire protocol (same framing as the server) --

def frame(payload):
    return struct.pack("!I", len(payload)) + payload


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    hdr = recvn(sock, 4)
    if hdr is None:
        return None
    n = struct.unpack("!I", hdr)[0]
    if n == 0:
        return b""
    return recvn(sock, n)


OP_LOGIN = 0x01


def auth_login(host, port, user, password):
    """Authenticate with the auth server, return the JWT string."""
    sock = socket.create_connection((host, port), timeout=5)
    try:
        user_b = user.encode()
        pw_b = password.encode()
        payload = (bytes([OP_LOGIN])
                   + struct.pack("!H", len(user_b)) + user_b
                   + struct.pack("!H", len(pw_b)) + pw_b)
        sock.sendall(frame(payload))
        resp = recv_frame(sock)
        if resp is None:
            raise RuntimeError("auth server closed connection")
        text = resp.decode(errors="replace")
        if text.startswith("ERR"):
            raise RuntimeError(f"auth failed: {text}")
        return text
    finally:
        sock.close()


def parse_message(text):
    """Split 'nick: body' into (nick, body). Returns (None, text) for system messages."""
    if ": " in text:
        nick, body = text.split(": ", 1)
        if nick and all(c.isalnum() or c in "-_" for c in nick):
            return nick, body
    return None, text


# -- UI --

class ChatUI:
    def __init__(self, stdscr, sock, nick, host, port):
        self.stdscr = stdscr
        self.sock = sock
        self.nick = nick
        self.host = host
        self.port = port
        self.messages = []
        self.input_buf = ""
        self.cursor_pos = 0
        self.running = True
        self.lock = threading.Lock()
        self.dirty = True

        curses.start_color()
        curses.use_default_colors()
        for i, color in enumerate(NICK_COLORS):
            curses.init_pair(i + 1, color, -1)
        curses.init_pair(len(NICK_COLORS) + 1, 8, -1)

        curses.curs_set(1)
        self.stdscr.timeout(80)

    def draw(self):
        if not self.dirty:
            return
        self.dirty = False

        try:
            h, w = self.stdscr.getmaxyx()
            if h < 4 or w < 20:
                return
            self.stdscr.erase()

            # title bar
            title = f" vulnchat  {self.host}:{self.port} "
            self.stdscr.addnstr(0, 0, title.ljust(w), w - 1,
                                curses.A_REVERSE | curses.A_BOLD)

            # messages (rows 1 .. h-3)
            msg_rows = h - 3
            visible = self.messages[-msg_rows:]
            sys_pair = curses.color_pair(len(NICK_COLORS) + 1)

            for i, (ts, nick, body, is_sys) in enumerate(visible):
                row = 1 + i
                stamp = time.strftime("%H:%M", time.localtime(ts))
                col = 0

                self.stdscr.addnstr(row, col, f" {stamp} ", w - 1, curses.A_DIM)
                col = 7

                if is_sys:
                    self.stdscr.addnstr(row, col, body, w - col - 1,
                                        sys_pair | curses.A_DIM)
                else:
                    cpair = curses.color_pair(nick_color(nick))
                    self.stdscr.addnstr(row, col, nick, w - col - 1,
                                        cpair | curses.A_BOLD)
                    col += len(nick)
                    if col < w - 2:
                        self.stdscr.addnstr(row, col, f": {body}", w - col - 1)

            # separator
            sep = h - 2
            self.stdscr.addnstr(sep, 0, "─" * w, w - 1, curses.A_DIM)

            # input line
            prompt = f" {self.nick}> "
            irow = h - 1
            self.stdscr.addnstr(irow, 0, prompt, w - 1, curses.A_BOLD)
            pcol = len(prompt)
            if pcol < w - 1:
                self.stdscr.addnstr(irow, pcol, self.input_buf, w - pcol - 1)
            cpos = min(pcol + self.cursor_pos, w - 1)
            self.stdscr.move(irow, cpos)
            self.stdscr.refresh()
        except curses.error:
            pass

    def post(self, text, system=False):
        ts = time.time()
        if system:
            self.messages.append((ts, "", text, True))
        else:
            nick, body = parse_message(text)
            if nick:
                self.messages.append((ts, nick, body, False))
            else:
                self.messages.append((ts, "", text, True))
        self.dirty = True

    def recv_loop(self):
        while self.running:
            try:
                data = recv_frame(self.sock)
                if data is None:
                    with self.lock:
                        self.post("*** SERVER CLOSED CONNECTION ***", system=True)
                        self.post("press ctrl-c to exit", system=True)
                    self.running = False
                    break
                text = data.decode(errors="replace")
                with self.lock:
                    self.post(text)
            except (ConnectionResetError, BrokenPipeError, OSError):
                with self.lock:
                    self.post("*** CONNECTION LOST (server crash?) ***", system=True)
                    self.post("press ctrl-c to exit", system=True)
                self.running = False
                break

    def send(self, text):
        try:
            self.sock.sendall(frame(text.encode()))
        except (BrokenPipeError, OSError):
            self.post("*** SEND FAILED (server crash?) ***", system=True)
            self.running = False

    def run(self):
        self.post(f"connected as {self.nick}", system=True)
        self.post("type /help for commands, ctrl-c to quit", system=True)

        t = threading.Thread(target=self.recv_loop, daemon=True)
        t.start()

        while True:
            with self.lock:
                self.draw()
            try:
                ch = self.stdscr.getch()
            except curses.error:
                continue

            if ch == -1:
                continue

            with self.lock:
                self.dirty = True
                if ch == curses.KEY_RESIZE:
                    pass
                elif ch in (10, 13):
                    if self.input_buf:
                        line = self.input_buf
                        self.input_buf = ""
                        self.cursor_pos = 0
                        if line.startswith("/nick "):
                            new = line.split(" ", 1)[1].strip()
                            if new:
                                self.nick = new
                        self.send(line)
                elif ch in (curses.KEY_BACKSPACE, 127, 8):
                    if self.cursor_pos > 0:
                        self.input_buf = (self.input_buf[:self.cursor_pos - 1]
                                          + self.input_buf[self.cursor_pos:])
                        self.cursor_pos -= 1
                elif ch == curses.KEY_LEFT:
                    self.cursor_pos = max(0, self.cursor_pos - 1)
                elif ch == curses.KEY_RIGHT:
                    self.cursor_pos = min(len(self.input_buf), self.cursor_pos + 1)
                elif ch == 1:  # ctrl-a
                    self.cursor_pos = 0
                elif ch == 5:  # ctrl-e
                    self.cursor_pos = len(self.input_buf)
                elif ch == 21:  # ctrl-u
                    self.input_buf = self.input_buf[self.cursor_pos:]
                    self.cursor_pos = 0
                elif 32 <= ch <= 126:
                    self.input_buf = (self.input_buf[:self.cursor_pos]
                                      + chr(ch)
                                      + self.input_buf[self.cursor_pos:])
                    self.cursor_pos += 1


def main(stdscr, chat_host, chat_port, nick, jwt):
    sock = socket.create_connection((chat_host, chat_port), timeout=5)
    sock.settimeout(None)

    jwt_bytes = jwt.encode()
    sock.sendall(struct.pack("!I", len(jwt_bytes)) + jwt_bytes)

    ui = ChatUI(stdscr, sock, nick, chat_host, chat_port)
    try:
        ui.run()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print(f"usage: {sys.argv[0]} <auth_host> <auth_port> <chat_host> <chat_port> <user> <password>")
        sys.exit(1)

    auth_host = sys.argv[1]
    auth_port = int(sys.argv[2])
    chat_host = sys.argv[3]
    chat_port = int(sys.argv[4])
    user = sys.argv[5]
    password = sys.argv[6]

    print(f"authenticating {user} with {auth_host}:{auth_port}...")
    jwt = auth_login(auth_host, auth_port, user, password)
    print(f"got token, connecting to {chat_host}:{chat_port}...")

    curses.wrapper(lambda s: main(s, chat_host, chat_port, user, jwt))
