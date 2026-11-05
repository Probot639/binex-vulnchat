/* chat_client.c - curses chat client for vulnchat
 *
 * authenticates via libauthclient, connects to chatd with the JWT,
 * split-pane TUI. reader thread handles incoming frames while the
 * main thread runs the input loop.
 */
#include "auth_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <curses.h>

#define MAX_MSGS    512
#define INPUT_MAX   4096
#define FRAME_MAX   4096

struct msg {
    time_t ts;
    char   nick[64];
    char   body[4096];
    int    is_sys;
};

static struct msg msgs[MAX_MSGS];
static int nmsg;
static pthread_mutex_t msg_mtx = PTHREAD_MUTEX_INITIALIZER;

static char my_nick[64];
static int  chat_fd = -1;
static volatile int running = 1;

static char g_host[256];
static uint16_t g_port;



static int recvn(int fd, void *buf, size_t n)
{
    char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r <= 0)
            return -1;
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

static int send_frame(int fd, const void *data, uint32_t len)
{
    uint32_t nl = htonl(len);
    const char *p = data;
    size_t off;

    if (send(fd, &nl, 4, 0) != 4)
        return -1;
    off = 0;
    while (off < len) {
        ssize_t r = send(fd, p + off, len - off, 0);
        if (r <= 0)
            return -1;
        off += (size_t)r;
    }
    return 0;
}

static int recv_frame(int fd, char *buf, size_t cap)
{
    uint32_t nl, len;

    if (recvn(fd, &nl, 4) < 0)
        return -1;
    len = ntohl(nl);
    if (len == 0 || len >= cap)
        return -1;
    if (recvn(fd, buf, len) < 0)
        return -1;
    buf[len] = '\0';
    return (int)len;
}



static void post(const char *nick, const char *body, int is_sys)
{
    struct msg *m;

    pthread_mutex_lock(&msg_mtx);
    if (nmsg >= MAX_MSGS) {
        memmove(&msgs[0], &msgs[1], sizeof(struct msg) * (MAX_MSGS - 1));
        nmsg = MAX_MSGS - 1;
    }
    m = &msgs[nmsg++];
    m->ts = time(NULL);
    m->is_sys = is_sys;
    strncpy(m->nick, nick ? nick : "", sizeof(m->nick) - 1);
    m->nick[sizeof(m->nick) - 1] = '\0';
    strncpy(m->body, body, sizeof(m->body) - 1);
    m->body[sizeof(m->body) - 1] = '\0';
    pthread_mutex_unlock(&msg_mtx);
}

/* split "nick: body" */
static int parse_chatline(const char *text, char *nick, size_t ncap,
                          char *body, size_t bcap)
{
    const char *sep = strstr(text, ": ");
    size_t nlen, i;
    char c;

    if (!sep || sep == text)
        return 0;
    nlen = sep - text;
    for (i = 0; i < nlen; i++) {
        c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_'))
            return 0;
    }
    if (nlen >= ncap) nlen = ncap - 1;
    memcpy(nick, text, nlen);
    nick[nlen] = '\0';
    strncpy(body, sep + 2, bcap - 1);
    body[bcap - 1] = '\0';
    return 1;
}

static int nick_color(const char *nick)
{
    unsigned h = 0;
    const char *p;
    char c;

    for (p = nick; *p; p++) {
        c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = h * 31 + (unsigned)c;
    }
    return (int)(h % 6) + 1;
}



static void *recv_thread(void *arg)
{
    char buf[FRAME_MAX];
    char nick[64], body[4096];
    int n;

    (void)arg;

    while (running) {
        n = recv_frame(chat_fd, buf, sizeof(buf));
        if (n < 0) {
            if (running) {
                post(NULL, "*** connection lost ***", 1);
                running = 0;
            }
            break;
        }
        if (parse_chatline(buf, nick, sizeof(nick), body, sizeof(body)))
            post(nick, body, 0);
        else
            post(NULL, buf, 1);
    }
    return NULL;
}



static int dial(const char *host, uint16_t port)
{
    struct sockaddr_in addr;
    int fd;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(host);
        if (!he) return -1;
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}



static void draw(const char *input, int cursor)
{
    int h, w, msg_rows, start, i, row, col, sep, plen, cpos;
    char title[256], stamp[8], rest[4096], prompt[80];
    struct msg *m;
    struct tm *tm;

    getmaxyx(stdscr, h, w);
    if (h < 4 || w < 20)
        return;

    erase();

    /* title */
    snprintf(title, sizeof(title), " vulnchat  %s:%d ", g_host, g_port);
    attron(A_REVERSE | A_BOLD);
    mvaddnstr(0, 0, title, w - 1);
    for (i = (int)strlen(title); i < w; i++)
        addch(' ');
    attroff(A_REVERSE | A_BOLD);

    /* messages */
    msg_rows = h - 3;
    pthread_mutex_lock(&msg_mtx);

    start = nmsg - msg_rows;
    if (start < 0) start = 0;

    for (i = start; i < nmsg; i++) {
        row = 1 + (i - start);
        m = &msgs[i];
        tm = localtime(&m->ts);
        strftime(stamp, sizeof(stamp), "%H:%M", tm);

        attron(A_DIM);
        mvprintw(row, 0, " %s ", stamp);
        attroff(A_DIM);

        col = 7;
        if (m->is_sys) {
            attron(COLOR_PAIR(7) | A_DIM);
            mvaddnstr(row, col, m->body, w - col - 1);
            attroff(COLOR_PAIR(7) | A_DIM);
        } else {
            int cp = nick_color(m->nick);
            attron(COLOR_PAIR(cp) | A_BOLD);
            mvaddnstr(row, col, m->nick, w - col - 1);
            attroff(COLOR_PAIR(cp) | A_BOLD);
            col += (int)strlen(m->nick);
            if (col < w - 2) {
                snprintf(rest, sizeof(rest), ": %s", m->body);
                mvaddnstr(row, col, rest, w - col - 1);
            }
        }
    }

    pthread_mutex_unlock(&msg_mtx);

    /* separator */
    sep = h - 2;
    attron(A_DIM);
    for (i = 0; i < w; i++)
        mvaddch(sep, i, ACS_HLINE);
    attroff(A_DIM);

    /* input */
    snprintf(prompt, sizeof(prompt), " %s> ", my_nick);
    plen = (int)strlen(prompt);
    attron(A_BOLD);
    mvaddnstr(h - 1, 0, prompt, w - 1);
    attroff(A_BOLD);
    if (plen < w - 1)
        mvaddnstr(h - 1, plen, input, w - plen - 1);

    cpos = plen + cursor;
    if (cpos >= w) cpos = w - 1;
    move(h - 1, cpos);

    refresh();
}

static void ui_loop(void)
{
    char input[INPUT_MAX];
    int ilen = 0, cursor = 0, ch;
    const char *nn;

    memset(input, 0, sizeof(input));

    while (running) {
        draw(input, cursor);
        ch = getch();
        if (ch == ERR)
            continue;

        if (ch == KEY_RESIZE) {
            continue;
        } else if (ch == '\n' || ch == '\r') {
            if (ilen > 0) {
                input[ilen] = '\0';
                if (strncmp(input, "/nick ", 6) == 0) {
                    nn = input + 6;
                    while (*nn == ' ') nn++;
                    if (*nn) {
                        strncpy(my_nick, nn, sizeof(my_nick) - 1);
                        my_nick[sizeof(my_nick) - 1] = '\0';
                    }
                }
                send_frame(chat_fd, input, (uint32_t)ilen);
                memset(input, 0, sizeof(input));
                ilen = 0;
                cursor = 0;
            }
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (cursor > 0) {
                memmove(&input[cursor - 1], &input[cursor], ilen - cursor);
                ilen--;
                cursor--;
                input[ilen] = '\0';
            }
        } else if (ch == KEY_LEFT) {
            if (cursor > 0) cursor--;
        } else if (ch == KEY_RIGHT) {
            if (cursor < ilen) cursor++;
        } else if (ch == 1) {
            cursor = 0;
        } else if (ch == 5) {
            cursor = ilen;
        } else if (ch == 21) {
            memmove(input, &input[cursor], ilen - cursor);
            ilen -= cursor;
            cursor = 0;
            input[ilen] = '\0';
        } else if (ch >= 32 && ch <= 126 && ilen < INPUT_MAX - 1) {
            memmove(&input[cursor + 1], &input[cursor], ilen - cursor);
            input[cursor] = (char)ch;
            ilen++;
            cursor++;
            input[ilen] = '\0';
        }
    }
}


int main(int argc, char **argv)
{
    const char *auth_host, *chat_host, *user, *pw;
    uint16_t auth_port, chat_port;
    char jwt[2048];
    size_t jwt_len;
    auth_result_t rc;
    char joinbuf[FRAME_MAX];
    pthread_t rtid;

    if (argc < 7) {
        fprintf(stderr,
            "usage: %s <auth_host> <auth_port> <chat_host> <chat_port> <user> <pass>\n",
            argv[0]);
        return 1;
    }

    auth_host = argv[1];
    auth_port = (uint16_t)atoi(argv[2]);
    chat_host = argv[3];
    chat_port = (uint16_t)atoi(argv[4]);
    user      = argv[5];
    pw        = argv[6];

    strncpy(g_host, chat_host, sizeof(g_host) - 1);
    g_port = chat_port;
    strncpy(my_nick, user, sizeof(my_nick) - 1);

    fprintf(stderr, "authenticating %s with %s:%d...\n", user, auth_host, auth_port);
    rc = auth_login(auth_host, auth_port, user, pw,
                    jwt, sizeof(jwt), &jwt_len);
    if (rc != AUTH_OK) {
        fprintf(stderr, "auth failed: %s\n", auth_strerror(rc));
        return 1;
    }
    fprintf(stderr, "token ok (%zu bytes), connecting to %s:%d...\n",
            jwt_len, chat_host, chat_port);

    chat_fd = dial(chat_host, chat_port);
    if (chat_fd < 0) {
        fprintf(stderr, "connect to chatd failed\n");
        return 1;
    }

    if (send_frame(chat_fd, jwt, (uint32_t)jwt_len) < 0) {
        fprintf(stderr, "handshake failed\n");
        close(chat_fd);
        return 1;
    }

    /* drain join announcement so it doesn't clobber the first frame read */
    recv_frame(chat_fd, joinbuf, sizeof(joinbuf));

    /* curses */
    initscr();
    start_color();
    use_default_colors();
    init_pair(1, COLOR_RED, -1);
    init_pair(2, COLOR_GREEN, -1);
    init_pair(3, COLOR_YELLOW, -1);
    init_pair(4, COLOR_BLUE, -1);
    init_pair(5, COLOR_MAGENTA, -1);
    init_pair(6, COLOR_CYAN, -1);
    init_pair(7, 8, -1);
    curs_set(1);
    noecho();
    keypad(stdscr, TRUE);
    timeout(80);

    post(NULL, "connected", 1);
    post(NULL, "type /help for commands, ctrl-c to quit", 1);

    pthread_create(&rtid, NULL, recv_thread, NULL);

    ui_loop();

    endwin();
    close(chat_fd);
    fprintf(stderr, "disconnected\n");
    return 0;
}
