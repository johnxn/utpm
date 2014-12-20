#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "command_handler.h"
#include "rockey_apis.h"

#define UTPMD_NAME "utpmd"
#define UTPMD_SOCKET "/var/run/" UTPMD_NAME ".socket"
#define MAX_CLIENT 10
#define UTPMD_COMMAND_TIMEOUT 30
#define UTPM_REQUEST_LENGHT 1020

static int stopflag = 0;

static void signal_handler(int sig) {
    syslog(LOG_INFO, "signale received: %d", sig);
    if (sig == SIGTERM || sig == SIGQUIT || sig == SIGINT) stopflag = 1;
}

static void init_signal_handler(void) {
    syslog(LOG_INFO, "installing signal handlers");
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        syslog(LOG_ERR, "signal(SIGTERM) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGQUIT, signal_handler) == SIG_ERR) {
        syslog(LOG_ERR, "signal(SIGQUIT) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        syslog(LOG_ERR, "signal(SIGINT) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        syslog(LOG_ERR, "signal(SIGPIPE) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void daemonize(void) {
    pid_t sid, pid;
    syslog(LOG_INFO, "daemonizing");
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) exit(EXIT_SUCCESS);
    pid = getpid();
    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "setsid() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (chdir("/") < 0) {
        syslog(LOG_ERR, "chdir() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    syslog(LOG_INFO, "daemonizing succeed, pid=%d, sid=%d", pid, sid);
}

static int init_socket(const char *name) {
    int sock;
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "open socket failed: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_un un;
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, name, sizeof(un.sun_path));
    if (bind(sock, (struct sockaddr *)&un, sizeof(un)) < 0) {
        syslog(LOG_ERR, "bind socke failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    chmod(name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    listen(sock, MAX_CLIENT);
    return sock;
}

static void main_loop(void) {
    int sock, fd;
    struct sockaddr_un addr;
    unsigned int addr_len;
    syslog(LOG_INFO, "main loop start");
    unlink(UTPMD_SOCKET);
    sock = init_socket(UTPMD_SOCKET);
    if (sock < 0) {
        exit(EXIT_FAILURE);
    }
    syslog(LOG_INFO, "openning rockey");
    if (open_rockey(0, NULL) != DONGLE_SUCCESS) {
        syslog(LOG_ERR, "open rockey failed");
        exit(EXIT_FAILURE);
    }
    while (!stopflag) {
        unsigned char in[UTPM_REQUEST_LENGHT];
        unsigned char out[UTPM_REQUEST_LENGHT];
        int in_len, out_len;
        int res;
        fd_set rfds;
        struct timeval tv;
        addr_len = sizeof(addr);
        syslog(LOG_INFO, "waiting for connection");
        fd = accept(sock, (struct sockaddr *)&addr, &addr_len);
        in_len = 0;
        do {
            syslog(LOG_INFO, "waiting for commands");
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            tv.tv_sec = UTPMD_COMMAND_TIMEOUT;
            tv.tv_usec = 0;
            res = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (res < 0) {
                syslog(LOG_ERR, "select() failed: %s", strerror(errno));
                close(fd);
                break;
            }
            else if (res == 0) {
                syslog(LOG_INFO, "connection closed due to timeout");
                close(fd);
                break;
            }
            in_len = read(fd, in, sizeof(in));
            if (in_len > 0) {
                syslog(LOG_INFO, "received %d bytes", in_len);
                if ((res = handle_command(in, in_len, out, &out_len)) != 0) {
                    setup_error(out, &out_len, res);
                }
                res = write(fd, out, out_len);
                if (res < 0) {
                    syslog(LOG_ERR, "write() failed: %s", strerror(errno));
                    close(fd);
                    break;
                }
                syslog(LOG_INFO, "send %d bytes", out_len);
            }

        } while(in_len > 0);
        close(fd);
    }
    close(sock);
    unlink(UTPMD_SOCKET);
    syslog(LOG_INFO, "main loop end");
}

int main(int argc, char **argv) {
    openlog(UTPMD_NAME, 0, LOG_DAEMON);
    syslog(LOG_INFO, "starting utpm daemon");
    init_signal_handler();
    daemonize();
    main_loop();
    syslog(LOG_INFO, "stopping utpm daemon");
    closelog();
    return 0;
}
