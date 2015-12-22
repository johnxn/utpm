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
#include <linux/netlink.h>
#include "command_handler.h"
#include "rockey_apis.h"

#define UTPMD_NAME "utpmd"
#define UTPMD_SOCKET "/var/run/" UTPMD_NAME ".socket"
#define MAX_CLIENT 10
#define UTPMD_COMMAND_TIMEOUT 30
#define UTPM_REQUEST_LENGTH 1020

#define NETLINK_KUTPM 31

static int stopflag = 0;

static int client_fds[MAX_CLIENT];

static int client_init() {
    int i;
    for (i = 0; i < MAX_CLIENT; i++) {
        client_fds[i] = -1;
    }
}

static int client_add(int fd) {
    int i;
    for (i = 0; i < MAX_CLIENT; i++) {
        if (client_fds[i] == -1) {
            client_fds[i] = fd;
            return 0;
        }
    }
    return -1;
}

static int client_del(int fd) {
    int i;
    for (i = 0; i < MAX_CLIENT; i++) {
        if (client_fds[i] == fd) {
            client_fds[i] = -1;
            return 0;
        }
    }
    return -1;
}


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

static int init_netlink_socket() {
    int sock;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_KUTPM);
    if (sock < 0) {
        syslog(LOG_ERR, "create netlink socket failed.\n");
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        syslog(LOG_ERR, "bind netlink socket failed.\n");
        close(sock);
        return -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(UTPM_REQUEST_LENGTH));
    if (nlh == NULL) {
        syslog(LOG_ERR, "malloc() failed.\n");
        close(sock);
        return -1;
    }
    memset(nlh, 0, NLMSG_SPACE(UTPM_REQUEST_LENGTH));
    nlh->nlmsg_len = NLMSG_SPACE(UTPM_REQUEST_LENGTH);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), "handshake from utpmd.\n");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    //syslog(LOG_INFO, "sending handshake to kernel.\n");
    int errcode ;
    if ((errcode = sendmsg(sock, &msg, 0)) < 0) {
        syslog(LOG_ERR, "sendmsg() failed. errcode: %d\n", errcode);
        return -1;
    }
    //syslog(LOG_INFO, "init_netlink_socket() succeed.\n");
    return sock;
}

static int read_nl(int fd, unsigned char *buffer, int size) {
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(size));
    memset(nlh, 0, NLMSG_SPACE(size));

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(size);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (recvmsg(fd, &msg, 0) < 0) return -1;
    memcpy(buffer, NLMSG_DATA(nlh), NLMSG_PAYLOAD(nlh, 0));
    return NLMSG_PAYLOAD(nlh, 0);
}
static int write_nl(int fd, unsigned char *buffer, int size) {
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_nl dest_addr;
    memset(&iov, 0, sizeof(iov));
    memset(&msg, 0, sizeof(msg));
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(size));
    memset(nlh, 0, NLMSG_SPACE(size));
    nlh->nlmsg_len = NLMSG_SPACE(UTPM_REQUEST_LENGTH);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(size);

    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memcpy(NLMSG_DATA(nlh), buffer, size);
    
    if (sendmsg(fd, &msg, 0) < 0) return -1;
    return size;
}

static void main_loop(void) {
    unsigned char in[UTPM_REQUEST_LENGTH];
    unsigned char out[UTPM_REQUEST_LENGTH];
    int in_len, out_len;
    int sock, c_fd, nl_fd, fd;
    int res;
    int maxrfd;
    int i;
    struct sockaddr_un addr;
    unsigned int addr_len;
    fd_set rfds;
    fd_set allfds;

    syslog(LOG_INFO, "main loop start");
    syslog(LOG_INFO, "openning rockey");
    if (open_rockey(0, NULL) != DONGLE_SUCCESS) {
        syslog(LOG_ERR, "open rockey failed");
        exit(EXIT_FAILURE);
    }

    client_init();
    unlink(UTPMD_SOCKET);
    sock = init_socket(UTPMD_SOCKET);
    if (sock < 0) {
        exit(EXIT_FAILURE);
    }
    FD_ZERO(&allfds);
    FD_SET(sock, &allfds);
    maxrfd = sock;
    if ((nl_fd = init_netlink_socket()) >= 0) {
        syslog(LOG_INFO, "init_netlink_socket() succeed. nl_fd: %d", nl_fd);
        FD_SET(nl_fd, &allfds);
        client_add(nl_fd);
        maxrfd = nl_fd > maxrfd ? nl_fd : maxrfd;
    }
    else {
        syslog(LOG_INFO, "init_netlink_socket() failed, kernel not ready");
    }
    while (!stopflag) {
        rfds = allfds;
        
        if (select(maxrfd+1, &rfds, NULL, NULL, NULL) < 0) {
            syslog(LOG_ERR, "select() error");
            exit(EXIT_FAILURE);
        }
        if (FD_ISSET(sock, &rfds)) {
            c_fd = accept(sock, (struct sockaddr *)&addr, &addr_len);
            FD_SET(c_fd, &allfds);
            client_add(c_fd);
            maxrfd = c_fd > maxrfd ? c_fd : maxrfd;
            continue;
        }
        for (i = 0; i < MAX_CLIENT; ++i) {
            if (client_fds[i] != -1 && FD_ISSET(client_fds[i], &rfds)) {
                fd = client_fds[i];
                //in_len = read(fd, in, sizeof(in));
                if (fd == nl_fd) in_len = read_nl(fd, in , sizeof(in));
                else in_len = read(fd, in, sizeof(in));
                if (in_len < 0) {
                    syslog(LOG_ERR, "read() error");
                    FD_CLR(fd, &allfds);
                    client_del(fd);
                    close(fd);
                    continue;
                }
                else if (in_len == 0) {
                    syslog(LOG_INFO, "fd closed()");
                    FD_CLR(fd, &allfds);
                    client_del(fd);
                    close(fd);
                    continue;
                }
                syslog(LOG_INFO, "received %d bytes", in_len);
                if ((res = handle_command(in, in_len, out, &out_len)) != 0) {
                    setup_error(out, &out_len, res);
                }
                //res = write(fd, out, out_len);
                if (fd == nl_fd) {
                    res = write_nl(fd, out, out_len);
                }
                else res = write(fd, out, out_len);
                if (res < 0) {
                    syslog(LOG_ERR, "write() failed: %s", strerror(errno));
                    FD_CLR(fd, &allfds);
                    client_del(fd);
                    close(fd);
                    break;
                }
                syslog(LOG_INFO, "send %d bytes", out_len);
            }
        }

    }
    close(sock);
    unlink(UTPMD_SOCKET);
    syslog(LOG_INFO, "main loop end");

}

static void main_loop2(void) {
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
        unsigned char in[UTPM_REQUEST_LENGTH];
        unsigned char out[UTPM_REQUEST_LENGTH];
        int in_len, out_len;
        int res;
        fd_set rfds;
        int maxfd;
        struct timeval tv;
        addr_len = sizeof(addr);
        syslog(LOG_INFO, "waiting for connection");
        //fd = accept(sock, (struct sockaddr *)&addr, &addr_len);
        in_len = 0;
        do {
            syslog(LOG_INFO, "waiting for commands");
            FD_ZERO(&rfds);
            //FD_SET(fd, &rfds);
            FD_SET(sock, &rfds);
            //FD_SET(netlink_sock, &rfds);
            //tv.tv_sec = UTPMD_COMMAND_TIMEOUT;
            //tv.tv_usec = 0;
            //maxfd = sock > netlink_sock ? sock : netlink_sock;
            //res = select(fd + 1, &rfds, NULL, NULL, &tv);
            res = select(maxfd + 1, &rfds, NULL, NULL, NULL);
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
    //main_loop_k();
    syslog(LOG_INFO, "stopping utpm daemon");
    closelog();
    return 0;
}
