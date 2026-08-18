// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "client_status_socket.h"
#include "log.h"

#include <event2/event.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CLIENT_STATUS_REQ_MAX 64
#define CLIENT_STATUS_RESP_MAX 4096

struct client_status_socket_s {
    int fd;
    struct event *ev_read;
    mqvpn_client_t *client; /* borrowed; owner destroys this socket first */
};

static const char *
client_state_name(mqvpn_client_state_t state)
{
    static const char *const names[] = {
        "idle", "connecting", "authenticating", "tunnel_ready", "established",
        "reconnecting", "closed",
    };
    return state >= 0 && state < MQVPN_STATE__COUNT ? names[state] : "unknown";
}

static size_t
format_paths_json(mqvpn_client_t *client, char *out, size_t out_len)
{
    mqvpn_path_info_t paths[MQVPN_MAX_PATHS];
    int n_paths = 0;
    if (!client || mqvpn_client_get_paths(client, paths, MQVPN_MAX_PATHS, &n_paths) != MQVPN_OK) {
        return (size_t)snprintf(out, out_len, "{\"error\":\"status unavailable\"}\n");
    }

    size_t used = 0;
    int n = snprintf(out, out_len, "{\"state\":\"%s\",\"paths\":[",
                     client_state_name(mqvpn_client_get_state(client)));
    if (n < 0 || (size_t)n >= out_len) return 0;
    used = (size_t)n;

    for (int i = 0; i < n_paths; i++) {
        n = snprintf(out + used, out_len - used,
                     "%s{\"handle\":%lld,\"iface\":\"%s\",\"status\":\"%s\","
                     "\"srtt_ms\":%d,\"tx_bytes\":%llu,\"rx_bytes\":%llu}",
                     i ? "," : "", (long long)paths[i].handle, paths[i].name,
                     mqvpn_path_status_string(paths[i].status), paths[i].srtt_ms,
                     (unsigned long long)paths[i].bytes_tx,
                     (unsigned long long)paths[i].bytes_rx);
        if (n < 0 || (size_t)n >= out_len - used) {
            return (size_t)snprintf(out, out_len, "{\"error\":\"status response too large\"}\n");
        }
        used += (size_t)n;
    }
    n = snprintf(out + used, out_len - used, "]}\n");
    if (n < 0 || (size_t)n >= out_len - used) return 0;
    return used + (size_t)n;
}

static void
on_status_request(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    client_status_socket_t *socket = arg;
    for (;;) {
        struct sockaddr_un peer;
        socklen_t peer_len = sizeof(peer);
        char request[CLIENT_STATUS_REQ_MAX];
        ssize_t received = recvfrom(fd, request, sizeof(request) - 1, 0,
                                    (struct sockaddr *)&peer, &peer_len);
        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                LOG_WRN("client status socket recvfrom: %s", strerror(errno));
            return;
        }
        request[received] = '\0';
        while (received > 0 && isspace((unsigned char)request[received - 1]))
            request[--received] = '\0';

        char response[CLIENT_STATUS_RESP_MAX];
        size_t response_len;
        if (strcmp(request, "get_paths") == 0)
            response_len = format_paths_json(socket->client, response, sizeof(response));
        else
            response_len = (size_t)snprintf(response, sizeof(response),
                                            "{\"error\":\"unknown command\"}\n");
        if (response_len == 0) continue;
        if (sendto(fd, response, response_len, 0, (struct sockaddr *)&peer, peer_len) < 0)
            LOG_WRN("client status socket sendto: %s", strerror(errno));
    }
}

client_status_socket_t *
client_status_socket_create(struct event_base *eb, mqvpn_client_t *client)
{
    if (!eb || !client) return NULL;
    if (strlen(MQVPN_CLIENT_STATUS_SOCKET_PATH) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        LOG_ERR("client status socket path is too long");
        return NULL;
    }

    struct stat st;
    if (lstat(MQVPN_CLIENT_STATUS_SOCKET_PATH, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            LOG_ERR("client status socket path exists and is not a socket: %s",
                    MQVPN_CLIENT_STATUS_SOCKET_PATH);
            return NULL;
        }
        if (unlink(MQVPN_CLIENT_STATUS_SOCKET_PATH) < 0) {
            LOG_ERR("client status socket unlink(%s): %s", MQVPN_CLIENT_STATUS_SOCKET_PATH,
                    strerror(errno));
            return NULL;
        }
    } else if (errno != ENOENT) {
        LOG_ERR("client status socket lstat(%s): %s", MQVPN_CLIENT_STATUS_SOCKET_PATH,
                strerror(errno));
        return NULL;
    }

    client_status_socket_t *status_socket = calloc(1, sizeof(*status_socket));
    if (!status_socket) return NULL;
    status_socket->fd = -1;
    status_socket->client = client;

    status_socket->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (status_socket->fd < 0) {
        LOG_ERR("client status socket(): %s", strerror(errno));
        free(status_socket);
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", MQVPN_CLIENT_STATUS_SOCKET_PATH);
    /* chmod after bind is retained for clarity, but bind under 0177 first so
     * there is never a short permission window for another local account. */
    mode_t old_umask = umask(0177);
    int bind_rc = bind(status_socket->fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);
    if (bind_rc < 0) {
        LOG_ERR("client status socket bind(%s): %s", MQVPN_CLIENT_STATUS_SOCKET_PATH,
                strerror(errno));
        close(status_socket->fd);
        free(status_socket);
        return NULL;
    }
    if (chmod(MQVPN_CLIENT_STATUS_SOCKET_PATH, 0600) < 0)
        LOG_WRN("client status socket chmod(%s): %s", MQVPN_CLIENT_STATUS_SOCKET_PATH,
                strerror(errno));
    int flags = fcntl(status_socket->fd, F_GETFL, 0);
    if (flags < 0 || fcntl(status_socket->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("client status socket nonblocking: %s", strerror(errno));
        close(status_socket->fd);
        unlink(MQVPN_CLIENT_STATUS_SOCKET_PATH);
        free(status_socket);
        return NULL;
    }
    status_socket->ev_read = event_new(eb, status_socket->fd, EV_READ | EV_PERSIST,
                                       on_status_request, status_socket);
    if (!status_socket->ev_read) {
        LOG_ERR("client status socket event_new failed");
        close(status_socket->fd);
        unlink(MQVPN_CLIENT_STATUS_SOCKET_PATH);
        free(status_socket);
        return NULL;
    }
    event_add(status_socket->ev_read, NULL);
    LOG_INF("client status socket ready: %s", MQVPN_CLIENT_STATUS_SOCKET_PATH);
    return status_socket;
}

void
client_status_socket_destroy(client_status_socket_t *socket)
{
    if (!socket) return;
    if (socket->ev_read) {
        event_del(socket->ev_read);
        event_free(socket->ev_read);
    }
    if (socket->fd >= 0) close(socket->fd);
    struct stat st;
    if (lstat(MQVPN_CLIENT_STATUS_SOCKET_PATH, &st) == 0 && S_ISSOCK(st.st_mode))
        unlink(MQVPN_CLIENT_STATUS_SOCKET_PATH);
    free(socket);
}

int
client_status_socket_query(void)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "client status socket(): %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_un local;
    memset(&local, 0, sizeof(local));
    local.sun_family = AF_UNIX;
    /* Linux abstract address: no filesystem cleanup or collision between queries. */
    int name_len = snprintf(local.sun_path + 1, sizeof(local.sun_path) - 1,
                            "mqvpn-status-%ld", (long)getpid());
    if (name_len < 0 || (size_t)name_len >= sizeof(local.sun_path) - 1) {
        close(fd);
        return 1;
    }
    socklen_t local_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);
    if (bind(fd, (struct sockaddr *)&local, local_len) < 0) {
        fprintf(stderr, "client status bind: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    struct sockaddr_un server;
    memset(&server, 0, sizeof(server));
    server.sun_family = AF_UNIX;
    snprintf(server.sun_path, sizeof(server.sun_path), "%s", MQVPN_CLIENT_STATUS_SOCKET_PATH);
    if (connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
        fprintf(stderr, "client status unavailable at %s: %s\n", MQVPN_CLIENT_STATUS_SOCKET_PATH,
                strerror(errno));
        close(fd);
        return 1;
    }
    if (send(fd, "get_paths\n", 10, 0) != 10) {
        fprintf(stderr, "client status send: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    if (poll(&pfd, 1, 1000) != 1 || !(pfd.revents & POLLIN)) {
        fprintf(stderr, "client status query timed out\n");
        close(fd);
        return 1;
    }
    char response[CLIENT_STATUS_RESP_MAX];
    ssize_t n = recv(fd, response, sizeof(response) - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "client status recv: %s\n", n < 0 ? strerror(errno) : "empty response");
        close(fd);
        return 1;
    }
    response[n] = '\0';
    fputs(response, stdout);
    close(fd);
    return 0;
}
