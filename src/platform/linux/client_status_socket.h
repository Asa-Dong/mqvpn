// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Local, read-only status API for the Linux MQVPN client.
 *
 * This is deliberately separate from the server TCP control API: the router
 * only needs a root-local query of its own client object, and must never open
 * a network listener merely for health checks.
 */

#ifndef MQVPN_CLIENT_STATUS_SOCKET_H
#define MQVPN_CLIENT_STATUS_SOCKET_H

#include "libmqvpn.h"

struct event_base;

#define MQVPN_CLIENT_STATUS_SOCKET_PATH "/var/run/mqvpn-status.sock"

typedef struct client_status_socket_s client_status_socket_t;

/* Returns NULL on failure. The caller may continue without observability. */
client_status_socket_t *client_status_socket_create(struct event_base *eb,
                                                     mqvpn_client_t *client);
void client_status_socket_destroy(client_status_socket_t *socket);

/* CLI-side local query. Prints one JSON response to stdout. */
int client_status_socket_query(void);

#endif /* MQVPN_CLIENT_STATUS_SOCKET_H */
