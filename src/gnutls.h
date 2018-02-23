#ifndef __MOFOS_SSL_H
#define __MOFOS_SSL_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gnutls/gnutls.h>

#include "debug.h"

#if GNUTLS_VERSION_NUMBER < 030500
#error GNUTLS version 3.5.0 or higher required
#endif

#define dtls_global_init gnutls_global_init
#define dtls_global_free gnutls_global_deinit

struct mofos_dtls_server;
struct mofos_dtls_client;

typedef enum mofos_dtls_handler_status
(*mofos_dtls_loop_handler_t)(uint8_t *data,
			     size_t size,
			     void *user_data);

typedef int (*mofos_dtls_data_sender_t) (void *data,
                                         size_t size,
                                         void *user_data);

enum mofos_dtls_error
{
    MOFOS_DTLS_NO_ERROR = 0,
    MOFOS_DTLS_TIMEOUT,
    MOFOS_DTLS_FATAL,
};

enum mofos_dtls_handler_status
{
    MOFOS_DTLS_HANDLER_OK = 0, /* data processed */
    MOFOS_DTLS_HANDLER_EXIT, /* server exits cleanly */
    MOFOS_DTLS_HANDLER_FATAL, /* server exits with an error */
    MOFOS_DTLS_HANDLER_ROAM = 0xff,
};

int
mofos_dtls_global_init(void);

void
mofos_dtls_global_free(void);

struct mofos_dtls_client*
mofos_dtls_client_new(const char *hostname, const char* port);

void
mofos_dtls_client_free(struct mofos_dtls_client* client);

/**
 * roams a client connection (rebinds a new socket to the new
 * address)
 **/
int
mofos_dtls_client_roam(struct mofos_dtls_client *client,
                           const struct addrinfo *new_addr);

struct mofos_dtls_server*
mofos_dtls_server_new(const char* hostname,
		      const char* port);

void
mofos_dtls_server_free(struct mofos_dtls_server* srv);

/**
 * roams the server's socket to the new client address
 **/
int
mofos_dtls_server_roam(struct mofos_dtls_server *server,
                           const struct addrinfo *new_addr);

/**
 * sets the data handler for this instance of mofos_dtls_params
 * everytime the underlying socket receives data it will be passed to the
 * handler function alongside the provided user_data
 **/
void
mofos_dtls_server_set_data_handler(struct mofos_dtls_server* params,
                                        mofos_dtls_loop_handler_t handler);

/**
 * sets the data sender function to be used by the loop handler
 **/
void
mofos_dtls_server_set_data_sender(struct mofos_dtls_server *server,
                                       mofos_dtls_data_sender_t sender);

/**
 * sets the user data to be passed to the loop handler upon receiving
 * data
 **/
void
mofos_dtls_server_set_user_data(struct mofos_dtls_server* params,
                                     void *user_data);
/**
 * Runs the main server loop according to parameters in server
 **/
bool
mofos_dtls_server_main_loop_run(struct mofos_dtls_server* server);

/**
 * Prints detailed information about the given server using the given printer
 **/
void
mofos_dtls_server_describe(struct mofos_dtls_server* server, int fd,
                                mofos_printer printer);

#endif /* __MOFOS_SSL_H */
