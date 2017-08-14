#ifndef __DEF_SSL_H
#define __DEF_SSL_H

#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define CERTIFICATE_DIGEST "sha256"

typedef enum {
    SUCCESS = 0,
    TEMP_ERROR = 1,
    PERM_ERROR = 2,
    AGAIN = 3,
    EXIT = 4
} handler_status_t;

struct dtls_params {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int sockfd;
    struct sockaddr_in laddr;
};

typedef int (*server_response_sender_t) (struct dtls_params* params,
                                         const unsigned char* data,
                                         size_t data_len);

typedef handler_status_t (*server_loop_handler_t) (struct dtls_params* params,
                                                   struct sockaddr_in addr,
                                                   server_response_sender_t responder,
                                                   const unsigned char* data,
                                                   size_t data_len);

#define ssl_print_error(fmt, ...) debug("ssl: " fmt ": %s\n", \
                                        ERR_reason_error_string(ERR_get_error()))

/**
 * Global dtls init function (must be called before any other DTLS calls)
 **/
int dtls_global_init();

/**
 * Global DTLS exit function (should be called when done using DTLS)
 **/
void dtls_global_free();

/**
 * Initializes a generic dtls_params structure using the key given in keyname
 * @param params the structure to initialize
 * @param keyname the name of the key
 * @returns 0 on success, an error code otherwise
 **/
int dtls_init(struct dtls_params *params, const char* keyname);

/**
 * Server specific initialization of a struct dtls_params
 * @param params the server dtls_params structure
 * @returns 0 on success, an error code otherwise
 **/
int dtls_init_server(struct dtls_params *params, int port);

/**
 * Client specific initialization of a struct dtls_params
 * @param params the client dtls_params structure
 * @returns 0 on success, an error code otherwise
 **/
int dtls_init_client(struct dtls_params* params, const char* address,
                     const int port);

/**
 * DTLS connection routine
 **/
int dtls_client_connect(struct dtls_params* params);

/**
 * Main DTLS server loop
 * @param params DTLS parameters used for this server
 * @param handler callback used when data is received by this server
 * @returns 0 if server exited cleanly, error code otherwise
 **/
int dtls_server_loop(struct dtls_params* params, server_loop_handler_t handler);

void dtls_free(struct dtls_params* params);

#endif
