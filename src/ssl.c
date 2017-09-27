#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <assert.h>
#include "debug.h"
#include "ssl.h"

#define TIMEOUT_VALUE ((long) 2)

static int hash_bytes(unsigned char *buffer, size_t buflen)
{
    const EVP_MD* md = EVP_get_digestbyname(CERTIFICATE_DIGEST);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int hbtes;

	assert(ctx);

	EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, buffer, buflen);
    EVP_DigestFinal_ex(ctx, buffer, &hbtes);

    EVP_MD_CTX_destroy(ctx);

    return hbtes;
}

static int dtls_generate_cookie(SSL* ssl, unsigned char* cookie,
                                unsigned int *cookie_len)
{
    static int seed = 0;
    struct sockaddr_in addr;
    int sock, rc;
    socklen_t sz;

    if (!seed)
        seed = time(NULL);

    sock = SSL_get_wfd(ssl);

    rc = getpeername(sock, (struct sockaddr*) &addr, &sz);

    if (rc != 0)
    {
        print_errno();
        return -1;
    }

    *cookie_len = hash_bytes(cookie, sz);

    return 0;
}


static int dtls_cookie_verify(SSL* ssl, const unsigned char* cookie,
                              UNUSED unsigned int clen)
{
    return 0;
}

static inline int dtls_handle_error(SSL* ssl, const int rc)
{
    {
        if (rc == 0)
            switch (SSL_get_error(ssl, rc))
            {
            case SSL_ERROR_SYSCALL:
                print_errno("DTLSv1_listen");
                break;

            default:
                ssl_print_error("DTLSv1_listen");
            }
        else // rc = -1 indicates SSL fatal error
        {
            ssl_print_error("DTLSv1_listen fatal");
            switch (SSL_get_error(ssl, rc))
            {
            case SSL_ERROR_SSL:
                ERR_print_errors_fp(stderr);
                break;

            case SSL_ERROR_SYSCALL:
                print_errno("DTLSv1_listen");
                break;
            }
            return -1;
        }
    }
    return 0;
}

static int client_ssh_style_verification(UNUSED int preverif, X509_STORE_CTX *store)
{
    unsigned char key_bytes[EVP_MAX_KEY_LENGTH], digest_bytes[EVP_MAX_MD_SIZE];
    int err = X509_STORE_CTX_get_error(store);
    BIO* buffer = BIO_new_mem_buf(key_bytes, 4096);
    int read;
    unsigned int md_len;

    X509* cert = X509_STORE_CTX_get_current_cert(store);

    debug("verifying client certificate\n");

    read = PEM_write_bio_X509(buffer, cert);

    if (err < 0)
    {
        debug("Unable to read certificate!\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    const EVP_MD* md = EVP_get_digestbyname(CERTIFICATE_DIGEST);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (md == NULL)
    {
        debug("Unable to find sha256 digest (this is bad!)\n");
        return 0;
    }

    EVP_DigestInit(mdctx, md);
    EVP_DigestUpdate(mdctx, buffer, read);
    EVP_DigestFinal_ex(mdctx, digest_bytes, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    debug("Certificate has fingerprint: ");

    for (unsigned int i = 0; i < md_len; i++)
    {
        debug_multiprint("%02x", digest_bytes[i]);

        if (i + 1 < md_len)
            debug_multiprint(":");
    }


    return 1;
}

int dtls_global_init()
{
    SSL_load_error_strings();

    if (SSL_library_init() != 1)
    {
        ssl_print_error("unable to initialize openssl");
        return -1;
    }

    return 0;
}

int dtls_init(struct dtls_params *params, const char* keyname)
{
    int rc;
    char buffer[4096];

	assert(keyname != NULL);

    params->ctx = SSL_CTX_new(DTLSv1_method());

    if (params->ctx == NULL)
    {
        ssl_print_error("couldn't initialize ssl context");
        return -1;
    }

    rc = SSL_CTX_set_cipher_list(params->ctx, "DEFAULT");

    if (1 != rc)
    {
        ssl_print_error("Failed to set cipher list");
        return -1;
    }

    SSL_CTX_set_options(params->ctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_NONE, NULL);

    snprintf(buffer, 4096, "%s.pem", keyname);

    rc = SSL_CTX_use_PrivateKey_file(params->ctx, buffer, SSL_FILETYPE_PEM);

    if (1 != rc)
    {
        ssl_print_error("unable to load private key");
		fatal("tried loading %s\n", buffer);
    }

    snprintf(buffer, 4096, "%s.crt", keyname);

    rc = SSL_CTX_use_certificate_file(params->ctx, buffer, SSL_FILETYPE_PEM);

    if (1 != rc)
    {
        ssl_print_error("unable to load certificate");
		fatal("tried loading %s\n", buffer);
    }

    rc = SSL_CTX_check_private_key(params->ctx);

    if (1 != rc)
    {
        ssl_print_error("private key is invalid");
        return -1;
    }

    return 0;
}

int dtls_init_server(struct dtls_params *params, int lport)
{
    assert(params != NULL);
    assert(params->ctx != NULL);

    struct sockaddr_in laddr;
    int rc;

    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(lport);
    laddr.sin_addr.s_addr = INADDR_ANY;

    params->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (params->sockfd < 0)
    {
        debug("socket: %s\n", strerror(errno));
        return -errno;
    }

    rc = bind(params->sockfd, (struct sockaddr*) &laddr, sizeof(laddr));

    if (rc != 0)
    {
        print_errno("bind");
        return -errno;
    }

    params->laddr = laddr;

    SSL_CTX_set_cookie_verify_cb(params->ctx, dtls_cookie_verify);
    SSL_CTX_set_cookie_generate_cb(params->ctx, dtls_generate_cookie);

    params->ssl = SSL_new(params->ctx);

    if (params->ssl == NULL)
    {
        ssl_print_error("SSL_new");
        return -1;
    }

    params->bio = BIO_new_dgram(params->sockfd, BIO_NOCLOSE);

    if (params->bio == NULL)
    {
        ssl_print_error("BIO_new_dgram");
        return -1;
    }

    SSL_set_bio(params->ssl, params->bio, params->bio);

    return 0;
}

int dtls_init_client(struct dtls_params* params, const char* address, const int port)
{
    assert(params != NULL);
    assert(params->ctx != NULL);
    assert(address != NULL);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = INADDR_ANY,
        },
        .sin_port = 0,
    };

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    int rc = bind(sock, (struct sockaddr*) &addr, sizeof(addr));

    if (rc != 0)
    {
        debug("bind: %s\n", strerror(errno));
        return -errno;
    }

    params->laddr.sin_addr.s_addr = inet_addr(address);
    params->laddr.sin_family = AF_INET;
    params->laddr.sin_port = htons(port);

    debug("setting up client for %s:%d\n", inet_ntoa(params->laddr.sin_addr),
          port);

    rc = connect(sock, (struct sockaddr*) &params->laddr, sizeof(params->laddr));

    if (rc != 0)
    {
        debug("connect: %s\n", strerror(errno));
        return -errno;
    }

    params->ssl = SSL_new(params->ctx);

    if (params->ssl == NULL)
    {
        ssl_print_error("unable to create ssl instance\n");
        return -1;
    }

    params->bio = BIO_new_dgram(sock, BIO_NOCLOSE);

    if (params->bio == NULL)
    {
        ssl_print_error("unable to create dgram BIO");
        return -1;
    }

    BIO_ctrl(params->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 1, &params->laddr);

    SSL_set_bio(params->ssl, params->bio, params->bio);
    SSL_set_connect_state(params->ssl);

    return 0;
}

static int dtls_data_sender(struct dtls_params* params,
                            const unsigned char* data, size_t data_len)
{
    assert(params != NULL);
    assert(data != NULL);
    assert(data_len > 0);

    int read;

    read = SSL_write(params->ssl, data, data_len);

    if (read < 0)
    {
        dtls_handle_error(params->ssl, read);
    }

    return read;
}

int dtls_server_loop(struct dtls_params* params, server_loop_handler_t handler)
{
    unsigned char buffer[4096];
    handler_status_t status = PERM_ERROR;
    BIO_ADDR* client_addr = BIO_ADDR_new();
    int rc = 0;

    debug("server starting up...\n");

    do
    {
        while((rc = DTLSv1_listen(params->ssl, client_addr)) < 1)
        {
            if (dtls_handle_error(params->ssl, rc) < 0)
                return -1;
        }

        debug("connection from %s:%s\n", BIO_ADDR_hostname_string(client_addr, 1),
              BIO_ADDR_service_string(client_addr, 1));

        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        rc = bind(sockfd, (struct sockaddr*) &params->laddr, sizeof(params->laddr));
        if (rc != 0)
        {
            print_errno("bind");
            return -1;
        }

        rc = connect(sockfd, (struct sockaddr*) &client_addr, sizeof(client_addr));
        if (rc != 0)
        {
            print_errno("connect");
            return -1;
        }

        BIO *cbio = SSL_get_rbio(params->ssl);
        BIO_set_fd(cbio, sockfd, BIO_NOCLOSE);
        BIO_ctrl(cbio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);

        if (SSL_accept(params->ssl) != 1)
        {
            ssl_print_error("SSL_accept");
            return -1;
        }

        do
        {
            int read = SSL_read(params->ssl, buffer, 4096);

            if (read < 0)
            {
                ssl_print_error("SSL_read");
                continue;
            }
			else
			{
				debug("Read %d bytes from client\n", read);
			}

            //status = handler(params, client_addr, dtls_data_sender, buffer, read);
        } while(status != PERM_ERROR && status != EXIT);
    } while(status != EXIT && status != PERM_ERROR);

	BIO_ADDR_free(client_addr);

    debug("exiting server after %s\n", status == EXIT ? "exit" : "error");

    return (status == EXIT) ? 0 : 1;
}

int dtls_client_connect(struct dtls_params* params)
{
    assert(params);
    assert(params->ssl);
    assert(params->ctx);
    assert(params->bio);

    int rc;

connect:
    rc = SSL_connect(params->ssl);

    if (rc != 1)
    {
        rc = SSL_get_error(params->ssl, rc);

        switch (rc)
        {
        case SSL_ERROR_SYSCALL:
            print_errno("SSL_connect");
            break;

        case SSL_ERROR_WANT_CONNECT:
            goto connect;

        default:
            ssl_print_error("SSL_connect");
        }

        return -1;
    }

    return 0;
}

inline void dtls_global_free()
{
    ERR_free_strings();
}

void dtls_free(struct dtls_params* params)
{
    assert(params != NULL);

    close(params->sockfd);

    SSL_CTX_free(params->ctx);

    if (params->ssl != NULL)
        SSL_free(params->ssl);

    close(params->sockfd);
}
