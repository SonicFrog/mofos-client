#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>

#include "compiler.h"
#include "debug.h"
#include "gnutls.h"

#if GNUTLS_VERSION_NUMBER < 030500
#error "GnuTLS v3.5 or higher required"
#endif

#define MOFOS_DEFAULT_MTU 1400
#define MOFOS_DEFAULT_KEY_SIZE (512 / (sizeof(char)))

struct mofos_dtls_params
{
    char* hostname;
    uint16_t port;

    struct addrinfo* local_addr;
    struct addrinfo* remote_addr;

    gnutls_datum_t psk;
    gnutls_session_t session;
    int socket;

    mofos_dtls_data_sender_t sender;
    mofos_dtls_loop_handler_t handler;
    void *user_data;
};

struct mofos_dtls_server
{
    struct mofos_dtls_params *params;
    gnutls_psk_server_credentials_t credentials;
};

struct mofos_dtls_client
{
    struct mofos_dtls_params *params;
};

int mofos_dtls_global_init(void)
{
    return gnutls_global_init();
}

void mofos_dtls_global_free(void)
{
    gnutls_global_deinit();
}

static int
mofos_dtls_client_generate_psk(struct mofos_dtls_params* params,
                               const unsigned int key_size)
{
    int rc = 0;

    rc = gnutls_key_generate(&params->psk, key_size);
    if (rc < 0) {
        pgnutls_error("gnutls_key_generate", rc);
        return -1;
    }

    return 0;
}

void
mofos_dtls_server_set_data_handler(struct mofos_dtls_server* server,
                                   mofos_dtls_loop_handler_t handler)
{
    assert(server != NULL);
    assert(handler != NULL);

    server->params->handler = handler;
}

void
mofos_dtls_server_set_data_sender(struct mofos_dtls_server *server,
                                       mofos_dtls_data_sender_t sender)
{
    assert(server != NULL);
    assert(sender != NULL);

    server->params->sender = sender;
}

void
mofos_dtls_server_set_user_data(struct mofos_dtls_server *server,
                                     void *user_data)
{
    assert(server);

    server->params->user_data = user_data;
}

static int
mofos_dtls_params_init(struct mofos_dtls_params* params, const char* hostname,
                       const uint16_t port, int flags)
{
    assert(params);

    params->hostname = strdup(hostname);
    params->port = port;

    gnutls_init(&params->session, flags | GNUTLS_DATAGRAM);
    gnutls_priority_set(params->session, 0);
    /* TODO: MTU discovery */
    gnutls_dtls_set_mtu(params->session, MOFOS_DEFAULT_MTU);
    gnutls_set_default_priority(params->session);

    return 0;
}

static void
mofos_dtls_params_free(struct mofos_dtls_params* params)
{
    gnutls_deinit(params->session);
    close(params->socket);
    free(params->hostname);
    freeaddrinfo(params->remote_addr);
    freeaddrinfo(params->local_addr);
    free(params);
}

static int
mofos_dtls_bind_local_socket(const struct addrinfo* info,
			     struct addrinfo** bound)
{
    const struct addrinfo* current;
    int sockfd = -1, rc;

    for (current = info; current != NULL; current = current->ai_next)
    {
	sockfd = socket(current->ai_family,
			current->ai_socktype,
			current->ai_protocol);

	if (sockfd < 0)
	    continue;

	rc = bind(sockfd, current->ai_addr, current->ai_addrlen);

	if (rc) {
	    close(sockfd);
	    sockfd = -1;
	    continue;
	}

	break;
    }

    if (bound && current)
    {
	*bound = zalloc(sizeof(struct addrinfo));
	memcpy(*bound, current, sizeof(struct addrinfo));
    }
    else
    	return -1;

    return sockfd;
}

static int
mofos_dtls_connect_remote_socket(const struct addrinfo* remote)
{
    struct addrinfo hints = {
	.ai_flags = AI_PASSIVE | AI_ADDRCONFIG,
	.ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *result;
    struct addrinfo *effective;
    const struct addrinfo *current;
    int sockfd = -1;
    int rc;

    rc = getaddrinfo(NULL, "0", &hints, &result);

    if (rc) {
	error("unable to find a local socket to bind to: %s", gai_strerror(rc));
	return -1;
    }

    sockfd = mofos_dtls_bind_local_socket(result, &effective);

    if (sockfd < 0)
	return sockfd;

    for (current = remote; current != NULL; current = current->ai_next)
    {
	if (current->ai_family != result->ai_family)
	    continue;

	rc = connect(sockfd, current->ai_addr, current->ai_addrlen);

	if (rc)
	    error("unable to connect: %s", strerror(errno));
	else
	    break;
    }

    if (rc < 0)
    {
	error("connect: %s", strerror(errno));
	return -1;
    }

    return sockfd;
}

static struct mofos_dtls_params*
mofos_dtls_params_new(const char* hostname, const char* port, int flags)
{
    struct mofos_dtls_params * params = zalloc(sizeof(struct mofos_dtls_params));

    if (mofos_dtls_params_init(params, hostname, atoi(port), flags) < 0) {
        mofos_dtls_params_free(params);
        return NULL;
    }

    return params;
}

static int
mofos_dtls_server_init_psk(struct mofos_dtls_server *server,
			   const char* username)
{
    int rc, cstatus, fd;
    char tmpfile[] = "/tmp/mofos-XXXXXX";

    fd = mkstemp(tmpfile);

    if (fd < 0)
    {
	error("mkstemp(%s): %s", tmpfile);
	return errno;
    }

    rc = chmod(tmpfile, 0600);

    if (rc)
	warn("unable to chmod credentials file: %s", strerror(errno));

    debug("writing psk credentials to %s", tmpfile);

    if (fd < 0)
    {
	error("unable to create tmpfile %s: %s", tmpfile, strerror(errno));
	return errno;
    }

    rc = gnutls_psk_allocate_server_credentials(&server->credentials);

    if (rc)
    {
	pgnutls_error("server credentials allocation failed", rc);
	return -1;
    }

    rc = fork();

    if (rc == -1)
    {
	error("generating psk failed: fork: %s", strerror(errno));
	return errno;
    }
    else if (rc == 0)
    {
	/* make psktool shutup */
        fd = open("/dev/null", O_RDWR);
	if (fd < 0)
	{
	    error("open /dev/null: %s", strerror(errno));
	    return errno;
	}

	dup2(fd, 1); dup2(fd, 2);

	if (execlp("psktool", "psktool",
		   "-p", tmpfile, "-u", username,
		   (char*) NULL) == -1)
	    fatal("failed to execute psktool: %s", strerror(errno));
    }
    else if (rc > 0)
    {
	debug("running psktool in PID %d", rc);
	waitpid(rc, &cstatus, 0);

	if (WIFEXITED(cstatus))
	{
	    rc = gnutls_psk_set_server_credentials_file(server->credentials,
							tmpfile);
	    if (rc)
	    {
		pgnutls_error("gnutls_psk_set_server_credentials_file", rc);
	    }
	}
	else
	    switch (WEXITSTATUS(cstatus))
	    {
	    case EXIT_FAILURE:
		error("psktool failed");
		break;

	    case EX_SOFTWARE:
		error("psktool internal error");
		break;

	    default:
		error("unexpected psktool exit code: %d", WEXITSTATUS(cstatus));
		break;
	    }
    }

    return rc;
}

static ssize_t
mofos_dtls_client_recv(gnutls_transport_ptr_t ptr, void *buf, size_t sz)
{
    const struct mofos_dtls_params *params = ptr;
    struct addrinfo addr;
    ssize_t read;

    read = recvfrom(params->socket, buf, sz, 0,
                    (struct sockaddr*) &addr.ai_addr,
                    &addr.ai_addrlen);

    if (read < 0)
    {
	error("error in pull function: %s", strerror(errno));
	return -1;
    }

    debug("read %d bytes");

    /* update remote addr (mostly for server) */
    *params->remote_addr = addr;

    return read;
}

static ssize_t
mofos_dtls_client_send(gnutls_transport_ptr_t ptr, const void *buf, size_t sz)
{
    const struct mofos_dtls_params *params = ptr;
    socklen_t socklen = params->remote_addr->ai_addrlen;
    int rc;

    rc = sendto(params->socket, buf, sz, 0,
		params->remote_addr->ai_addr,
		socklen);

    debug("wrote %d bytes", rc);

    if (rc)
	error("error in push function: %s", strerror(errno));

    return rc;
}

static void
mofos_dtls_setup_transport(struct mofos_dtls_params *params)
{
    gnutls_transport_set_ptr(params->session, params);
    gnutls_transport_set_push_function(params->session, mofos_dtls_client_send);
    gnutls_transport_set_pull_function(params->session, mofos_dtls_client_recv);
}

static char*
mofos_dtls_address_describestr(const struct addrinfo* info)
{
    const socklen_t hostlen = 255, srvlen = 255;
    char hostname[hostlen], service[srvlen];
    int rc;

    rc = getnameinfo(info->ai_addr, info->ai_addrlen, hostname, hostlen,
		     service, srvlen, NI_NUMERICSERV);

    if (rc) {
	perror("getnameinfo");
	return NULL;
    }

    return strdup_safe(hostname);
}

static int
mofos_dtls_client_init_psk(struct mofos_dtls_params *params)
{
    int rc;
    gnutls_psk_client_credentials_t creds;
    char *username = getlogin();

    rc = gnutls_psk_allocate_client_credentials(&creds);
    if (rc < 0) {
        pgnutls_error("gnutls_psk_allocate_client_credentials", rc);
        return -1;
    }

    rc = mofos_dtls_client_generate_psk(params, MOFOS_DEFAULT_KEY_SIZE);
    if (rc < 0) {
        return -1;
    }

    rc = gnutls_psk_set_client_credentials(creds, username, &params->psk,
                                           GNUTLS_PSK_KEY_RAW);
    if (rc < 0) {
        pgnutls_error("gnutls_psk_set_client_credentials", rc);
        return -1;
    }

    rc = gnutls_credentials_set(params->session, GNUTLS_CRD_PSK, &creds);
    if (rc < 0) {
        pgnutls_error("gnutls_credentials_set", rc);
        return -1;
    }

    return 0;
}

static int
mofos_dtls_rebind_socket(struct mofos_dtls_params *params,
                         const struct addrinfo *new_addr)
{
    int sockfd, rc, optval;

    sockfd = socket(new_addr->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

#if defined(IP_DONTFRAG)
    optval = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAG, (const void*) &optval,
               sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
    optval = IP_PMTUDISC_DO;
    setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, (const void*) &optval,
               sizeof(optval));
#endif

    rc = bind(sockfd, new_addr->ai_addr, new_addr->ai_addrlen);
    if (rc < 0) {
        perror("bind");
        return -1;
    }

    params->socket = sockfd;

    return 0;
}

static int
mofos_dtls_reconnect_socket(struct mofos_dtls_params *params,
                            const struct addrinfo *new_addr)
{
    unimplemented;
    return 0;
}

int
mofos_dtls_client_roam(struct mofos_dtls_client *params,
                       const struct addrinfo *new_addr)
{
    unimplemented;
    return 0;
}

int
mofos_dtls_server_roam(struct mofos_dtls_server *server,
		       const struct addrinfo* new_addr)
{
    int rc = 0;
    struct mofos_dtls_params *params = server->params;

    rc = mofos_dtls_reconnect_socket(params, new_addr);

    return rc;
}

void
mofos_dtls_client_free(struct mofos_dtls_client *client)
{
    mofos_dtls_params_free(client->params);
    free(client);
}

static int
mofos_dtls_client_init(struct mofos_dtls_client *client,
		       const char* hostname, const char *port)
{
    int rc = 0;
    struct mofos_dtls_params *params = client->params;
    struct addrinfo *available;
    struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG,
	.ai_socktype = SOCK_DGRAM,
    };

    rc = getaddrinfo(hostname, port, &hints, &available);
    if (rc != 0) {
        error("unable to find address information: %s", gai_strerror(rc));
	return rc;
    }

    rc = mofos_dtls_connect_remote_socket(available);

    client->params = mofos_dtls_params_new(hostname, port, GNUTLS_CLIENT);

    rc = mofos_dtls_client_init_psk(params);
    if (rc < 0)
        return rc;

    mofos_dtls_setup_transport(params);

    return 0;
}

struct mofos_dtls_client*
mofos_dtls_client_new(const char* hostname,
		      const char* port)
{
    struct mofos_dtls_client* client = NULL;
    int rc = 0;

    client = zalloc(sizeof(struct mofos_dtls_client));

    debug("creating new mofos network client");

    client->params = mofos_dtls_params_new(hostname, port, GNUTLS_CLIENT);

    if (client->params == NULL)
    {
	error("failed to allocate network: %s", strerror(errno));
	free(client);
	return NULL;
    }

    rc = mofos_dtls_client_init(client, hostname, port);

    if (rc) {
	mofos_dtls_client_free(client);
	return NULL;
    }

    debug("client initialization finished");

    return client;
}

struct mofos_dtls_server*
mofos_dtls_server_new(const char* hostname, const char* port)
{
    int sock, rc;
    struct mofos_dtls_server *server = NULL;
    struct addrinfo *addr, *list, hints = {
	.ai_flags = AI_PASSIVE | AI_ADDRCONFIG,
	.ai_socktype = SOCK_DGRAM,
    };

    server = zalloc(sizeof(struct mofos_dtls_server));

    debug("creating new mofos server");

    server->params = mofos_dtls_params_new(hostname, port, GNUTLS_SERVER);

    if (server->params == NULL) {
	free(server);
	return NULL;
    }

    rc = getaddrinfo(hostname, port, &hints, &list);

    if (rc)
    {
	error("unable to find any address matching %s:%s: %s",
	      hostname, port, strerror(errno));
	mofos_dtls_params_free(server->params);
	free(server);
	return NULL;
    }

    sock = mofos_dtls_bind_local_socket(list, &addr);

    if (sock < 0)
    {
	error("unable to bind socket: %s", strerror(errno));
	mofos_dtls_server_free(server);
	return NULL;
    }

    server->params->local_addr = addr;
    server->params->socket = sock;

    mofos_dtls_server_init_psk(server, getlogin());
    mofos_dtls_setup_transport(server->params);

    debug("mofos server created successfully");
    return server;
}

void
mofos_dtls_server_free(struct mofos_dtls_server* srv)
{
    mofos_dtls_params_free(srv->params);
    free(srv);
}

bool
mofos_dtls_server_main_loop_run(struct mofos_dtls_server *server)
{
    struct mofos_dtls_params *params = server->params;
    enum mofos_dtls_handler_status status;
    const struct addrinfo *remote_addr = params->remote_addr;
    char *ip1 = mofos_dtls_address_describestr(remote_addr), *ip2;
    uint8_t bytes[MOFOS_DEFAULT_MTU];
    ssize_t read = 0;
    int rc;

    debug("starting mofos server loop");

    do {
        read = gnutls_record_recv(params->session, bytes, MOFOS_DEFAULT_MTU);

        if (read < 0) {
            if (gnutls_error_is_fatal(read)) {
                pgnutls_error("gnutls_record_recv", read);
                return false;
            }

	    debug("failed to read from client: %s\n");
            continue;
        }

        if (remote_addr->ai_addr != params->remote_addr->ai_addr) {
	    #define BUF_LEN 255
	    char new_remote[BUF_LEN], remote[BUF_LEN];
	    int rc;

	    rc  = getnameinfo(remote_addr->ai_addr, remote_addr->ai_addrlen,
			      remote, BUF_LEN,
			      NULL, 0, NI_NUMERICHOST);

	    if (rc) {
		perror("getnameinfo");
		abort();
	    }

	    rc = getnameinfo(params->remote_addr->ai_addr,
			     params->remote_addr->ai_addrlen,
			     new_remote, BUF_LEN,
			     NULL, 0, NI_NUMERICHOST);

	    if (rc) {
		perror("getnameinfo");
		abort();
	    }

	    ip1 = mofos_dtls_address_describestr(remote_addr);
	    ip2 = mofos_dtls_address_describestr(params->remote_addr);
	    debug("client roamed from %s to %s", ip1, ip2);
	    free(ip1);
	    free(ip2);

            remote_addr = params->remote_addr;
            mofos_dtls_rebind_socket(params, params->remote_addr);
        }

	debug("received %d bytes from %s:%s", ip1);

        if (remote_addr->ai_addr != params->remote_addr->ai_addr) {
            if (mofos_dtls_server_roam(server, params->remote_addr) < 0) {
                debug("failed to roam server to new client!");
                break;
            }
        }

        status = params->handler(bytes, read, params->user_data);
    } while (status != MOFOS_DTLS_HANDLER_FATAL &&
             status != MOFOS_DTLS_HANDLER_EXIT);

    if (status == MOFOS_DTLS_HANDLER_EXIT)
	debug("mofos server exiting on client request");
    else
	debug("mofos server exiting after error");

    rc = gnutls_bye(params->session, GNUTLS_SHUT_RDWR);
    if (rc < 0) {
        pgnutls_error("gnutls_bye", rc);
        return -1;
    }

    return status == MOFOS_DTLS_HANDLER_EXIT;
}

static void
mofos_dtls_address_describe(struct addrinfo* info, int fd,
                            mofos_printer printer)
{
    socklen_t hostlen = 255, servlen = 255;
    char hostname[hostlen], service[servlen];
    int rc;

    assert(info != NULL);

    rc = getnameinfo(info->ai_addr, info->ai_addrlen, hostname,
                     hostlen, service, servlen, NI_NUMERICSERV);
    if (rc < 0) {
        perror("getnameinfo");
        return;
    }

    printer(fd, "%s:%s", hostname, service);
}

static void
mofos_dtls_server_gnutls_describe(struct mofos_dtls_server *server,
                                  int fd, mofos_printer printer)
{
    const char* tmp;
    gnutls_credentials_type_t cred;
    gnutls_kx_algorithm_t kx;
    bool dhe, ecdh;

    dhe = ecdh = false;

    tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(server->params->session));

    printer(fd, "using %s with ", tmp);

    kx = gnutls_kx_get(server->params->session);
    tmp = gnutls_kx_get_name(kx);

    printer(fd, "key_exchange %s, ", tmp);

    tmp = gnutls_cipher_get_name(gnutls_cipher_get(server->params->session));
    printer(fd, "cipher %s, ", tmp);

    tmp = gnutls_mac_get_name(gnutls_mac_get(server->params->session));
    printer(fd, "mac %s\n", tmp);

    cred = gnutls_auth_get_type(server->params->session);
    switch (cred) {
    case GNUTLS_CRD_IA:
        break;

#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:
        printer(fd, "srp session with username %s\n",
                gnutls_srp_server_get_username(server->params->session));
        break;
#endif

    case GNUTLS_CRD_PSK:
        if (gnutls_psk_client_get_hint(server->params->session) != NULL)
            printer(fd, "PSK authentication -- hint: %s\n",
                    gnutls_psk_client_get_hint(server->params->session));

        if (gnutls_psk_server_get_username(server->params->session) != NULL)
            printer(fd, "PSK authentication, connected as %s\n",
                    gnutls_psk_server_get_username(server->params->session));

        ecdh = kx == GNUTLS_KX_ECDHE_PSK;
        dhe = kx == GNUTLS_KX_DHE_PSK;
        break;


    default:
        printer(fd, "non standard mode");
    }

    if (ecdh)
        printer(fd, "ephemeral ECDH curve %s\n",
                gnutls_ecc_curve_get_name(
                    gnutls_ecc_curve_get(server->params->session)));
    else if (dhe)
        printer(fd, "ephemeral DH using prime of %d bits",
                gnutls_dh_get_prime_bits(server->params->session));
}

void
mofos_dtls_server_describe(struct mofos_dtls_server *server,
                           int fd, mofos_printer printer)
{
    printer(fd, "mofos server listening on ");
    mofos_dtls_address_describe(server->params->local_addr, fd, printer);
    printer(fd, "\n");
    mofos_dtls_server_gnutls_describe(server, fd, printer);
}
