#include <check.h>
#include <stdio.h>
#include <pthread.h>

#include "../src/debug.h"
#include "ssl_test.h"

#include "../src/gnutls.h"

#define TEST_HOST "localhost"
#define TEST_PORT "8080"

struct mofos_dtls_server *srv;

static void setup(void)
{
    int rc = mofos_dtls_global_init();

    if (rc)
	abort();
}

static struct mofos_dtls_client*
make_mofos_client(const char *hostname, const char* port)
{
    struct mofos_dtls_client* client = NULL;

    client = mofos_dtls_client_new(hostname, port);

    ck_assert_ptr_nonnull(client);

    return client;
}

static void teardown(void)
{
    mofos_dtls_global_free();
}

START_TEST(test_ssl_server_create)
{
    struct mofos_dtls_server *srv = mofos_dtls_server_new(TEST_HOST, TEST_PORT);

    ck_assert_ptr_nonnull(srv);
}
END_TEST

START_TEST(test_ssl_server_recv)
{
    struct mofos_dtls_server *srv = mofos_dtls_server_new(TEST_HOST, TEST_PORT);
    struct mofos_dtls_client* cli = make_mofos_client(TEST_HOST, TEST_PORT);

    ck_assert_ptr_nonnull(srv);
    ck_assert_ptr_nonnull(cli);
}
END_TEST

static enum mofos_dtls_handler_status
ssl_server_test_handshake_handler(uint8_t *data, size_t size, void *user_data)
{
    ck_assert_ptr_nonnull(user_data);
    ck_assert_ptr_nonnull(data);

    ck_assert_mem_eq(data, user_data, size);

    return MOFOS_DTLS_HANDLER_EXIT;
}

static void*
ssl_server_thread_runner(void *server)
{
    struct mofos_dtls_server* srv = server;

    ck_assert_ptr_nonnull(srv);

    ck_assert_int_ne(0, mofos_dtls_server_main_loop_run(srv));

    return NULL;
}

START_TEST(test_ssl_server_handshake_valid)
{
    struct mofos_dtls_server* srv = mofos_dtls_server_new(TEST_HOST, TEST_PORT);
    struct mofos_dtls_client* cli = mofos_dtls_client_new(TEST_HOST, TEST_PORT);
    uint8_t *data = calloc(sizeof(uint8_t), 1024);
    pthread_t server = 0;
    int rc;
    void *retval;

    ck_assert_ptr_nonnull(data);
    ck_assert_ptr_nonnull(srv);

    mofos_dtls_server_set_user_data(srv, data);
    mofos_dtls_server_set_data_handler(srv, ssl_server_test_handshake_handler);

    rc = pthread_create(&server, NULL, ssl_server_thread_runner, srv);
    ck_assert_int_eq(rc, 0);

    rc = pthread_join(server, &retval);

    ck_assert_int_eq(rc, 0);

    ck_assert_ptr_null(retval);

    free(data);
    mofos_dtls_server_free(srv);
    mofos_dtls_client_free(cli);
}
END_TEST

START_TEST(test_ssl_server_handshake)
{
    struct mofos_dtls_server *srv = mofos_dtls_server_new(TEST_HOST, TEST_PORT);

    ck_assert_ptr_nonnull(srv);

    mofos_dtls_server_free(srv);
}
END_TEST

TCase* ssl_tcase(void)
{
    TCase *tc;

    tc = tcase_create("SSL");

    tcase_add_checked_fixture(tc, setup, teardown);
    tcase_add_test(tc, test_ssl_server_create);
    tcase_add_test(tc, test_ssl_server_recv);
    tcase_add_test(tc, test_ssl_server_handshake_valid);
    tcase_add_test(tc, test_ssl_server_handshake);

    return tc;
}
