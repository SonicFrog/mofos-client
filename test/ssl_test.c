#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <arpa/inet.h>

#include <CUnit/CUnit.h>

#include <debug.h>
#include <ssl.h>

#define TEST_PORT 1200

static const unsigned char test_data[] = {
    'a', 'b', 'c', 'd'
};
const int test_data_sz = sizeof(test_data) / sizeof(test_data[0]);

int ssl_test_suite_init()
{
    return dtls_global_init();
}

int ssl_test_suite_cleanup()
{
    dtls_global_free();
    return 0;
}

static struct dtls_params *make_server_dtls_params()
{
    struct dtls_params* params = calloc(sizeof(struct dtls_params), 1);
    int rc;

    rc = dtls_init(params, "server");

    CU_ASSERT_EQUAL(rc, 0);

    rc = dtls_init_server(params, TEST_PORT);

    CU_ASSERT_EQUAL(rc, 0);

    return params;
}

void ssl_test_server_setup()
{
    struct dtls_params* params = make_server_dtls_params();

    dtls_free(params);
}


static handler_status_t test_server_loop_handler(struct dtls_params* params,
                                                 struct sockaddr_in addr,
                                                 server_response_sender_t resp,
                                                 const unsigned char* data,
                                                 size_t data_len)
{
    static int call_count = 0;

    CU_ASSERT_PTR_NOT_NULL(resp);

    call_count++;

    if (call_count == 1)
    {
        CU_ASSERT_EQUAL(data_len, test_data_sz);

        for (int i = 0; i < test_data_sz; i++)
        {
            CU_ASSERT_EQUAL(test_data[i], data[i]);
        }
        return SUCCESS;
    }

    return EXIT;
}

static void *test_server_loop_sender(void *args)
{
    struct dtls_params* params = malloc(sizeof(struct dtls_params));
    int rc;

    rc = dtls_init(params, "client");

    if (rc != 0)
    {
        debug("dtls_init: %s\n", strerror(errno));
        return NULL;
    }

    rc = dtls_init_client(params, "127.0.0.1", 1200);

    if (rc != 0)
    {
        debug("dtls_init_client: %s\n", strerror(errno));
        return NULL;
    }

    rc = dtls_client_connect(params);

    if (rc != 0)
    {
        debug("dtls_connect_client: %s\n", strerror(errno));
        return NULL;
    }

    debug("starting client\n");

    return NULL;
}

void ssl_test_server_loop()
{
    struct dtls_params* params;
    int rc;
    pthread_t client_thread;
    struct sockaddr_in saddr = {
        .sin_family = AF_INET,
        .sin_port = htons(TEST_PORT),
        .sin_addr = { inet_addr("127.0.0.1") }
    };

    params = make_server_dtls_params();

    rc = pthread_create(&client_thread, NULL, test_server_loop_sender,
                        (void *) &saddr);

    CU_ASSERT_EQUAL(rc, 0);

    rc = dtls_server_loop(params, test_server_loop_handler);

    CU_ASSERT_EQUAL(rc, 0);

    dtls_free(params);

    pthread_join(client_thread, NULL);
}

static handler_status_t ssl_test_loop_handler_null()
{
    return EXIT;
}

static void *server_thread(void *args)
{
    struct dtls_params* params = (struct dtls_params*) args;

    dtls_server_loop(params, ssl_test_loop_handler_null);

    return NULL;
}

void ssl_test_client_connect()
{
    struct dtls_params params, *sparams = make_server_dtls_params();
    pthread_t sthread;
    int rc;

    rc = dtls_init(&params, "client");

    CU_ASSERT_EQUAL(rc, 0);

    rc = dtls_init_server(&params, TEST_PORT);

    CU_ASSERT_EQUAL(rc, 0);

    rc = dtls_init_client(&params, "127.0.0.1", TEST_PORT);

    CU_ASSERT_EQUAL(rc, 0);

    pthread_create(&sthread, NULL, server_thread, (void *) sparams);

    rc = dtls_client_connect(&params);

    CU_ASSERT_EQUAL(rc, 0);

    pthread_join(sthread, NULL);
}
