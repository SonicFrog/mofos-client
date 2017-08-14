#ifndef __DEF_SSL_TEST_H
#define __DEF_SSL_TEST_H

int ssl_test_suite_init();
int ssl_test_suite_cleanup();

void ssl_test_server_setup();
void ssl_test_server_loop();
void ssl_test_client_connect();

#endif
