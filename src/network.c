#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "util.h"

struct mofos_network_request_queuer
{

};

struct mofos_network_queue
{

};

typedef int (*resend_callback) (uint32_t id, void *sender);

void mofos_network_queue_request(struct mofos_network_queue *q,
				uint32_t id);

void mofos_network_queue_request(struct mofos_network_queue *q,
				 uint32_t id)
{

}
