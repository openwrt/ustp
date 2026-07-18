#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#include <libubox/uloop.h>
#include "bridge_track.h"
#include "packet.h"
#include "worker.h"

static atomic_uint processed;

void bridge_one_second(void)
{
	atomic_fetch_add(&processed, 1);
}

void bridge_event_handler(void) {}
void packet_rcv(void) {}
int bridge_create(int bridge_idx, CIST_BridgeConfig *cfg)
{
	(void)bridge_idx;
	(void)cfg;
	return 0;
}
void bridge_delete(int bridge_idx) { (void)bridge_idx; }

int uloop_timeout_set(struct uloop_timeout *timeout, int msecs)
{
	(void)timeout;
	(void)msecs;
	return 0;
}

static void *tick_producer(void *arg)
{
	struct worker_event event = { .type = WORKER_EV_ONE_SECOND };
	unsigned int count = *(unsigned int *)arg;
	unsigned int i;

	for (i = 0; i < count; i++)
		assert(worker_queue_event(&event));
	return NULL;
}

static void test_parallel_ticks(void)
{
	enum { THREAD_COUNT = 4, TICKS_PER_THREAD = 10000 };
	pthread_t threads[THREAD_COUNT];
	unsigned int ticks = TICKS_PER_THREAD;
	unsigned int i;

	atomic_store(&processed, 0);
	assert(worker_init() == 0);
	for (i = 0; i < THREAD_COUNT; i++)
		assert(pthread_create(&threads[i], NULL, tick_producer, &ticks) == 0);
	for (i = 0; i < THREAD_COUNT; i++)
		assert(pthread_join(threads[i], NULL) == 0);

	for (i = 0; i < 5000 && atomic_load(&processed) <
			THREAD_COUNT * TICKS_PER_THREAD; i++)
		usleep(1000);
	assert(atomic_load(&processed) == THREAD_COUNT * TICKS_PER_THREAD);
	worker_cleanup();
}

int main(void)
{
	struct worker_event event = { .type = WORKER_EV_ONE_SECOND };

	assert(worker_init() == 0);
	assert(worker_queue_event(&event));
	assert(worker_queue_event(&event));
	worker_cleanup();
	assert(!worker_queue_event(&event));
	assert(atomic_load(&processed) <= 2);
	test_parallel_ticks();
	return 0;
}
