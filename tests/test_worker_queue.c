#include <assert.h>
#include <limits.h>
#include <string.h>

#include "worker_queue.h"

static struct worker_event event(enum worker_event_type type, int bridge_idx)
{
	return (struct worker_event) {
		.type = type,
		.bridge_idx = bridge_idx,
	};
}

static void test_order_and_wraparound(void)
{
	struct worker_event_queue queue;
	struct worker_event out;
	unsigned int i;

	worker_event_queue_init(&queue);
	for (i = 0; i < WORKER_QUEUE_SIZE; i++) {
		struct worker_event in = event(WORKER_EV_BRIDGE_ADD, i);
		assert(worker_event_queue_push(&queue, &in));
	}
	assert(!worker_event_queue_push(&queue,
		&(struct worker_event) { .type = WORKER_EV_BRIDGE_REMOVE }));

	for (i = 0; i < WORKER_QUEUE_SIZE / 2; i++) {
		assert(worker_event_queue_pop(&queue, &out));
		assert(out.bridge_idx == (int)i);
	}
	for (i = WORKER_QUEUE_SIZE; i < WORKER_QUEUE_SIZE * 3 / 2; i++) {
		struct worker_event in = event(WORKER_EV_BRIDGE_REMOVE, i);
		assert(worker_event_queue_push(&queue, &in));
	}
	for (i = WORKER_QUEUE_SIZE / 2; i < WORKER_QUEUE_SIZE * 3 / 2; i++) {
		assert(worker_event_queue_pop(&queue, &out));
		assert(out.bridge_idx == (int)i);
	}
	assert(!worker_event_queue_pop(&queue, &out));
}

static void test_reserve_and_coalescing(void)
{
	struct worker_event_queue queue;
	struct worker_event out;
	unsigned int i;

	worker_event_queue_init(&queue);
	for (i = 0; i < WORKER_QUEUE_SIZE - WORKER_CONTROL_RESERVE; i++) {
		struct worker_event in = event(WORKER_EV_BRIDGE_ADD, i);
		assert(worker_event_queue_push(&queue, &in));
	}
	assert(!worker_event_queue_push(&queue,
		&(struct worker_event) { .type = WORKER_EV_RECV_PACKET }));
	for (; i < WORKER_QUEUE_SIZE; i++) {
		struct worker_event in = event(WORKER_EV_BRIDGE_REMOVE, i);
		assert(worker_event_queue_push(&queue, &in));
	}
	assert(queue.count == WORKER_QUEUE_SIZE);

	worker_event_queue_init(&queue);
	assert(worker_event_queue_push(&queue,
		&(struct worker_event) { .type = WORKER_EV_RECV_PACKET }));
	assert(worker_event_queue_push(&queue,
		&(struct worker_event) { .type = WORKER_EV_RECV_PACKET }));
	assert(worker_event_queue_push(&queue,
		&(struct worker_event) { .type = WORKER_EV_BRIDGE_EVENT }));
	assert(queue.count == 2);
	assert(worker_event_queue_pop(&queue, &out));
	assert(out.type == WORKER_EV_RECV_PACKET && out.count == 1);
	assert(worker_event_queue_pop(&queue, &out));
	assert(out.type == WORKER_EV_BRIDGE_EVENT && out.count == 1);
}

static void test_tick_count(void)
{
	struct worker_event_queue queue;
	struct worker_event tick = event(WORKER_EV_ONE_SECOND, 0);
	struct worker_event out;
	unsigned int i;

	worker_event_queue_init(&queue);
	for (i = 0; i < 1000; i++)
		assert(worker_event_queue_push(&queue, &tick));
	assert(queue.count == 1);
	assert(worker_event_queue_pop(&queue, &out));
	assert(out.type == WORKER_EV_ONE_SECOND && out.count == 1000);

	worker_event_queue_init(&queue);
	tick.count = UINT_MAX;
	assert(worker_event_queue_push(&queue, &tick));
	queue.events[queue.head].count = UINT_MAX;
	assert(worker_event_queue_push(&queue, &tick));
	assert(worker_event_queue_pop(&queue, &out));
	assert(out.count == UINT_MAX);
}

int main(void)
{
	test_order_and_wraparound();
	test_reserve_and_coalescing();
	test_tick_count();
	return 0;
}
