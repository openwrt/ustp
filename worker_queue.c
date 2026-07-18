/*
 * ustp - OpenWrt STP/RSTP/MSTP daemon
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.
 */
#include <limits.h>
#include <string.h>

#include "worker_queue.h"

static bool worker_event_is_background(enum worker_event_type type)
{
	return type == WORKER_EV_RECV_PACKET ||
	       type == WORKER_EV_BRIDGE_EVENT ||
	       type == WORKER_EV_ONE_SECOND;
}

static int worker_event_queue_find(const struct worker_event_queue *queue,
				   enum worker_event_type type)
{
	unsigned int i;

	for (i = 0; i < queue->count; i++) {
		unsigned int pos = (queue->head + i) % WORKER_QUEUE_SIZE;

		if (queue->events[pos].type == type)
			return pos;
	}

	return -1;
}

void worker_event_queue_init(struct worker_event_queue *queue)
{
	memset(queue, 0, sizeof(*queue));
}

bool worker_event_queue_push(struct worker_event_queue *queue,
			     const struct worker_event *event)
{
	unsigned int limit = WORKER_QUEUE_SIZE;
	unsigned int pos;
	int pending;

	if (worker_event_is_background(event->type)) {
		pending = worker_event_queue_find(queue, event->type);
		if (pending >= 0) {
			if (event->type == WORKER_EV_ONE_SECOND &&
			    queue->events[pending].count < UINT_MAX)
				queue->events[pending].count++;
			return true;
		}
		limit -= WORKER_CONTROL_RESERVE;
	}

	if (queue->count >= limit)
		return false;

	pos = (queue->head + queue->count) % WORKER_QUEUE_SIZE;
	queue->events[pos] = *event;
	queue->events[pos].count = 1;
	queue->count++;

	return true;
}

bool worker_event_queue_pop(struct worker_event_queue *queue,
			    struct worker_event *event)
{
	if (!queue->count)
		return false;

	*event = queue->events[queue->head];
	queue->head = (queue->head + 1) % WORKER_QUEUE_SIZE;
	queue->count--;

	return true;
}
