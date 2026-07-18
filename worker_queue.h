/*
 * ustp - OpenWrt STP/RSTP/MSTP daemon
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.
 */
#ifndef __WORKER_QUEUE_H
#define __WORKER_QUEUE_H

#include "worker.h"

struct worker_event_queue {
	struct worker_event events[WORKER_QUEUE_SIZE];
	unsigned int head;
	unsigned int count;
};

void worker_event_queue_init(struct worker_event_queue *queue);
bool worker_event_queue_push(struct worker_event_queue *queue,
			     const struct worker_event *event);
bool worker_event_queue_pop(struct worker_event_queue *queue,
			    struct worker_event *event);

#endif
