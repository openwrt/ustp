/*
 * driver.h    Driver-specific code.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 * Authors: Vitalii Demianets <dvitasgs@gmail.com>
 */

#ifndef _MSTP_DRIVER_H
#define _MSTP_DRIVER_H

#include "mstp.h"

static inline int
driver_set_new_state(per_tree_port_t *ptp, int new_state)
{
	return new_state;
}

static inline void
driver_flush_all_fids(per_tree_port_t *ptp)
{
    MSTP_IN_all_fids_flushed(ptp);
}

static inline unsigned int
driver_set_ageing_time(port_t *prt, unsigned int ageingTime)
{
	return ageingTime;
}

static inline bool
driver_create_msti(bridge_t *br, __u16 mstid)
{
	return true;
}

static inline bool
driver_delete_msti(bridge_t *br, __u16 mstid)
{
	return true;
}

static inline bool
driver_create_bridge(bridge_t *br, __u8 *macaddr)
{
	return true;
}

static inline bool
driver_create_port(port_t *prt, __u16 portno)
{
	return true;
}

static inline void driver_delete_bridge(bridge_t *br)
{
}

static inline void driver_delete_port(port_t *prt)
{
}

#endif /* _MSTP_DRIVER_H */
