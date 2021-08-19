/*****************************************************************************
  Copyright (c) 2006 EMC Corporation.
  Copyright (c) 2011 Factor-SPE

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.

  The full GNU General Public License is included in this distribution in the
  file called LICENSE.

  Authors: Srinivas Aji <Aji_Srinivas@emc.com>
  Authors: Vitalii Demianets <dvitasgs@gmail.com>

******************************************************************************/

/* #define MISC_TEST_FUNCS */

#include <config.h>

#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <libubox/uloop.h>

#include "bridge_ctl.h"
#include "netif_utils.h"
#include "packet.h"
#include "log.h"
#include "mstp.h"
#include "driver.h"
#include "bridge_track.h"
#include "worker.h"
#include "ubus.h"

#define APP_NAME	"ustpd"

static int print_to_syslog = 1;
int log_level = LOG_LEVEL_DEFAULT;


int main(int argc, char *argv[])
{
	int c;

	while((c = getopt(argc, argv, "sv:")) != -1) {
		switch (c) {
		case 's':
			print_to_syslog = 0;
			break;
		case 'v': {
			char *end;
			long l;
			l = strtoul(optarg, &end, 0);
			if(*optarg == 0 || *end != 0 || l > LOG_LEVEL_MAX) {
				ERROR("Invalid loglevel %s", optarg);
				exit(1);
			}
			log_level = l;
			break;
		}
		default:
			return -1;
		}
	}

	if (print_to_syslog)
		openlog(APP_NAME, LOG_PID, LOG_DAEMON);

	uloop_init();

	TST(worker_init() == 0, -1);
	TST(packet_sock_init() == 0, -1);
	TST(netsock_init() == 0, -1);
	TST(init_bridge_ops() == 0, -1);
	ustp_ubus_init();

	uloop_run();
	bridge_track_fini();
	worker_cleanup();
	ustp_ubus_exit();
	uloop_done();

	return 0;
}

/*********************** Logging *********************/

#include <stdarg.h>
#include <time.h>

static void vDprintf(int level, const char *fmt, va_list ap)
{
	if(level > log_level)
		return;

	if(!print_to_syslog)
	{
		char logbuf[256];
		logbuf[255] = 0;
		time_t clock;
		struct tm *local_tm;
		time(&clock);
		local_tm = localtime(&clock);
		int l = strftime(logbuf, sizeof(logbuf) - 1, "%F %T ", local_tm);
		vsnprintf(logbuf + l, sizeof(logbuf) - l - 1, fmt, ap);
		printf("%s\n", logbuf);
		fflush(stdout);
	}
	else
	{
		vsyslog((level <= LOG_LEVEL_INFO) ? LOG_INFO : LOG_DEBUG, fmt, ap);
	}
}

void Dprintf(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vDprintf(level, fmt, ap);
	va_end(ap);
}
