#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include "mstp.h"

int log_level;

void Dprintf(int level, const char *fmt, ...);
void Dprintf(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

void hmac_md5(unsigned char *text, int text_len, unsigned char *key,
	      int key_len, caddr_t digest)
{
	(void)text;
	(void)text_len;
	(void)key;
	(void)key_len;
	memset(digest, 0, 16);
}

void MSTP_OUT_set_state(per_tree_port_t *ptp, int new_state)
{
	ptp->state = new_state;
}

void MSTP_OUT_flush_all_fids(per_tree_port_t *ptp)
{
	MSTP_IN_all_fids_flushed(ptp);
}

void MSTP_OUT_set_ageing_time(port_t *prt, unsigned int ageing_time)
{
	(void)prt;
	(void)ageing_time;
}

void MSTP_OUT_tx_bpdu(port_t *prt, bpdu_t *bpdu, int size)
{
	(void)prt;
	(void)bpdu;
	(void)size;
}

void MSTP_OUT_shutdown_port(port_t *prt)
{
	(void)prt;
}

static void assert_priority(const bridge_identifier_t *id, unsigned int step)
{
	assert(GET_PRIORITY_FROM_IDENTIFIER(*id) == step << 4);
}

int main(void)
{
	const __u8 mac[ETH_ALEN] = { 0x60, 0xbe, 0xb4, 0x15, 0x16, 0xc0 };
	bridge_t br = {};
	port_t *port;
	tree_t *cist;
	per_tree_port_t *ptp;
	CIST_BridgeStatus status;
	unsigned int priorities[] = { 0, 1, 8, 15 };
	unsigned int i;

	strcpy(br.sysdeps.name, "br-test");
	assert(MSTP_IN_bridge_create(&br, (__u8 *)mac));
	port = calloc(1, sizeof(*port));
	assert(port);
	port->bridge = &br;
	strcpy(port->sysdeps.name, "eth-test");
	assert(MSTP_IN_port_create_and_add_tail(port, 1));
	cist = GET_CIST_TREE(&br);
	ptp = GET_CIST_PTP_FROM_PORT(port);

	for (i = 0; i < sizeof(priorities) / sizeof(priorities[0]); i++) {
		assert(MSTP_IN_set_cist_bridge_priority(&br, priorities[i]) == 0);
		MSTP_IN_get_cist_bridge_status(&br, &status);
		assert_priority(&status.bridge_id, priorities[i]);
		assert_priority(&cist->BridgePriority.RootID, priorities[i]);
		assert_priority(&cist->BridgePriority.RRootID, priorities[i]);
		assert_priority(&cist->BridgePriority.DesignatedBridgeID,
				priorities[i]);
		assert(!memcmp(status.bridge_id.s.mac_address, mac, ETH_ALEN));
		assert(ptp->reselect);
		assert(!ptp->selected);
	}
	assert(MSTP_IN_set_cist_bridge_priority(&br, 16) == -1);
	assert_priority(&cist->BridgeIdentifier, 15);

	MSTP_IN_set_bridge_enable(&br, true);
	assert(MSTP_IN_set_cist_bridge_priority(&br, 1) == 0);
	assert_priority(&cist->BridgeIdentifier, 1);
	assert_priority(&cist->rootPriority.RootID, 1);
	assert_priority(&ptp->designatedPriority.DesignatedBridgeID, 1);
	assert(ptp->selected);
	assert(!ptp->reselect);

	MSTP_IN_delete_bridge(&br);
	return 0;
}
