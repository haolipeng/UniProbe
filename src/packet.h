#ifndef NET_THREAT_DETECT_PACKET_H
#define NET_THREAT_DETECT_PACKET_H

#include "common.h"

packet_context_t *acs_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch);
static packet_context_t *acs_lookup_context(struct cds_hlist_head *list, const char *name);
void acs_get_stats(packet_context_t *ctx);
int net_run(const char *in_iface);

#endif // NET_THREAT_DETECT_PACKET_DEFINE_H
