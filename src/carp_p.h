#ifndef __CARP_P_H__
#define __CARP_P_H__ 1

static struct carp_softc sc;
static struct timeval now;
static pcap_t *dev_desc;
static int dev_desc_fd = -1;
static int carp_suppress_preempt;

static void carp_send_ad_all(struct carp_softc *sc);

#endif
