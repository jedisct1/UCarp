#include <config.h>
#include "ucarp.h"
#include "garp.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

int gratuitous_arp(const int dev_desc_fd)
{
    struct ether_header eh;
    static unsigned char arp[28] = {
            0x00, 0x01,   /* MAC address type */
            0x08, 0x00,   /* Protocol address type */
            0x06, 0x04,   /* MAC address size, protocol address size */
            0x00, 0x01,   /* OP (1=request, 2=reply) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* Sender MAC */
            0x00, 0x00, 0x00, 0x00,               /* Sender IP */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   /* Target MAC */
            0xff, 0xff, 0xff, 0xff                /* Target IP */
    };    
    unsigned char *pkt;
    int rc;

    if (ETHER_ADDR_LEN > 6) {
	abort();
    }

    /*
     * - Gratuitous ARPs should use requests for the highest interoperability.
     * - Target MAC and IP should match sender
     * http://www1.ietf.org/mail-archive/web/dhcwg/current/msg03797.html
     * http://en.wikipedia.org/wiki/Address_Resolution_Protocol
     * http://ettercap.sourceforge.net/forum/viewtopic.php?t=2392
     * http://wiki.ethereal.com/Gratuitous_ARP
     */
    arp[7] = 0x01;                                 /* request op */
    memcpy(&arp[8], hwaddr, sizeof hwaddr);        /* Sender MAC */
    memcpy(&arp[14], &vaddr.s_addr, (size_t) 4U);  /* Sender IP */
    memcpy(&arp[18], hwaddr, sizeof hwaddr);       /* Target MAC */
    memcpy(&arp[24], &vaddr.s_addr, (size_t) 4U);  /* Target IP */

    memset(&eh, 0, sizeof eh);
    memcpy(&eh.ether_shost, hwaddr, sizeof hwaddr);
    memset(&eh.ether_dhost, 0xff, ETHER_ADDR_LEN);
    eh.ether_type = htons(ETHERTYPE_ARP);

    if ((pkt = ALLOCA(sizeof eh + sizeof arp)) == NULL) {
        logfile(LOG_ERR, _("out of memory to send gratuitous ARP"));
        return -1;
    }
    memcpy(pkt, &eh, sizeof eh);
    memcpy(pkt + sizeof eh, arp, sizeof arp);

    do {
	rc = write(dev_desc_fd, pkt, sizeof eh + sizeof arp);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        logfile(LOG_ERR, _("write() in garp: %s"), strerror(errno));
        ALLOCA_FREE(pkt);
        return -1;
    }
    ALLOCA_FREE(pkt);
    
    return 0;
}
