#include <config.h>
#include "ucarp.h"
#include "fillmac.h"
#include <sys/ioctl.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#ifdef HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#ifdef HAVE_NET_IF_TYPES_H
# include <net/if_types.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#ifndef HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#ifdef PF_PACKET
# define HWINFO_DOMAIN PF_PACKET
#else
# define HWINFO_DOMAIN PF_INET
#endif
#ifdef SOCK_PACKET
# define HWINFO_TYPE SOCK_PACKET
#else
# define HWINFO_TYPE SOCK_DGRAM
#endif   

int fill_mac_address(void)
{
    int s;

    if ((s = socket(HWINFO_DOMAIN, HWINFO_TYPE, 0)) == -1) {
        logfile(LOG_ERR, _("Unable to open raw device: [%s]"),
                strerror(errno));
        return -1;
    }
#ifdef SIOCGIFHWADDR
    {
        struct ifreq ifr;
        
        if (strlen(interface) >= sizeof ifr.ifr_name) {
            logfile(LOG_ERR, _("Interface name too long"));
            return -1;
        }
        strncpy(ifr.ifr_name, interface, sizeof ifr.ifr_name);
        if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) {
            logfile(LOG_ERR,
                    _("Unable to get hardware info about an interface: %s"),
                    strerror(errno));
            (void) close(s);
            return -1;
        }
        switch (ifr.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
        case ARPHRD_IEEE802:
            break;
        default:
            logfile(LOG_ERR, _("Unknown hardware type [%u]"),
                    (unsigned int) ifr.ifr_hwaddr.sa_family);
        }
        memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, sizeof hwaddr);
    }
#elif defined(HAVE_GETIFADDRS)
    {   
        struct ifaddrs *ifas;
        struct ifaddrs *ifa;
        struct sockaddr_dl *sadl;
        struct ether_addr *ea;
        
        if (getifaddrs(&ifas) != 0) {
            logfile(LOG_ERR, _("Unable to get interface address: %s"),
                    strerror(errno));
            return -1;
        }
        ifa = ifas;
        while (ifa != NULL) {
            if (strcmp(ifa->ifa_name, interface) == 0 &&
                ifa->ifa_addr->sa_family == AF_LINK) {
                sadl = (struct sockaddr_dl *) ifa->ifa_addr;
                if (sadl == NULL || sadl->sdl_type != IFT_ETHER ||
                    sadl->sdl_alen <= 0) {
                    logfile(LOG_ERR,
                            _("Invalid media / hardware address for [%s]"),
                            interface);
                    return -1;
                }
                ea = (struct ether_addr *) LLADDR(sadl);
                memcpy(hwaddr, ea, sizeof hwaddr);
                
                return 0;
            }
            ifa = ifa->ifa_next;
        }
        return -1;
    }
#elif defined(SIOCGLIFNUM)
    {
        struct lifconf lifc;
        struct lifnum lifn;
        struct lifreq *lifr;
        caddr_t *lifrspace;
        struct arpreq arpreq;
        
        lifn.lifn_flags = 0;
        lifn.lifn_family = AF_INET;
        if (ioctl(s, SIOCGLIFNUM, &lifn) < 0) {
            logfile(LOG_ERR, _("ioctl SIOCGLIFNUM error"));
            return -1;
        }
        if (lifn.lifn_count <= 0) {
            logfile(LOG_ERR, _("No interface found"));
            return -1;            
        }
        lifc.lifc_family = lifn.lifn_family;
        lifc.lifc_len = lifn.lifn_count * sizeof *lifr;
        lifrspace = ALLOCA(lifc.lifc_len);
        lifc.lifc_buf = (caddr_t) lifrspace;
        if (ioctl(s, SIOCGLIFCONF, &lifc) < 0) {
            logfile(LOG_ERR, _("ioctl SIOCGLIFCONF error"));
            ALLOCA_FREE(lifrspace);
            return -1;
        }        
        lifr = lifc.lifc_req;
	for(;;) {
	    if (lifn.lifn_count <= 0) {
		logfile(LOG_ERR, _("Interface [%s] not found"), interface);
		ALLOCA_FREE(lifrspace);
		return -1;            		
	    }
	    lifn.lifn_count--;
            if (strcmp(lifr->lifr_name, interface) == 0) {
                break;
            }	   
            lifr++;
        }
        memcpy(&arpreq.arp_pa, &lifr->lifr_addr, sizeof arpreq.arp_pa);
        ALLOCA_FREE(lifrspace);
        if (ioctl(s, SIOCGARP, &arpreq) != 0) {
            logfile(LOG_ERR, _("Unable to get hardware info about [%s]"),
                    interface);
            return -1;
        }       
        memcpy(hwaddr, &arpreq.arp_ha.sa_data, sizeof hwaddr);
    }
#endif
    
    (void) close(s);    
    
    return 0;
}
