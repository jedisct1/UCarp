#ifndef __UCARP_H__
#define __UCARP_H__ 1

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
# include <stdarg.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#else
# if HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <limits.h>
#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <signal.h>
#include <sys/types.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#elif defined(HAVE_SYS_FCNTL_H)
# include <sys/fcntl.h>
#endif
#ifdef HAVE_IOCTL_H
# include <ioctl.h>
#elif defined(HAVE_SYS_IOCTL_H)
# include <sys/ioctl.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <arpa/inet.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <poll.h>
#include <pcap.h>

#ifdef __sun__
# define u_int8_t uint8_t
# define u_int16_t uint16_t
# define u_int32_t uint32_t
# define u_int64_t uint64_t
# define ether_shost ether_shost.ether_addr_octet
# define ether_dhost ether_dhost.ether_addr_octet
#endif

#include "gettext.h"
#define  _(txt) gettext(txt)
#define N_(txt) txt

#include "mysnprintf.h"
#include "crypto.h"
#ifndef USE_SYSTEM_CRYPT_SHA1
# include "crypto-sha1.h"
#else
# include <sha1.h>
#endif
#include "ip_carp.h"

#ifndef errno
extern int errno;
#endif

#ifdef HAVE_ALLOCA
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# endif
# define ALLOCA(X) alloca(X)
# define ALLOCA_FREE(X) do { } while (0)
#else
# define ALLOCA(X) malloc(X)
# define ALLOCA_FREE(X) free(X)
#endif

#ifdef DEFINE_GLOBALS
# define SYSLOG_NAMES    1        /* for -f */
#endif
#include <syslog.h>
#ifndef HAVE_SYSLOG_NAMES
# include "syslognames.h"
#endif
#ifndef MAX_SYSLOG_LINE
# define MAX_SYSLOG_LINE 4096U
#endif

#ifndef __GNUC__
# define __packed__
#endif

#define _COMA_ ,

#define ETHERNET_MTU 1500
#ifndef ETHER_ADDR_LEN
# define ETHER_ADDR_LEN 6
#endif
#ifndef IPPROTO_CARP
# define IPPROTO_CARP 112
#endif
#ifndef timercmp
# define timercmp(tvp, uvp, cmp) \
        (((tvp)->tv_sec == (uvp)->tv_sec) ? \
             ((tvp)->tv_usec cmp (uvp)->tv_usec) : \
             ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef HAVE_SETEUID
# ifdef HAVE_SETREUID
#  define seteuid(X) setreuid(-1, (X))
# elif defined(HAVE_SETRESUID)
#  define seteuid(X) setresuid(-1, (X), -1)
# else
#  define seteuid(X) (-1)
# endif
#endif
#ifndef HAVE_SETEGID
# ifdef HAVE_SETREGID
#  define setegid(X) setregid(-1, (X))
# elif defined(HAVE_SETRESGID)
#  define setegid(X) setresgid(-1, (X), -1)
# else
#  define setegid(X) (-1)
# endif
#endif

#ifndef HAVE_STRTOULL
# ifdef HAVE_STRTOQ
#  define strtoull(X, Y, Z) strtoq(X, Y, Z)
# else
#  define strtoull(X, Y, Z) strtoul(X, Y, Z)
# endif
#endif

#ifndef ULONG_LONG_MAX
# define ULONG_LONG_MAX (1ULL << 63)
#endif

#ifdef WITH_DMALLOC
# define _exit(X) exit(X)
#endif

#define CAPTURE_TIMEOUT 1000

#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

struct carp_softc {
    int if_flags;                       /* current flags to treat UP/DOWN */
    struct ifnet *sc_ifp;
    struct in_ifaddr *sc_ia;    /* primary iface address */
#ifdef INET6
    struct in6_ifaddr *sc_ia6;  /* primary iface address v6 */
    struct ip6_moptions sc_im6o;
#endif /* INET6 */
    
    enum { INIT = 0, BACKUP, MASTER }   sc_state;

    int sc_flags_backup;
    int sc_suppress;
    
    int sc_sendad_errors;
#define CARP_SENDAD_MAX_ERRORS  3
    int sc_sendad_success;
#define CARP_SENDAD_MIN_SUCCESS 3
    
    int sc_vhid;
    int sc_advskew;
    int sc_naddrs;
    int sc_naddrs6;
    int sc_advbase;             /* seconds */
    int sc_init_counter;
    u_int64_t sc_counter;
    int sc_delayed_arp;
    
    /* authentication */
#define CARP_HMAC_PAD   64
    unsigned char sc_key[CARP_KEY_LEN];
    unsigned char sc_pad[CARP_HMAC_PAD];
    SHA1_CTX sc_sha1;
    
    struct timeval sc_ad_tmo;   /* advertisement timeout */
    struct timeval sc_md_tmo;   /* master down timeout */
    struct timeval sc_md6_tmo;  /* master down timeout */
};

#define CARP_AUTHLEN 7
#define DEFAULT_ADVBASE 1U
#define DEFAULT_DEAD_RATIO 3U
#define SECONDS_TO_WAIT_AFTER_INTERFACE_IS_DOWN 10U

#define DEFAULT_FACILITY LOG_DAEMON

int docarp(void);

#include "globals.h"

#endif
