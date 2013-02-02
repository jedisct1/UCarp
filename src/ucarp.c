
#define DEFINE_GLOBALS 1

#include <config.h>
#include "ucarp.h"
#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include "log.h"
#include "daemonize.h"
#include "ucarp_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void usage(void)
{
    puts("\n" PACKAGE_STRING " - " __DATE__ "\n");
    fputs(_(
        "--interface=<if> (-i <if>): bind interface <if>\n"
        "--srcip=<ip> (-s <ip>): source (real) IP address of that host\n"
        "--mcast=<ip> (-m <ip>): multicast group IP address (default 224.0.0.18)\n"
        "--vhid=<id> (-v <id>): virtual IP identifier (1-255)\n"
        "--pass=<pass> (-p <pass>): password\n"
        "--passfile=<file> (-o <file>): read password from file\n"
        "--preempt (-P): becomes a master as soon as possible\n"
        "--neutral (-n): don't run downscript at start if backup\n"
        "--addr=<ip> (-a <ip>): virtual shared IP address\n"
        "--help (-h): summary of command-line options\n"
        "--advbase=<seconds> (-b <seconds>): advertisement frequency\n"
        "--advskew=<skew> (-k <skew>): advertisement skew (0-255)\n"
        "--upscript=<file> (-u <file>): run <file> to become a master\n"
        "--downscript=<file> (-d <file>): run <file> to become a backup\n"
        "--deadratio=<ratio> (-r <ratio>): ratio to consider a host as dead\n"
        "--debug (-D: enable debug output\n"
        "--shutdown (-z): call shutdown script at exit\n"
        "--daemonize (-B): run in background\n"
        "--ignoreifstate (-S): ignore interface state (down, no carrier)\n"
        "--nomcast (-M): use broadcast (instead of multicast) advertisements\n"
        "--facility=<facility> (-f): set syslog facility (default=daemon)\n"
        "--xparam=<value> (-x): extra parameter to send to up/down scripts\n"       
        "\n"
        "Sample usage:\n"
        "\n"
        "Manage the 10.1.1.252 shared virtual address on interface eth0, with\n"
        "1 as a virtual address idenfitier, mypassword as a password, and\n"
        "10.1.1.1 as a real permanent address for this host.\n"
        "Call /etc/vip-up.sh when the host becomes a master, and\n"
        "/etc/vip-down.sh when the virtual IP address has to be disabled.\n"
        "\n"
        "ucarp --interface=eth0 --srcip=10.1.1.1 --vhid=1 --pass=mypassword \\\n"
        "      --addr=10.1.1.252 \\\n"
        "      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh\n"
        "\n\n"    
        "Please report bugs to "), stdout);
    puts(PACKAGE_BUGREPORT ".\n");
    
    exit(EXIT_SUCCESS);
}

static void init_rand(void)
{
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#elif defined(HAVE_RANDOM)
    srandom((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#else
    srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#endif    
}

static void die_mem(void)
{
    logfile(LOG_ERR, _("Out of memory"));
    
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int option_index = 0;
    int fodder;
    
#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
    
    if (argc <= 1) {
        usage();
    }        
    inet_pton(AF_INET, DEFAULT_MCASTIP, &mcastip);
    while ((fodder = getopt_long(argc, argv, GETOPT_OPTIONS, long_options,
                                 &option_index)) != -1) {
        switch (fodder) {
        case 'h': {
            usage();
        }
        case 'i': {
            free(interface);
            if ((interface = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;            
        }
        case 's': {
            if (inet_pton(AF_INET, optarg, &srcip) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            break;
        }
        case 'm': {
            if (inet_pton(AF_INET, optarg, &mcastip) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            break;            
        }
        case 'v': {
            vhid = (unsigned char) strtoul(optarg, NULL, 0);
            break;            
        }       
        case 'p': {
            free(pass);
            if ((pass = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;            
        }
        case 'o': {
            char buf[512U];
            char *p;
            FILE *pw;
            if ((pw = fopen(optarg, "r")) == NULL) {
                logfile(LOG_ERR,
                        _("unable to open passfile %s for reading: %s"),
                        optarg, strerror(errno));
                return 1;
            }
            if (fgets(buf, sizeof buf, pw) == NULL) {
                logfile(LOG_ERR, _("error reading passfile %s: %s"), optarg,
                        ferror(pw) ?
                        strerror(errno) : _("unexpected end of file"));
                return 1;
            }
            fclose(pw);
            p = strchr(buf, '\n');
            if (p != NULL) {
                *p = 0;
            }
            if ((pass = strdup(buf)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'P': {
            preempt = 1;
            break;
        }
        case 'n': {
            neutral = 1;
            break;
        }
        case 'a': {
            free(vaddr_arg);
            if (inet_pton(AF_INET, optarg, &vaddr) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            vaddr_arg = strdup(optarg);
            break;
        }
        case 'b': {
            advbase = (unsigned char) strtoul(optarg, NULL, 0);
            break;            
        }
        case 'k': {
            advskew = (unsigned char) strtoul(optarg, NULL, 0);            
            break;            
        }
        case 'd': {
            free(downscript);
            if ((downscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'D': {
            debug = 1;
            break;
        }
        case 'u': {
            free(upscript);
            if ((upscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'r': {
            dead_ratio = (unsigned int) strtoul(optarg, NULL, 0);
            break;
        }
        case 'z': {
            shutdown_at_exit = 1;
            break;
        }
        case 'B': {
            daemonize = 1;
            break;
        }
        case 'S': {
            ignoreifstate = 1;
            break;
        }
        case 'f': {
            int n = 0;
            
            if (strcasecmp(optarg, "none") == 0) {
                no_syslog = 1;
                break;
            }
            while (facilitynames[n].c_name &&
                   strcasecmp(facilitynames[n].c_name, optarg) != 0) {
                n++;
            }
            if (facilitynames[n].c_name) {
                syslog_facility = facilitynames[n].c_val;
            } else {
                logfile(LOG_ERR, _("Unknown syslog facility: [%s]"), optarg);
            }
            break;
        }
        case 'x': {
            free(xparam);
            if ((xparam = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'M': {
            no_mcast = 1;
            break;
        }
        default: {
            usage();
        }
        }
    }
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        openlog("ucarp", LOG_PID, syslog_facility);
    }
#endif    
    if (interface == NULL || *interface == 0) {        
        interface = pcap_lookupdev(NULL);
        if (interface == NULL || *interface == 0) {
            logfile(LOG_ERR, _("You must supply a network interface"));
            return 1;
        }
        logfile(LOG_INFO, _("Using [%s] as a network interface"), interface);
    }
    if (vhid == 0) {
        logfile(LOG_ERR, _("You must supply a valid virtual host id"));
        return 1;
    }
    if (pass == NULL || *pass == 0) {
        logfile(LOG_ERR, _("You must supply a password"));
        return 1;
    }
    if (advbase == 0 && advskew == 0) {
        logfile(LOG_ERR, _("You must supply an advertisement time base"));
        return 1;
    }
    if (srcip.s_addr == 0) {
        logfile(LOG_ERR, _("You must supply a persistent source address"));
        return 1;
    }
    if (vaddr.s_addr == 0) {
        logfile(LOG_ERR, _("You must supply a virtual host address"));
        return 1;
    }
    if (upscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going up"));
    }
    if (downscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going down"));
    }
    if (dead_ratio <= 0U) {
        logfile(LOG_ERR, _("Dead ratio can't be zero"));
        return 1;
    }
    dodaemonize();
    init_rand();
    if (docarp() != 0) {
        return 2;
    }
    
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        closelog();
    }
#endif    
    
    return 0;
}
