#include <config.h>
#include "ucarp.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static unsigned int open_max(void)
{
    long z;
    
    if ((z = (long) sysconf(_SC_OPEN_MAX)) < 0L) {
        logfile(LOG_ERR, "_SC_OPEN_MAX");
        _exit(EXIT_FAILURE);
    }
    return (unsigned int) z;
}

static int closedesc_all(const int closestdin)
{
    int fodder;
    
    if (closestdin != 0) {
        (void) close(0);
        if ((fodder = open("/dev/null", O_RDONLY)) == -1) {
            return -1;
        }
        (void) dup2(fodder, 0);
        if (fodder > 0) {
            (void) close(fodder);
        }
    }
    if ((fodder = open("/dev/null", O_WRONLY)) == -1) {
        return -1;
    }
    (void) dup2(fodder, 1);
    (void) dup2(1, 2);
    if (fodder > 2) {
        (void) close(fodder);
    }    
    return 0;
}

void dodaemonize(void)
{ 
    pid_t child;
    unsigned int i;

    /* Contributed by Jason Lunz - also based on APUI code, see open_max() */
    if (daemonize != 0) {
        if ((child = fork()) == (pid_t) -1) {
            logfile(LOG_ERR, _("Unable to get in background: [fork: %s]"),
                    strerror(errno));
            return;
        } else if (child != (pid_t) 0) {
            _exit(EXIT_SUCCESS);       /* parent exits */
        }         
        if (setsid() == (pid_t) -1) {
            logfile(LOG_WARNING,
                    _("Unable to detach from the current session: %s"),
                    strerror(errno));  /* continue anyway */
        }
        chdir("/");
        i = open_max();        
        do {
            if (isatty((int) i)) {
                (void) close((int) i);
            }
            i--;
        } while (i > 2U);
        if (closedesc_all(1) != 0) {
            logfile(LOG_ERR,
                    _("Unable to detach: /dev/null can't be duplicated"));
            _exit(EXIT_FAILURE);
        }
    }
}

