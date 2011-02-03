localedir = $(datadir)/locale

INCLUDES = -DLOCALEDIR=\"$(localedir)\"

sbin_PROGRAMS = \
	ucarp

ucarp_SOURCES = \
	gettext.h \
	ucarp.c \
	ucarp.h \
	carp.c \
	carp_p.h \
	ucarp_p.h \
	ip_carp.h \
	crypto-sha1.c \
	crypto.h \
	crypto-sha1.h \
	globals.h \
	fillmac.c \
	fillmac.h \
	bsd-getopt_long.h \
	bsd-getopt_long.c \
	garp.c \
	garp.h \
	spawn.c \
	spawn.h \
	fakesnprintf.c \
	fakesnprintf.h \
	mysnprintf.c \
	mysnprintf.h \
	log.c \
	log.h \
	daemonize.c \
	daemonize.h \
	syslognames.h

ucarp_LDADD = \
	$(LTLIBINTL)

