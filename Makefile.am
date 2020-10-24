pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = secudp.pc

secudpincludedir=$(includedir)/secudp
secudpinclude_HEADERS = \
	include/secudp/callbacks.h \
	include/secudp/secudp.h \
	include/secudp/list.h \
	include/secudp/protocol.h \
	include/secudp/time.h \
	include/secudp/types.h \
	include/secudp/unix.h \
	include/secudp/utility.h \
	include/secudp/win32.h \
	include/secudp/crypto.h

lib_LTLIBRARIES = libsecudp.la
libsecudp_la_SOURCES = callbacks.c compress.c host.c list.c packet.c peer.c protocol.c unix.c win32.c crypto.c
# see info '(libtool) Updating version info' before making a release
libsecudp_la_LDFLAGS = $(AM_LDFLAGS) -version-info 7:4:0
AM_CPPFLAGS = -I$(top_srcdir)/include

ACLOCAL_AMFLAGS = -Im4
