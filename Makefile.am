pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = SecUdp.pc

SecUdpincludedir=$(includedir)/SecUdp
SecUdpinclude_HEADERS = \
	include/SecUdp/callbacks.h \
	include/SecUdp/SecUdp.h \
	include/SecUdp/list.h \
	include/SecUdp/protocol.h \
	include/SecUdp/time.h \
	include/SecUdp/types.h \
	include/SecUdp/unix.h \
	include/SecUdp/utility.h \
	include/SecUdp/win32.h

lib_LTLIBRARIES = SecUdp.la
SecUdp_la_SOURCES = callbacks.c compress.c host.c list.c packet.c peer.c protocol.c unix.c win32.c
# see info '(libtool) Updating version info' before making a release
SecUdp_la_LDFLAGS = $(AM_LDFLAGS) -version-info 7:4:0
AM_CPPFLAGS = -I$(top_srcdir)/include

ACLOCAL_AMFLAGS = -Im4
