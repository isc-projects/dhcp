AM_CPPFLAGS = -DLOCALSTATEDIR='"@localstatedir@"'

sbin_PROGRAMS = dhcrelay
dhcrelay_SOURCES = dhcrelay.c
dhcrelay_LDADD = ../common/libdhcp.a ../omapip/libomapi.a \
		 @BINDLIBIRSDIR@/libirs.a \
		 @BINDLIBDNSDIR@/libdns.a \
		 @BINDLIBISCCFGDIR@/libisccfg.a \
		 @BINDLIBISCDIR@/libisc.a
man_MANS = dhcrelay.8
EXTRA_DIST = $(man_MANS)

