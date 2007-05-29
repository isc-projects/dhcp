AM_CPPFLAGS = -I.. -DLOCALSTATEDIR='"@localstatedir@"'

dist_sysconf_DATA = dhcpd.conf
sbin_PROGRAMS = dhcpd
dhcpd_SOURCES = dhcpd.c dhcp.c bootp.c confpars.c db.c class.c failover.c \
		omapi.c mdb.c stables.c salloc.c ddns.c dhcpleasequery.c \
		dhcpv6.c mdb6.c

# libomapi.a this is here twice to handle circular library dependencies :(
dhcpd_LDADD = ../common/libdhcp.a ../omapip/libomapi.a ../dst/libdst.a \
	      ../dhcpctl/libdhcpctl.a ../minires/libres.a \
	      ../omapip/libomapi.a

man_MANS = dhcpd.8 dhcpd.conf.5 dhcpd.leases.5
EXTRA_DIST = $(man_MANS)

