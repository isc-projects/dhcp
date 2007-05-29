bin_PROGRAMS = omshell
lib_LIBRARIES = libdhcpctl.a
noinst_PROGRAMS = cltest
man_MANS = omshell.1 dhcpctl.3
EXTRA_DIST = $(man_MANS)

omshell_SOURCES = omshell.c
omshell_LDADD = libdhcpctl.a ../common/libdhcp.a ../minires/libres.a \
                ../omapip/libomapi.a ../dst/libdst.a

libdhcpctl_a_SOURCES = dhcpctl.c callback.c remote.c

cltest_SOURCES = cltest.c
cltest_LDADD = libdhcpctl.a ../common/libdhcp.a ../minires/libres.a \
               ../omapip/libomapi.a ../dst/libdst.a
