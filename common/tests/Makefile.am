SUBDIRS = .

AM_CPPFLAGS = $(ATF_CFLAGS) -I$(top_srcdir)/includes

ATF_TESTS = alloc_unittest hash_unittest

check_PROGRAMS = $(ATF_TESTS)

alloc_unittest_SOURCES = test_alloc.c $(top_srcdir)/tests/t_api_dhcp.c
alloc_unittest_LDADD = $(ATF_LDFLAGS)
alloc_unittest_LDADD += ../libdhcp.a  \
	../../omapip/libomapi.a ../../bind/lib/libdns.a \
        ../../bind/lib/libisc.a


hash_unittest_SOURCES = hash_unittest.c $(top_srcdir)/tests/t_api_dhcp.c
hash_unittest_LDADD = $(ATF_LDFLAGS)
hash_unittest_LDADD += ../libdhcp.a  \
	../../omapip/libomapi.a ../../bind/lib/libdns.a \
        ../../bind/lib/libisc.a

check: $(ATF_TESTS)
	atf-run | atf-report
