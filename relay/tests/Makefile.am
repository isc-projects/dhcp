SUBDIRS = .

AM_CPPFLAGS = $(ATF_CFLAGS) -DUNIT_TEST -I$(top_srcdir)/includes
AM_CPPFLAGS += -DLOCALSTATEDIR='"."'

EXTRA_DIST = Atffile

# for autotools debugging only
info:
	@echo "ATF_CFLAGS=$(ATF_CFLAGS)"
	@echo "ATF_LDFLAGS=$(ATF_LDFLAGS)"
	@echo "ATF_LIBS=$(ATF_LIBS)"

DHCPSRC = ../dhcrelay.c

DHCPLIBS = $(top_builddir)/common/libdhcp.a \
	  $(top_builddir)/omapip/libomapi.a \
	  $(top_builddir)/dst/libdst.a \
	  $(top_builddir)/minires/libres.a

ATF_TESTS =
if HAVE_ATF

ATF_TESTS += relay_unittests

relay_unittests_SOURCES = $(DHCPSRC)
relay_unittests_SOURCES += relay_unittests.c

relay_unittests_LDADD = $(ATF_LDFLAGS)
relay_unittests_LDADD += $(DHCPLIBS)

check: $(ATF_TESTS)
	@if test $(top_srcdir) != ${top_builddir}; then \
		cp $(top_srcdir)/relay/tests/Atffile Atffile; \
	fi
	sh ${top_builddir}/tests/unittest.sh

distclean-local:
	@if test $(top_srcdir) != ${top_builddir}; then \
		rm -f Atffile;
	fi

endif

check_PROGRAMS = $(ATF_TESTS)
