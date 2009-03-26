#
# automake adds dependencies that we don't like, so we explicitly remove them
#
Makefile:

#
# We have a lot of files that we want shipped with the distribution.
#
EXTRA_DIST = RELNOTES LICENSE \
	     contrib/3.0b1-lease-convert contrib/dhclient-tz-exithook.sh \
	     contrib/dhcp.spec contrib/sethostname.sh contrib/solaris.init \
	     contrib/ms2isc/Registry.pm contrib/ms2isc/ms2isc.pl \
	     contrib/ms2isc/readme.txt \
	     doc/IANA-arp-parameters doc/Makefile doc/References.html \
	     doc/References.txt doc/References.xml doc/api+protocol \
	     doc/ja_JP.eucJP/dhclient-script.8 doc/ja_JP.eucJP/dhclient.8 \
	     doc/ja_JP.eucJP/dhclient.conf.5 doc/ja_JP.eucJP/dhclient.leases.5 \
	     doc/ja_JP.eucJP/dhcp-eval.5 doc/ja_JP.eucJP/dhcp-options.5

SUBDIRS = includes tests common minires dst omapip client dhcpctl relay server

nobase_include_HEADERS = dhcpctl/dhcpctl.h

