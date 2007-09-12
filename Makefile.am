#
# automake adds dependencies that we don't like, so we explicitly remove them
#
Makefile:

#
# We have a lot of files that we want shipped with the distribution.
#
EXTRA_DIST = RELNOTES \
	     contrib/3.0b1-lease-convert contrib/dhclient-tz-exithook.sh \
	     contrib/dhcp.spec contrib/sethostname.sh contrib/solaris.init \
	     contrib/ms2isc/Registry.pm contrib/ms2isc/ms2isc.pl \
	     contrib/ms2isc/readme.txt \
	     doc/IANA-arp-parameters doc/Makefile doc/References.html \
	     doc/References.txt doc/References.xml doc/api+protocol \
	     doc/ja_JP.eucJP/dhclient-script.8 doc/ja_JP.eucJP/dhclient.8 \
	     doc/ja_JP.eucJP/dhclient.conf.5 doc/ja_JP.eucJP/dhclient.leases.5 \
	     doc/ja_JP.eucJP/dhcp-eval.5 doc/ja_JP.eucJP/dhcp-options.5 \
	     tests/failover/dhcp-1.cf tests/failover/dhcp-2.cf \
	     tests/failover/new-failover \
	     tests/DHCPv6/000-badmsgtype.pl \
	     tests/DHCPv6/010-solicit-noclientid.pl \
	     tests/DHCPv6/011-solicit-serverid.pl \
	     tests/DHCPv6/020-advertise-mcast.pl \
	     tests/DHCPv6/030-request-noclientid.pl \
	     tests/DHCPv6/031-request-noserverid.pl \
	     tests/DHCPv6/032-request-badduid.pl \
	     tests/DHCPv6/110-information-request-ia_na.pl \
	     tests/DHCPv6/111-information-request-ia_ta.pl \
	     tests/DHCPv6/112-badduid.pl \
	     tests/DHCPv6/210-solicit-nohost.pl \
	     tests/DHCPv6/211-solicit-opt-in-na.pl \
	     tests/DHCPv6/212-solicit-opt-in-na-norapidcommit.pl \
	     tests/DHCPv6/280-release-nohost.pl \
	     tests/DHCPv6/281-release-bad-address.pl \
	     tests/DHCPv6/282-release-no-address.pl \
	     tests/DHCPv6/283-release.pl \
	     tests/DHCPv6/290-decline-nohost.pl \
	     tests/DHCPv6/291-decline-bad-address.pl \
	     tests/DHCPv6/292-decline-no-address.pl \
	     tests/DHCPv6/293-decline.pl \
	     tests/DHCPv6/README tests/DHCPv6/dhcp_client.pm \
	     tests/DHCPv6/stubcli-opt-in-na.pl tests/DHCPv6/stubcli.pl \
	     tests/DHCPv6/test-a.conf tests/DHCPv6/test-b.conf

SUBDIRS = includes common minires dst omapip client dhcpctl relay server

nobase_include_HEADERS = dhcpctl/dhcpctl.h

