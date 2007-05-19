AC_INIT([DHCP], [4.0.0-dev-2006-12-06], [dhcp-users@isc.org])

# we specify "foreign" to avoid having to have the GNU mandated files,
# like AUTHORS, COPYING, and such
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_RANLIB
AC_CONFIG_HEADERS([includes/config.h])

# we sometimes need to know byte order for building packets
AC_C_BIGENDIAN(AC_SUBST(byte_order, BIG_ENDIAN), 
	       AC_SUBST(byte_order, LITTLE_ENDIAN))
AC_DEFINE_UNQUOTED([DHCP_BYTE_ORDER], [$byte_order], 
		   [Define to BIG_ENDIAN for MSB (Motorola or SPARC CPUs)
		    or LITTLE_ENDIAN for LSB (Intel CPUs).])

# DHCPv6 is off by default
AC_ARG_ENABLE(dhcpv6,
	AC_HELP_STRING([--enable-dhcpv6],
		       [enable support for DHCPv6 (default is NO)]),
	AC_DEFINE([DHCPv6], [1], 
		  [Define to 1 to include DHCPv6 support.]))

# Allow specification of alternate state files
AC_ARG_WITH(srv-lease-file,
	AC_HELP_STRING([--with-srv-lease-file=PATH],
		       [File for dhcpd leases 
		        (default is LOCALSTATEDIR/db/dhcpd.leases)]),
	AC_DEFINE_UNQUOTED([_PATH_DHCPD_DB], ["$withval"],
			   [File for dhcpd leases.]))
AC_ARG_WITH(cli-lease-file,
	AC_HELP_STRING([--with-cli-lease-file=PATH],
		       [File for dhclient leases 
		        (default is LOCALSTATEDIR/db/dhclient.leases)]),
	AC_DEFINE_UNQUOTED([_PATH_DHCLIENT_DB], ["$withval"],
			   [File for dhclient leases.]))
AC_ARG_WITH(srv-pid-file,
	AC_HELP_STRING([--with-srv-pid-file=PATH],
		       [File for dhcpd process information
		        (default is LOCALSTATEDIR/run/dhcpd.pid)]),
	AC_DEFINE_UNQUOTED([_PATH_DHCPD_PID], ["$withval"],
			   [File for dhcpd process information.]))
AC_ARG_WITH(cli-pid-file,
	AC_HELP_STRING([--with-cli-pid-file=PATH],
		       [File for dhclient process information
		        (default is LOCALSTATEDIR/run/dhclient.pid)]),
	AC_DEFINE_UNQUOTED([_PATH_DHCLIENT], ["$withval"],
			   [File for dhclient process information.]))
AC_ARG_WITH(relay-pid-file,
	AC_HELP_STRING([--with-relay-pid-file=PATH],
		       [File for dhcrelay process information
		        (default is LOCALSTATEDIR/run/dhcrelay.pid)]),
	AC_DEFINE_UNQUOTED([_PATH_DHCRELAY_PID], ["$withval"],
			   [File for dhcrelay process information.]))

# figure out what IPv4 interface code to use
AC_CHECK_HEADER(linux/filter.h, 
	AC_DEFINE([USE_LPF], [1], 
		  [Define to 1 to use the Linux Packet Filter interface code.]))
AC_CHECK_HEADER(sys/dlpi.h, 
	AC_DEFINE([USE_DLPI], [1], 
		  [Define to 1 to use DLPI interface code.]))
AC_CHECK_HEADER(net/bpf.h,
	AC_DEFINE([USE_BPF], [1],
		  [Define to 1 to use the 
		   Berkeley Packet Filter interface code.]))

# find an MD5 library
AC_SEARCH_LIBS(MD5_Init, [crypto])
AC_SEARCH_LIBS(MD5Init, [crypto])

# Solaris needs some libraries for functions
AC_SEARCH_LIBS(socket, [socket])
AC_SEARCH_LIBS(inet_ntoa, [nsl])

AC_SEARCH_LIBS(inet_aton, [socket nsl], , 
	AC_DEFINE([NEED_INET_ATON], [1], 
		  [Define to 1 if the inet_aton() function is missing.]))

# check for /dev/random (declares HAVE_DEV_RANDOM)
AC_CHECK_FILE(/dev/random,
	AC_DEFINE([HAVE_DEV_RANDOM], [1], 
		  [Define to 1 if you have the /dev/random file.]))

# see if there is a "sa_len" field in our interface information structure
AC_CHECK_MEMBER(struct sockaddr.sa_len,
	AC_DEFINE([HAVE_SA_LEN], [], 
		  [Define to 1 if the sockaddr structure has a length field.]),
	,
	[#include <sys/socket.h>])

AC_OUTPUT(
  Makefile
  client/Makefile
  common/Makefile
  dhcpctl/Makefile
  dst/Makefile
  includes/Makefile
  minires/Makefile
  omapip/Makefile
  relay/Makefile
  server/Makefile
)

