/* sunos4.h

   System dependencies for SunOS 4 (tested on 4.1.4)... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

/* Basic Integer Types not defined in SunOS headers... */

#define int8_t		char
#define int16_t		short
#define int32_t		int

#define u_int8_t	unsigned char
#define u_int16_t	unsigned short 
#define u_int32_t	unsigned int

#define	ssize_t		int

/* No endian.h either. */
/*
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */
#define LITTLE_ENDIAN   1234    /* LSB first: i386, vax */
#define BIG_ENDIAN      4321    /* MSB first: 68000, ibm, net */
#define PDP_ENDIAN      3412    /* LSB first in word, MSW first in long */

#define BYTE_ORDER      BIG_ENDIAN

/* The jmp_buf type is an array on SunOS, so we can't dereference it
   and must declare it differently. */
#define jbp_decl(x)	jmp_buf x
#define jref(x)		(x)
#define jdref(x)	(x)
#define jrefproto	jmp_buf

#include <syslog.h>
#include <sys/types.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>
#include <poll.h>

extern int h_errno;

#include <net/if.h>
#include <net/if_arp.h>

/*
 * Definitions for IP type of service (ip_tos)
 */
#define IPTOS_LOWDELAY          0x10
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_RELIABILITY       0x04
/*      IPTOS_LOWCOST           0x02 XXX */

/* SunOS systems don't have /var/run, but some sites have added it.
   If you want to put dhcpd.pid in /var/run, define _PATH_DHCPD_PID
   in site.h. */
#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID "/etc/dhcrelay.pid"
#endif

#ifdef __GNUC__
/* Varargs stuff: use stdarg.h instead ... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define VA_start(list, last) va_start (list, last)
#define va_dcl
#else /* !__GNUC__*/
/* Varargs stuff... */
#include <varargs.h>
#define VA_DOTDOTDOT va_alist
#define VA_start(list, last) va_start (list)
#endif /* !__GNUC__*/

/* SunOS doesn't support limited sprintfs. */
#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define NO_SNPRINTF

/* SunOS doesn't supply strerror... */
#define NO_STRERROR
char *strerror PROTO ((int));

#define NEED_INET_ATON

/* By default, use NIT API for receiving and sending packets... */
#if defined (USE_DEFAULT_NETWORK)
#  define USE_NIT
#endif

#define EOL	'\n'
#define VOIDPTR	void *

#include <time.h>
#include <sys/time.h>

#define TIME time_t
#define GET_TIME(x)	time ((x))
