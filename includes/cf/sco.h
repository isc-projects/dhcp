/* sco.h

   System dependencies for SCO ODT 3.0...

   Based on changes contributed by Gerald Rosenberg. */

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

#include <syslog.h>
#include <sys/types.h>

/* Basic Integer Types not defined in SCO headers... */

typedef char int8_t;
typedef short int16_t;
typedef long int32_t; 

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t; 
typedef unsigned long u_int32_t;

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>

extern int h_errno;

#include <net/if.h>
#include <net/if_arp.h>

/* XXX dunno if this is required for SCO... */
/*
 * Definitions for IP type of service (ip_tos)
 */
#define IPTOS_LOWDELAY          0x10
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_RELIABILITY       0x04
/*      IPTOS_LOWCOST           0x02 XXX */

/* SCO doesn't have /var/run. */
#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID "/etc/dhcrelay.pid"
#endif

#if !defined (INADDR_LOOPBACK)
#define INADDR_LOOPBACK	((u_int32_t)0x7f000001)
#endif

/* Varargs stuff: use stdarg.h instead ... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define VA_start(list, last) va_start (list, last)
#define va_dcl

/* SCO doesn't support limited sprintfs. */
#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define NO_SNPRINTF

/* By default, use BSD Socket API for receiving and sending packets.
   This actually works pretty well on Solaris, which doesn't censor
   the all-ones broadcast address. */
#if defined (USE_DEFAULT_NETWORK)
# define USE_SOCKETS
#endif

#define EOL	'\n'
#define VOIDPTR	void *

/*
 * Time stuff...
 *
 * Definitions for an ISC DHCPD system that uses time_t
 * to represent time internally as opposed to, for example,  struct timeval.)
 */

#include <time.h>

#define TIME time_t
#define GET_TIME(x)	time ((x))
