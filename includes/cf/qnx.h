/* qnx.h

   System dependencies for QNX...
*/

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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <setjmp.h>
#include <limits.h>
#include <syslog.h>
#include <sys/select.h>

#include <sys/wait.h>
#include <signal.h>

#include <netdb.h>
extern int h_errno;

#include <net/if.h>
#define INADDR_LOOPBACK ((u_long)0x7f000001)

/* Varargs stuff... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define va_dcl
#define VA_start(list, last) va_start (list, last)

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID "/etc/dhcrelay.pid"
#endif

#define EOL	'\n'
#define VOIDPTR void *

/* Time stuff... */
#include <sys/time.h>
#define TIME time_t
#define GET_TIME(x)	time ((x))
#define TIME_DIFF(high, low)	 	(*(high) - *(low))
#define SET_TIME(x, y)	(*(x) = (y))
#define ADD_TIME(d, s1, s2) (*(d) = *(s1) + *(s2))
#define SET_MAX_TIME(x)	(*(x) = INT_MAX)

typedef unsigned char	u_int8_t;
typedef unsigned short	u_int16_t;
typedef unsigned long	u_int32_t;
typedef signed short	int16_t;
typedef signed long	int32_t;

#define strcasecmp( s1, s2 )			stricmp( s1, s2 )
#define strncasecmp( s1, s2, n )		strnicmp( s1, s2, n )
#define vsnprintf( buf, size, fmt, list )	vsprintf( buf, fbuf, list )
#define random()				rand()

#define HAVE_SA_LEN
#define BROKEN_TM_GMT
#define USE_SOCKETS
#define NO_SNPRINTF
#undef AF_LINK

/*
    NOTE: to get the routing of the 255.255.255.255 broadcasts to work
    under QNX, you need to issue the following command before starting
    the daemon:

    	route add -interface 255.255.255.0 <hostname>

    where <hostname> is replaced by the hostname or IP number of the
    machine that dhcpd is running on.
*/
