/* cygwin32.h

   System dependencies for Win32, compiled with Cygwin32... */

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

#include <sys/time.h>

#define IN
#define OUT
#undef fd_set
#undef FD_SET
#undef FD_CLR
#undef FD_ZERO
#undef FD_ISSET
#undef FD_ISCLR
#undef FD_SETSIZE
#define IFNAMSIZ 16
#include <winsock.h>

#include <syslog.h>
#include <string.h>
#include <paths.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <setjmp.h>
#include <limits.h>

#include <sys/wait.h>
#include <signal.h>

#define NO_H_ERRNO

#include <sys/param.h>

/* Varargs stuff... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define va_dcl
#define VA_start(list, last) va_start (list, last)
#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define NO_SNPRINTF

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"//e/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB "//e/etc/dhcpd.leases"
#endif
#ifndef _PATH_DHCPD_CONF
#define _PATH_DHCPD_CONF "//e/etc/dhcpd.conf"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "//e/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCLIENT_DB
#define _PATH_DHCLIENT_DB "//e/etc/dhclient.leases"
#endif
#ifndef _PATH_DHCLIENT_CONF
#define _PATH_DHCLIENT_CONF "//e/etc/dhclient.conf"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID "//e/etc/dhcrelay.pid"
#endif

#ifndef _PATH_RESOLV_CONF
#define _PATH_RESOLV_CONF "//e/etc/resolv.conf"
#endif

#define int8_t		char
#define int16_t		short 
#define int32_t		long 

#define u_int8_t	unsigned char		/* Not quite POSIX... */
#define u_int16_t	unsigned short 
#define u_int32_t	unsigned long 

#define EOL	'\n'
#define VOIDPTR void *

/* Time stuff... */
#define TIME time_t
#define GET_TIME(x)	time ((x))

#if defined (USE_DEFAULT_NETWORK)
#  define USE_SOCKETS
#endif

#ifdef __alpha__
#define PTRSIZE_64BIT
#endif
