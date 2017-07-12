/* cygwin32.h

   System dependencies for Win32, compiled with Cygwin32...   This
   doesn't work yet, so don't get too excited! */

/*
 * Copyright (c) 2004-2017 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-2003 by Internet Software Consortium
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
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

/* XXX: System is not believed to have vsnprintf.  Someone please verify. */
#define NO_SNPRINTF

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"//e/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCPD6_PID
#define _PATH_DHCPD6_PID "//e/etc/dhcpd6.pid"
#endif
#ifndef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB "//e/etc/dhcpd.leases"
#endif
#ifndef _PATH_DHCPD6_DB
#define _PATH_DHCPD6_DB "//e/etc/dhcpd6.leases"
#endif
#ifndef _PATH_DHCPD_CONF
#define _PATH_DHCPD_CONF "//e/etc/dhcpd.conf"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "//e/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCLIENT6_PID
#define _PATH_DHCLIENT6_PID "//e/etc/dhclient6.pid"
#endif
#ifndef _PATH_DHCLIENT_DB
#define _PATH_DHCLIENT_DB "//e/etc/dhclient.leases"
#endif
#ifndef _PATH_DHCLIENT6_DB
#define _PATH_DHCLIENT6_DB "//e/etc/dhclient6.leases"
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
