/* ultrix.h

   System dependencies for Ultrix 4.2 (tested on 4.2a+multicast)... */

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

/* Ultrix uses the old 4.2BSD-style syslog(). */
#include <sys/syslog.h>
#define SYSLOG_4_2

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>

extern int h_errno;

#include <net/if.h>

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID "/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID "/etc/dhcrelay.pid"
#endif

#define int8_t		char
#define int16_t		short 
#define int32_t		long 
#define	ssize_t		long

#define u_int8_t	unsigned char		/* Not quite POSIX... */
#define u_int16_t	unsigned short 
#define u_int32_t	unsigned long 

#define	ssize_t		size_t

/* The jmp_buf type is an array on ultrix, so we can't dereference it
   and must declare it differently. */
#define jbp_decl(x)	jmp_buf x
#define jref(x)		(x)
#define jdref(x)	(x)
#define jrefproto	jmp_buf

#define IPTOS_LOWDELAY		0x10
/*      IPTOS_LOWCOST		0x02 XXX */

/* Varargs stuff... */
#include <varargs.h>
#define VA_DOTDOTDOT va_alist
#define VA_start(list, last) va_start (list)
#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define NO_SNPRINTF
#define NEED_INET_ATON

#define INADDR_LOOPBACK	((u_int32_t)0x7f000001)
#define EOL	'\n'
#define VOIDPTR	void *

/*
 * Time stuff...
 *
 * Definitions for an ISC DHCPD system that uses time_t
 * to represent time internally as opposed to, for example,  struct timeval.)
 */

#define TIME time_t
#define GET_TIME(x)	time ((x))

/* Ultrix doesn't provide an endian.h, but it only runs on little-endian
   machines, so we'll just hack around the issue. */
#define BIG_ENDIAN 1
#define LITTLE_ENDIAN 2
#define BYTE_ORDER LITTLE_ENDIAN

#if defined (USE_DEFAULT_NETWORK)
#  define USE_UPF
#endif
