/* ultrix.h

   System dependencies for Ultrix 4.2 (tested on 4.2a+multicast)... */

/*
 * Copyright 1996 The Board of Trustees of The Leland Stanford
 * Junior University. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.  Stanford University
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 *
 * This file was contributed by Jonathan Stone.
 */

/*
 * Copyright (c) 1996 The Internet Software Consortium.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of RadioMail Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY RADIOMAIL CORPORATION AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * RADIOMAIL CORPORATION OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file was contributed by Jonathan Stone.
 */

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>

#include <netdb.h>
extern int h_errno;

#include <net/if.h>

/*#define _PATH_DHCPD_PID	"/var/run/dhcpd.pid"*/

/*
 * Ultrix systems don't have /var/run, but some sites have added it.
 * if yours  is one, edit this file or define _PATH_DHCPD_PID externally.
 */

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID	"/etc/dhcpd.pid"
#endif


/* Varargs stuff... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define VA_start(list, last) va_start (list, last)
#define va_dcl
#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define snprintf(buf, size, fmt, a1, a2, a3) \
	sprintf(buf, fmt, a1, a2, a3) \

#define INADDR_LOOPBACK	((u_int) htonl((u_int)0x7f000001))
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
#define TIME_DIFF(high, low)	 	(*(high) - *(low))
#define SET_TIME(x, y)	(*(x) = (y))
#define ADD_TIME(d, s1, s2) (*(d) = *(s1) + *(s2))
#define SET_MAX_TIME(x)	(*(x) = INT_MAX)


#if defined (USE_DEFAULT_NETWORK)
#  define USE_SOCKETS
#endif
