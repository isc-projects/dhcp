/* ultrix.h

   System dependencies for Ultrix 4.2 (tested on 4.2a+multicast)... */

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

/* Time stuff... */
#include <sys/time.h>
#define TIME /*struct timeval*/ time_t
#define GET_TIME(x)	gettimeofday ((x), (struct timezone *)0)
#define TIME_DIFF(high, low)	 					\
  (((high) -> tv_sec == (low) -> tv_sec)				\
   ? ((high) -> tv_usec > (low) -> tv_usec				\
      ? 1 : (((high) -> tv_usec == (low) -> tv_usec) ? 0 : -1))		\
   : (high) -> tv_sec - (low) -> tv_sec)
#define SET_TIME(x, y)	(((x) -> tv_sec = ((y))), ((x) -> tv_usec = 0))
#define ADD_TIME(d, s1, s2) {						\
		 (d) -> tv_usec = (s1) -> tv_usec + (s2) -> tv_usec;	\
		 if ((d) -> tv_usec > 1000000 || (d) -> tv_usec < -1000000) { \
			 (d) -> tv_sec = (d) -> tv_usec / 1000000;	\
			 (d) -> tv_usec %= 1000000;			\
		 } else							\
			 (d) -> tv_sec = 0;				\
		 (d) -> tv_sec += (s1) -> tv_sec + (s2) -> tv_sec;	\
	}
#define SET_MAX_TIME(x)	(((x) -> tv_sec = INT_MAX),			\
			 ((x) -> tv_usec = 999999))


