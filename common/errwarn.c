/* errwarn.c

   Errors and warnings... */

/*
 * Copyright (c) 1996 The Internet Software Consortium.
 * All Rights Reserved.
 * Copyright (c) 1995 RadioMail Corporation.  All rights reserved.
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
 * 3. Neither the name of RadioMail Corporation, the Internet Software
 *    Consortium nor the names of its contributors may be used to endorse
 *    or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY RADIOMAIL CORPORATION, THE INTERNET
 * SOFTWARE CONSORTIUM AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL RADIOMAIL CORPORATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software was written for RadioMail Corporation by Ted Lemon
 * under a contract with Vixie Enterprises.   Further modifications have
 * been made for the Internet Software Consortium under a contract
 * with Vixie Laboratories.
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <errno.h>

static void do_percentm PROTO ((char *obuf, char *ibuf));

static char mbuf [1024];
static char fbuf [1024];

/* Log an error message, then exit... */

void error (ANSI_DECL(char *) fmt, VA_DOTDOTDOT)
     KandR (char *fmt;)
     va_dcl
{
  va_list list;
  extern int logged_in;

  do_percentm (fbuf, fmt);

  VA_start (list, fmt);
  vsnprintf (mbuf, sizeof mbuf, fbuf, list);
  va_end (list);
#ifndef DEBUG
  syslog (log_priority | LOG_ERR, mbuf);
#else
  write (1, mbuf, strlen (mbuf));
  write (1, "\n", 1);
#endif

  cleanup ();
  exit (1);
}

/* Log a warning message... */

int warn (ANSI_DECL (char *) fmt, VA_DOTDOTDOT)
     KandR (char *fmt;)
     va_dcl
{
  va_list list;

  do_percentm (fbuf, fmt);

  VA_start (list, fmt);
  vsnprintf (mbuf, sizeof mbuf, fbuf, list);
  va_end (list);
#ifndef DEBUG
  syslog (log_priority | LOG_ERR, mbuf);
#else
  write (1, mbuf, strlen (mbuf));
  write (1, "\n", 1);
#endif
  return 0;
}

/* Log a note... */

int note (ANSI_DECL (char *) fmt, VA_DOTDOTDOT)
     KandR (char *fmt;)
     va_dcl
{
  va_list list;

  do_percentm (fbuf, fmt);

  VA_start (list, fmt);
  vsnprintf (mbuf, sizeof mbuf, fbuf, list);
  va_end (list);
#ifndef DEBUG
  syslog (log_priority | LOG_INFO, mbuf);
#else
  write (1, mbuf, strlen (mbuf));
  write (1, "\n", 1);
#endif
  return 0;
}

/* Log a debug message... */

int debug (ANSI_DECL (char *) fmt, VA_DOTDOTDOT)
     KandR (char *fmt;)
     va_dcl
{
  va_list list;

  do_percentm (fbuf, fmt);

  VA_start (list, fmt);
  vsnprintf (mbuf, sizeof mbuf, fbuf, list);
  va_end (list);
#ifndef DEBUG
  syslog (log_priority | LOG_DEBUG, mbuf);
#else
  write (1, mbuf, strlen (mbuf));
  write (1, "\n", 1);
#endif
  return 0;
}

/* Find %m in the input string and substitute an error message string. */

static void do_percentm (obuf, ibuf)
     char *obuf;
     char *ibuf;
{
  char *s = ibuf;
  char *p = obuf;
  int infmt = 0;

  while (*s)
    {
      if (infmt)
	{
	  if (*s == 'm')
	    {
	      strcpy (p - 1, strerror (errno));
	      p += strlen (p);
	      ++s;
	    }
	  else
	    *p++ = *s++;
	  infmt = 0;
	}
      else
	{
	  if (*s == '%')
	    infmt = 1;
	  *p++ = *s++;
	}
    }
  *p = 0;
}


int parse_warn (ANSI_DECL (char *) fmt, VA_DOTDOTDOT)
	KandR (char *fmt;)
	va_dcl
{
	extern int tline, tlpos;
	va_list list;
	
	do_percentm (mbuf, fmt);
#ifndef NO_SNPRINTF
	snprintf (fbuf, sizeof fbuf, "dhcpd.conf line %d char %d: %s",
		  tline, tlpos, mbuf);
#else
	sprintf (fbuf, "dhcpd.conf line %d char %d: %s", tline, tlpos, mbuf);
#endif
	
	VA_start (list, fmt);
	vsnprintf (mbuf, sizeof mbuf, fbuf, list);
	va_end (list);
#ifndef DEBUG
	syslog (log_priority | LOG_ERR, mbuf);
#else
	write (1, mbuf, strlen (mbuf));
	write (1, "\n", 1);
#endif
	return 0;
}

#ifdef NO_STRERROR
char *strerror (err)
	int err;
{
	extern char *sys_errlist [];
	extern int sys_nerr;
	static char errbuf [128];

	if (err < 0 || err >= sys_nerr) {
		sprintf (errbuf, "Error %d", err);
		return errbuf;
	}
	return sys_errlist [err];
}
#endif /* NO_STRERROR */
