/* dhcpd.c

   DHCP Server Daemon. */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
 * All rights reserved.
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
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

static char copyright[] =
"Copyright 1995, 1996 The Internet Software Consortium.";
static char arr [] = "All rights reserved.";
static char message [] = "Internet Software Consortium DHCPD $Name:  $";

#include "dhcpd.h"

static void usage PROTO ((void));

TIME cur_time;
TIME default_lease_time = 43200; /* 12 hours... */
TIME max_lease_time = 86400; /* 24 hours... */
struct tree_cache *global_options [256];

struct iaddr server_identifier;
int server_identifier_matched;

#ifdef USE_FALLBACK
struct interface_info fallback_interface;
#endif

u_int16_t server_port;
int log_priority;

int main (argc, argv, envp)
	int argc;
	char **argv, **envp;
{
	int i;
	struct sockaddr_in name;
	struct servent *ent;
#ifndef DEBUG
	int pid;
#endif

#ifdef SYSLOG_4_2
	openlog ("dhcpd", LOG_NDELAY);
	log_priority = LOG_DAEMON;
#else
	openlog ("dhcpd", LOG_NDELAY, LOG_DAEMON);
#endif

#ifndef	NO_PUTENV
	/* ensure mktime() calls are processed in UTC */
	putenv("TZ=GMT0");
#endif /* !NO_PUTENV */

#ifndef DEBUG
#ifndef SYSLOG_4_2
	setlogmask (LOG_UPTO (LOG_INFO));
#endif

	/* Become a daemon... */
	if ((pid = fork ()) < 0)
		error ("Can't fork daemon: %m");
	else if (pid)
		exit (0);
	/* Become session leader and get pid... */
	pid = setsid ();
#endif	
	note (message);
	note (copyright);
	note (arr);

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv [i], "-p")) {
			if (++i == argc)
				usage ();
			server_port = htons (atoi (argv [i]));
			debug ("binding to user-specified port %d",
			       ntohs (server_port));
		} else
			usage ();
	}

	/* Default to the DHCP/BOOTP port. */
	if (!server_port)
	{
		ent = getservbyname ("dhcp", "udp");
		if (!ent)
			server_port = htons (67);
		else
			server_port = ent -> s_port;
		endservent ();
	}
  
	/* Get the current time... */
	GET_TIME (&cur_time);

	/* Read the dhcpd.conf file... */
	readconf ();

	/* Start up the database... */
	db_startup ();

	/* Discover all the network interfaces and initialize them. */
	discover_interfaces ();

	/* Write a pid file. */
	unlink (_PATH_DHCPD_PID);
	if ((i = open (_PATH_DHCPD_PID, O_WRONLY | O_CREAT, 0640)) >= 0) {
		char obuf [20];
		sprintf (obuf, "%d\n", (int)getpid ());
		write (i, obuf, strlen (obuf));
		close (i);
	}

	/* Receive packets and dispatch them... */
	dispatch ();

	/* Not reached */
	return 0;
}

/* Print usage message. */

static void usage ()
{
	error ("Usage: dhcpd [-p <port>] [-a <ip-addr>]");
}

void cleanup ()
{
}
