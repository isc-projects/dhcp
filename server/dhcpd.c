/* dhcpd.c

   DHCP Server Daemon. */

/*
 * Copyright (c) 1995, 1996, 1997, 1998, 1999
 * The Internet Software Consortium.   All rights reserved.
 *
 * Redistribution and use of this source file, source files derived in whole
 * or in part from this source file, and binary files derived in whole or in
 * part from this source file, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *    This copyright notice must appear directly below any initial commentary
 *    describing the file, and may not be preceded by any other copyright
 *    notice.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium (hereafter
 *    referred to as "the ISC") nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 4. This software is a part of the ISC DHCP Distribution.  Redistributions
 *    of this source file or binary files derived from this source file
 *    MUST include all documentation accompanying the ISC release from
 *    which such redistributions are derived of this source file, specifically
 *    the following files (listed relative to the top of the ISC DHCP
 *    distribution directory tree):
 *
 *		README
 *		common/dhcp-contrib.5
 *		common/dhcp-options.5
 *		server/dhcpd.8
 *		server/dhcpd.conf.5
 *		server/dhcpd.leases.5
 *		client/dhclient.8
 *		client/dhclient.conf.5
 *		client/dhclient-script.8
 *		client/dhclient.leases.5
 *		relay/dhcrelay.8
 *
 *    Absence of these files from a distribution you receive does not excuse
 *    you from this requirement - if the distribution you receive does not
 *    contain these files, you must get them from the ISC and include them
 *    in any redistribution of this source file or any derivative work based
 *    wholly or in part on this source file.   It is permissible in a binary
 *    redistribution derived from this source file to include formatted
 *    versions of the manual pages mentioned above, and also to add to or
 *    correct the manual pages and README file mentioned above so long as the
 *    sections labeled CONTRIBUTIONS in these documents are unchanged except
 *    with respect to formatting, so long as the order in which the
 *    CONTRIBUTIONS section appears in these documents is not changed, and
 *    so long as the dhcp-contrib.5 manual page is unchanged except with
 *    respect to formatting.   It is also permissible to redistribute this
 *    source file, source files derived wholly or in part from this source
 *    file, and binaries derived wholly or in part from this source file
 *    accompanied by the aforementioned manual pages translated into another
 *    language.   In this case, the CONTRIBUTIONS section and the
 *    dhcp-contrib.5 section may either be left in their original language
 *    or translated into the new language with such care and diligence as
 *    is required to preserve the original meaning.
 * 5. If, in addition to the documentation mentioned in section 4, this
 *    source file, a source file derived wholly or in part from this source
 *    file, or a binary file derived wholly or in part from this source file
 *    is redistributed with additional printed or electronic documentation,
 *    then that documentation must refer to the dhcp-contrib.5 manual page
 *    in as conspicuous a way as the aforementioned documentation refers to
 *    it, and the dhcp-contrib.5 manual page must be converted into the same
 *    format and be made easily accessible to any recipient of such
 *    redistributions.
 *
 * THIS SOFTWARE IS PROVIDED BY THE ISC AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE ISC OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the ISC by Ted Lemon <mellon@isc.org>
 * in cooperation with Vixie Enterprises and Internet Engines, Inc.  To
 * learn more about the ISC, see ``http://www.vix.com/isc''.   Development
 * of this software is funded through contributions and support contracts.
 * Please see the dhcp-contrib manual page that accompanies this file for
 * information on how you can contribute.
 */

#ifndef lint
static char ocopyright[] =
"$Id: dhcpd.c,v 1.56 1999/02/25 23:30:40 mellon Exp $ Copyright 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.";
#endif

  static char copyright[] =
"Copyright 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.";
static char arr [] = "All rights reserved.";
static char message [] = "Internet Software Consortium DHCP Server V3.0-alpha 980225";
static char contrib [] = "\nPlease contribute if you find this software useful.";
static char url [] = "For info, please visit http://www.isc.org/dhcp-contrib.html\n";

#include "dhcpd.h"

static void usage PROTO ((void));

TIME cur_time;
struct group root_group;

struct iaddr server_identifier;
int server_identifier_matched;

u_int16_t local_port;
u_int16_t remote_port;

int log_priority;
#ifdef DEBUG
int log_perror = -1;
#else
int log_perror = 1;
#endif

char *path_dhcpd_conf = _PATH_DHCPD_CONF;
char *path_dhcpd_db = _PATH_DHCPD_DB;
char *path_dhcpd_pid = _PATH_DHCPD_PID;

int dhcp_max_agent_option_packet_length = DHCP_MTU_MAX;

int main (argc, argv, envp)
	int argc;
	char **argv, **envp;
{
	int i, status;
	struct servent *ent;
	char *s;
	int cftest = 0;
#ifndef DEBUG
	int pidfilewritten = 0;
	int pid;
	char pbuf [20];
	int daemon = 1;
#endif
	int quiet = 0;

	/* Initially, log errors to stderr as well as to syslogd. */
#ifdef SYSLOG_4_2
	openlog ("dhcpd", LOG_NDELAY);
	log_priority = DHCPD_LOG_FACILITY;
#else
	openlog ("dhcpd", LOG_NDELAY, DHCPD_LOG_FACILITY);
#endif

#ifndef DEBUG
#ifndef SYSLOG_4_2
#ifndef __CYGWIN32__ /* XXX */
	setlogmask (LOG_UPTO (LOG_INFO));
#endif
#endif
#endif	

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv [i], "-p")) {
			if (++i == argc)
				usage ();
			for (s = argv [i]; *s; s++)
				if (!isdigit (*s))
					log_fatal ("%s: not a valid UDP port",
					       argv [i]);
			status = atoi (argv [i]);
			if (status < 1 || status > 65535)
				log_fatal ("%s: not a valid UDP port",
				       argv [i]);
			local_port = htons (status);
			log_debug ("binding to user-specified port %d",
			       ntohs (local_port));
		} else if (!strcmp (argv [i], "-f")) {
#ifndef DEBUG
			daemon = 0;
#endif
		} else if (!strcmp (argv [i], "-d")) {
#ifndef DEBUG
			daemon = 0;
#endif
			log_perror = -1;
		} else if (!strcmp (argv [i], "-cf")) {
			if (++i == argc)
				usage ();
			path_dhcpd_conf = argv [i];
		} else if (!strcmp (argv [i], "-lf")) {
			if (++i == argc)
				usage ();
			path_dhcpd_db = argv [i];
		} else if (!strcmp (argv [i], "-pf")) {
			if (++i == argc)
				usage ();
			path_dhcpd_pid = argv [i];
                } else if (!strcmp (argv [i], "-t")) {
			/* test configurations only */
#ifndef DEBUG
			daemon = 0;
#endif
			cftest = 1;
			log_perror = -1;
		} else if (!strcmp (argv [i], "-q")) {
			quiet = 1;
			quiet_interface_discovery = 1;
		} else if (argv [i][0] == '-') {
			usage ();
		} else {
			struct interface_info *tmp =
				((struct interface_info *)
				 dmalloc (sizeof *tmp, "get_interface_list"));
			if (!tmp)
				log_fatal ("Insufficient memory to %s %s",
				       "record interface", argv [i]);
			memset (tmp, 0, sizeof *tmp);
			strcpy (tmp -> name, argv [i]);
			tmp -> next = interfaces;
			tmp -> flags = INTERFACE_REQUESTED;
			interfaces = tmp;
		}
	}

	if (!quiet) {
		log_info (message);
		log_info (copyright);
		log_info (arr);
		log_info (contrib);
		log_info (url);
	}

	/* Default to the DHCP/BOOTP port. */
	if (!local_port)
	{
		ent = getservbyname ("dhcp", "udp");
		if (!ent)
			local_port = htons (67);
		else
			local_port = ent -> s_port;
#ifndef __CYGWIN32__ /* XXX */
		endservent ();
#endif
	}
  
	remote_port = htons (ntohs (local_port) + 1);

	/* Get the current time... */
	GET_TIME (&cur_time);

	/* Initialize DNS support... */
#if 0
	dns_startup (); 
#endif

	/* Start the interactive client listener. */
	interact_startup ();

	/* Set up the client classification system. */
	classification_setup ();

	/* Read the dhcpd.conf file... */
	if (!readconf ())
		log_fatal ("Configuration file errors encountered -- exiting");

        /* test option should cause an early exit */
 	if (cftest) 
 		exit(0);

	/* Start up the database... */
	db_startup ();

	/* Discover all the network interfaces and initialize them. */
	discover_interfaces (DISCOVER_SERVER);

	/* Initialize icmp support... */
	icmp_startup (1, lease_pinged);

#ifndef DEBUG
	if (daemon) {
		/* First part of becoming a daemon... */
		if ((pid = fork ()) < 0)
			log_fatal ("Can't fork daemon: %m");
		else if (pid)
			exit (0);
	}

	/* Read previous pid file. */
	if ((i = open (path_dhcpd_pid, O_RDONLY)) >= 0) {
		status = read (i, pbuf, (sizeof pbuf) - 1);
		close (i);
		pbuf [status] = 0;
		pid = atoi (pbuf);

		/* If the previous server process is not still running,
		   write a new pid file immediately. */
		if (pid && (pid == getpid() || kill (pid, 0) < 0)) {
			unlink (path_dhcpd_pid);
			if ((i = open (path_dhcpd_pid,
				       O_WRONLY | O_CREAT, 0640)) >= 0) {
				sprintf (pbuf, "%d\n", (int)getpid ());
				write (i, pbuf, strlen (pbuf));
				close (i);
				pidfilewritten = 1;
			}
		} else
			log_fatal ("There's already a DHCP server running.\n");
	}

	/* If we were requested to log to stdout on the command line,
	   keep doing so; otherwise, stop. */
	if (log_perror == -1)
		log_perror = 1;
	else
		log_perror = 0;

	if (daemon) {
		/* Become session leader and get pid... */
		close (0);
		close (1);
		close (2);
		pid = setsid ();
	}

	/* If we didn't write the pid file earlier because we found a
	   process running the logged pid, but we made it to here,
	   meaning nothing is listening on the bootp port, then write
	   the pid file out - what's in it now is bogus anyway. */
	if (!pidfilewritten) {
		unlink (path_dhcpd_pid);
		if ((i = open (path_dhcpd_pid,
			       O_WRONLY | O_CREAT, 0640)) >= 0) {
			sprintf (pbuf, "%d\n", (int)getpid ());
			write (i, pbuf, strlen (pbuf));
			close (i);
			pidfilewritten = 1;
		}
	}
#endif /* !DEBUG */

	/* Set up the bootp packet handler... */
	bootp_packet_handler = do_packet;

	/* Receive packets and dispatch them... */
	dispatch ();

	/* Not reached */
	return 0;
}

/* Print usage message. */

static void usage ()
{
	log_info (message);
	log_info (copyright);
	log_info (arr);

	log_fatal ("Usage: dhcpd [-p <UDP port #>] [-d] [-f] [-cf config-file]%s",
	       "\n            [-lf lease-file] [if0 [...ifN]]");
}

void cleanup ()
{
}

void lease_pinged (from, packet, length)
	struct iaddr from;
	u_int8_t *packet;
	int length;
{
	struct lease *lp;

	/* Don't try to look up a pinged lease if we aren't trying to
	   ping one - otherwise somebody could easily make us churn by
	   just forging repeated ICMP EchoReply packets for us to look
	   up. */
	if (!outstanding_pings)
		return;

	lp = find_lease_by_ip_addr (from);

	if (!lp) {
		log_info ("unexpected ICMP Echo Reply from %s", piaddr (from));
		return;
	}

	if (!lp -> state) {
		log_error ("ICMP Echo Reply for %s arrived late or is spurious.\n",
		      piaddr (from));
		return;
	}

	if (lp -> ends > cur_time) {
		log_error ("ICMP Echo reply arrived while lease %s was valid.\n",
		      piaddr (from));
	}

	/* At this point it looks like we pinged a lease and got a
	   response, which shouldn't have happened. */
	free_lease_state (lp -> state, "lease_pinged");
	lp -> state = (struct lease_state *)0;

	abandon_lease (lp, "pinged before offer");
	cancel_timeout (lease_ping_timeout, lp);
	--outstanding_pings;
}

void lease_ping_timeout (vlp)
	void *vlp;
{
	struct lease *lp = vlp;

	--outstanding_pings;
	dhcp_reply (lp);
}
