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

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static void usage PROTO ((void));

TIME cur_time;
TIME default_lease_time = 43200; /* 12 hours... */
TIME max_lease_time = 86400; /* 24 hours... */

struct subnet *local_subnet;
u_int32_t *server_addrlist;
int server_addrcount;
u_int16_t server_port;

int main (argc, argv, envp)
	int argc;
	char **argv, **envp;
{
	struct in_addr addr;
	int port = 0;
	int i;
	struct sockaddr_in name;
	struct iaddr taddr;
	u_int32_t *addrlist = (u_int32_t *)0;
	int addrcount = 0;
	struct tree *addrtree = (struct tree *)0;
	struct servent *ent;
	int sock;
	int pid;
	int result;
	int flag;

	openlog ("dhcpd", LOG_NDELAY, LOG_DAEMON);
#ifndef DEBUG
	setlogmask (LOG_UPTO (LOG_INFO));

	/* Become a daemon... */
	if ((pid = fork ()) < 0)
		error ("Can't fork daemon: %m");
	else if (pid)
		exit (0);
	/* Become session leader and get pid... */
	pid = setsid ();
#endif	
	for (i = 1; i < argc; i++) {
		if (!strcmp (argv [i], "-p")) {
			if (++i == argc)
				usage ();
			server_port = htons (atoi (argv [i]));
			debug ("binding to user-specified port %d\n",
			       ntohs (server_port));
#if 0
		} else if (!strcmp (argv [i], "-a")) {
			if (++i == argc)
				usage ();
			if (inet_aton (argv [i], &addr)) {
				addrtree =
					tree_concat (addrtree,
						     tree_const
						     ((unsigned char *)&addr,
						      sizeof addr));
			} else {
				addrtree = tree_concat (addrtree,
							tree_host_lookup
							(argv [i]));
			}
#endif
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

#if 0
	/* If addresses were specified on the command line, resolve them;
	   otherwise, just get a list of the addresses that are configured
	   on this host and listen on all of them. */
	if (addrtree) {
		tree_evaluate ((unsigned char **)&addrlist,
			       &addrcount, addrtree);
		addrcount /= 4;
		if (!addrcount)
			error ("Server addresses resolve to nothing.");
	} else {
/*		addrlist = get_interface_list (&addrcount); */
#endif
		addr.s_addr = 0;
		addrlist = (u_int32_t *)&(addr.s_addr);
		addrcount = 1;
#if 0
	}
#endif

	taddr.len = 0;
	server_addrlist = get_interface_list (&server_addrcount);
	for (i = 0; i < server_addrcount; i++) {
		struct sockaddr_in foo;
		foo.sin_addr.s_addr = server_addrlist [i];
		printf ("Address %d: %s\n", i, inet_ntoa (foo.sin_addr));

		if (server_addrlist [i] != htonl (INADDR_LOOPBACK)) {
			if (taddr.len) {
				error ("dhcpd currently does not support "
				       "multiple interfaces");
			}
			taddr.len = 4;
			memcpy (taddr.iabuf, &server_addrlist [i], 4);
			local_subnet = find_subnet (taddr);
		}
	}

	/* Listen on the specified (or default) port on each specified
	   (or default) IP address. */
	for (i = 0; i < addrcount; i++) {
		listen_on (server_port, addrlist [i]);
	}

	/* Write a pid file. */
	if ((i = open (_PATH_DHCPD_PID, O_WRONLY | O_CREAT)) >= 0) {
		char obuf [20];
		sprintf (obuf, "%d\n", getpid ());
		write (i, obuf, strlen (obuf));
		close (i);
	}

	dump_subnets ();

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

void do_packet (packbuf, len, from_port, from, sock)
	unsigned char *packbuf;
	int len;
	unsigned long from_port;
	struct iaddr from;
	int sock;
{
	struct packet *tp;
	struct dhcp_packet *tdp;
	struct iaddr ia;

	if (!(tp = new_packet ("do_packet")))
		return;
	if (!(tdp = new_dhcp_packet ("do_packet"))) {
		free_packet (tp, "do_packet");
		return;
	}
	memcpy (tdp, packbuf, len);
	memset (tp, 0, sizeof *tp);
	tp -> raw = tdp;
	tp -> packet_length = len;
	tp -> client_port = from_port;
	tp -> client_addr = from;
	tp -> client_sock = sock;
	
	/* If this came through a gateway, find the corresponding subnet... */
	if (tp -> raw -> giaddr.s_addr) {
		ia.len = 4;
		memcpy (ia.iabuf, &tp -> raw -> giaddr, 4);
		tp -> subnet = find_subnet (ia);
	} else {
		tp -> subnet = local_subnet;
	}

	/* If the subnet from whence this packet came is unknown to us,
	   drop it on the floor... */
	if (!tp -> subnet)
		note ("Packet from unknown subnet: %s",
		      inet_ntoa (tp -> raw -> giaddr));
	else {
		parse_options (tp);
		if (tp -> options_valid &&
		    tp -> options [DHO_DHCP_MESSAGE_TYPE].data)
			dhcp (tp);
		else
			bootp (tp);
	}
}

void dump_packet (tp)
	struct packet *tp;
{
	struct dhcp_packet *tdp = tp -> raw;

	debug ("op = %d  htype = %d  hlen = %d  hops = %d",
	       tdp -> op, tdp -> htype, tdp -> hlen, tdp -> hops);
	debug ("xid = %x  secs = %d  flags = %x",
	       tdp -> xid, tdp -> secs, tdp -> flags);
	debug ("ciaddr = %s  yiaddr = %s",
	       inet_ntoa (tdp -> ciaddr), inet_ntoa (tdp -> yiaddr));
	debug ("siaddr = %s  giaddr = %s",
	       inet_ntoa (tdp -> siaddr), inet_ntoa (tdp -> giaddr));
	debug ("chaddr = %02.2x:%02.2x:%02.2x:%02.2x:%02.2x:%02.2x",
	       ((unsigned char *)(tdp -> chaddr)) [0],
	       ((unsigned char *)(tdp -> chaddr)) [1],
	       ((unsigned char *)(tdp -> chaddr)) [2],
	       ((unsigned char *)(tdp -> chaddr)) [3],
	       ((unsigned char *)(tdp -> chaddr)) [4],
	       ((unsigned char *)(tdp -> chaddr)) [5]);
	debug ("filename = %s\n", tdp -> file);
	debug ("server_name = %s\n", tdp -> sname);
	if (tp -> options_valid) {
		int i;

		for (i = 0; i < 256; i++) {
			if (tp -> options [i].data)
				printf ("  %s = %s\n",
					dhcp_options [i].name,
					pretty_print_option
					(i, tp -> options [i].data,
					 tp -> options [i].len));
		}
	}
}

/* Based on the contents of packet, figure out which interface address
   to use from server_addrlist.   Currently just picks the first
   interface. */

u_int32_t pick_interface (packet)
	struct packet *packet;
{
	if (server_addrlist)
		return server_addrlist [0];
	return 0;
}
