/* dhclient.c

   DHCP client program.   Intended for testing. */

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

#include "dhcpd.h"
#include "dhctoken.h"

void do_a_packet (int);
void do_a_line (int);

TIME cur_time;
unsigned char packbuf [65536];	/* Should cover the gnarliest MTU... */

int main (argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
	FILE *cfile = stdin;
	char *val;
	struct sockaddr_in name;
	int sock;
	int flag;
	int token;
	struct dhcp_packet incoming, raw;
	struct packet ip, outgoing;
	struct sockaddr_in from, to;
	struct iaddr ifrom;
	int fromlen = sizeof from;
	int max = 0;
	int count;
	int result;
	int i;
	struct host_decl decl;
	int xid = 1;

	memset (&ip, 0, sizeof ip);

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	/* Get the current time... */
	GET_TIME (&cur_time);

	name.sin_family = AF_INET;
	name.sin_port = htons (2001);
	name.sin_addr.s_addr = htonl (INADDR_ANY);
	memset (name.sin_zero, 0, sizeof (name.sin_zero));

	/* List addresses on which we're listening. */
	note ("Receiving on %s, port %d",
	      inet_ntoa (name.sin_addr), htons (name.sin_port));
	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		error ("Can't create dhcp socket: %m");

	flag = 1;
	if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR,
			&flag, sizeof flag) < 0)
		error ("Can't set SO_REUSEADDR option on dhcp socket: %m");

	if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST,
			&flag, sizeof flag) < 0)
		error ("Can't set SO_BROADCAST option on dhcp socket: %m");

	if (bind (sock, (struct sockaddr *)&name, sizeof name) < 0)
		error ("Can't bind to dhcp address: %m");

	if (fork() > 0) {
		while (1)
			do_a_packet (sock);
	} else {
		while (1)
			do_a_line (sock);
	}
}

/* statement :== host_statement */

void parse_client_statement (cfile, decl)
	FILE *cfile;
	struct host_decl *decl;
{
	char *val;
	jmp_buf bc;
	int token;

	switch (next_token (&val, cfile)) {
	      case PACKET:
		memset (decl, 0, sizeof decl);
		if (!setjmp (bc)) {
			do {
				token = peek_token (&val, cfile);
				if (token == SEMI) {
					token = next_token (&val, cfile);
					break;
				}
				parse_host_decl (cfile, &bc, decl);
			} while (1);
		}
		break;
	      default:
		parse_warn ("expecting a declaration.");
		skip_to_semi (cfile);
		break;
	}
}

void cleanup ()
{
}

void do_a_packet (sock)
	int sock;
{
	struct sockaddr_in name;
	int flag;
	struct dhcp_packet incoming;
	struct packet ip;
	struct sockaddr_in from;
	struct iaddr ifrom;
	int fromlen = sizeof from;
	int max = 0;
	int count;
	int result;
	int i;
	int xid = 1;

	if ((result = recvfrom (sock, packbuf, sizeof packbuf, 0,
				(struct sockaddr *)&from, &fromlen)) < 0) {
		warn ("recvfrom failed: %m");
		sleep (5);
		return;
	}
	note ("request from %s, port %d",
	      inet_ntoa (from.sin_addr), htons (from.sin_port));
	ifrom.len = 4;
	memcpy (ifrom.iabuf, &from.sin_addr, ifrom.len);
	memcpy (&incoming, packbuf, result);
	memset (&ip, 0, sizeof ip);
	ip.raw = &incoming;
	ip.packet_length = result;
	ip.client_port = ntohs (from.sin_port);
	ip.client_addr = ifrom;
	ip.client_sock = sock;
	parse_options (&ip);

	dump_packet (&ip);
}

void do_a_line (sock)
	int sock;
{
	int bufs = 0;
	FILE *cfile = stdin;
	char *val;
	int flag;
	int token;
	struct dhcp_packet raw;
	struct packet outgoing;
	struct sockaddr_in to;
	int max = 0;
	int count;
	int result;
	int i;
	struct host_decl decl;
	int xid = 1;

	/* Parse a packet declaration from stdin, or exit if
	   we've hit EOF. */
	token = peek_token (&val, cfile);
	if (token == EOF)
		return;
	memset (&decl, 0, sizeof decl);
	parse_client_statement (cfile, &decl);

	/* Fill in a packet based on the information
	   entered by the user. */
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;
	
	/* Copy in the filename if given; otherwise, flag
	   the filename buffer as available for options. */
	if (decl.filename)
		strncpy (raw.file,
			 decl.filename, sizeof raw.file);
	else
		bufs |= 1;
		
	/* Copy in the server name if given; otherwise, flag
	   the server_name buffer as available for options. */
	if (decl.server_name)
		strncpy (raw.sname,
			 decl.server_name, sizeof raw.sname);
	else
		bufs |= 2;
		
	if (decl.interface_count) {
		memcpy (raw.chaddr,
			decl.interfaces [0].haddr,
			decl.interfaces [0].hlen);
		raw.htype = decl.interfaces [0].htype;
		raw.hlen = decl.interfaces [0].hlen;
		if (decl.interface_count > 1)
			note ("Only one interface used.");
	} else {
		raw.htype = raw.hlen = 0;
	}
	
	cons_options ((struct packet *)0,
		      &outgoing, decl.options, bufs);
	
	if (decl.ciaddr) {
		tree_evaluate (decl.ciaddr);
		memcpy (&raw.ciaddr, decl.ciaddr -> value, decl.ciaddr -> len);
	} else
		memset (&raw.ciaddr, 0, sizeof raw.ciaddr);
		
	if (decl.yiaddr) {
		tree_evaluate (decl.yiaddr);
		memcpy (&raw.yiaddr,
			decl.yiaddr -> value,
			decl.yiaddr -> len);
	} else
		memset (&raw.yiaddr, 0, sizeof raw.yiaddr);
	
	if (decl.siaddr) {
		tree_evaluate (decl.siaddr);
		memcpy (&raw.siaddr,
			decl.siaddr -> value,
			decl.siaddr -> len);
	} else
		memset (&raw.siaddr, 0, sizeof raw.siaddr);
	
	if (decl.giaddr) {
		tree_evaluate (decl.giaddr);
		memcpy (&raw.giaddr,
			decl.giaddr -> value,
			decl.giaddr -> len);
	} else
		memset (&raw.giaddr, 0, sizeof raw.giaddr);
	
	raw.xid = xid++;
	raw.xid = htons (raw.xid);
	raw.secs = 0;
	raw.flags = 0;
	raw.hops = 0;
	raw.op = BOOTREQUEST;
		
	to.sin_port = htons (2000);
	to.sin_addr.s_addr = INADDR_BROADCAST;
	to.sin_family = AF_INET;
	to.sin_len = sizeof to;
	memset (to.sin_zero, 0, sizeof to.sin_zero);
	
	note ("Sending dhcp request to %s, port %d",
	      inet_ntoa (to.sin_addr), htons (to.sin_port));
	
	errno = 0;
	result = sendto (sock, &raw,
			 outgoing.packet_length,
			 0, (struct sockaddr *)&to, sizeof to);
	if (result < 0)
		warn ("sendto: %m");
}
