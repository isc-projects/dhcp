/* bootp.c

   BOOTP Protocol support. */

/*
 * Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.
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

void bootp (packet)
	struct packet *packet;
{
	int result;
	struct host_decl *hp = find_host_by_addr (packet -> raw -> htype,
						  packet -> raw -> chaddr,
						  packet -> raw -> hlen);
	struct dhcp_packet *reply;
	struct sockaddr_in to;

	/* If the packet is from a host we don't know, drop it on
	   the floor. XXX */
	if (!hp) {
		note ("Can't find record for BOOTP host %s",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr));
		return;
	}
	/* If we don't have a fixed address for it, drop it on the floor.
	   XXX */
	if (!hp -> fixed_addr || !tree_evaluate (hp -> fixed_addr)) {
		note ("No fixed address for BOOTP host %s (%s)",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr),
		      hp -> name);
		return;
	}
	reply = new_dhcp_packet ("bootp");
	if (!reply) {
		free_dhcp_packet (packet -> raw, "bootp");
		free_packet (packet, "bootp");
		return;
	}
	/* Take the fields that we care about... */
	reply -> op = BOOTREPLY;
	reply -> htype = packet -> raw -> htype;
	reply -> hlen = packet -> raw -> hlen;
	memcpy (reply -> chaddr, packet -> raw -> chaddr, reply -> hlen);
	memset (&reply -> chaddr [reply -> hlen], 0,
		(sizeof reply -> chaddr) - reply -> hlen);
	reply -> hops = packet -> raw -> hops;
	reply -> xid = packet -> raw -> xid;
	reply -> secs = packet -> raw -> secs;
	reply -> flags = 0;
	reply -> ciaddr = packet -> raw -> ciaddr;
	if (!tree_evaluate (hp -> fixed_addr))
		warn ("tree_evaluate failed.");
	debug ("fixed_addr: %x %d %d %d %d %x",
	       *(int *)(hp -> fixed_addr -> value), hp -> fixed_addr -> len,
	       hp -> fixed_addr -> buf_size, hp -> fixed_addr -> timeout,
	       hp -> fixed_addr -> tree);
	memcpy (&reply -> yiaddr, hp -> fixed_addr -> value,
		sizeof reply -> yiaddr);
	reply -> siaddr.s_addr = pick_interface (packet);
	reply -> giaddr = packet -> raw -> giaddr;
	if (hp -> server_name) {
		strncpy (reply -> sname, hp -> server_name,
			 (sizeof reply -> sname) - 1);
		reply -> sname [(sizeof reply -> sname) - 1] = 0;
	}
	if (hp -> filename) {
		strncpy (reply -> file, hp -> filename,
			 (sizeof reply -> file) - 1);
		reply -> file [(sizeof reply -> file) - 1] = 0;
	}
	reply -> options [0] = 0;
	/* XXX gateways? */
	to.sin_port = server_port;

#if 0
	if (packet -> raw -> flags & BOOTP_BROADCAST)
#endif
		to.sin_addr.s_addr = INADDR_BROADCAST;
#if 0
	else
		to.sin_addr.s_addr = INADDR_ANY;
#endif

	memset (reply -> options, 0, sizeof (reply -> options));
	/* If we got the magic cookie, send it back. */
	if (packet -> options_valid)
		memcpy (reply -> options, packet -> raw -> options, 4);
	to.sin_port = packet -> client.sin_port;
	to.sin_family = AF_INET;
	to.sin_len = sizeof to;
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	note ("Sending bootp reply to %s, port %d",
	      inet_ntoa (to.sin_addr), htons (to.sin_port));

	errno = 0;
	result = sendto (packet -> client_sock, reply,
			 ((char *)(&reply -> options) - (char *)reply) + 64,
			 0, (struct sockaddr *)&to, sizeof to);
	if (result < 0)
		warn ("sendto: %m");
}
