/* bootp.c

   BOOTP Protocol support. */

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

void bootp (packet)
	struct packet *packet;
{
	int result;
	struct host_decl *hp = find_host_by_addr (packet -> raw -> htype,
						  packet -> raw -> chaddr,
						  packet -> raw -> hlen);
	struct packet outgoing;
	struct dhcp_packet raw;
	struct sockaddr_in to;
	struct tree_cache *options [256];
	int i;

	/* If the packet is from a host we don't know, drop it on
	   the floor. XXX */
	if (!hp) {
		note ("Can't find record for BOOTP host %s",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr));
		return;
	}

	/* If we don't have a fixed address for it, drop it. */
	if (!hp -> fixed_addr || !tree_evaluate (hp -> fixed_addr)) {
		note ("No fixed address for BOOTP host %s (%s)",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr),
		      hp -> name);
		return;
	}

	/* Set up the outgoing packet... */
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* Come up with a list of options that we want to send to this
	   client.   Start with the per-subnet options, and then override
	   those with client-specific options. */

	memcpy (options, packet -> subnet -> options, sizeof options);

	for (i = 0; i < 256; i++) {
		if (hp -> options [i])
			options [i] = hp -> options [i];
	}

	/* Pack the options into the buffer.   Unlike DHCP, we can't
	   pack options into the filename and server name buffers. */

	cons_options (packet, &outgoing, options, 0);
	

	/* Take the fields that we care about... */
	raw.op = BOOTREPLY;
	raw.htype = packet -> raw -> htype;
	raw.hlen = packet -> raw -> hlen;
	memcpy (raw.chaddr, packet -> raw -> chaddr, raw.hlen);
	memset (&raw.chaddr [raw.hlen], 0,
		(sizeof raw.chaddr) - raw.hlen);
	raw.hops = packet -> raw -> hops;
	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = 0;
	raw.ciaddr = packet -> raw -> ciaddr;
	if (!tree_evaluate (hp -> fixed_addr))
		warn ("tree_evaluate failed.");
	debug ("fixed_addr: %x %d %d %d %d %x",
	       *(int *)(hp -> fixed_addr -> value), hp -> fixed_addr -> len,
	       hp -> fixed_addr -> buf_size, hp -> fixed_addr -> timeout,
	       hp -> fixed_addr -> tree);
	memcpy (&raw.yiaddr, hp -> fixed_addr -> value,
		sizeof raw.yiaddr);
	raw.siaddr.s_addr = pick_interface (packet);
	raw.giaddr = packet -> raw -> giaddr;
	if (hp -> server_name) {
		strncpy (raw.sname, hp -> server_name,
			 (sizeof raw.sname) - 1);
		raw.sname [(sizeof raw.sname) - 1] = 0;
	}
	if (hp -> filename) {
		strncpy (raw.file, hp -> filename,
			 (sizeof raw.file) - 1);
		raw.file [(sizeof raw.file) - 1] = 0;
	}

	/* If this was gatewayed, send it back to the gateway... */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = server_port;
	/* Otherwise, broadcast it on the local network. */
	} else {
		to.sin_addr.s_addr = INADDR_BROADCAST;
		to.sin_port = htons (ntohs (server_port) + 1); /* XXX */
	}

	to.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	note ("Sending BOOTREPLY to %s, address %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      inet_ntoa (packet -> raw -> yiaddr));

	errno = 0;
	result = sendto (packet -> client_sock, &raw, outgoing.packet_length,
			 0, (struct sockaddr *)&to, sizeof to);
	if (result < 0)
		warn ("sendto: %m");
}
