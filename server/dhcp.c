/* dhcp.c

   DHCP Protocol support. */

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

void dhcp (packet)
	struct packet *packet;
{
	struct lease *uid_lease, *ip_lease, *hw_lease, *lease;
	struct iaddr cip;
	struct lease lt;
	TIME lease_time;

	dump_packet (packet);

	/* Try to find a lease that's been assigned to the specified
	   unique client identifier. */
	if (packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len)
		uid_lease =
			find_lease_by_uid (packet -> options
					   [DHO_DHCP_CLIENT_IDENTIFIER].data,
					   packet -> options
					   [DHO_DHCP_CLIENT_IDENTIFIER].len);
	else
		uid_lease = (struct lease *)0;

	/* Try to find a lease that's been attached to the client's
	   hardware address... */
	hw_lease = find_lease_by_hw_addr (packet -> raw -> chaddr,
					  packet -> raw -> hlen);

	/* Try to find a lease that's been allocated to the client's
	   IP address. */
	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len &&
	    packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len
	    <= sizeof cip.iabuf) {
		cip.len = packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len;
		memcpy (cip.iabuf,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len);
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		ip_lease = find_lease_by_ip_addr (cip);
	} else
		ip_lease = (struct lease *)0;

	printf ("First blush:\n");
	if (ip_lease) {
		printf ("ip_lease: ");
		print_lease (ip_lease);
	}
	if (hw_lease) {
		printf ("hw_lease: ");
		print_lease (hw_lease);
	}
	if (uid_lease) {
		printf ("uid_lease: ");
		print_lease (uid_lease);
	}

	/* Toss extra pointers to the same lease... */
	if (ip_lease == hw_lease)
		ip_lease = (struct lease *)0;
	if (hw_lease == uid_lease)
		hw_lease = (struct lease *)0;
	if (ip_lease == uid_lease)
		ip_lease = (struct lease *)0;

	printf ("Second blush:\n");
	if (ip_lease) {
		printf ("ip_lease: ");
		print_lease (ip_lease);
	}
	if (hw_lease) {
		printf ("hw_lease: ");
		print_lease (hw_lease);
	}
	if (uid_lease) {
		printf ("uid_lease: ");
		print_lease (uid_lease);
	}

	/* If we got an ip address lease, make sure it isn't assigned to
	   some *other* client!   If it was assigned to this client, we'd
	   have zeroed it out above, so the only way we can take it at this
	   point is if some other client had it but it's timed out, or if no
	   other client has ever had it. */
	if (ip_lease &&
	    ip_lease -> ends >= cur_time)
		ip_lease = (struct lease *)0;

	/* Now eliminate leases that are on the wrong subnet... */
	if (ip_lease && packet -> subnet != ip_lease -> contain) {
		release_lease (ip_lease);
		ip_lease = (struct lease *)0;
	}
	if (uid_lease && packet -> subnet != uid_lease -> contain) {
		release_lease (uid_lease);
		uid_lease = (struct lease *)0;
	}
	if (hw_lease && packet -> subnet != hw_lease -> contain) {
		release_lease (hw_lease);
		hw_lease = (struct lease *)0;
	}

	printf ("Third blush:\n");
	if (ip_lease) {
		printf ("ip_lease: ");
		print_lease (ip_lease);
	}
	if (hw_lease) {
		printf ("hw_lease: ");
		print_lease (hw_lease);
	}
	if (uid_lease) {
		printf ("uid_lease: ");
		print_lease (uid_lease);
	}

	/* At this point, if ip_lease is nonzero, we can assign it to
	   this client. */
	lease = ip_lease;

	/* If we got a lease that matched the client identifier, we may want
	   to use it, but if we already have a lease we like, we must free
	   the lease that matched the client identifier. */
	if (uid_lease) {
		if (lease) {
			release_lease (uid_lease);
		} else
			lease = uid_lease;
	}

	/* The lease that matched the hardware address is treated likewise. */
	if (hw_lease) {
		if (lease) {
			release_lease (hw_lease);
		} else
			lease = hw_lease;
	}

	/* If we didn't find a lease, try to allocate one... */
	if (!lease) {
		lease = packet -> subnet -> last_lease;

		/* If there are no leases in that subnet that have
		   expired, we have nothing to offer this client. */
		if (lease -> ends >= cur_time) {
			note ("no free leases on subnet %s",
			      piaddr (packet -> subnet -> net));
			return;
		}
		lease -> host = (struct host_decl *)0;
	}

	/* At this point, we have a lease that we can offer the client.
	   Now we construct a lease structure that contains what we want,
	   and call supersede_lease to do the right thing with it. */

	memset (&lt, 0, sizeof lt);

	/* Use the ip address of the lease that we finally found in
	   the database. */
	lt.ip_addr = lease -> ip_addr;

	/* Start now. */
	lt.starts = cur_time;

	/* Figure out how long a lease to assign. */
	if (packet -> options [DHO_DHCP_LEASE_TIME].len == 4) {
		lease_time = getULong (packet ->
				       options [DHO_DHCP_LEASE_TIME].data);

		/* Don't let the client ask for a longer lease than
		   is supported for this subnet. */
		if (lease_time > packet -> subnet -> max_lease_time)
			lease_time = packet -> subnet -> max_lease_time;
	} else
		lease_time = packet -> subnet -> default_lease_time;
	lt.ends = cur_time + lease_time;

	lt.timestamp = cur_time;

	/* Record the uid, if given... */
	if (packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len) {
		lt.uid_len =
			packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len;
		lt.uid = packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].data;
		packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].data =
			(unsigned char *)0;
		packet -> options [DHO_DHCP_CLIENT_IDENTIFIER].len = 0;
	}

	/* Record the hardware address, if given... */
	lt.hardware_addr.hlen = packet -> raw -> hlen;
	lt.hardware_addr.htype = packet -> raw -> htype;
	memcpy (lt.hardware_addr.haddr, packet -> raw -> chaddr,
		packet -> raw -> hlen);

	lt.host = lease -> host; /* XXX */
	lt.contain = lease -> contain;

	/* Record the transaction id... */
	lt.xid = packet -> raw -> xid;

	/* Install the new information about this lease in the database. */
	supersede_lease (lease, &lt);

	/* Send a response to the client... */
	dump_subnets ();
}
