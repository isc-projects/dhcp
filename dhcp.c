/* dhcp.c

   DHCP Protocol engine. */

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

static char dhcp_message [256];

void dhcp (packet)
	struct packet *packet;
{
	switch (packet -> packet_type) {
	      case DHCPDISCOVER:
		dhcpdiscover (packet);
		break;

	      case DHCPREQUEST:
		dhcprequest (packet);
		break;

	      case DHCPRELEASE:
		dhcprelease (packet);
		break;

	      case DHCPDECLINE:
		dhcpdecline (packet);
		break;

	      case DHCPINFORM:
		dhcpinform (packet);
		break;

	      default:
		break;
	}
}

void dhcpdiscover (packet)
	struct packet *packet;
{
	struct lease *lease = find_lease (packet);

	debug ("Received DHCPDISCOVER from %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr));

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

	ack_lease (packet, lease, DHCPOFFER, cur_time + 120);
}

void dhcprequest (packet)
	struct packet *packet;
{
	struct lease *lease = find_lease (packet);
	struct iaddr cip;

	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		cip.len = 4;
		memcpy (cip.iabuf,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data,
			4);
	} else {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr.s_addr, 4);
	}

	debug ("Received DHCPREQUEST from %s for %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr),
	       piaddr (cip));

	/* If a client on our local network wants to renew a lease on
	   an address off our local network, NAK it. */
	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		if (!addr_eq (packet -> subnet -> net,
			      subnet_number (cip,
					     packet -> subnet -> netmask))) {
			nak_lease (packet, &cip);
			return;
		}
	}

	if (packet -> raw -> ciaddr.s_addr) {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		if (!addr_eq (packet -> subnet -> net,
			      subnet_number (cip,
					     packet -> subnet -> netmask))) {
			nak_lease (packet, &cip);
			return;
		}
	}

	/* Look for server identifier... */
	if (packet -> options [DHO_DHCP_SERVER_IDENTIFIER].len) {
		/* If there is one, and it isn't this server, and
		   we have a lease for this client, let it go. */
		if (memcmp (packet ->
			    options [DHO_DHCP_SERVER_IDENTIFIER].data,
			    siaddr.iabuf, siaddr.len)) {
			if (lease)
				release_lease (lease);
			return;
		}
	} else {
		return;
	}

	/* If we didn't find a lease, don't try to allocate one... */
	if (!lease) {
		nak_lease (packet, &cip);
		return;
	}

	ack_lease (packet, lease, DHCPACK, 0);
}

void dhcprelease (packet)
	struct packet *packet;
{
	struct lease *lease = find_lease (packet);

	debug ("Received DHCPRELEASE from %s for %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr),
	       inet_ntoa (packet -> raw -> ciaddr));

	/* If we found a lease, release it. */
	if (lease) {
		release_lease (lease);
	}
}

void dhcpdecline (packet)
	struct packet *packet;
{
	struct lease *lease = find_lease (packet);
	struct iaddr cip;

	if (packet -> options [DHO_DHCP_REQUESTED_ADDRESS].len) {
		cip.len = 4;
		memcpy (cip.iabuf,
			packet -> options [DHO_DHCP_REQUESTED_ADDRESS].data,
			4);
	} else {
		cip.len = 0;
	}

	debug ("Received DHCPDECLINE from %s for %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr),
	       piaddr (cip));

	/* If we found a lease, mark it as unusable and complain. */
	if (lease) {
		abandon_lease (lease);
	}
}

void dhcpinform (packet)
	struct packet *packet;
{
	debug ("Received DHCPINFORM from %s for %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr),
	       inet_ntoa (packet -> raw -> ciaddr));

}

void nak_lease (packet, cip)
	struct packet *packet;
	struct iaddr *cip;
{
	struct sockaddr_in to;
	int result;
	struct dhcp_packet raw;
	unsigned char nak = DHCPNAK;
	struct packet outgoing;

	struct tree_cache *options [256];
	struct tree_cache dhcpnak_tree;
	struct tree_cache dhcpmsg_tree;

	memset (options, 0, sizeof options);
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* Set DHCP_MESSAGE_TYPE to DHCPNAK */
	options [DHO_DHCP_MESSAGE_TYPE] = &dhcpnak_tree;
	options [DHO_DHCP_MESSAGE_TYPE] -> value = &nak;
	options [DHO_DHCP_MESSAGE_TYPE] -> len = sizeof nak;
	options [DHO_DHCP_MESSAGE_TYPE] -> buf_size = sizeof nak;
	options [DHO_DHCP_MESSAGE_TYPE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE_TYPE] -> tree = (struct tree *)0;

	/* Set DHCP_MESSAGE to whatever the message is */
	options [DHO_DHCP_MESSAGE] = &dhcpmsg_tree;
	options [DHO_DHCP_MESSAGE] -> value = dhcp_message;
	options [DHO_DHCP_MESSAGE] -> len = strlen (dhcp_message);
	options [DHO_DHCP_MESSAGE] -> buf_size = strlen (dhcp_message);
	options [DHO_DHCP_MESSAGE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE] -> tree = (struct tree *)0;

	/* Do not use the client's requested parameter list. */
	packet -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].len = 0;
	packet -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].data =
		(unsigned char *)0;

	/* Set up the option buffer... */
	cons_options (packet, &outgoing, options, 0);

/*	memset (&raw.ciaddr, 0, sizeof raw.ciaddr);*/
	memcpy (&raw.siaddr, siaddr.iabuf, 4);
	raw.giaddr = packet -> raw -> giaddr;
	memcpy (raw.chaddr, packet -> raw -> chaddr, sizeof raw.chaddr);
	raw.hlen = packet -> raw -> hlen;
	raw.htype = packet -> raw -> htype;

	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = packet -> raw -> flags | htons (BOOTP_BROADCAST);
	raw.hops = packet -> raw -> hops;
	raw.op = BOOTREPLY;

	/* If this was gatewayed, send it back to the gateway.
	   Otherwise, broadcast it on the local network. */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = server_port;
	} else {
		memcpy (&to.sin_addr.s_addr, cip->iabuf, 4);
		to.sin_port = packet->client_port;
	}

	to.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	note ("Sending DHCPNAK to %s at IP address %s",
	       print_hw_addr (packet -> raw -> htype,
			      packet -> raw -> hlen,
			      packet -> raw -> chaddr),
	      inet_ntoa (to.sin_addr), htons (to.sin_port));

	errno = 0;
	result = sendpkt (packet, &raw, outgoing.packet_length,
				(struct sockaddr *) &to, sizeof(to));
	if (result < 0)
		warn ("sendpkt: %m");

#ifdef DEBUG
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
	dump_packet (&outgoing);
	dump_raw ((unsigned char *)&raw, outgoing.packet_length);
#endif
}

void ack_lease (packet, lease, offer, when)
	struct packet *packet;
	struct lease *lease;
	unsigned char offer;
	TIME when;
{
	struct lease lt;
	TIME lease_time;

	int bufs = 0;
	struct packet outgoing;
	struct dhcp_packet raw;
	struct tree_cache *options [256];
	struct sockaddr_in to;
	int result;

	struct tree_cache dhcpoffer_tree;
	unsigned char lease_time_buf [4];
	struct tree_cache lease_time_tree;
	struct tree_cache server_id_tree;
	struct tree_cache vendor_class_tree;
	struct tree_cache user_class_tree;

	struct class *vendor_class, *user_class;
	char *filename;
	int i;

	if (packet -> options [DHO_DHCP_CLASS_IDENTIFIER].len) {
		vendor_class =
			find_class (0,
				    packet ->
				    options [DHO_DHCP_CLASS_IDENTIFIER].data,
				    packet ->
				    options [DHO_DHCP_CLASS_IDENTIFIER].len);
	} else {
		vendor_class = (struct class *)0;
	}

	if (packet -> options [DHO_DHCP_USER_CLASS_ID].len) {
		user_class =
			find_class (0,
				    packet ->
				    options [DHO_DHCP_USER_CLASS_ID].data,
				    packet ->
				    options [DHO_DHCP_USER_CLASS_ID].len);
	} else {
		user_class = (struct class *)0;
	}

	if (user_class && user_class -> filename)
		filename = user_class -> filename;
	else if (vendor_class  && vendor_class -> filename)
		filename = vendor_class -> filename;
	else filename = (char *)0;

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

	lt.offered_expiry = cur_time + lease_time;
	if (when)
		lt.ends = when;
	else
		lt.ends = lt.offered_expiry;

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

	/* Install the new information about this lease in the database.
	   If this is a DHCPACK and we can't write the lease, don't
	   ACK it either. */
	if (!(supersede_lease (lease, &lt, offer == DHCPACK)
	      || offer != DHCPACK))
	  return;

	/* Send a response to the client... */

	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* Copy in the filename if given; otherwise, flag the filename
	   buffer as available for options. */
	if (filename)
		strncpy (raw.file, filename, sizeof raw.file);
	else
		bufs |= 1;

	/* Copy in the server name if given; otherwise, flag the
	   server_name buffer as available for options. */
	bufs |= 2; /* XXX */

	memcpy (raw.chaddr, packet -> raw -> chaddr, packet -> raw -> hlen);
	raw.hlen = packet -> raw -> hlen;
	raw.htype = packet -> raw -> htype;

	/* Start out with the subnet options... */
	memcpy (options, packet -> subnet -> options, sizeof options);

	/* If we have a vendor class, install those options, superceding
	   any subnet options. */
	if (vendor_class) {
		for (i = 0; i < 256; i++)
			if (vendor_class -> options [i])
				options [i] = vendor_class -> options [i];
	}

	/* If we have a user class, install those options, superceding
	   any subnet and vendor class options. */
	if (user_class) {
		for (i = 0; i < 256; i++)
			if (user_class -> options [i])
				options [i] = user_class -> options [i];
	}

	/* Now put in options that override those. */
	options [DHO_DHCP_MESSAGE_TYPE] = &dhcpoffer_tree;
	options [DHO_DHCP_MESSAGE_TYPE] -> value = &offer;
	options [DHO_DHCP_MESSAGE_TYPE] -> len = sizeof offer;
	options [DHO_DHCP_MESSAGE_TYPE] -> buf_size = sizeof offer;
	options [DHO_DHCP_MESSAGE_TYPE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE_TYPE] -> tree = (struct tree *)0;

	options [DHO_DHCP_SERVER_IDENTIFIER] = &server_id_tree;
	options [DHO_DHCP_SERVER_IDENTIFIER] -> value = siaddr.iabuf;
	options [DHO_DHCP_SERVER_IDENTIFIER] -> len = siaddr.len;
	options [DHO_DHCP_SERVER_IDENTIFIER] -> buf_size = siaddr.len;
	options [DHO_DHCP_SERVER_IDENTIFIER] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_SERVER_IDENTIFIER] -> tree = (struct tree *)0;

	/* If we used the vendor class the client specified, we have to
	   return it. */
	if (vendor_class) {
		options [DHO_DHCP_CLASS_IDENTIFIER] = &vendor_class_tree;
		options [DHO_DHCP_CLASS_IDENTIFIER] -> value =
			vendor_class -> name;
		options [DHO_DHCP_CLASS_IDENTIFIER] -> len = 
			strlen (vendor_class -> name);
		options [DHO_DHCP_CLASS_IDENTIFIER] -> buf_size =
			strlen (vendor_class -> name);
		options [DHO_DHCP_CLASS_IDENTIFIER] -> timeout = 0xFFFFFFFF;
		options [DHO_DHCP_CLASS_IDENTIFIER] -> tree = (struct tree *)0;
	}

	/* If we used the user class the client specified, we have to return
	   it. */
	if (user_class) {
		options [DHO_DHCP_USER_CLASS_ID] = &user_class_tree;
		options [DHO_DHCP_USER_CLASS_ID] -> value =
			user_class -> name;
		options [DHO_DHCP_USER_CLASS_ID] -> len = 
			strlen (user_class -> name);
		options [DHO_DHCP_USER_CLASS_ID] -> buf_size =
			strlen (user_class -> name);
		options [DHO_DHCP_USER_CLASS_ID] -> timeout = 0xFFFFFFFF;
		options [DHO_DHCP_USER_CLASS_ID] -> tree = (struct tree *)0;
	}

	/* Sanity check the lease time. */
 	if ((lease->offered_expiry - cur_time) < 0)
 		putULong(lease_time_buf, packet->subnet->default_lease_time);
 	else if (lease -> offered_expiry - cur_time >
		 packet -> subnet -> max_lease_time) 
 		putULong (lease_time_buf, packet -> subnet -> max_lease_time);
	else 
		putULong(lease_time_buf, lease -> offered_expiry - cur_time);

	putULong (lease_time_buf, lease -> offered_expiry - cur_time);
	options [DHO_DHCP_LEASE_TIME] = &lease_time_tree;
	options [DHO_DHCP_LEASE_TIME] -> value = lease_time_buf;
	options [DHO_DHCP_LEASE_TIME] -> len = sizeof lease_time_buf;
	options [DHO_DHCP_LEASE_TIME] -> buf_size = sizeof lease_time_buf;
	options [DHO_DHCP_LEASE_TIME] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_LEASE_TIME] -> tree = (struct tree *)0;

	cons_options (packet, &outgoing, options, bufs);

	raw.ciaddr = packet -> raw -> ciaddr;
	memcpy (&raw.yiaddr, lease -> ip_addr.iabuf, 4);
	memcpy (&raw.siaddr, siaddr.iabuf, 4);
	raw.giaddr = packet -> raw -> giaddr;

	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = packet -> raw -> flags;
	raw.hops = packet -> raw -> hops;
	raw.op = BOOTREPLY;

	/* If this was gatewayed, send it back to the gateway... */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = server_port;

	/* If it comes from a client who already knows its address,
	   sent it directly to that client. */
	} else if (raw.ciaddr.s_addr && offer == DHCPACK) {
		to.sin_addr = packet -> raw -> ciaddr;
		to.sin_port = htons (ntohs (server_port) + 1); /* XXX */

	/* Otherwise, if we can (we can't), unicast it to the client's
	   hardware address */

	/* Otherwise, broadcast it on the local network. */
	} else {
		memcpy (&to.sin_addr.s_addr, lease -> ip_addr.iabuf, 4);
		to.sin_port = htons (ntohs (server_port) + 1); /* XXX */
	}

	to.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	note ("Sending %s to %s at IP address %s",
	      offer == DHCPACK ? "DHCPACK" : "DHCPOFFER",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      inet_ntoa (to.sin_addr), htons (to.sin_port));

	errno = 0;
	result = sendpkt (packet, &raw, outgoing.packet_length,
				(struct sockaddr *) &to, sizeof(to));
	if (result < 0)
		warn ("sendpkt: %m");

#ifdef DEBUG
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
	dump_packet (&outgoing);
	dump_raw ((unsigned char *)&raw, outgoing.packet_length);
#endif
}

struct lease *find_lease (packet)
	struct packet *packet;
{
	struct lease *uid_lease, *ip_lease, *hw_lease, *lease;
	struct iaddr cip;

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

	/* Toss extra pointers to the same lease... */
	if (ip_lease == hw_lease)
		ip_lease = (struct lease *)0;
	if (hw_lease == uid_lease)
		hw_lease = (struct lease *)0;
	if (ip_lease == uid_lease)
		ip_lease = (struct lease *)0;

	/* If we got an ip address lease, make sure it isn't assigned to
	   some *other* client!   If it was assigned to this client, we'd
	   have zeroed it out above, so the only way we can take it at this
	   point is if some other client had it but it's timed out, or if no
	   other client has ever had it. */
	if (ip_lease &&
	    ip_lease -> ends >= cur_time)
		ip_lease = (struct lease *)0;

	/* If we've already eliminated the lease, it wasn't there to
	   begin with.   If we have come up with a matching lease,
	   set the message to bad network in case we have to throw it out. */
	if (!ip_lease && !hw_lease && !uid_lease) {
		strcpy (dhcp_message, "requested address not available");
	} else {
		strcpy (dhcp_message, "requested address on bad subnet");
	}

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

	return lease;
}
