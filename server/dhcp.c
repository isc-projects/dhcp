/* dhcp.c

   DHCP Protocol engine. */

/*
 * Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.
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
"$Id: dhcp.c,v 1.73 1998/11/19 20:56:36 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int outstanding_pings;

static char dhcp_message [256];

void dhcp (packet)
	struct packet *packet;
{
	if (!locate_network (packet) && packet -> packet_type != DHCPREQUEST)
		return;

	/* Classify the client. */
	classify_client (packet);

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
	struct lease *lease;
	char msgbuf [1024];

	sprintf (msgbuf, "DHCPDISCOVER from %s via %s",
		 print_hw_addr (packet -> raw -> htype,
				packet -> raw -> hlen,
				packet -> raw -> chaddr),
		 (packet -> raw -> giaddr.s_addr
		  ? inet_ntoa (packet -> raw -> giaddr)
		  : packet -> interface -> name));

	lease = find_lease (packet, packet -> shared_network, 0);

	/* Sourceless packets don't make sense here. */
	if (!packet -> shared_network) {
		note ("Packet from unknown subnet: %s",
		      inet_ntoa (packet -> raw -> giaddr));
		return;
	}

	/* If we didn't find a lease, try to allocate one... */
	if (!lease) {
		lease = allocate_lease (packet,
					packet -> shared_network -> pools, 0);
		if (!lease) {
			note ("no free leases on network %s match %s",
			      packet -> shared_network -> name,
			      print_hw_addr (packet -> raw -> htype,
					     packet -> raw -> hlen,
					     packet -> raw -> chaddr));
			return;
		}
	}

	ack_lease (packet, lease, DHCPOFFER, cur_time + 120, msgbuf);
}

void dhcprequest (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;
	struct subnet *subnet;
	int ours = 0;
	struct option_cache *oc;
	struct data_string data;
	int status;
	char msgbuf [1024];

	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_REQUESTED_ADDRESS);
	memset (&data, 0, sizeof data);
	if (oc &&
	    evaluate_option_cache (&data, packet, &packet -> options, oc)) {
		cip.len = 4;
		memcpy (cip.iabuf, data.data, 4);
		data_string_forget (&data, "dhcprequest");
	} else {
		oc = (struct option_cache *)0;
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr.s_addr, 4);
	}
	subnet = find_subnet (cip);

	/* Find the lease that matches the address requested by the
	   client. */

	if (subnet)
		lease = find_lease (packet, subnet -> shared_network, &ours);
	else
		lease = (struct lease *)0;

	sprintf (msgbuf, "DHCPREQUEST for %s from %s via %s",
		 piaddr (cip),
		 print_hw_addr (packet -> raw -> htype,
				packet -> raw -> hlen,
				packet -> raw -> chaddr),
		 (packet -> raw -> giaddr.s_addr
		  ? inet_ntoa (packet -> raw -> giaddr)
		  : packet -> interface -> name));

	/* If a client on a given network REQUESTs a lease on an
	   address on a different network, NAK it.  If the Requested
	   Address option was used, the protocol says that it must
	   have been broadcast, so we can trust the source network
	   information.

	   If ciaddr was specified and Requested Address was not, then
	   we really only know for sure what network a packet came from
	   if it came through a BOOTP gateway - if it came through an
	   IP router, we'll just have to assume that it's cool.

	   If we don't think we know where the packet came from, it
	   came through a gateway from an unknown network, so it's not
	   from a RENEWING client.  If we recognize the network it
	   *thinks* it's on, we can NAK it even though we don't
	   recognize the network it's *actually* on; otherwise we just
	   have to ignore it.

	   We don't currently try to take advantage of access to the
	   raw packet, because it's not available on all platforms.
	   So a packet that was unicast to us through a router from a
	   RENEWING client is going to look exactly like a packet that
	   was broadcast to us from an INIT-REBOOT client.

	   Since we can't tell the difference between these two kinds
	   of packets, if the packet appears to have come in off the
	   local wire, we have to treat it as if it's a RENEWING
	   client.  This means that we can't NAK a RENEWING client on
	   the local wire that has a bogus address.  The good news is
	   that we won't ACK it either, so it should revert to INIT
	   state and send us a DHCPDISCOVER, which we *can* work with.

	   Because we can't detect that a RENEWING client is on the
	   wrong wire, it's going to sit there trying to renew until
	   it gets to the REBIND state, when we *can* NAK it because
	   the packet will get to us through a BOOTP gateway.  We
	   shouldn't actually see DHCPREQUEST packets from RENEWING
	   clients on the wrong wire anyway, since their idea of their
	   local router will be wrong.  In any case, the protocol
	   doesn't really allow us to NAK a DHCPREQUEST from a
	   RENEWING client, so we can punt on this issue. */

	if (!packet -> shared_network ||
	    (packet -> raw -> ciaddr.s_addr &&
	     packet -> raw -> giaddr.s_addr) ||
	    oc) {
		
		/* If we don't know where it came from but we do know
		   where it claims to have come from, it didn't come
		   from there.   Fry it. */
		if (!packet -> shared_network) {
			if (subnet) {
				note ("%s: wrong network.", msgbuf);
				nak_lease (packet, &cip);
				return;
			}
			/* Otherwise, ignore it. */
			return;
		}

		/* If we do know where it came from and it asked for an
		   address that is not on that shared network, nak it. */
		subnet = find_grouped_subnet (packet -> shared_network, cip);
		if (!subnet) {
			note ("%s: wrong network.", msgbuf);
			nak_lease (packet, &cip);
			return;
		}
	}

	/* If we found a lease for the client but it's not the one the
	   client asked for, don't send it - some other server probably
	   made the cut. */
	if (lease && !addr_eq (lease -> ip_addr, cip)) {
		/* If we found the address the client asked for, but
                   it wasn't what got picked, the lease belongs to us,
                   so we can tenuously justify NAKing it. */
		if (ours) {
			note ("%s: wrong lease %s.", msgbuf, piaddr (cip));
			nak_lease (packet, &cip);
		} else
			note ("%s: unknown lease %s", msgbuf, piaddr (cip));
		return;
	}

	/* If the address the client asked for is ours, but it wasn't
           available for the client, NAK it. */
	if (!lease && ours) {
		note ("%s: lease %s unavailable.", msgbuf, piaddr (cip));
		nak_lease (packet, &cip);
		return;
	}

	/* If we own the lease that the client is asking for,
	   and it's already been assigned to the client, ack it. */
	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_CLIENT_IDENTIFIER);
	if (oc)
		status = evaluate_option_cache (&data, packet,
						&packet -> options, oc);
	else
		status = 0;
	if (status && lease &&
	    ((lease -> uid_len && lease -> uid_len == data.len &&
	      !memcmp (data.data,
		       lease -> uid, lease -> uid_len)) ||
	     (lease -> hardware_addr.hlen == packet -> raw -> hlen &&
	      lease -> hardware_addr.htype == packet -> raw -> htype &&
	      !memcmp (lease -> hardware_addr.haddr,
		       packet -> raw -> chaddr,
		       packet -> raw -> hlen)))) {
		data_string_forget (&data, "dhcprequest");
		ack_lease (packet, lease, DHCPACK, 0, msgbuf);
		return;
	}
	note ("%s: unknown lease %s.", msgbuf, piaddr (cip));
	data_string_forget (&data, "dhcprequest");
}

void dhcprelease (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;
	struct option_cache *oc;
	struct data_string data;

	/* DHCPRELEASE must not specify address in requested-address
           option, but old protocol specs weren't explicit about this,
           so let it go. */
	if ((oc = lookup_option (packet -> options.dhcp_hash,
				 DHO_DHCP_REQUESTED_ADDRESS))) {
		note ("DHCPRELEASE from %s specified requested-address.",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr));
	}

	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_CLIENT_IDENTIFIER);
	memset (&data, 0, sizeof data);
	if (oc &&
	    evaluate_option_cache (&data, packet, &packet -> options, oc)) {
		lease = find_lease_by_uid (data.data, data.len);
		data_string_forget (&data, "dhcprelease");
	} else
		lease = (struct lease *)0;

	/* The client is supposed to pass a valid client-identifier,
	   but the spec on this has changed historically, so try the
	   IP address in ciaddr if the client-identifier fails. */
	if (!lease) {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		lease = find_lease_by_ip_addr (cip);
	}


	note ("DHCPRELEASE of %s from %s via %s (%sfound)",
	      inet_ntoa (packet -> raw -> ciaddr),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name,
	      lease ? "" : "not ");

	/* If we found a lease, release it. */
	if (lease) {
		release_lease (lease);
	}
}

void dhcpdecline (packet)
	struct packet *packet;
{
	struct lease *lease;
	struct iaddr cip;
	struct option_cache *oc;
	struct data_string data;

	/* DHCPDECLINE must specify address. */
	if (!(oc = lookup_option (packet -> options.dhcp_hash,
				  DHO_DHCP_REQUESTED_ADDRESS)))
		return;
	memset (&data, 0, sizeof data);
	if (!evaluate_option_cache (&data, packet, &packet -> options, oc))
		return;

	cip.len = 4;
	memcpy (cip.iabuf, data.data, 4);
	data_string_forget (&data, "dhcpdecline");
	lease = find_lease_by_ip_addr (cip);

	note ("DHCPDECLINE on %s from %s via %s",
	      piaddr (cip),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);

	/* If we found a lease, mark it as unusable and complain. */
	if (lease) {
		abandon_lease (lease, "declined.");
	}
}

void dhcpinform (packet)
	struct packet *packet;
{
	note ("DHCPINFORM from %s",
	      inet_ntoa (packet -> raw -> ciaddr));
}

void nak_lease (packet, cip)
	struct packet *packet;
	struct iaddr *cip;
{
	struct sockaddr_in to;
	struct in_addr from;
	int result;
	struct dhcp_packet raw;
	unsigned char nak = DHCPNAK;
	struct packet outgoing;
	struct hardware hto;
	int i;
	struct data_string data;
	struct option_state options;
	struct expression *expr;
	struct option_cache *oc = (struct option_cache *)0;

	memset (&options, 0, sizeof options);
	memset (&outgoing, 0, sizeof outgoing);
	memset (&raw, 0, sizeof raw);
	outgoing.raw = &raw;

	/* Set DHCP_MESSAGE_TYPE to DHCPNAK */
	if (!option_cache_allocate (&oc, "nak_lease")) {
		warn ("No memory for DHCPNAK message type.");
		return;
	}
	if (!make_const_data (&oc -> expression, &nak, sizeof nak, 0, 0)) {
		warn ("No memory for expr_const expression.");
		option_cache_dereference (&oc, "nak_lease");
		return;
	}
	oc -> option = dhcp_universe.options [DHO_DHCP_MESSAGE_TYPE];
	save_option (options.dhcp_hash, oc);
	option_cache_dereference (&oc, "nak_lease");
		     
	/* Set DHCP_MESSAGE to whatever the message is */
	if (!option_cache_allocate (&oc, "nak_lease")) {
		warn ("No memory for DHCPNAK message type.");
		return;
	}
	if (!make_const_data (&oc -> expression,
			      dhcp_message, strlen (dhcp_message), 1, 0)) {
		warn ("No memory for expr_const expression.");
		option_cache_dereference (&oc, "nak_lease");
		return;
	}
	oc -> option = dhcp_universe.options [DHO_DHCP_MESSAGE];
	save_option (options.dhcp_hash, oc);
	option_cache_dereference (&oc, "nak_lease");
		     
	/* Do not use the client's requested parameter list. */
	delete_option (packet -> options.dhcp_hash,
		       DHO_DHCP_PARAMETER_REQUEST_LIST);

	/* Set up the option buffer... */
	outgoing.packet_length =
		cons_options (packet, outgoing.raw, 0, &options,
			      packet -> agent_options, 0, 0, 0);

/*	memset (&raw.ciaddr, 0, sizeof raw.ciaddr);*/
	raw.siaddr = packet -> interface -> primary_address;
	raw.giaddr = packet -> raw -> giaddr;
	memcpy (raw.chaddr, packet -> raw -> chaddr, sizeof raw.chaddr);
	raw.hlen = packet -> raw -> hlen;
	raw.htype = packet -> raw -> htype;

	raw.xid = packet -> raw -> xid;
	raw.secs = packet -> raw -> secs;
	raw.flags = packet -> raw -> flags | htons (BOOTP_BROADCAST);
	raw.hops = packet -> raw -> hops;
	raw.op = BOOTREPLY;

	/* Report what we're sending... */
	note ("DHCPNAK on %s to %s via %s",
	      piaddr (*cip),
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr),
	      packet -> raw -> giaddr.s_addr
	      ? inet_ntoa (packet -> raw -> giaddr)
	      : packet -> interface -> name);



#ifdef DEBUG_PACKET
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
	dump_packet (&outgoing);
	dump_raw ((unsigned char *)&raw, outgoing.packet_length);
#endif

	hto.htype = packet -> raw -> htype;
	hto.hlen = packet -> raw -> hlen;
	memcpy (hto.haddr, packet -> raw -> chaddr, hto.hlen);

	/* Set up the common stuff... */
	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	from = packet -> interface -> primary_address;

	/* Make sure that the packet is at least as big as a BOOTP packet. */
	if (outgoing.packet_length < BOOTP_MIN_LEN)
		outgoing.packet_length = BOOTP_MIN_LEN;

	/* If this was gatewayed, send it back to the gateway.
	   Otherwise, broadcast it on the local network. */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = local_port;

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					packet, &raw, outgoing.packet_length,
					from, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");
		return;
#endif
	} else {
		to.sin_addr.s_addr = htonl (INADDR_BROADCAST);
		to.sin_port = remote_port;
	}

	errno = 0;
	result = send_packet (packet -> interface,
			      packet, &raw, outgoing.packet_length,
			      from, &to, (struct hardware *)0);
	if (result < 0)
		warn ("send_packet: %m");
}

void ack_lease (packet, lease, offer, when, msg)
	struct packet *packet;
	struct lease *lease;
	unsigned int offer;
	TIME when;
	char *msg;
{
	struct lease lt;
	struct lease_state *state;
	TIME lease_time;
	TIME offered_lease_time;
	struct data_string d1;
	TIME comp_lease_time;
	struct option_cache *oc;
	struct expression *expr;
	int status;
	int option_tag_size = 1; /* XXX */

	int i, j, s1, s2;
	int val;

	/* If we're already acking this lease, don't do it again. */
	if (lease -> state)
		return;

	/* Allocate a lease state structure... */
	state = new_lease_state ("ack_lease");
	if (!state)
		error ("unable to allocate lease state!");
	memset (state, 0, sizeof *state);

	/* Replace the old lease hostname with the new one, if it's changed. */
	oc = lookup_option (packet -> options.dhcp_hash, DHO_HOST_NAME);
	memset (&d1, 0, sizeof d1);
	if (oc)
		s1 = evaluate_option_cache (&d1, packet,
					    &packet -> options, oc);
	if (oc && status &&
	    lease -> client_hostname &&
	    strlen (lease -> client_hostname) == d1.len &&
	    !memcmp (lease -> client_hostname, d1.data, d1.len)) {
		/* Hasn't changed. */
		data_string_forget (&d1, "ack_lease");
	} else if (oc && s1) {
		if (lease -> client_hostname)
			dfree (lease -> client_hostname, "ack_lease");
		lease -> client_hostname =
			dmalloc (d1.len + 1, "ack_lease");
		if (!lease -> client_hostname)
			warn ("no memory for client hostname.\n");
		else {
			memcpy (lease -> client_hostname, d1.data, d1.len);
			lease -> client_hostname [d1.len] = 0;
		}
		data_string_forget (&d1, "ack_lease");
	} else if (lease -> client_hostname) {
		dfree (lease -> client_hostname, "ack_lease");
		lease -> client_hostname = 0;
	}

	/* Process all of the executable statements associated with
	   this lease. */
	memset (&state -> options, 0, sizeof state -> options);
	
	/* Steal the agent options from the packet. */
	if (packet -> options.agent_options) {
		state -> options.agent_options =
			packet -> options.agent_options;
		packet -> options.agent_options = (struct agent_options *)0;
	}

	/* Execute the subnet statements. */
	execute_statements_in_scope (packet, &state -> options,
				     &state -> options,
				     lease -> subnet -> group,
				     (struct group *)0);

	/* Vendor and user classes are only supported for DHCP clients. */
	if (offer) {
		for (i = packet -> class_count; i > 0; i--) {
                        execute_statements_in_scope
				(packet, &state -> options,
				 &state -> options,
				 packet -> classes [i - 1] -> group,
				 (struct group *)0);
		}
	}

	/* If we have a host_decl structure, run the options associated
	   with its group. */
	if (lease -> host)
		execute_statements_in_scope (packet, &state -> options,
					     &state -> options,
					     lease -> host -> group,
					     lease -> subnet -> group);

	/* Make sure this packet satisfies the configured minimum
	   number of seconds. */
	if ((oc = lookup_option (state -> options.server_hash,
				 SV_MIN_SECS))) {
		if (evaluate_option_cache (&d1, packet,
					   &packet -> options, oc)) {
			if (d1.len && packet -> raw -> secs < d1.data [0]) {
				data_string_forget (&d1, "ack_lease");
				note ("%s: %d secs < %d",
				      packet -> raw -> secs, d1.data [0]);
				return;
			}
			data_string_forget (&d1, "ack_lease");
		}
	}

	/* Try to find a matching host declaration for this lease. */
	if (!lease -> host) {
		struct host_decl *hp;

		/* Try to find a host_decl that matches the client
		   identifier or hardware address on the packet, and
		   has no fixed IP address.   If there is one, hang
		   it off the lease so that its option definitions
		   can be used. */
		oc = lookup_option (packet -> options.dhcp_hash,
				    DHO_DHCP_CLIENT_IDENTIFIER);
		if (oc &&
		    evaluate_option_cache (&d1, packet,
					   &packet -> options, oc)) {
			hp = find_hosts_by_uid (d1.data, d1.len);
			data_string_forget (&d1, "dhcpdiscover");
			if (!hp)
				hp = find_hosts_by_haddr
					(packet -> raw -> htype,
					 packet -> raw -> chaddr,
					 packet -> raw -> hlen);
			for (; hp; hp = hp -> n_ipaddr) {
				if (!hp -> fixed_addr)
					break;
			}
			lease -> host = hp;
		} else
			lease -> host = (struct host_decl *)0;
	}

	/* Drop the request if it's not allowed for this client. */
	if (!lease -> host &&
	    (oc = lookup_option (state -> options.server_hash,
				 SV_BOOT_UNKNOWN_CLIENTS))) {
		if (evaluate_option_cache (&d1, packet,
					   &packet -> options, oc)) {
			if (d1.len && !d1.data [0]) {
				note ("%s: unknown", msg);
				data_string_forget (&d1, "ack_lease");
				return;
			}
			data_string_forget (&d1, "ack_lease"); /* mmm, C... */
		}
	} 

	/* Drop the request if it's not allowed for this client. */
	if (!offer &&
	    (oc = lookup_option (state -> options.server_hash,
				 SV_ALLOW_BOOTP))) {
		if (evaluate_option_cache (&d1, packet,
					   &packet -> options, oc)) {
			if (d1.len && !d1.data [0]) {
				data_string_forget (&d1, "ack_lease");
				note ("%s: bootp disallowed", msg);
				return;
			}
			data_string_forget (&d1, "ack_lease");
		}
	} 

	/* Drop the request if booting is specifically denied. */
	oc = lookup_option (state -> options.server_hash, SV_ALLOW_BOOTING);
	if (oc &&
	    evaluate_option_cache (&d1, packet, &packet -> options, oc)) {
		if (d1.len && !d1.data [0]) {
			note ("%s: booting disallowed", msg);
			data_string_forget (&d1, "ack_lease");
			return;
		}
		data_string_forget (&d1, "ack_lease");
	}

	/* If we are configured to do per-class billing, do it. */
	if (have_billing_classes) {

		/* See if the lease is currently being billed to a
		   class, and if so, whether or not it can continue to
		   be billed to that class. */
		if (lease -> billing_class) {
			for (i = 0; i < packet -> class_count; i++)
				if (packet -> classes [i] ==
				    lease -> billing_class)
					break;
			if (i == packet -> class_count)
				unbill_class (lease, lease -> billing_class);
		}
		
		/* If we don't have an active billing, see if we need
		   one, and if we do, try to do so. */
		if (!lease -> billing_class) {
			for (i = 0; i < packet -> class_count; i++) {
				if (!packet -> classes [i] -> lease_limit)
					break;
			}
			if (i == packet -> class_count) {
				for (i = 0; i < packet -> class_count; i++)
					if (bill_class (lease,
							packet -> classes [i]))
						break;
				if (i == packet -> class_count) {
					note ("%s: no available billing", msg);
					return;
				}
			}
		}
	}

	/* Figure out the filename. */
	oc = lookup_option (state -> options.server_hash, SV_FILENAME);
	if (oc)
		evaluate_option_cache (&state -> filename,
				       packet, &packet -> options, oc);

	/* Choose a server name as above. */
	oc = lookup_option (state -> options.server_hash, SV_SERVER_NAME);
	if (oc)
		evaluate_option_cache (&state -> server_name, packet,
				       &packet -> options, oc);

	/* At this point, we have a lease that we can offer the client.
	   Now we construct a lease structure that contains what we want,
	   and call supersede_lease to do the right thing with it. */
	memset (&lt, 0, sizeof lt);

	/* Use the ip address of the lease that we finally found in
	   the database. */
	lt.ip_addr = lease -> ip_addr;

	/* Start now. */
	lt.starts = cur_time;

	/* Figure out how long a lease to assign.    If this is a
	   dynamic BOOTP lease, its duration must be infinite. */
	if (offer) {
		if ((oc = lookup_option (packet -> options.dhcp_hash,
					 DHO_DHCP_LEASE_TIME)))
			s1 = evaluate_option_cache (&d1, packet,
						    &packet -> options, oc);
		else
			s1 = 0;
		if (s1 && d1.len == sizeof (u_int32_t)) {
			lease_time = getULong (d1.data);
			data_string_forget (&d1, "ack_lease");
			comp_lease_time = DEFAULT_MAX_LEASE_TIME;
			if ((oc = lookup_option (state -> options.server_hash,
						 SV_MAX_LEASE_TIME))) {
				if (evaluate_option_cache (&d1, packet,
							   &packet -> options,
							   oc)) {
					if (d1.len == sizeof (u_int32_t))
						comp_lease_time =
							getULong (d1.data);
					data_string_forget (&d1, "ack_lease");
				}
			}

			/* Enforce the maximum lease length. */
			if (lease_time > comp_lease_time)
				lease_time = comp_lease_time;
			
		} else {
			if (s1)
				data_string_forget (&d1, "ack_lease");
			
			lease_time = DEFAULT_DEFAULT_LEASE_TIME;
			if ((oc = lookup_option (state -> options.server_hash,
						 SV_DEFAULT_LEASE_TIME))) {
				if (evaluate_option_cache (&d1, packet,
							   &packet -> options,
							   oc)) {
					if (d1.len == sizeof (u_int32_t))
						lease_time =
							getULong (d1.data);
					data_string_forget (&d1, "ack_lease");
				}
			}
		}
		
		comp_lease_time = DEFAULT_MIN_LEASE_TIME;
		if ((oc = lookup_option (state -> options.server_hash,
					 SV_MIN_LEASE_TIME))) {
			if (evaluate_option_cache (&d1, packet,
						   &packet -> options, oc)) {
				if (d1.len == sizeof (u_int32_t))
					comp_lease_time = getULong (d1.data);
				data_string_forget (&d1, "ack_lease");
			}
		}

		if (lease_time < comp_lease_time)
			lease_time = comp_lease_time;

		state -> offered_expiry = cur_time + lease_time;
		if (when)
			lt.ends = when;
		else
			lt.ends = state -> offered_expiry;
	} else {
		lease_time = MAX_TIME - cur_time;

		if ((oc = lookup_option (state -> options.server_hash,
					 SV_BOOTP_LEASE_LENGTH))) {
			if (evaluate_option_cache (&d1, packet,
						   &packet -> options, oc)) {
				if (d1.len == sizeof (u_int32_t))
					lease_time = getULong (d1.data);
				data_string_forget (&d1, "ack_lease");
			}
		}

		if ((oc = lookup_option (state -> options.server_hash,
					 SV_BOOTP_LEASE_CUTOFF))) {
			if (evaluate_option_cache (&d1, packet,
						   &packet -> options, oc)) {
				if (d1.len == sizeof (u_int32_t))
					lease_time = (getULong (d1.data) -
						      cur_time);
				data_string_forget (&d1, "ack_lease");
			}
		}

		lt.ends = state -> offered_expiry = cur_time + lease_time;
		lt.flags = BOOTP_LEASE;
	}

	lt.timestamp = cur_time;

	/* Record the uid, if given... */
	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_CLIENT_IDENTIFIER);
	if (oc &&
	    evaluate_option_cache (&d1, packet, &packet -> options, oc)) {
		if (d1.len <= sizeof lt.uid_buf) {
			memcpy (lt.uid_buf, d1.data, d1.len);
			lt.uid = lt.uid_buf;
			lt.uid_max = sizeof lt.uid_buf;
			lt.uid_len = d1.len;
		} else {
			lt.uid_max = d1.len;
			lt.uid_len = d1.len;
			lt.uid = (unsigned char *)dmalloc (lt.uid_max,
							   "ack_lease");
			/* XXX inelegant */
			if (!lt.uid)
				error ("can't allocate memory for large uid.");
			memcpy (lt.uid, d1.data, lt.uid_len);
		}
		data_string_forget (&d1, "ack_lease");
	}

	lt.host = lease -> host;
	lt.subnet = lease -> subnet;
	lt.shared_network = lease -> shared_network;
	lt.billing_class = lease -> billing_class;

	/* Don't call supersede_lease on a mocked-up lease. */
	if (lease -> flags & STATIC_LEASE) {
		/* Copy the hardware address into the static lease
		   structure. */
		lease -> hardware_addr.hlen = packet -> raw -> hlen;
		lease -> hardware_addr.htype = packet -> raw -> htype;
		memcpy (lease -> hardware_addr.haddr, packet -> raw -> chaddr,
			sizeof packet -> raw -> chaddr); /* XXX */
	} else {
		/* Record the hardware address, if given... */
		lt.hardware_addr.hlen = packet -> raw -> hlen;
		lt.hardware_addr.htype = packet -> raw -> htype;
		memcpy (lt.hardware_addr.haddr, packet -> raw -> chaddr,
			sizeof packet -> raw -> chaddr);

		/* Install the new information about this lease in the
		   database.  If this is a DHCPACK or a dynamic BOOTREPLY
		   and we can't write the lease, don't ACK it (or BOOTREPLY
		   it) either. */

		if (!(supersede_lease (lease, &lt, !offer || offer == DHCPACK)
		      || (offer && offer != DHCPACK))) {
			note ("%s: database update failed", msg);
			return;
		}
	}

	/* Remember the interface on which the packet arrived. */
	state -> ip = packet -> interface;

	/* Set a flag if this client is a lame Microsoft client that NUL
	   terminates string options and expects us to do likewise. */
	lease -> flags &= ~MS_NULL_TERMINATION;
	if ((oc = lookup_option (packet -> options.dhcp_hash,
				 DHO_HOST_NAME))) {
		if (evaluate_option_cache (&d1, packet,
					   &packet -> options, oc)) {
			if (d1.data [d1.len - 1] == '\0')
				lease -> flags |= MS_NULL_TERMINATION;
			data_string_forget (&d1, "ack_lease");
		}
	}

	/* Remember the giaddr, xid, secs, flags and hops. */
	state -> giaddr = packet -> raw -> giaddr;
	state -> ciaddr = packet -> raw -> ciaddr;
	state -> xid = packet -> raw -> xid;
	state -> secs = packet -> raw -> secs;
	state -> bootp_flags = packet -> raw -> flags;
	state -> hops = packet -> raw -> hops;
	state -> offer = offer;

	/* Get the Maximum Message Size option from the packet, if one
	   was sent. */
	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_MAX_MESSAGE_SIZE);
	if (oc &&
	    evaluate_option_cache (&d1, packet, &packet -> options, oc)) {
		if (d1.len == sizeof (u_int16_t))
			state -> max_message_size = getUShort (d1.data);
		data_string_forget (&d1, "ack_lease");
	}

	/* Steal the agent options from the packet. */
	if (packet -> agent_options) {
		state -> agent_options = packet -> agent_options;
		packet -> agent_options = (struct agent_options *)0;
	}

	/* Now, if appropriate, put in DHCP-specific options that
           override those. */
	if (state -> offer) {
		i = DHO_DHCP_MESSAGE_TYPE;
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     &state -> offer,
					     option_tag_size, 0, 0)) {
				oc -> option =
					dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}
		i = DHO_DHCP_SERVER_IDENTIFIER;
		if (!(oc = lookup_option (state -> options.dhcp_hash, i))) {
		 use_primary:
			oc = (struct option_cache *)0;
			if (option_cache_allocate (&oc, "ack_lease")) {
				if (make_const_data
				    (&oc -> expression,
				     ((unsigned char *)
				      &state -> ip -> primary_address),
				     sizeof state -> ip -> primary_address,
				     0, 0)) {
					oc -> option =
						dhcp_universe.options [i];
					save_option
						(state -> options.dhcp_hash,
						 oc);
				}
				option_cache_dereference (&oc, "ack_lease");
			}
			state -> from.len =
				sizeof state -> ip -> primary_address;
			memcpy (state -> from.iabuf,
				&state -> ip -> primary_address,
				state -> from.len);
		} else {
			if (evaluate_option_cache (&d1, packet,
						   &packet -> options, oc)) {
				if (!d1.len ||
				    d1.len > sizeof state -> from.iabuf)
					goto use_primary;
				memcpy (state -> from.iabuf, d1.data, d1.len);
				state -> from.len = d1.len;
				data_string_forget (&d1, "ack_lease");
			} else
				goto use_primary;
		}

		offered_lease_time =
			state -> offered_expiry - cur_time;

		putULong ((unsigned char *)&state -> expiry,
			  offered_lease_time);
		i = DHO_DHCP_LEASE_TIME;
		if (lookup_option (state -> options.dhcp_hash, i))
			warn ("dhcp-lease-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     (unsigned char *)&state -> expiry,
					     sizeof state -> expiry, 0, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}

		/* Renewal time is lease time * 0.5. */
		offered_lease_time /= 2;
		putULong ((unsigned char *)&state -> renewal,
			  offered_lease_time);
		i = DHO_DHCP_RENEWAL_TIME;
		if (lookup_option (state -> options.dhcp_hash, i))
			warn ("dhcp-renewal-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     (unsigned char *)
					     &state -> renewal,
					     sizeof state -> renewal, 0, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}

		/* Rebinding time is lease time * 0.875. */
		offered_lease_time += (offered_lease_time / 2
				       + offered_lease_time / 4);
		putULong ((unsigned char *)&state -> rebind,
			  offered_lease_time);
		i = DHO_DHCP_REBINDING_TIME;
		if (lookup_option (state -> options.dhcp_hash, i))
			warn ("dhcp-rebinding-time option for %s overridden.",
			      inet_ntoa (state -> ciaddr));
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     (unsigned char *)&state -> rebind,
					     sizeof state -> rebind, 0, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}
	}

	/* Use the subnet mask from the subnet declaration if no other
	   mask has been provided. */
	i = DHO_SUBNET_MASK;
	if (!lookup_option (state -> options.dhcp_hash, i)) {
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     lease -> subnet -> netmask.iabuf,
					     lease -> subnet -> netmask.len,
					     0, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}
	}

	/* Use the hostname from the host declaration if there is one
	   and no hostname has otherwise been provided, and if the 
	   use-host-decl-name flag is set. */
	i = DHO_HOST_NAME;
	j = SV_USE_HOST_DECL_NAMES;
	if (!lookup_option (state -> options.dhcp_hash, i) &&
	    lease -> host && lease -> host -> name &&
	    (evaluate_boolean_option_cache
	     (packet, &packet -> options,
	      (lookup_option
	       (state -> options.server_hash, j))))) {
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     lease -> host -> name,
					     strlen (lease -> host -> name),
					     1, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}
	}

	/* If we don't have a hostname yet, and we've been asked to do
	   a reverse lookup to find the hostname, do it. */
	j = SV_GET_LEASE_HOSTNAMES;
	if (!lookup_option (state -> options.dhcp_hash, i) &&
	    (evaluate_boolean_option_cache
	     (packet, &packet -> options,
	      lookup_option (state -> options.server_hash, j)))) {
		struct in_addr ia;
		struct hostent *h;
		
		memcpy (&ia, lease -> ip_addr.iabuf, 4);
		
		h = gethostbyaddr ((char *)&ia, sizeof ia, AF_INET);
		if (!h)
			warn ("No hostname for %s", inet_ntoa (ia));
		else {
			oc = (struct option_cache *)0;
			if (option_cache_allocate (&oc, "ack_lease")) {
				if (make_const_data (&oc -> expression,
						     h -> h_name,
						     strlen (h -> h_name) + 1,
						     1, 1)) {
					oc -> option =
						dhcp_universe.options [i];
					save_option
						(state -> options.dhcp_hash,
						 oc);
				}
				option_cache_dereference (&oc, "ack_lease");
			}
		}
	}

	/* If so directed, use the leased IP address as the router address.
	   This supposedly makes Win95 machines ARP for all IP addresses,
	   so if the local router does proxy arp, you win. */

	if (evaluate_boolean_option_cache
	    (packet, &state -> options,
	     lookup_option (state -> options.server_hash,
			    SV_USE_LEASE_ADDR_FOR_DEFAULT_ROUTE))) {
		i = DHO_ROUTERS;
		oc = (struct option_cache *)0;
		if (option_cache_allocate (&oc, "ack_lease")) {
			if (make_const_data (&oc -> expression,
					     lease -> ip_addr.iabuf,
					     lease -> ip_addr.len, 0, 0)) {
				oc -> option = dhcp_universe.options [i];
				save_option (state -> options.dhcp_hash, oc);
			}
			option_cache_dereference (&oc, "ack_lease");
		}
	}

#ifdef DEBUG_PACKET
	dump_packet (packet);
	dump_raw ((unsigned char *)packet -> raw, packet -> packet_length);
#endif

	lease -> state = state;

	note ("%s", msg);

	/* If this is a DHCPOFFER, ping the lease address before actually
	   sending the offer. */
	if (offer == DHCPOFFER && !(lease -> flags & STATIC_LEASE)) {
		icmp_echorequest (&lease -> ip_addr);
		add_timeout (cur_time + 1, lease_ping_timeout, lease);
		++outstanding_pings;
	} else {
		dhcp_reply (lease);
	}
}

void dhcp_reply (lease)
	struct lease *lease;
{
	int bufs = 0;
	int packet_length;
	struct dhcp_packet raw;
	struct sockaddr_in to;
	struct in_addr from;
	struct hardware hto;
	int result;
	int i;
	struct lease_state *state = lease -> state;
	int nulltp, bootpp;
	struct agent_options *a, *na;
	struct option_tag *ot, *not;
	struct data_string d1;
	struct option_cache *oc;

	if (!state)
		error ("dhcp_reply was supplied lease with no state!");

	/* Compose a response for the client... */
	memset (&raw, 0, sizeof raw);
	memset (&d1, 0, sizeof d1);

	/* Copy in the filename if given; otherwise, flag the filename
	   buffer as available for options. */
	if (state -> filename.len && state -> filename.data) {
		memcpy (raw.file,
			state -> filename.data,
			state -> filename.len > sizeof raw.file
			? sizeof raw.file : state -> filename.len);
		if (sizeof raw.file > state -> filename.len)
			memset (&raw.file [state -> filename.len], 0,
				(sizeof raw.file) - state -> filename.len);
	} else
		bufs |= 1;

	/* Copy in the server name if given; otherwise, flag the
	   server_name buffer as available for options. */
	if (state -> server_name.len && state -> server_name.data) {
		memcpy (raw.sname,
			state -> server_name.data,
			state -> server_name.len > sizeof raw.sname
			? sizeof raw.sname : state -> server_name.len);
		if (sizeof raw.sname > state -> server_name.len)
			memset (&raw.sname [state -> server_name.len], 0,
				(sizeof raw.sname) - state -> server_name.len);
	} else
		bufs |= 2; /* XXX */

	memcpy (raw.chaddr, lease -> hardware_addr.haddr, sizeof raw.chaddr);
	raw.hlen = lease -> hardware_addr.hlen;
	raw.htype = lease -> hardware_addr.htype;

	/* See if this is a Microsoft client that NUL-terminates its
	   strings and expects us to do likewise... */
	if (lease -> flags & MS_NULL_TERMINATION)
		nulltp = 1;
	else
		nulltp = 0;

	/* See if this is a bootp client... */
	if (state -> offer)
		bootpp = 0;
	else
		bootpp = 1;

	/* Insert such options as will fit into the buffer. */
	packet_length = cons_options ((struct packet *)0, &raw,
				      state -> max_message_size,
				      &state -> options,
				      state -> agent_options,
				      bufs, nulltp, bootpp);

	memcpy (&raw.ciaddr, &state -> ciaddr, sizeof raw.ciaddr);
	memcpy (&raw.yiaddr, lease -> ip_addr.iabuf, 4);

	/* Figure out the address of the next server. */
	raw.siaddr = state -> ip -> primary_address;
	if ((oc =
	     lookup_option (state -> options.server_hash, SV_NEXT_SERVER))) {
		if (evaluate_option_cache (&d1, (struct packet *)0,
					   (struct option_state *)0, oc)) {
			/* If there was more than one answer,
			   take the first. */
			if (d1.len >= 4 && d1.data)
				memcpy (&raw.siaddr, d1.data, 4);
			data_string_forget (&d1, "dhcp_reply");
		}
	}

	/*
	 * Free all of the entries in the option_state structure
	 * now that we're done with them.
	 */

	option_state_dereference (&state -> options);

	raw.giaddr = state -> giaddr;

	raw.xid = state -> xid;
	raw.secs = state -> secs;
	raw.flags = state -> bootp_flags;
	raw.hops = state -> hops;
	raw.op = BOOTREPLY;

	/* Say what we're doing... */
	note ("%s on %s to %s via %s",
	      (state -> offer
	       ? (state -> offer == DHCPACK ? "DHCPACK" : "DHCPOFFER")
	       : "BOOTREPLY"),
	      piaddr (lease -> ip_addr),
	      print_hw_addr (lease -> hardware_addr.htype,
			     lease -> hardware_addr.hlen,
			     lease -> hardware_addr.haddr),
	      state -> giaddr.s_addr
	      ? inet_ntoa (state -> giaddr)
	      : state -> ip -> name);

	/* Set up the hardware address... */
	hto.htype = lease -> hardware_addr.htype;
	hto.hlen = lease -> hardware_addr.hlen;
	memcpy (hto.haddr, lease -> hardware_addr.haddr, hto.hlen);

	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

#ifdef DEBUG_PACKET
	dump_raw ((unsigned char *)&raw, packet_length);
#endif

	/* Make sure outgoing packets are at least as big
	   as a BOOTP packet. */
	if (packet_length < BOOTP_MIN_LEN)
		packet_length = BOOTP_MIN_LEN;

	/* If this was gatewayed, send it back to the gateway... */
	if (raw.giaddr.s_addr) {
		to.sin_addr = raw.giaddr;
		to.sin_port = local_port;

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					(struct packet *)0,
					&raw, packet_length,
					raw.siaddr, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");

		free_lease_state (state, "dhcp_reply fallback 1");
		lease -> state = (struct lease_state *)0;
		return;
#endif

	/* If it comes from a client who already knows its address and
	   is not requesting a broadcast response, sent it directly to
	   that client. */
	} else if (raw.ciaddr.s_addr && state -> offer == DHCPACK &&
		   !(raw.flags & htons (BOOTP_BROADCAST))) {
		to.sin_addr = state -> ciaddr;
		to.sin_port = remote_port; /* XXX */

#ifdef USE_FALLBACK
		result = send_fallback (&fallback_interface,
					(struct packet *)0,
					&raw, packet_length,
					raw.siaddr, &to, &hto);
		if (result < 0)
			warn ("send_fallback: %m");
		free_lease_state (state, "dhcp_reply fallback 1");
		lease -> state = (struct lease_state *)0;
		return;
#endif

	/* Otherwise, broadcast it on the local network. */
	} else {
		to.sin_addr.s_addr = htonl (INADDR_BROADCAST);
		to.sin_port = remote_port; /* XXX */
	}

	memcpy (&from, state -> from.iabuf, sizeof from);

	result = send_packet (state -> ip,
			      (struct packet *)0, &raw, packet_length,
			      from, &to, &hto);
	if (result < 0)
		warn ("sendpkt: %m");

	free_lease_state (state, "dhcp_reply");
	lease -> state = (struct lease_state *)0;
}

struct lease *find_lease (packet, share, ours)
	struct packet *packet;
	struct shared_network *share;
	int *ours;
{
	struct lease *uid_lease, *ip_lease, *hw_lease;
	struct lease *lease = (struct lease *)0;
	struct iaddr cip;
	struct host_decl *hp, *host = (struct host_decl *)0;
	struct lease *fixed_lease;
	struct option_cache *oc;
	struct data_string d1;
	int have_client_identifier = 0;
	struct data_string client_identifier;
	int status;

	/* Try to find a host or lease that's been assigned to the
	   specified unique client identifier. */
	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_CLIENT_IDENTIFIER);
	memset (&client_identifier, 0, sizeof client_identifier);
	if (oc &&
	    evaluate_option_cache (&client_identifier,
				   packet, &packet -> options, oc)) {
		/* Remember this for later. */
		have_client_identifier = 1;

		/* First, try to find a fixed host entry for the specified
		   client identifier... */
		hp = find_hosts_by_uid (client_identifier.data,
					client_identifier.len);
		if (hp) {
			/* Remember if we know of this client. */
			packet -> known = 1;
			fixed_lease = mockup_lease (packet, share, hp);
		} else
			fixed_lease = (struct lease *)0;

		if (fixed_lease) {
#if defined (DEBUG_FIND_LEASE)
			note ("Found host for client identifier: %s.",
			      piaddr (fixed_lease -> ip_addr));
#endif
			uid_lease = (struct lease *)0;
		} else {
			host = hp;	/* Save the host if we found one. */

			uid_lease = find_lease_by_uid (client_identifier.data,
						       client_identifier.len);

			/* Find the lease matching this uid that's on the
			   network the packet came from (if any). */
			for (; uid_lease; uid_lease = uid_lease -> n_uid)
				if (uid_lease -> shared_network == share)
					break;
			fixed_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
			note ("Found lease for client identifier: %s.",
			      piaddr (uid_lease -> ip_addr));
#endif
			if (uid_lease &&
			    (uid_lease -> flags & ABANDONED_LEASE)) {
				uid_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
			note ("...but it was abandoned.");
#endif
			}
		}
	} else {
		uid_lease = (struct lease *)0;
		fixed_lease = (struct lease *)0;
	}

	/* If we didn't find a fixed lease using the uid, try doing
	   it with the hardware address... */
	if (!fixed_lease && !host) {
		hp = find_hosts_by_haddr (packet -> raw -> htype,
					  packet -> raw -> chaddr,
					  packet -> raw -> hlen);
		if (hp) {
			/* Remember if we know of this client. */
			packet -> known = 1;
			host = hp; /* Save it for later. */
			fixed_lease = mockup_lease (packet, share, hp);
#if defined (DEBUG_FIND_LEASE)
			if (fixed_lease) {
				note ("Found host for hardware address: %s.",
				      piaddr (fixed_lease -> ip_addr));
			}
#endif
		}
	}

	/* Try to find a lease that's been attached to the client's
	   hardware address... */
	hw_lease = find_lease_by_hw_addr (packet -> raw -> chaddr,
					  packet -> raw -> hlen);
	/* Find the lease that's on the network the packet came from
	   (if any). */
	for (; hw_lease; hw_lease = hw_lease -> n_hw) {
		if (hw_lease -> shared_network == share) {
			if (hw_lease -> flags & ABANDONED_LEASE)
				continue;
			/* If we're allowed to use this lease, do so. */
			if (!((hw_lease -> pool -> prohibit_list &&
			       permitted (packet,
					  hw_lease -> pool -> prohibit_list)) ||
			      (hw_lease -> pool -> permit_list &&
			       !permitted (packet,
					   hw_lease -> pool -> permit_list))))
				break;
		}
	}
#if defined (DEBUG_FIND_LEASE)
	if (hw_lease)
		note ("Found lease for hardware address: %s.",
		      piaddr (hw_lease -> ip_addr));
#endif

	/* Try to find a lease that's been allocated to the client's
	   IP address. */

	oc = lookup_option (packet -> options.dhcp_hash,
			    DHO_DHCP_REQUESTED_ADDRESS);
	memset (&d1, 0, sizeof d1);
	if (oc)
		status = evaluate_option_cache (&d1, packet,
						&packet -> options, oc);
	if (oc && status && d1.len == 4) {
			cip.len = 4;
			memcpy (cip.iabuf, d1.data, cip.len);
			ip_lease = find_lease_by_ip_addr (cip);
	} else if (packet -> raw -> ciaddr.s_addr) {
		cip.len = 4;
		memcpy (cip.iabuf, &packet -> raw -> ciaddr, 4);
		ip_lease = find_lease_by_ip_addr (cip);
	} else
		ip_lease = (struct lease *)0;
	if (oc && status)
		data_string_forget (&d1, "find_lease");

#if defined (DEBUG_FIND_LEASE)
	if (ip_lease)
		note ("Found lease for requested address: %s.",
		      piaddr (ip_lease -> ip_addr));
#endif

	/* If ip_lease is valid at this point, set ours to one, so that
	   even if we choose a different lease, we know that the address
	   the client was requesting was ours, and thus we can NAK it. */
	if (ip_lease && ours)
		*ours = 1;

	/* If the requested IP address isn't on the network the packet
	   came from, don't use it.  Allow abandoned leases to be matched
	   here - if the client is requesting it, there's a decent chance
	   that it's because the lease database got trashed and a client
	   that thought it had this lease answered an ARP or PING, causing the
	   lease to be abandoned.   If so, this request probably came from
	   that client. */
	if (ip_lease && (ip_lease -> shared_network != share)) {
		note ("...but it was on the wrong shared network.");
		ip_lease = (struct lease *)0;
	}

	/* Toss ip_lease if it hasn't yet expired and the uid doesn't
	   match */
	if (ip_lease &&
	    ip_lease -> ends >= cur_time &&
	    ip_lease -> uid &&
	    (!have_client_identifier ||
	     ip_lease -> uid_len != client_identifier.len ||
	     memcmp (ip_lease -> uid, client_identifier.data,
		     ip_lease -> uid_len))) {
#if defined (DEBUG_FIND_LEASE)
		if (ip_lease)
			note ("rejecting lease for requested address.");
#endif
		ip_lease = (struct lease *)0;
	}

	/* If for some reason the client has more than one lease
	   on the subnet that matches its uid, pick the one that
	   it asked for and (if we can) free the other. */
	if (ip_lease && uid_lease && ip_lease != uid_lease) {
		if (uid_lease && have_client_identifier &&
		    (ip_lease -> uid_len == client_identifier.len) &&
		    !memcmp (client_identifier.data,
			     ip_lease -> uid, ip_lease -> uid_len)) {
			if (uid_lease -> ends > cur_time)
				warn ("client %s has duplicate leases on %s",
				      print_hw_addr (packet -> raw -> htype,
						     packet -> raw -> hlen,
						     packet -> raw -> chaddr),
				      ip_lease -> shared_network -> name);

			/* If the client is REQUESTing the lease, it shouldn't
			   still be using the old one, so we can free it for
			   allocation.   This is only true if the duplicate
			   lease is on the same network, of course. */

			if (packet -> packet_type == DHCPREQUEST &&
			    share == uid_lease -> shared_network)
				dissociate_lease (uid_lease);

			uid_lease = ip_lease;
			ip_lease = (struct lease *)0;
		}
	}

	/* Toss hw_lease if it hasn't yet expired and the uid doesn't
	   match, except that if the hardware address matches and the
	   client is now doing dynamic BOOTP (and thus hasn't provided
	   a uid) we let the client get away with it. */
	if (hw_lease &&
	    hw_lease -> ends >= cur_time &&
	    hw_lease -> uid &&
	    (!have_client_identifier ||
	     hw_lease -> uid_len != client_identifier.len ||
	     memcmp (hw_lease -> uid, client_identifier.data,
		     hw_lease -> uid_len))) {
		hw_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("rejecting lease for hardware address.");
#endif
	}

	/* Toss extra pointers to the same lease... */
	if (ip_lease == hw_lease) {
		ip_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("hardware lease and ip lease are identical.");
#endif
	}
	if (hw_lease == uid_lease) {
#if defined (DEBUG_FIND_LEASE)
		note ("hardware lease and uid lease are identical.");
#endif
		hw_lease = (struct lease *)0;
	}
	if (ip_lease == uid_lease) {
		ip_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("uid lease and ip lease are identical.");
#endif
	}

	/* If we've already eliminated the lease, it wasn't there to
	   begin with.   If we have come up with a matching lease,
	   set the message to bad network in case we have to throw it out. */
	if (!ip_lease && !hw_lease && !uid_lease) {
		strcpy (dhcp_message, "requested address not available");
	} else {
		strcpy (dhcp_message, "requested address on bad subnet");
	}

	/* Now eliminate leases that are on the wrong network... */
	if (ip_lease &&
	    (share != ip_lease -> shared_network)) {
		release_lease (ip_lease);
		ip_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("lease on requested address is on wrong network.");
#endif
	}
	if (uid_lease &&
	    (share != uid_lease -> shared_network)) {
		release_lease (uid_lease);
		uid_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("lease matching uid is on wrong network.");
#endif
	}
	if (hw_lease &&
	    (share != hw_lease -> shared_network)) {
		release_lease (hw_lease);
		hw_lease = (struct lease *)0;
#if defined (DEBUG_FIND_LEASE)
		note ("lease matching hardware address is on wrong network.");
#endif
	}

	/* At this point, if fixed_lease is nonzero, we can assign it to
	   this client. */
	if (fixed_lease) {
		lease = fixed_lease;
#if defined (DEBUG_FIND_LEASE)
		note ("choosing fixed address.");
#endif
	}

	/* If we got a lease that matched the ip address and don't have
	   a better offer, use that; otherwise, release it. */
	if (ip_lease) {
		if (lease) {
			/* XXX How is it possible to get here? */
			if (packet -> packet_type == DHCPREQUEST)
				release_lease (ip_lease);
#if defined (DEBUG_FIND_LEASE)
			note ("not choosing requested address (!).");
#endif
		} else {
#if defined (DEBUG_FIND_LEASE)
			note ("choosing lease on requested address.");
#endif
			lease = ip_lease;
			lease -> host = (struct host_decl *)0;
		}
	}

	/* If we got a lease that matched the client identifier, we may want
	   to use it, but if we already have a lease we like, we must free
	   the lease that matched the client identifier. */
	if (uid_lease) {
		if (lease) {
			if (packet -> packet_type == DHCPREQUEST)	
				dissociate_lease (uid_lease);
#if defined (DEBUG_FIND_LEASE)
			note ("not choosing uid lease.");
#endif
		} else {
			lease = uid_lease;
			lease -> host = (struct host_decl *)0;
#if defined (DEBUG_FIND_LEASE)
			note ("choosing uid lease.");
#endif
		}
	}

	/* The lease that matched the hardware address is treated likewise. */
	if (hw_lease) {
		if (lease) {
			if (packet -> packet_type == DHCPREQUEST)	
				dissociate_lease (hw_lease);
#if defined (DEBUG_FIND_LEASE)
			note ("not choosing hardware lease.");
#endif
		} else {
			lease = hw_lease;
			lease -> host = (struct host_decl *)0;
#if defined (DEBUG_FIND_LEASE)
			note ("choosing hardware lease.");
#endif
		}
	}

	/* If we found a host_decl but no matching address, try to
	   find a host_decl that has no address, and if there is one,
	   hang it off the lease so that we can use the supplied
	   options. */
	if (lease && host && !lease -> host) {
		for (; host; host = host -> n_ipaddr) {
			if (!host -> fixed_addr) {
				lease -> host = host;
				break;
			}
		}
	}

	if (have_client_identifier)
		data_string_forget (&client_identifier, "find_lease");

#if defined (DEBUG_FIND_LEASE)
	if (lease)
		note ("Returning lease: %s.",
		      piaddr (lease -> ip_addr));
	else
		note ("Not returning a lease.");
#endif

	/* If we find an abandoned lease, take it, but print a
	   warning message, so that if it continues to lose,
	   the administrator will eventually investigate. */
	if (lease && lease -> flags & ABANDONED_LEASE) {
		warn ("Reclaiming REQUESTed abandoned IP address %s.\n",
		      piaddr (lease -> ip_addr));
		lease -> flags &= ~ABANDONED_LEASE;
	}

	return lease;
}

/* Search the provided host_decl structure list for an address that's on
   the specified shared network.  If one is found, mock up and return a
   lease structure for it; otherwise return the null pointer. */

struct lease *mockup_lease (packet, share, hp)
	struct packet *packet;
	struct shared_network *share;
	struct host_decl *hp;
{
	static struct lease mock;
	
	mock.subnet = find_host_for_network (&hp, &mock.ip_addr, share);
	if (!mock.subnet)
		return (struct lease *)0;
	mock.next = mock.prev = (struct lease *)0;
	mock.shared_network = mock.subnet -> shared_network;
	mock.host = hp;
	mock.uid = hp -> client_identifier.data;
	mock.uid_len = hp -> client_identifier.len;
	mock.hardware_addr = hp -> interface;
	mock.starts = mock.timestamp = mock.ends = MIN_TIME;
	mock.flags = STATIC_LEASE;
	return &mock;
}

/* Look through all the pools in a list starting with the specified pool
   for a free lease.   We try to find a virgin lease if we can.   If we
   don't find a virgin lease, we try to find a non-virgin lease that's
   free.   If we can't find one of those, we try to reclaim an abandoned
   lease.   If all of these possibilities fail to pan out, we don't return
   a lease at all. */

struct lease *allocate_lease (packet, pool, ok)
	struct packet *packet;
	struct pool *pool;
	int ok;
{
	struct lease *lease, *lp;
	struct permit *permit;

	if (!pool)
		return (struct lease *)0;

	/* If we aren't elegible to try this pool, try a subsequent one. */
	if ((pool -> prohibit_list &&
	     permitted (packet, pool -> prohibit_list)) ||
	    (pool -> permit_list && !permitted (packet, pool -> permit_list)))
		return allocate_lease (packet, pool -> next, ok);

	lease = pool -> last_lease;

	/* If there are no leases in the pool that have
	   expired, try the next one. */
	if (!lease || lease -> ends > cur_time)
		return allocate_lease (packet, pool -> next, ok);

	/* If we find an abandoned lease, and no other lease qualifies
	   better, take it. */
	if (lease -> flags & ABANDONED_LEASE) {
		/* If we already have a non-abandoned lease that we didn't
		   love, but that's okay, don't reclaim the abandoned lease. */
		if (ok)
			return allocate_lease (packet, pool -> next, ok);
		lp = allocate_lease (packet, pool -> next, 0);
		if (!lp) {
			warn ("Reclaiming abandoned IP address %s.",
			      piaddr (lease -> ip_addr));
			lease -> flags &= ~ABANDONED_LEASE;
			return lease;
		}
		return lp;
	}

	/* If there's a lease we could take, but it had previously been
	   allocated to a different client, try for a virgin lease before
	   stealing it. */
	if (lease -> uid_len || lease -> hardware_addr.hlen) {
		/* If we're already in that boat, no need to consider
		   allocating this particular lease. */
		if (ok)
			return allocate_lease (packet, pool -> next, ok);

		lp = allocate_lease (packet, pool -> next, 1);
		if (lp)
			return lp;
		return lease;
	}

	return lease;
}

/* Determine whether or not a permit exists on a particular permit list
   that matches the specified packet, returning nonzero if so, zero if
   not. */

int permitted (packet, permit_list)
	struct packet *packet;
	struct permit *permit_list;
{
	struct permit *p;
	int i;

	for (p = permit_list; p; p = p -> next) {
		switch (p -> type) {
		      case permit_unknown_clients:
			if (!packet -> known)
				return 1;
			break;

		      case permit_known_clients:
			if (packet -> known)
				return 1;
			break;

		      case permit_authenticated_clients:
			if (packet -> authenticated)
				return 1;
			break;

		      case permit_unauthenticated_clients:
			if (!packet -> authenticated)
				return 1;
			break;

		      case permit_all_clients:
			return 1;

		      case permit_dynamic_bootp_clients:
			if (!packet -> options_valid ||
			    !packet -> packet_type)
				return 1;
			break;
			
		      case permit_class:
			for (i = 0; i < packet -> class_count; i++)
				if (p -> class == packet -> classes [i])
					return 1;
			break;
		}
	}
	return 0;
}

